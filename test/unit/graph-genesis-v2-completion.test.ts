import { createHash } from 'node:crypto';
import { chmod, lstat, link, mkdir, mkdtemp, readdir, rename, rm, symlink, writeFile } from 'node:fs/promises';
import { appendFileSync, existsSync, mkdirSync, renameSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import type { GraphGenesisProtectedFile, GraphGenesisWorkspace } from '../../src/stage/graph-genesis.js';
import { SyntheticPostStateV2Authority } from '../../src/stage/graph-genesis-v2-post-state.js';

const roots: string[] = [];
const INVALID = 'graph_genesis_v2_post_state_invalid';
const digest = (value: string) => createHash('sha256').update(value).digest('hex');
const binding = Object.freeze({
  evidenceOrigin: 'synthetic_fixture' as const,
  actionId: '11111111-1111-4111-8111-111111111111',
  approvalId: '22222222-2222-4222-8222-222222222222',
  planHash: digest('plan'), executionEnvelopeHash: digest('envelope'), workspaceBinding: digest('workspace'),
});

afterEach(async () => { await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))); });

async function fixture(lock = '{\n  "name": "fixture",\n  "lockfileVersion": 3,\n  "packages": {}\n}\n') {
  const root = await mkdtemp(join(tmpdir(), 'apg-v2-post-state-')); roots.push(root); await chmod(root, 0o700);
  const protectedContents = new Map([
    ['package.json', '{"name":"fixture"}\n'], ['user.npmrc', ''], ['global.npmrc', ''], ['broker-profile.sb', '(version 1)\n'],
  ]);
  for (const [name, contents] of protectedContents) { await writeFile(join(root, name), contents, { mode: 0o600 }); await chmod(join(root, name), 0o600); }
  for (const name of ['cache', 'logs', 'tmp']) { await mkdir(join(root, name), { mode: 0o700 }); await chmod(join(root, name), 0o700); }
  await writeFile(join(root, 'package-lock.json'), lock, { mode: 0o600 }); await chmod(join(root, 'package-lock.json'), 0o600);
  const protectedFiles: GraphGenesisProtectedFile[] = [];
  for (const [name, contents] of protectedContents) {
    const info = await lstat(join(root, name));
    protectedFiles.push(Object.freeze({ name, device: info.dev, inode: info.ino, mode: 0o600, size: Buffer.byteLength(contents), sha256: digest(contents) }));
  }
  const info = await lstat(root);
  const workspace: GraphGenesisWorkspace = Object.freeze({ workspaceVersion: 1, rootRealpath: root, device: info.dev, inode: info.ino, owner: info.uid, mode: 0o700, protectedFiles: Object.freeze(protectedFiles), initialManifestDigest: digest('initial') });
  return { root, workspace, lockPath: join(root, 'package-lock.json') };
}

async function capture(root: Awaited<ReturnType<typeof fixture>>, checkpoint?: () => void) {
  return new SyntheticPostStateV2Authority().capture({ ...binding, workspace: root.workspace, ...(checkpoint === undefined ? {} : { checkpoint }) });
}

describe('V2 synthetic post-state adversarial boundary', () => {
  it('accepts bounded whitespace JSON but rejects duplicate keys before JSON.parse last-key wins', async () => {
    const valid = await fixture(' \n { "name" : "fixture", "lockfileVersion" : 3, "packages" : { } } \n');
    await expect(capture(valid)).resolves.toMatchObject({ evidenceOrigin: 'synthetic_fixture' });
    const duplicate = await fixture('{"name":"first","name":"second","lockfileVersion":3,"packages":{}}');
    await expect(capture(duplicate)).rejects.toThrow(INVALID);
  });

  it.each(['symlink', 'hardlink', 'executable', 'archive', 'node_modules'] as const)('rejects a nested %s', async (kind) => {
    const value = await fixture();
    const cache = join(value.root, 'cache');
    if (kind === 'symlink') await symlink(value.lockPath, join(cache, 'nested-link'));
    if (kind === 'hardlink') { await writeFile(join(cache, 'base'), 'x', { mode: 0o600 }); await link(join(cache, 'base'), join(cache, 'second')); }
    if (kind === 'executable') { await writeFile(join(cache, 'run'), 'x', { mode: 0o700 }); await chmod(join(cache, 'run'), 0o700); }
    if (kind === 'archive') await writeFile(join(cache, 'payload.tgz'), 'x', { mode: 0o600 });
    if (kind === 'node_modules') { await mkdir(join(cache, 'node_modules'), { mode: 0o700 }); await chmod(join(cache, 'node_modules'), 0o700); }
    await expect(capture(value)).rejects.toThrow(INVALID);
  });

  it('rejects special permission bits rather than masking them away', async () => {
    const value = await fixture();
    await chmod(value.lockPath, 0o1600);
    await expect(capture(value)).rejects.toThrow(INVALID);
  });

  it('rejects depth and per-log byte ceilings without a broad traversal escape', async () => {
    const deep = await fixture(); let directory = join(deep.root, 'cache');
    for (let index = 0; index < 65; index += 1) { directory = join(directory, `d${index}`); await mkdir(directory, { mode: 0o700 }); await chmod(directory, 0o700); }
    await expect(capture(deep)).rejects.toThrow(INVALID);
    const logs = await fixture(); await writeFile(join(logs.root, 'logs', 'too-large'), Buffer.alloc(512 * 1024 + 1), { mode: 0o600 });
    await expect(capture(logs)).rejects.toThrow(INVALID);
  });

  it('fails closed when checkpoints observe concurrent lock growth or root replacement', async () => {
    const growth = await fixture();
    await expect(capture(growth, () => { if (existsSync(growth.lockPath)) appendFileSync(growth.lockPath, ' '); })).rejects.toThrow(INVALID);

    const replaced = await fixture(); const moved = `${replaced.root}-moved`; let swapped = false; let checkpoints = 0;
    await expect(capture(replaced, () => {
      checkpoints += 1;
      if (!swapped && checkpoints >= 2 && existsSync(replaced.root)) {
        swapped = true; renameSync(replaced.root, moved); mkdirSync(replaced.root, { mode: 0o700 });
      }
    })).rejects.toThrow(INVALID);
  });

  it('revalidates a retained state and rejects nested directory replacement after capture', async () => {
    const value = await fixture(); const authority = new SyntheticPostStateV2Authority();
    const state = await authority.capture({ ...binding, workspace: value.workspace });
    const oldCache = join(value.root, 'cache-old'); let checkpoints = 0; let swapped = false;
    await expect(authority.revalidate(state, () => {
      checkpoints += 1;
      if (!swapped && checkpoints >= 3) {
        swapped = true; renameSync(join(value.root, 'cache'), oldCache); mkdirSync(join(value.root, 'cache'), { mode: 0o700 });
      }
    })).rejects.toThrow(INVALID);
  });

  it('closes an opened descriptor when a post-open checkpoint cancels', async () => {
    const value = await fixture(); let checkpoints = 0;
    const descriptorCount = (await readdir('/dev/fd')).length;
    await expect(capture(value, () => {
      checkpoints += 1;
      // capture: root pre/post, protected lstat pre/post, protected open pre, then post-open.
      if (checkpoints === 6) throw new Error('cancelled');
    })).rejects.toThrow(INVALID);
    expect((await readdir('/dev/fd')).length).toBe(descriptorCount);
    // A subsequent whole capture must use the same fixture cleanly.
    await expect(capture(value)).resolves.toMatchObject({ evidenceOrigin: 'synthetic_fixture' });
  });
});
