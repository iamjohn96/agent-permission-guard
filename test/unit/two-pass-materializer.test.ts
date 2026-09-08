import {
  chmodSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import {
  BoundedArchiveWorker,
  repositoryArchiveWorkerOptions,
} from '../../src/stage/bounded-archive-worker.js';
import {
  SyntheticMaterializationAuditAuthority,
  SyntheticTwoPassMaterializer,
} from '../../src/stage/two-pass-materializer.js';
import {
  createArchiveAdversarialFixtureCorpus,
  fixturePolicyLimits,
} from '../fixtures/archive-adversarial-fixtures.js';

const temporaryPaths: string[] = [];

afterEach(() => {
  for (const path of temporaryPaths.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe('synthetic two-pass POSIX materializer', () => {
  it('writes only through the parent, revalidates the tree, and publishes an authenticated seal', async () => {
    const environment = await createEnvironment();
    const fixture = acceptedFixture('valid_minimal');
    const audit = new SyntheticMaterializationAuditAuthority();
    const materializer = new SyntheticTwoPassMaterializer(environment.worker);

    const ready = await materializer.materialize(
      fixture.encodedBytes,
      fixturePolicyLimits,
      environment.stageParent,
      audit,
    );

    expect(materializer.authenticates(ready)).toBe(true);
    expect(materializer.authenticates({ ...ready })).toBe(false);
    expect(audit.events).toEqual(['materialization_started', 'ready_to_commit', 'ready']);
    expect(audit.records[0]?.evidence).toMatchObject({
      treeDigest: null,
      sealDigest: null,
    });
    expect(audit.records[1]?.evidence).toMatchObject({
      treeDigest: ready.treeDigest,
      sealDigest: null,
    });
    expect(audit.records[2]?.evidence).toMatchObject({
      treeDigest: ready.treeDigest,
      sealDigest: ready.sealDigest,
    });
    expect(readFileSync(join(ready.pendingRoot, 'package.json'), 'utf8'))
      .toBe('{"name":"fixture","version":"1.0.0"}\n');
    expect(readFileSync(join(ready.pendingRoot, 'index.js'), 'utf8')).toBe('export default 1;\n');
    expect(lstatSync(ready.pendingRoot).mode & 0o777).toBe(0o700);
    expect(lstatSync(join(ready.pendingRoot, 'package.json')).mode & 0o777).toBe(0o644);
    expect(lstatSync(ready.sealPath).mode & 0o777).toBe(0o400);
    expect(lstatSync(ready.sealPath).nlink).toBe(1);

    const seal = JSON.parse(readFileSync(ready.sealPath, 'utf8')) as Record<string, unknown>;
    expect(seal).toMatchObject({
      sealVersion: 1,
      state: 'sealed_pending_audit',
      rootName: basename(ready.pendingRoot),
      artifactSha512: ready.artifactSha512,
      runtimeDigest: ready.runtimeDigest,
      transcriptDigest: ready.transcriptDigest,
      treeDigest: ready.treeDigest,
      sealDigest: ready.sealDigest,
    });
  });

  it('materializes explicit directories and empty executable files without implicit parents', async () => {
    const environment = await createEnvironment();
    const fixture = acceptedFixture('valid_directory_and_empty_executable');
    const ready = await new SyntheticTwoPassMaterializer(environment.worker).materialize(
      fixture.encodedBytes,
      fixturePolicyLimits,
      environment.stageParent,
      new SyntheticMaterializationAuditAuthority(),
    );

    expect(lstatSync(join(ready.pendingRoot, 'lib')).mode & 0o777).toBe(0o755);
    expect(lstatSync(join(ready.pendingRoot, 'lib', 'empty.js')).mode & 0o777).toBe(0o755);
    expect(lstatSync(join(ready.pendingRoot, 'lib', 'empty.js')).size).toBe(0);
  });

  it('requires the pre-write audit and quarantines pre-seal audit or writer failures', async () => {
    const fixture = acceptedFixture('valid_minimal');

    const before = await createEnvironment();
    await expect(new SyntheticTwoPassMaterializer(before.worker).materialize(
      fixture.encodedBytes,
      fixturePolicyLimits,
      before.stageParent,
      new SyntheticMaterializationAuditAuthority('materialization_started'),
    )).rejects.toMatchObject({ code: 'stage_audit_incomplete' });
    expect(stageChildren(before.stageParent)).toEqual([]);

    const preCommit = await createEnvironment();
    await expect(new SyntheticTwoPassMaterializer(preCommit.worker).materialize(
      fixture.encodedBytes,
      fixturePolicyLimits,
      preCommit.stageParent,
      new SyntheticMaterializationAuditAuthority('ready_to_commit'),
    )).rejects.toMatchObject({ code: 'stage_audit_incomplete' });
    expect(stageChildren(preCommit.stageParent).filter((name) => name.startsWith('pending-'))).toHaveLength(1);
    expect(stageChildren(preCommit.stageParent).some((name) => name.endsWith('.seal.json'))).toBe(false);

    const writerFailure = await createEnvironment();
    const materializer = new SyntheticTwoPassMaterializer(writerFailure.worker, (point) => {
      if (point !== 'after_pending_root') return;
      const pending = pendingRoot(writerFailure.stageParent);
      symlinkSync('/private/tmp', join(pending, 'package.json'));
    });
    await expect(materializer.materialize(
      fixture.encodedBytes,
      fixturePolicyLimits,
      writerFailure.stageParent,
      new SyntheticMaterializationAuditAuthority(),
    )).rejects.toMatchObject({ code: 'materialization_failed' });
    expect(stageChildren(writerFailure.stageParent).some((name) => name.endsWith('.seal.json'))).toBe(false);
  });

  it('blocks READY when terminal audit fails after seal publication and never repeats writes', async () => {
    const environment = await createEnvironment();
    const fixture = acceptedFixture('valid_minimal');
    const audit = new SyntheticMaterializationAuditAuthority('ready');
    let afterEntryCount = 0;
    const materializer = new SyntheticTwoPassMaterializer(environment.worker, (point) => {
      if (point === 'after_entry') afterEntryCount += 1;
    });

    await expect(materializer.materialize(
      fixture.encodedBytes,
      fixturePolicyLimits,
      environment.stageParent,
      audit,
    )).rejects.toMatchObject({ code: 'stage_audit_incomplete' });

    expect(afterEntryCount).toBe(2);
    expect(audit.events).toEqual(['materialization_started', 'ready_to_commit']);
    expect(stageChildren(environment.stageParent).filter((name) => name.endsWith('.seal.json')))
      .toHaveLength(1);
    expect(stageChildren(environment.stageParent).filter((name) =>
      name.startsWith('pending-') && lstatSync(join(environment.stageParent, name)).isDirectory()))
      .toHaveLength(1);
  });

  it('detects a post-write tree mutation before sealing', async () => {
    const environment = await createEnvironment();
    const fixture = acceptedFixture('valid_minimal');
    const materializer = new SyntheticTwoPassMaterializer(environment.worker, (point) => {
      if (point !== 'before_tree_verification') return;
      writeFileSync(join(pendingRoot(environment.stageParent), 'index.js'), 'changed\n');
    });

    await expect(materializer.materialize(
      fixture.encodedBytes,
      fixturePolicyLimits,
      environment.stageParent,
      new SyntheticMaterializationAuditAuthority(),
    )).rejects.toMatchObject({ code: 'tree_changed' });
    expect(stageChildren(environment.stageParent).some((name) => name.endsWith('.seal.json'))).toBe(false);
  });

  it('detects pending-root permission drift and intermediate directory replacement', async () => {
    const fixture = acceptedFixture('valid_minimal');
    const rootDrift = await createEnvironment();
    const rootDriftMaterializer = new SyntheticTwoPassMaterializer(rootDrift.worker, (point) => {
      if (point === 'after_pending_root') chmodSync(pendingRoot(rootDrift.stageParent), 0o755);
    });
    await expect(rootDriftMaterializer.materialize(
      fixture.encodedBytes,
      fixturePolicyLimits,
      rootDrift.stageParent,
      new SyntheticMaterializationAuditAuthority(),
    )).rejects.toMatchObject({ code: 'materialization_failed' });

    const directoryFixture = acceptedFixture('valid_directory_and_empty_executable');
    const directoryDrift = await createEnvironment();
    let replaced = false;
    const directoryDriftMaterializer = new SyntheticTwoPassMaterializer(directoryDrift.worker, (point) => {
      if (point !== 'after_entry' || replaced) return;
      replaced = true;
      const path = join(pendingRoot(directoryDrift.stageParent), 'lib');
      rmSync(path, { recursive: true, force: true });
      mkdirPrivate(path);
    });
    await expect(directoryDriftMaterializer.materialize(
      directoryFixture.encodedBytes,
      fixturePolicyLimits,
      directoryDrift.stageParent,
      new SyntheticMaterializationAuditAuthority(),
    )).rejects.toMatchObject({ code: 'materialization_failed' });
    expect(stageChildren(directoryDrift.stageParent).some((name) => name.endsWith('.seal.json'))).toBe(false);
  });

  it('fails closed on seal-name preexistence and non-private parent directories', async () => {
    const fixture = acceptedFixture('valid_minimal');
    const collision = await createEnvironment();
    const materializer = new SyntheticTwoPassMaterializer(collision.worker, (point) => {
      if (point !== 'before_seal') return;
      const pending = pendingRoot(collision.stageParent);
      writeFileSync(join(collision.stageParent, `${basename(pending)}.seal.json`), 'occupied', { mode: 0o600 });
    });
    await expect(materializer.materialize(
      fixture.encodedBytes,
      fixturePolicyLimits,
      collision.stageParent,
      new SyntheticMaterializationAuditAuthority(),
    )).rejects.toMatchObject({ code: 'stage_seal_invalid' });

    const unsafe = await createEnvironment();
    chmodSync(unsafe.stageParent, 0o755);
    await expect(new SyntheticTwoPassMaterializer(unsafe.worker).materialize(
      fixture.encodedBytes,
      fixturePolicyLimits,
      unsafe.stageParent,
      new SyntheticMaterializationAuditAuthority(),
    )).rejects.toMatchObject({ code: 'materialization_failed' });
  });
});

async function createEnvironment(): Promise<Readonly<{
  worker: BoundedArchiveWorker;
  stageParent: string;
}>> {
  const root = temporaryDirectory('apg-two-pass-');
  const workerCwd = join(root, 'worker');
  const stageParent = join(root, 'stages');
  for (const path of [workerCwd, stageParent]) {
    mkdirPrivate(path);
  }
  const worker = await BoundedArchiveWorker.create(
    repositoryArchiveWorkerOptions(process.cwd(), workerCwd, { timeoutMs: 10_000 }),
  );
  return Object.freeze({ worker, stageParent });
}

function mkdirPrivate(path: string): void {
  mkdirSync(path, { mode: 0o700 });
  chmodSync(path, 0o700);
}

function temporaryDirectory(prefix: string): string {
  const path = mkdtempSync(join(tmpdir(), prefix));
  chmodSync(path, 0o700);
  temporaryPaths.push(path);
  return path;
}

function acceptedFixture(id: string) {
  const fixture = createArchiveAdversarialFixtureCorpus().find((candidate) => candidate.id === id);
  if (fixture?.expectation.kind !== 'accept') throw new Error('test_fixture_missing');
  return fixture;
}

function stageChildren(stageParent: string): readonly string[] {
  return readdirSync(stageParent).sort();
}

function pendingRoot(stageParent: string): string {
  const name = stageChildren(stageParent).find((candidate) => candidate.startsWith('pending-'));
  if (name === undefined) throw new Error('test_pending_root_missing');
  return join(stageParent, name);
}
