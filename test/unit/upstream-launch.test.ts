import {
  chmodSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  truncateSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import {
  LaunchProfileAuthority,
  MAX_UPSTREAM_EXECUTABLE_BYTES,
  prepareUpstreamLaunch,
  revalidatePreparedUpstreamLaunch,
  UpstreamLaunchError,
  type PreparedUpstreamLaunch,
} from '../../src/launch/upstream-launch.js';
import { connectStdioUpstream } from '../../src/transport/stdio-upstream.js';
import type { StdioUpstreamConfig } from '../../src/transport/types.js';

const temporaryPaths: string[] = [];

afterEach(() => {
  for (const path of temporaryPaths.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe('upstream launch integrity foundation', () => {
  it('resolves PATH once, ignores empty entries, and freezes the exact launch configuration', async () => {
    const root = temporaryDirectory();
    const bin = join(root, 'bin');
    mkdirSync(bin);
    const cwdCommand = executable(join(root, 'safe-command'), '#!/bin/sh\nexit 12\n');
    const pathCommand = executable(join(bin, 'safe-command'), '#!/bin/sh\nexit 0\n');
    const args = ['private-script.js'];
    const environment: Record<string, string> = { PATH: `:${bin}`, APG_PUBLIC_TEST: 'one' };

    const prepared = await prepareUpstreamLaunch({
      serverId: 'fixture-upstream',
      command: 'safe-command',
      args,
      cwd: root,
      env: environment,
    });
    args[0] = 'mutated.js';
    environment.PATH = root;

    expect(prepared.executable.resolvedPath).toBe(realpathSync(pathCommand));
    expect(prepared.executable.resolvedPath).not.toBe(realpathSync(cwdCommand));
    expect(prepared.arguments).toEqual(['private-script.js']);
    expect(prepared.environment.PATH).toBe(`:${bin}`);
    expect(prepared.cwd).toBe(realpathSync(root));
    expect(prepared.launchConfigurationAssurance).toBe('prepared_snapshot');
    expect(prepared.serverProvenanceAssurance).toBe('configured_label_only');
    expect(Object.isFrozen(prepared)).toBe(true);
    expect(Object.isFrozen(prepared.executable)).toBe(true);
    expect(Object.isFrozen(prepared.arguments)).toBe(true);
    expect(Object.isFrozen(prepared.environment)).toBe(true);
    await expect(revalidatePreparedUpstreamLaunch(prepared)).resolves.toBeUndefined();
  });

  it('canonicalizes explicit relative paths and symlinks without changing provenance assurance', async () => {
    const root = temporaryDirectory();
    const bin = join(root, 'bin');
    mkdirSync(bin);
    const target = executable(join(bin, 'target'), '#!/bin/sh\nexit 0\n');
    symlinkSync(target, join(bin, 'linked'));

    const prepared = await prepareUpstreamLaunch({
      serverId: 'fixture-upstream',
      command: './bin/linked',
      args: [],
      cwd: root,
      env: {},
    });

    expect(prepared.executable.resolvedPath).toBe(realpathSync(target));
    expect(prepared.serverProvenanceAssurance).toBe('configured_label_only');
  });

  it('does not represent interpreters or launchers as package provenance', async () => {
    const root = temporaryDirectory();
    const launcher = executable(join(root, 'npx'), '#!/bin/sh\nexit 0\n');
    const launches = await Promise.all([
      prepareUpstreamLaunch({
        serverId: 'node-fixture',
        command: process.execPath,
        args: ['private-server.js'],
        cwd: root,
        env: {},
      }),
      prepareUpstreamLaunch({
        serverId: 'npx-fixture',
        command: launcher,
        args: ['package@1.2.3'],
        cwd: root,
        env: {},
      }),
    ]);

    expect(launches.map((launch) => launch.serverProvenanceAssurance)).toEqual([
      'configured_label_only',
      'configured_label_only',
    ]);
  });

  it('fails closed on the first existing PATH candidate instead of silently falling through', async () => {
    const root = temporaryDirectory();
    const blockedBin = join(root, 'blocked-bin');
    const fallbackBin = join(root, 'fallback-bin');
    mkdirSync(blockedBin);
    mkdirSync(fallbackBin);
    writeFileSync(join(blockedBin, 'safe-command'), 'not executable', { mode: 0o600 });
    executable(join(fallbackBin, 'safe-command'), '#!/bin/sh\nexit 0\n');

    await expect(prepareUpstreamLaunch({
      serverId: 'fixture-upstream',
      command: 'safe-command',
      args: [],
      cwd: root,
      env: { PATH: `${blockedBin}:${fallbackBin}` },
    })).rejects.toMatchObject({ code: 'executable_not_executable' });
  });

  it('binds server, arguments, cwd, and environment into an internal launch digest', async () => {
    const root = temporaryDirectory();
    const secondCwd = join(root, 'second');
    mkdirSync(secondCwd);
    const command = executable(join(root, 'safe-command'), '#!/bin/sh\nexit 0\n');
    const base = await prepareUpstreamLaunch(config(command, root));
    const variants = await Promise.all([
      prepareUpstreamLaunch({ ...config(command, root), serverId: 'other-upstream' }),
      prepareUpstreamLaunch({ ...config(command, root), args: ['other-argument'] }),
      prepareUpstreamLaunch({ ...config(command, root), cwd: secondCwd }),
      prepareUpstreamLaunch({ ...config(command, root), env: { PATH: '/public/test' } }),
    ]);

    expect(new Set(variants.map((variant) => variant.launchDigest)).has(base.launchDigest)).toBe(false);
    expect(new Set(variants.map((variant) => variant.launchDigest)).size).toBe(variants.length);
  });

  it('fails closed when the executable changes after preparation', async () => {
    const root = temporaryDirectory();
    const command = executable(join(root, 'safe-command'), '#!/bin/sh\nexit 0\n');
    const prepared = await prepareUpstreamLaunch(config(command, root));

    writeFileSync(command, '#!/bin/sh\nexit 7\n', { mode: 0o700 });

    await expect(revalidatePreparedUpstreamLaunch(prepared)).rejects.toMatchObject({
      code: 'executable_changed',
    });
  });

  it('fails closed when the canonical working directory is replaced', async () => {
    const root = temporaryDirectory();
    const workingDirectory = join(root, 'working');
    const movedDirectory = join(root, 'working-original');
    mkdirSync(workingDirectory);
    const command = executable(join(root, 'safe-command'), '#!/bin/sh\nexit 0\n');
    const prepared = await prepareUpstreamLaunch(config(command, workingDirectory));

    renameSync(workingDirectory, movedDirectory);
    mkdirSync(workingDirectory);

    await expect(revalidatePreparedUpstreamLaunch(prepared)).rejects.toMatchObject({
      code: 'working_directory_changed',
    });
  });

  it('does not spawn a changed executable during transport connection', async () => {
    const root = temporaryDirectory();
    const marker = join(root, 'must-not-exist');
    const command = executable(join(root, 'safe-command'), '#!/bin/sh\nexit 0\n');
    const prepared = await prepareUpstreamLaunch(config(command, root));

    writeFileSync(command, `#!/bin/sh\nprintf started > ${JSON.stringify(marker)}\n`, { mode: 0o700 });

    await expect(connectStdioUpstream(prepared)).rejects.toMatchObject({ code: 'executable_changed' });
    expect(() => readFileSync(marker)).toThrow();
  });

  it('rejects raw or forged transport configuration before process creation', async () => {
    const forged = {
      serverId: 'fixture-upstream',
      executable: { resolvedPath: process.execPath },
      arguments: [],
      cwd: process.cwd(),
      environment: {},
    } as unknown as PreparedUpstreamLaunch;

    await expect(connectStdioUpstream(forged)).rejects.toMatchObject({
      code: 'prepared_launch_invalid',
    });
  });

  it('rejects unavailable, non-regular, non-executable, and oversized targets', async () => {
    const root = temporaryDirectory();
    const nonExecutable = join(root, 'non-executable');
    writeFileSync(nonExecutable, 'data', { mode: 0o600 });
    const oversized = join(root, 'oversized');
    writeFileSync(oversized, '', { mode: 0o700 });
    truncateSync(oversized, MAX_UPSTREAM_EXECUTABLE_BYTES + 1);

    await expect(prepareUpstreamLaunch(config(join(root, 'missing'), root))).rejects.toMatchObject({
      code: 'executable_unavailable',
    });
    await expect(prepareUpstreamLaunch(config(root, root))).rejects.toMatchObject({
      code: 'executable_not_regular',
    });
    await expect(prepareUpstreamLaunch(config(nonExecutable, root))).rejects.toMatchObject({
      code: 'executable_not_executable',
    });
    await expect(prepareUpstreamLaunch(config(oversized, root))).rejects.toMatchObject({
      code: 'executable_too_large',
    });
  });

  it('uses bounded errors that do not reveal private paths or arguments', async () => {
    const root = temporaryDirectory();
    const privateCommand = join(root, 'private-secret-command');
    let error: unknown;
    try {
      await prepareUpstreamLaunch({
        ...config(privateCommand, root),
        args: ['private-secret-argument'],
      });
    } catch (caught) {
      error = caught;
    }

    expect(error).toBeInstanceOf(UpstreamLaunchError);
    expect(String(error)).toContain('executable_unavailable');
    expect(String(error)).not.toContain(root);
    expect(String(error)).not.toContain('private-secret');
  });

  it('rejects NUL-bearing private configuration before filesystem access', async () => {
    await expect(prepareUpstreamLaunch({
      serverId: 'fixture-upstream',
      command: 'command\0private',
      args: [],
      env: {},
    })).rejects.toMatchObject({ code: 'invalid_configuration' });
    await expect(prepareUpstreamLaunch({
      serverId: 'fixture-upstream',
      command: 'command',
      args: ['argument\0private'],
      env: {},
    })).rejects.toMatchObject({ code: 'invalid_configuration' });
    await expect(prepareUpstreamLaunch({
      serverId: 'fixture-upstream',
      command: 'command',
      args: [],
      env: { 'INVALID=NAME': 'private' },
    })).rejects.toMatchObject({ code: 'invalid_configuration' });
  });
});

describe('synthetic launch profiles', () => {
  it('authenticates only results created by the owning authority', () => {
    const authority = new LaunchProfileAuthority([{
      id: 'synthetic.node-script.v0',
      inspect(input) {
        return { codeSelectors: [input.arguments[0] ?? 'none'] };
      },
    }]);
    const otherAuthority = new LaunchProfileAuthority([]);
    const result = authority.inspect('synthetic.node-script.v0', {
      executablePath: process.execPath,
      arguments: ['synthetic-server.js'],
      cwd: '/synthetic',
      environment: {},
    });

    expect(authority.authenticates(result)).toBe(true);
    expect(otherAuthority.authenticates(result)).toBe(false);
    expect(authority.authenticates({
      profileId: result.profileId,
      assurance: result.assurance,
      codeSelectors: result.codeSelectors,
    })).toBe(false);
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.codeSelectors)).toBe(true);
  });

  it('fails closed for unknown or malformed profile results', () => {
    const authority = new LaunchProfileAuthority([{
      id: 'synthetic.invalid.v0',
      inspect: () => ({ codeSelectors: [''] }),
    }]);
    const input = {
      executablePath: process.execPath,
      arguments: [] as readonly string[],
      cwd: '/synthetic',
      environment: {},
    };

    expect(() => authority.inspect('unknown', input)).toThrowError('launch_profile_unknown');
    expect(() => authority.inspect('synthetic.invalid.v0', input)).toThrowError('launch_profile_invalid');
  });
});

function config(command: string, cwd: string): StdioUpstreamConfig {
  return {
    serverId: 'fixture-upstream',
    command,
    args: ['synthetic-argument'],
    cwd,
    env: {},
  };
}

function executable(path: string, contents: string): string {
  writeFileSync(path, contents, { mode: 0o700 });
  chmodSync(path, 0o700);
  return path;
}

function temporaryDirectory(): string {
  const path = join(
    tmpdir(),
    `apg-upstream-launch-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`,
  );
  mkdirSync(path, { mode: 0o700 });
  temporaryPaths.push(path);
  return path;
}
