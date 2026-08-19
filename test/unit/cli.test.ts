import { chmodSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

import { collectDoctorChecks, parseDoctorArguments } from '../../src/cli/doctor.js';
import { parseInitArguments, runInit } from '../../src/cli/init.js';
import { isEntryPointPath } from '../../src/cli/main.js';

const temporaryPaths: string[] = [];

afterEach(() => {
  for (const path of temporaryPaths.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe('apg init', () => {
  it('creates a private starter policy without creating the audit database', () => {
    const directory = temporaryDirectory();
    runInit({ directory });

    expect(readFileSync(join(directory, 'policy.yaml'), 'utf8')).toContain('version: 1');
    expect(() => readFileSync(join(directory, 'audit.sqlite'))).toThrow();
  });

  it('refuses to overwrite an existing policy', () => {
    const directory = temporaryDirectory();
    const policyPath = join(directory, 'policy.yaml');
    writeFileSync(policyPath, 'existing', { mode: 0o600 });

    expect(() => runInit({ directory })).toThrow(/Refusing to overwrite/);
    expect(readFileSync(policyPath, 'utf8')).toBe('existing');
  });

  it('parses the default and explicit directory forms', () => {
    expect(parseInitArguments([])).toEqual({ directory: '.apg' });
    expect(parseInitArguments(['--directory', 'custom'])).toEqual({ directory: 'custom' });
    expect(() => parseInitArguments(['--force'])).toThrow(/Usage/);
  });
});

describe('apg doctor', () => {
  it('validates policy, audit path, loopback port, and an executable without running it', async () => {
    const directory = temporaryDirectory();
    const policyPath = join(directory, 'policy.yaml');
    const markerPath = join(directory, 'must-not-exist');
    const commandPath = join(directory, 'safe-command');
    writeFileSync(policyPath, 'version: 1\nrules: []\n', { mode: 0o600 });
    writeFileSync(commandPath, `#!/bin/sh\ntouch ${markerPath}\n`, { mode: 0o700 });
    chmodSync(commandPath, 0o700);

    const checks = await collectDoctorChecks({
      policyPath,
      auditDbPath: join(directory, 'audit.sqlite'),
      dashboardPort: 0,
      command: commandPath,
    });

    expect(checks.every((check) => check.status !== 'fail')).toBe(true);
    expect(() => readFileSync(markerPath)).toThrow();
  });

  it('fails closed on an invalid policy and missing command', async () => {
    const directory = temporaryDirectory();
    const policyPath = join(directory, 'policy.yaml');
    writeFileSync(policyPath, 'version: 999\n', { mode: 0o600 });

    const checks = await collectDoctorChecks(
      {
        policyPath,
        auditDbPath: join(directory, 'audit.sqlite'),
        dashboardPort: 0,
        command: 'definitely-not-an-apg-command',
      },
      { PATH: directory },
    );

    expect(checks.find((check) => check.name === 'Policy')?.status).toBe('fail');
    expect(checks.find((check) => check.name === 'Upstream command')?.status).toBe('fail');
  });

  it('parses defaults and a command-only diagnostic', () => {
    expect(parseDoctorArguments([])).toEqual({
      policyPath: '.apg/policy.yaml',
      auditDbPath: '.apg/audit.sqlite',
      dashboardPort: 47_831,
    });
    expect(parseDoctorArguments(['--dashboard-port', '0', '--', 'node', '--example-arg'])).toEqual({
      policyPath: '.apg/policy.yaml',
      auditDbPath: '.apg/audit.sqlite',
      dashboardPort: 0,
      command: 'node',
    });
  });
});

describe('CLI entry point', () => {
  it('recognizes an npm-style symlink to the packaged executable', () => {
    const directory = temporaryDirectory();
    const executable = join(directory, 'main.js');
    const binLink = join(directory, 'apg');
    writeFileSync(executable, '#!/usr/bin/env node\n', { mode: 0o700 });
    symlinkSync(executable, binLink);

    expect(isEntryPointPath(binLink, pathToFileURL(executable).href)).toBe(true);
    expect(isEntryPointPath(undefined, pathToFileURL(executable).href)).toBe(false);
  });
});

function temporaryDirectory(): string {
  const path = join(tmpdir(), `apg-cli-${crypto.randomUUID()}`);
  mkdirSync(path, { mode: 0o700 });
  temporaryPaths.push(path);
  return path;
}
