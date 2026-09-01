import { chmodSync, existsSync, mkdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import {
  InstallExecutionPlanError,
  LocalInstallExecutionPlanner,
} from '../../src/install/execution-plan.js';
import { parseInstallRequest } from '../../src/install/parser.js';
import type { ResolvedPackageMetadata } from '../../src/install/types.js';
import {
  validateInstallPlanPreconditions,
  verifyInstallExecution,
} from '../../src/install/verifier.js';

const temporaryPaths: string[] = [];

afterEach(() => {
  for (const path of temporaryPaths.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe('Install Guard execution plan', () => {
  it('pins an exact package, executable, arguments, cwd, and file state without executing the fake runner', async () => {
    const fixture = executionFixture('npm');
    const marker = join(fixture.directory, 'must-not-exist');
    writeFileSync(fixture.executable, `#!/bin/sh\ntouch ${marker}\n`, { mode: 0o700 });
    chmodSync(fixture.executable, 0o700);
    const request = parseInstallRequest('npm', ['yaml@latest', '--save-exact'], fixture.project);

    const plan = await fixture.planner.create(request, metadata(), 30_000);

    expect(plan).toMatchObject({
      runner: 'npm',
      packageName: 'yaml',
      originalSpecifier: 'latest',
      resolvedVersion: '2.9.0',
      options: ['--save-exact'],
      workingDirectory: realpathSync(fixture.project),
      timeoutMs: 30_000,
    });
    expect(plan.arguments).toEqual([
      'install',
      '--no-audit',
      '--no-fund',
      '--registry=https://registry.npmjs.org/',
      '--save-exact',
      'yaml@2.9.0',
    ]);
    expect(plan.planHash).toMatch(/^[0-9a-f]{64}$/);
    expect(() => Object.assign(plan, { resolvedVersion: '3.0.0' })).toThrow();
    expect(existsSync(marker)).toBe(false);
  });

  it('selects one exact npx binary and rejects ambiguous binary metadata', async () => {
    const fixture = executionFixture('npx');
    const request = parseInstallRequest('npx', ['yaml@latest'], fixture.project);
    const plan = await fixture.planner.create(request, metadata({ executableBins: { yaml: 'bin.mjs' } }), 30_000);

    expect(plan.executableBin).toBe('yaml');
    expect(plan.arguments).toEqual([
      '--yes',
      '--registry=https://registry.npmjs.org/',
      '--package=yaml@2.9.0',
      '--',
      'yaml',
    ]);

    await expect(fixture.planner.create(request, metadata({
      executableBins: { first: 'first.js', second: 'second.js' },
    }), 30_000)).rejects.toThrow(/ambiguous/);
  });

  it('rejects project npm configuration without reading or exposing its contents', async () => {
    const fixture = executionFixture('npm');
    writeFileSync(join(fixture.project, '.npmrc'), '//registry.example.test/:_authToken=private-value\n');
    const request = parseInstallRequest('npm', ['yaml@2.9.0'], fixture.project);

    const error = await fixture.planner.create(request, metadata(), 30_000).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(InstallExecutionPlanError);
    expect(String(error)).toContain('.npmrc');
    expect(String(error)).not.toContain('private-value');
  });

  it('detects executable or project state changes after approval', async () => {
    const fixture = executionFixture('npm');
    const request = parseInstallRequest('npm', ['yaml@2.9.0'], fixture.project);
    const plan = await fixture.planner.create(request, metadata(), 30_000);

    await expect(validateInstallPlanPreconditions(plan)).resolves.toBeUndefined();
    await expect(validateInstallPlanPreconditions({ ...plan, planHash: '0'.repeat(64) })).rejects.toThrow(/plan identity/);
    writeFileSync(join(fixture.project, 'package.json'), '{"name":"changed"}\n');
    await expect(validateInstallPlanPreconditions(plan)).rejects.toThrow(/manifest or lockfile changed/);
  });

  it('revalidates canonical options even when a caller bypasses the CLI parser', async () => {
    const fixture = executionFixture('npm');
    const parsed = parseInstallRequest('npm', ['yaml@2.9.0'], fixture.project);

    await expect(fixture.planner.create({ ...parsed, options: ['--force'] }, metadata(), 30_000))
      .rejects.toThrow(/options/);
  });

  it('verifies the exact installed version from a resulting npm lockfile', async () => {
    const fixture = executionFixture('npm');
    const request = parseInstallRequest('npm', ['yaml@2.9.0'], fixture.project);
    const plan = await fixture.planner.create(request, metadata(), 30_000);
    writeFileSync(join(fixture.project, 'package-lock.json'), JSON.stringify({
      lockfileVersion: 3,
      packages: {
        'node_modules/yaml': {
          version: '2.9.0',
          integrity: `sha512-${Buffer.alloc(64, 0xaa).toString('base64')}`,
        },
      },
    }));

    await expect(verifyInstallExecution(plan, true)).resolves.toEqual({
      status: 'verified',
      exactPackageVersionObserved: true,
      approvedIntegrityObserved: true,
      changedFiles: ['package-lock.json'],
      reasonCodes: [],
    });

    writeFileSync(join(fixture.project, 'package-lock.json'), JSON.stringify({
      lockfileVersion: 3,
      packages: {
        'node_modules/yaml': {
          version: '2.9.0',
          integrity: `sha512-${Buffer.alloc(64, 0xbb).toString('base64')}`,
        },
      },
    }));
    await expect(verifyInstallExecution(plan, true)).resolves.toMatchObject({
      status: 'failed',
      exactPackageVersionObserved: true,
      approvedIntegrityObserved: false,
      reasonCodes: ['approved_integrity_not_observed'],
    });
  });
});

function executionFixture(runner: 'npm' | 'npx'): Readonly<{
  directory: string;
  project: string;
  executable: string;
  planner: LocalInstallExecutionPlanner;
}> {
  const directory = join(tmpdir(), `apg-plan-${crypto.randomUUID()}`);
  const bin = join(directory, 'bin');
  const project = join(directory, 'project');
  const executable = join(bin, runner);
  const nodeExecutable = join(bin, 'node');
  mkdirSync(bin, { recursive: true, mode: 0o700 });
  mkdirSync(project, { mode: 0o700 });
  writeFileSync(executable, '#!/bin/sh\nexit 99\n', { mode: 0o700 });
  writeFileSync(nodeExecutable, '#!/bin/sh\nexit 98\n', { mode: 0o700 });
  chmodSync(executable, 0o700);
  chmodSync(nodeExecutable, 0o700);
  writeFileSync(join(project, 'package.json'), '{"name":"fixture","private":true}\n');
  temporaryPaths.push(directory);
  return {
    directory,
    project,
    executable,
    planner: new LocalInstallExecutionPlanner({
      environment: { PATH: bin },
      now: () => new Date('2026-09-01T00:04:00.000Z'),
    }),
  };
}

function metadata(
  override: Partial<ResolvedPackageMetadata> = {},
): ResolvedPackageMetadata {
  return {
    packageName: 'yaml',
    version: '2.9.0',
    registry: 'https://registry.npmjs.org/',
    observedAt: '2026-09-01T00:00:00.000Z',
    lifecycleScripts: [],
    tarballUrl: 'https://registry.npmjs.org/yaml/-/yaml-2.9.0.tgz',
    integrity: `sha512-${Buffer.alloc(64, 0xaa).toString('base64')}`,
    executableBins: { yaml: 'bin.mjs' },
    advisories: [],
    possibleTyposquat: false,
    packageIsNew: false,
    publisherIsNew: false,
    repositoryMissing: false,
    provenanceInconsistent: false,
    mutableSource: false,
    evidenceComplete: true,
    ...override,
  };
}
