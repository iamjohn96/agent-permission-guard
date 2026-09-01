import { chmodSync, existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { LocalInstallExecutionPlanner } from '../../src/install/execution-plan.js';
import { parseInstallRequest } from '../../src/install/parser.js';
import { ControlledLocalInstallRunner } from '../../src/install/runner.js';
import type { ResolvedPackageMetadata } from '../../src/install/types.js';

const temporaryPaths: string[] = [];

afterEach(() => {
  for (const path of temporaryPaths.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe.skipIf(process.platform === 'win32')('controlled local install runner', () => {
  it('uses a known executable without a shell, strips credential environment, bounds output, and verifies the lockfile', async () => {
    const fixture = await runnerFixture(`#!/bin/sh
if [ -n "$NPM_TOKEN" ] || [ -n "$NODE_OPTIONS" ]; then exit 41; fi
printf 'token=fake-output-secret\\n'
printf 'Bearer abcdefghijklmnopqrstuvwxyz\\n' >&2
i=0
while [ "$i" -lt 7000 ]; do printf '0123456789'; i=$((i + 1)); done
printf '%s' '{"lockfileVersion":3,"packages":{"node_modules/yaml":{"version":"2.9.0","integrity":"sha512-qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqg=="}}}' > package-lock.json
`);
    const previousToken = process.env.NPM_TOKEN;
    const previousNodeOptions = process.env.NODE_OPTIONS;
    process.env.NPM_TOKEN = 'fake-parent-token';
    process.env.NODE_OPTIONS = '--trace-warnings';
    try {
      const result = await new ControlledLocalInstallRunner().run(fixture.plan);

      expect(result).toMatchObject({
        status: 'completed',
        exitCode: 0,
        verification: {
          status: 'verified',
          exactPackageVersionObserved: true,
          approvedIntegrityObserved: true,
          changedFiles: ['package-lock.json'],
        },
        output: { truncated: true },
      });
      expect(result.output?.stdoutBytes).toBeGreaterThan(65_536);
      expect(result.output?.stdoutPreview).toContain('token=[REDACTED]');
      expect(result.output?.stdoutPreview).not.toContain('fake-output-secret');
      expect(result.output?.stderrPreview).toContain('Bearer [REDACTED]');
      expect(result.output?.stderrPreview).not.toContain('abcdefghijklmnopqrstuvwxyz');
    } finally {
      restoreEnvironment('NPM_TOKEN', previousToken);
      restoreEnvironment('NODE_OPTIONS', previousNodeOptions);
    }
  });

  it('terminates the fake process group after the approved timeout', async () => {
    const fixture = await runnerFixture('#!/bin/sh\n/bin/sleep 10\n', 1_000);
    const startedAt = Date.now();

    const result = await new ControlledLocalInstallRunner().run(fixture.plan);

    expect(result.status).toBe('timed_out');
    expect(result.exitCode).not.toBe(0);
    expect(Date.now() - startedAt).toBeLessThan(5_000);
    expect(result.verification?.status).toBe('limited');
  });

  it('cancels the fake process group through an AbortSignal', async () => {
    const fixture = await runnerFixture('#!/bin/sh\n/bin/sleep 10\n', 30_000);
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 20).unref();

    const result = await new ControlledLocalInstallRunner().run(fixture.plan, controller.signal);

    expect(result.status).toBe('cancelled');
    expect(result.verification?.reasonCodes).toContain('process_not_completed');
  });

  it('fails before executing when an approved project file changes', async () => {
    const fixture = await runnerFixture('#!/bin/sh\ntouch runner-was-called\n');
    writeFileSync(join(fixture.project, 'package.json'), '{"name":"changed"}\n');

    await expect(new ControlledLocalInstallRunner().run(fixture.plan)).rejects.toThrow(/manifest or lockfile changed/);
    expect(existsSync(join(fixture.project, 'runner-was-called'))).toBe(false);
  });
});

async function runnerFixture(script: string, timeoutMs = 30_000): Promise<Readonly<{
  directory: string;
  project: string;
  plan: Awaited<ReturnType<LocalInstallExecutionPlanner['create']>>;
}>> {
  const directory = join(tmpdir(), `apg-runner-${crypto.randomUUID()}`);
  const bin = join(directory, 'bin');
  const project = join(directory, 'project');
  const executable = join(bin, 'npm');
  const nodeExecutable = join(bin, 'node');
  mkdirSync(bin, { recursive: true, mode: 0o700 });
  mkdirSync(project, { mode: 0o700 });
  writeFileSync(executable, script, { mode: 0o700 });
  writeFileSync(nodeExecutable, '#!/bin/sh\nexit 98\n', { mode: 0o700 });
  chmodSync(executable, 0o700);
  chmodSync(nodeExecutable, 0o700);
  writeFileSync(join(project, 'package.json'), '{"name":"fixture","private":true}\n');
  temporaryPaths.push(directory);

  const planner = new LocalInstallExecutionPlanner({
    environment: { PATH: bin },
    now: () => new Date('2026-09-01T00:04:00.000Z'),
  });
  const request = parseInstallRequest('npm', ['yaml@2.9.0', '--save-exact'], project);
  const plan = await planner.create(request, metadata(), timeoutMs);
  return { directory, project, plan };
}

function metadata(): ResolvedPackageMetadata {
  return {
    packageName: 'yaml',
    version: '2.9.0',
    registry: 'https://registry.npmjs.org/',
    observedAt: '2026-09-01T00:00:00.000Z',
    lifecycleScripts: [],
    tarballUrl: 'https://registry.npmjs.org/yaml/-/yaml-2.9.0.tgz',
    integrity: `sha512-${Buffer.alloc(64, 0xaa).toString('base64')}`,
    advisories: [],
    possibleTyposquat: false,
    packageIsNew: false,
    publisherIsNew: false,
    repositoryMissing: false,
    provenanceInconsistent: false,
    mutableSource: false,
    evidenceComplete: true,
  };
}

function restoreEnvironment(name: string, value: string | undefined): void {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}
