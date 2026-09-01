import { chmodSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

import { collectDoctorChecks, parseDoctorArguments } from '../../src/cli/doctor.js';
import { parseInitArguments, runInit } from '../../src/cli/init.js';
import { parseInspectArguments, runInspect } from '../../src/cli/inspect.js';
import { parseInstallArguments, runInstall } from '../../src/cli/install.js';
import { isEntryPointPath, parseProxyArguments } from '../../src/cli/main.js';
import { LocalInstallExecutionPlanner } from '../../src/install/execution-plan.js';
import type { NpmRegistryTransport, RegistryResponse } from '../../src/install/npm-registry.js';
import type {
  InstallExecutionPlan,
  InstallExecutionResult,
  InstallRunnerAdapter,
} from '../../src/install/types.js';

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
      dashboardStatePath: join(directory, 'dashboard.json'),
      command: commandPath,
    });

    expect(checks.every((check) => check.status !== 'fail')).toBe(true);
    expect(checks.find((check) => check.name === 'Dashboard state')?.status).toBe('pass');
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
    expect(parseDoctorArguments([
      '--dashboard-port', '0',
      '--dashboard-state', '.apg/dashboard.json',
      '--', 'node', '--example-arg',
    ])).toEqual({
      policyPath: '.apg/policy.yaml',
      auditDbPath: '.apg/audit.sqlite',
      dashboardPort: 0,
      dashboardStatePath: '.apg/dashboard.json',
      command: 'node',
    });
  });
});

describe('apg proxy arguments', () => {
  it('parses an opt-in dashboard state path', () => {
    expect(parseProxyArguments([
      'proxy',
      '--policy', '.apg/policy.yaml',
      '--audit-db', '.apg/audit.sqlite',
      '--dashboard-state', '.apg/dashboard.json',
      '--', 'node', 'server.js',
    ])).toEqual({
      policyPath: '.apg/policy.yaml',
      auditDbPath: '.apg/audit.sqlite',
      dashboardPort: 47_831,
      dashboardStatePath: '.apg/dashboard.json',
      command: 'node',
      args: ['server.js'],
    });
  });
});

describe('apg inspect', () => {
  it('parses a package and an optional explicit HTTPS registry', () => {
    expect(parseInspectArguments(['npm', 'yaml@latest'], '/tmp/project')).toEqual({
      runner: 'npm',
      packageSpec: 'yaml@latest',
      registry: 'https://registry.npmjs.org/',
      workingDirectory: '/tmp/project',
    });
    expect(parseInspectArguments([
      'npx', '@scope/pkg@1.0.0', '--registry', 'https://packages.example.test/npm/',
    ], '/tmp/project')).toMatchObject({
      runner: 'npx',
      registry: 'https://packages.example.test/npm/',
    });
  });

  it.each([
    { argv: [] },
    { argv: ['pip', 'package'] },
    { argv: ['npm'] },
    { argv: ['npm', 'yaml', '--json'] },
    { argv: ['npm', 'yaml', '--registry'] },
  ])('rejects unsupported inspect arguments: $argv', ({ argv }) => {
    expect(() => parseInspectArguments(argv, '/tmp/project')).toThrow(/Usage/);
  });

  it('prints a bounded decision using a fake registry without installing anything', async () => {
    const output: string[] = [];
    const transport = new InspectFakeTransport({
      status: 200,
      contentType: 'application/vnd.npm.install-v1+json',
      body: {
        name: 'yaml',
        'dist-tags': { latest: '2.9.0' },
        versions: {
          '2.9.0': {
            name: 'yaml',
            version: '2.9.0',
            hasInstallScript: false,
            dist: { tarball: 'https://registry.npmjs.org/yaml/-/yaml-2.9.0.tgz' },
            readme: 'private response content must not be printed',
          },
        },
      },
    });

    await runInspect(parseInspectArguments(['npm', 'yaml@latest'], '/tmp/project'), {
      transport,
      output: { write: (chunk) => { output.push(String(chunk)); return true; } },
    });

    const text = output.join('');
    expect(text).toContain('Resolved version: 2.9.0');
    expect(text).toContain('Decision: ASK');
    expect(text).toContain('limited_registry_evidence');
    expect(text).toContain('no package was downloaded or installed');
    expect(text).not.toContain('private response content');
    expect(transport.requests).toBe(1);
  });

  it('reports Deny when a mutable tag cannot be resolved', async () => {
    const output: string[] = [];
    await runInspect(parseInspectArguments(['npm', 'yaml@latest'], '/tmp/project'), {
      transport: new InspectFakeTransport(new Error('private registry failure')),
      output: { write: (chunk) => { output.push(String(chunk)); return true; } },
    });

    expect(output.join('')).toContain('Decision: DENY');
    expect(output.join('')).not.toContain('private registry failure');
  });
});

describe('apg install', () => {
  it('parses supported package options separately from bounded APG controls', () => {
    expect(parseInstallArguments([
      'npm',
      'yaml@latest',
      '--save-exact',
      '--registry', 'https://registry.npmjs.org',
      '--timeout-seconds', '60',
      '--approval-ttl-seconds', '30',
      '--dashboard-port', '0',
    ], '/tmp/project')).toEqual({
      request: {
        runner: 'npm',
        packageName: 'yaml',
        requestedSpecifier: 'latest',
        options: ['--save-exact'],
        workingDirectory: '/tmp/project',
      },
      registry: 'https://registry.npmjs.org/',
      timeoutMs: 60_000,
      approvalTtlMs: 30_000,
      policyPath: '.apg/policy.yaml',
      auditDbPath: '.apg/audit.sqlite',
      dashboardPort: 0,
    });
  });

  it.each([
    { argv: ['npm'] },
    { argv: ['pip', 'yaml'] },
    { argv: ['npm', 'yaml', '--timeout-seconds', '0'] },
    { argv: ['npm', 'yaml', '--dashboard-port', '70000'] },
    { argv: ['npm', 'yaml', '--registry', 'https://user:secret@registry.npmjs.org'] },
    { argv: ['npx', 'yaml', '--ignore-existing'] },
  ])('rejects unsafe or unsupported install arguments: $argv', ({ argv }) => {
    expect(() => parseInstallArguments(argv, '/tmp/project')).toThrow(/Usage/);
  });

  it('runs the install lifecycle through the local dashboard using fake registry and runner only', async () => {
    const directory = temporaryDirectory();
    const project = join(directory, 'project');
    const bin = join(directory, 'bin');
    const policyPath = join(directory, 'policy.yaml');
    const auditDbPath = join(directory, 'audit.sqlite');
    const executable = join(bin, 'npm');
    const nodeExecutable = join(bin, 'node');
    mkdirSync(project, { mode: 0o700 });
    mkdirSync(bin, { mode: 0o700 });
    writeFileSync(join(project, 'package.json'), '{"name":"fixture","private":true}\n');
    writeFileSync(executable, '#!/bin/sh\nexit 91\n', { mode: 0o700 });
    writeFileSync(nodeExecutable, '#!/bin/sh\nexit 90\n', { mode: 0o700 });
    chmodSync(executable, 0o700);
    chmodSync(nodeExecutable, 0o700);
    writeFileSync(policyPath, 'version: 1\nrules: []\n', { mode: 0o600 });

    const output: string[] = [];
    const errors: string[] = [];
    const runner = new CliFakeInstallRunner();
    const running = runInstall(parseInstallArguments([
      'npm', 'yaml@latest', '--save-exact',
      '--policy', policyPath,
      '--audit-db', auditDbPath,
      '--dashboard-port', '0',
    ], project), {
      transport: new InspectFakeTransport(okInstallPackument()),
      planner: new LocalInstallExecutionPlanner({ environment: { PATH: bin } }),
      runner,
      output: { write: (chunk) => { output.push(String(chunk)); return true; } },
      errorOutput: { write: (chunk) => { errors.push(String(chunk)); return true; } },
    });

    const dashboard = await waitForInstallDashboard(errors);
    const pending = await waitForDashboardApproval(dashboard);
    const approvalResponse = await fetch(`${dashboard.origin}/api/approvals/${pending.id}/approve`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${dashboard.token}` },
    });
    expect(approvalResponse.status).toBe(200);

    await expect(running).resolves.toMatchObject({ status: 'completed' });
    expect(runner.plans).toHaveLength(1);
    expect(runner.plans[0]).toMatchObject({
      originalSpecifier: 'latest',
      resolvedVersion: '2.9.0',
    });
    expect(output.join('')).toContain('Status: COMPLETED');
    expect(output.join('')).toContain('direct npm/npx remains outside coverage');
    expect(errors.join('')).toContain('Direct npm/npx commands bypass APG');
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

class InspectFakeTransport implements NpmRegistryTransport {
  requests = 0;

  constructor(private readonly response: RegistryResponse | Error) {}

  async getPackage(): Promise<RegistryResponse> {
    this.requests += 1;
    if (this.response instanceof Error) throw this.response;
    return this.response;
  }
}

class CliFakeInstallRunner implements InstallRunnerAdapter {
  readonly plans: InstallExecutionPlan[] = [];

  async run(plan: InstallExecutionPlan): Promise<InstallExecutionResult> {
    this.plans.push(plan);
    return {
      status: 'completed',
      exitCode: 0,
      durationMs: 3,
      summary: 'fake CLI execution',
      verification: {
        status: 'verified',
        exactPackageVersionObserved: true,
        approvedIntegrityObserved: true,
        changedFiles: [],
        reasonCodes: [],
      },
    };
  }
}

function okInstallPackument(): RegistryResponse {
  return {
    status: 200,
    contentType: 'application/vnd.npm.install-v1+json',
    body: {
      name: 'yaml',
      'dist-tags': { latest: '2.9.0' },
      versions: {
        '2.9.0': {
          name: 'yaml',
          version: '2.9.0',
          hasInstallScript: false,
          dist: {
            tarball: 'https://registry.npmjs.org/yaml/-/yaml-2.9.0.tgz',
            integrity: `sha512-${Buffer.alloc(64, 0xaa).toString('base64')}`,
          },
        },
      },
    },
  };
}

async function waitForInstallDashboard(errors: readonly string[]): Promise<Readonly<{
  origin: string;
  token: string;
}>> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const match = errors.join('').match(/(http:\/\/127\.0\.0\.1:\d+\/#token=([^\s]+))/);
    if (match?.[1] !== undefined && match[2] !== undefined) {
      return { origin: new URL(match[1]).origin, token: decodeURIComponent(match[2]) };
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error('Timed out waiting for install dashboard');
}

async function waitForDashboardApproval(
  dashboard: Readonly<{ origin: string; token: string }>,
): Promise<Readonly<{ id: string }>> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const response = await fetch(`${dashboard.origin}/api/approvals`, {
      headers: { Authorization: `Bearer ${dashboard.token}` },
    });
    const body = await response.json() as { approvals?: Array<{ id: string }> };
    const pending = body.approvals?.[0];
    if (pending !== undefined) return pending;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error('Timed out waiting for install approval');
}
