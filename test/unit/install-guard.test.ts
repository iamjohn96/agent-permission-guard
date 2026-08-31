import { describe, expect, it } from 'vitest';

import { LocalApprovalService } from '../../src/approval/service.js';
import { AuditQueryService } from '../../src/audit/query-service.js';
import { SqliteAuditRecorder } from '../../src/audit/recorder.js';
import { openAuditDatabase } from '../../src/db/database.js';
import { InstallAuditAdapter } from '../../src/install/audit.js';
import { InMemoryInstallMetadataProvider } from '../../src/install/metadata.js';
import { InstallParseError, parseInstallRequest } from '../../src/install/parser.js';
import { evaluateInstallPolicy } from '../../src/install/policy.js';
import { scoreInstallRisk } from '../../src/install/risk.js';
import { InstallGuardService } from '../../src/install/service.js';
import type {
  InstallExecutionResult,
  InstallRequest,
  InstallRunnerAdapter,
  ResolvedPackageMetadata,
} from '../../src/install/types.js';

const workingDirectory = '/tmp/apg-install-test';

describe('Install Guard parser', () => {
  it('normalizes one registry package and supported options', () => {
    expect(parseInstallRequest('npm', ['--save-exact', 'yaml@2.9.0', '--save-dev'], workingDirectory)).toEqual({
      runner: 'npm',
      packageName: 'yaml',
      requestedSpecifier: '2.9.0',
      options: ['--save-dev', '--save-exact'],
      workingDirectory,
    });
  });

  it('parses scoped packages without confusing the scope marker for a version', () => {
    expect(parseInstallRequest('npx', ['--yes', '@modelcontextprotocol/server@2.0.0'], workingDirectory)).toMatchObject({
      runner: 'npx',
      packageName: '@modelcontextprotocol/server',
      requestedSpecifier: '2.0.0',
      options: ['--yes'],
    });
  });

  it.each([
    ['npm', ['left-pad', 'yaml']],
    ['npm', ['yaml;whoami']],
    ['npm', ['https://example.com/package.tgz']],
    ['npm', ['../local-package']],
    ['npm', ['yaml', '--force']],
    ['npx', ['yaml', '--save-dev']],
  ] as const)('rejects ambiguous or unsupported %s input %j', (runner, args) => {
    expect(() => parseInstallRequest(runner, args, workingDirectory)).toThrow(InstallParseError);
  });

  it('requires an absolute working directory as part of the approval identity', () => {
    expect(() => parseInstallRequest('npm', ['yaml'], 'relative/project')).toThrow(/absolute path/);
  });
});

describe('Install Guard offline metadata', () => {
  it('resolves only an exact fixture key and fails closed for other requests', async () => {
    const request = parseInstallRequest('npm', ['yaml@2.9.0'], workingDirectory);
    const metadata = safeMetadata();
    const provider = new InMemoryInstallMetadataProvider([{
      request,
      resolution: { status: 'resolved', metadata },
    }]);

    await expect(provider.resolve(request)).resolves.toEqual({ status: 'resolved', metadata });
    await expect(provider.resolve({ ...request, requestedSpecifier: 'latest' })).resolves.toMatchObject({
      status: 'unavailable',
    });
  });
});

describe('Install Guard risk and built-in policy', () => {
  it('allows an exactly resolved registry package with no material signal', () => {
    expect(evaluateInstallPolicy({ status: 'resolved', metadata: safeMetadata() })).toEqual({
      effectiveDecision: 'allow',
      reasonCodes: ['verified_registry_package'],
      risk: { score: 0, band: 'low', signals: [] },
    });
  });

  it('asks when lifecycle scripts exist', () => {
    const evaluation = evaluateInstallPolicy({
      status: 'resolved',
      metadata: { ...safeMetadata(), lifecycleScripts: ['postinstall'] },
    });

    expect(evaluation).toMatchObject({ effectiveDecision: 'ask', risk: { score: 35, band: 'medium' } });
    expect(evaluation.reasonCodes).toContain('lifecycle_scripts');
  });

  it('denies an unresolved exact version even when no other metadata exists', () => {
    expect(evaluateInstallPolicy({ status: 'unresolved', reason: 'tag did not resolve' })).toMatchObject({
      effectiveDecision: 'deny',
      risk: { score: 100, band: 'critical' },
    });
  });

  it('never silently allows unavailable or contradictory metadata', () => {
    expect(evaluateInstallPolicy({ status: 'unavailable', reason: 'offline' }).effectiveDecision).toBe('ask');
    expect(evaluateInstallPolicy({ status: 'contradictory', reason: 'mismatch' }).effectiveDecision).toBe('ask');
  });

  it('uses the strictest decision when explain-only and blocking signals coexist', () => {
    const evaluation = evaluateInstallPolicy({
      status: 'resolved',
      metadata: {
        ...safeMetadata(),
        packageIsNew: true,
        repositoryMissing: true,
        advisories: [{ id: 'APG-TEST-1', severity: 'critical' }],
      },
    });

    expect(evaluation.effectiveDecision).toBe('deny');
    expect(evaluation.risk.score).toBe(100);
    expect(evaluation.reasonCodes).toEqual(['critical_advisory', 'new_package', 'repository_missing']);
  });

  it('escalates combined explain-only signals when their total risk is high', () => {
    const evaluation = evaluateInstallPolicy({
      status: 'resolved',
      metadata: {
        ...safeMetadata(),
        packageIsNew: true,
        publisherIsNew: true,
      },
    });

    expect(evaluation).toMatchObject({ effectiveDecision: 'ask', risk: { score: 50, band: 'high' } });
    expect(evaluation.reasonCodes).toEqual([
      'new_package',
      'new_publisher',
      'install_risk_escalation',
    ]);
  });

  it('deduplicates stable risk reason codes', () => {
    const assessment = scoreInstallRisk({
      status: 'resolved',
      metadata: {
        ...safeMetadata(),
        advisories: [
          { id: 'APG-TEST-1', severity: 'high' },
          { id: 'APG-TEST-2', severity: 'high' },
        ],
      },
    });

    expect(assessment.signals.filter((signal) => signal.code === 'high_advisory')).toHaveLength(1);
  });
});

describe('Install Guard approval and audit integration', () => {
  it('runs a safe request through the fake runner and records it in the existing audit chain', async () => {
    const fixture = createServiceFixture(safeMetadata());
    try {
      const result = await fixture.service.run(fixture.request, 1_000);

      expect(result.status).toBe('completed');
      expect(fixture.runner.requests).toHaveLength(1);
      expect(fixture.auditQuery.listRecent(10)).toMatchObject({
        hashChainValid: true,
        calls: [{
          serverId: 'install-guard',
          toolName: 'npm_install',
          effectiveDecision: 'allow',
          status: 'completed',
        }],
      });
    } finally {
      fixture.close();
    }
  });

  it('shows an install-specific one-time approval before invoking the fake runner', async () => {
    const fixture = createServiceFixture({ ...safeMetadata(), lifecycleScripts: ['postinstall'] });
    try {
      const running = fixture.service.run(fixture.request, 1_000);
      const pending = await waitForPending(fixture.approvals);

      expect(pending).toMatchObject({
        kind: 'install',
        serverId: 'install-guard',
        toolName: 'npm install',
        arguments: { package: 'yaml@2.9.0' },
      });
      expect(fixture.runner.requests).toHaveLength(0);
      expect(fixture.approvals.decide(pending.id, 'approved')).toBe('approved');
      await expect(running).resolves.toMatchObject({ status: 'completed' });
      expect(fixture.runner.requests).toHaveLength(1);
      expect(fixture.auditQuery.listRecent(10).calls[0]).toMatchObject({
        approvalStatus: 'approved',
        status: 'completed',
      });
    } finally {
      fixture.close();
    }
  });

  it('never invokes the runner after denial and preserves the request snapshot', async () => {
    const fixture = createServiceFixture({ ...safeMetadata(), lifecycleScripts: ['install'] });
    const mutableOptions = ['--save-exact'];
    const mutableRequest: InstallRequest = { ...fixture.request, options: mutableOptions };
    try {
      const running = fixture.service.run(mutableRequest, 1_000);
      mutableOptions.push('--save-dev');
      const pending = await waitForPending(fixture.approvals);
      expect(pending.arguments).toMatchObject({ options: ['--save-exact'] });
      fixture.approvals.decide(pending.id, 'denied');

      await expect(running).resolves.toMatchObject({ status: 'approval_denied' });
      expect(fixture.runner.requests).toHaveLength(0);
      expect(fixture.auditQuery.listRecent(10).calls[0]).toMatchObject({
        approvalStatus: 'denied',
        status: 'approval_denied',
      });
    } finally {
      fixture.close();
    }
  });

  it('blocks mutable targets when metadata fails before exact resolution', async () => {
    const request = parseInstallRequest('npm', ['yaml@latest'], workingDirectory);
    const fixture = createServiceFixture(undefined, request, {
      status: 'unavailable',
      reason: 'offline',
    });
    try {
      await expect(fixture.service.run(request, 1_000)).resolves.toMatchObject({ status: 'denied' });
      expect(fixture.approvals.listPending()).toHaveLength(0);
      expect(fixture.runner.requests).toHaveLength(0);
    } finally {
      fixture.close();
    }
  });

  it('does not invoke the runner when approval expires', async () => {
    const fixture = createServiceFixture({ ...safeMetadata(), lifecycleScripts: ['prepare'] });
    try {
      await expect(fixture.service.run(fixture.request, 5)).resolves.toMatchObject({
        status: 'approval_expired',
      });
      expect(fixture.runner.requests).toHaveLength(0);
      expect(fixture.auditQuery.listRecent(10).calls[0]).toMatchObject({
        approvalStatus: 'expired',
        status: 'approval_expired',
      });
    } finally {
      fixture.close();
    }
  });

  it('records a runner failure without retaining its raw error text', async () => {
    const fixture = createServiceFixture(safeMetadata(), undefined, undefined, true);
    try {
      await expect(fixture.service.run(fixture.request, 1_000)).resolves.toMatchObject({ status: 'failed' });
      const call = fixture.auditQuery.listRecent(10).calls[0];
      expect(call).toMatchObject({ status: 'failed', errorCode: 'install_runner_failed' });
      expect(JSON.stringify(call)).not.toContain('private runner detail');
    } finally {
      fixture.close();
    }
  });
});

function safeMetadata(): ResolvedPackageMetadata {
  return {
    packageName: 'yaml',
    version: '2.9.0',
    registry: 'https://registry.npmjs.org',
    observedAt: '2026-08-31T00:00:00.000Z',
    lifecycleScripts: [],
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

class FakeInstallRunner implements InstallRunnerAdapter {
  readonly requests: InstallRequest[] = [];

  constructor(private readonly shouldFail = false) {}

  async run(request: InstallRequest): Promise<InstallExecutionResult> {
    this.requests.push(request);
    if (this.shouldFail) throw new Error('private runner detail');
    return { status: 'completed', exitCode: 0, durationMs: 12, summary: 'fake execution completed' };
  }
}

function createServiceFixture(
  metadata: ResolvedPackageMetadata | undefined,
  requestedInput?: InstallRequest,
  overrideResolution?: Awaited<ReturnType<InMemoryInstallMetadataProvider['resolve']>>,
  runnerShouldFail = false,
): Readonly<{
  request: InstallRequest;
  service: InstallGuardService;
  runner: FakeInstallRunner;
  approvals: LocalApprovalService;
  auditQuery: AuditQueryService;
  close(): void;
}> {
  const request = requestedInput ?? parseInstallRequest('npm', ['yaml@2.9.0'], workingDirectory);
  const resolution = overrideResolution ?? (metadata === undefined
    ? { status: 'unavailable' as const, reason: 'offline fixture' }
    : { status: 'resolved' as const, metadata });
  const provider = new InMemoryInstallMetadataProvider([{ request, resolution }]);
  const approvals = new LocalApprovalService();
  const database = openAuditDatabase(':memory:');
  const recorder = new SqliteAuditRecorder(database);
  const auditQuery = new AuditQueryService(database, recorder);
  const runner = new FakeInstallRunner(runnerShouldFail);
  const service = new InstallGuardService({
    metadata: provider,
    approvals,
    audit: new InstallAuditAdapter(recorder),
    runner,
  });

  return {
    request,
    service,
    runner,
    approvals,
    auditQuery,
    close: () => {
      approvals.close();
      database.close();
    },
  };
}

async function waitForPending(approvals: LocalApprovalService) {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const request = approvals.listPending()[0];
    if (request !== undefined) return request;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error('Timed out waiting for Install Guard approval');
}
