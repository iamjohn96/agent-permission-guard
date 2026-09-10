import { createHash, randomUUID } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { LocalApprovalService } from '../../src/approval/service.js';
import { PortableReceiptService, serializePortableReceipt, verifyPortableReceipt } from '../../src/audit/portable-receipt.js';
import { AuditQueryService } from '../../src/audit/query-service.js';
import { SqliteAuditRecorder } from '../../src/audit/recorder.js';
import { startDashboard } from '../../src/dashboard/server.js';
import {
  openAuditDatabase,
  openExistingGraphGenesisAuditDatabase,
  type ExistingGraphGenesisAuditDatabase,
} from '../../src/db/database.js';
import { ExactGraphCandidateAuthority } from '../../src/stage/exact-production-graph.js';
import {
  GraphGenesisCandidateArtifactAuthority,
  GraphGenesisCandidateArtifactImporter,
  ProductionGraphGenesisTerminalProofSource,
} from '../../src/stage/graph-genesis-candidate-artifact.js';
import { PostStateBoundGraphGenesisCleanupAuthority } from '../../src/stage/graph-genesis-cleanup.js';
import {
  GraphGenesisExecutionEnvelopeAuthority,
  ProductionGraphGenesisSessionAuthority,
  SyntheticGraphGenesisStartLeaseAuthority,
  SyntheticNetworkFreeGraphGenesisOrchestrator,
  graphGenesisDigest,
  graphGenesisDirectoryIdentityDigest,
} from '../../src/stage/graph-genesis-composition.js';
import {
  FinalizedGraphGenesisWorkspaceAuthority,
  GraphGenesisAuditGate,
  HardenedGraphGenesisPlanAuthority,
  OwnedContainmentProbeAuthority,
  OwnedHostPlatformAuthority,
  OwnedRuntimeVersionAuthority,
  RuntimeFileSnapshotAuthority,
  computeWorkspaceBinding,
  type ContainmentProbeExecutor,
  type HostPlatformProbeExecutor,
  type RuntimeVersionProbeExecutor,
  type GraphGenesisDurableAuditSink,
} from '../../src/stage/graph-genesis-hardening.js';
import { HardenedGraphGenesisPostStateAuthority } from '../../src/stage/graph-genesis-workspace.js';
import { SeatbeltLoopbackContainmentAuthority } from '../../src/stage/graph-genesis-containment.js';
import { RuntimeTreeSnapshotAuthority, buildGraphGenesisLaunch } from '../../src/stage/graph-genesis.js';
import { PACKAGE_STAGE_HARD_CEILINGS } from '../../src/stage/profile.js';

const NOW = new Date('2026-09-08T01:00:00.000Z');
const temporaryPaths: string[] = [];

afterEach(() => {
  for (const path of temporaryPaths.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe('production Graph Genesis approval and execution composition foundation', () => {
  it('keeps the composition foundation free of public DNS, HTTPS, and npm spawn behind the live owner', () => {
    const source = readFileSync(join(process.cwd(), 'src/stage/graph-genesis-composition.ts'), 'utf8');
    expect(source).not.toMatch(/node:dns|node:https|SystemRegistryAddressResolver|NodePinnedHttpsClient|NodeGraphGenesisSpawnAdapter/);
    expect(source).not.toMatch(/import\s+\{[^}]*\bspawn\b|\bexecFile\s*\(|npm-cli/);
    const cli = readFileSync(join(process.cwd(), 'src/cli/main.ts'), 'utf8');
    const readiness = readFileSync(join(process.cwd(), 'src/cli/graph-genesis.ts'), 'utf8');
    expect(cli).toContain('runGraphGenesisReadiness');
    expect(readiness).toContain("await import('../stage/graph-genesis-live.js')");
    expect(readiness).not.toMatch(/node:dns|node:https|node:child_process|openAuditDatabase|startDashboard|npm-cli/);
  });

  it('binds the exact envelope, persists approval before visibility, and issues a two-phase one-time start lease', async () => {
    const fixture = await planFixture();
    const source = existingAuditSource();
    const database = source.database;
    const approvals = new LocalApprovalService(() => NOW);
    try {
      const envelopes = new GraphGenesisExecutionEnvelopeAuthority(fixture.plans);
      const prepared = envelopeFixture(envelopes, fixture, undefined, source);
      const sessions = new ProductionGraphGenesisSessionAuthority(fixture.plans, envelopes, approvals);
      const { audit, recorder } = sessions.createBoundAuditSession(
        source, prepared.envelope, prepared.privateCapsule, () => NOW,
      );
      const executionAudit = sessions.createExecutionAuditGate(audit, prepared.envelope);
      expect(executionAudit.implementationKind).toBe('production');
      expect(prepared.envelope).toMatchObject({
        runtimeManifestDigest: '6'.repeat(64),
        containmentEvidenceDigest: fixture.prepared.plan.containmentEvidenceDigest,
      });
      expect(prepared.envelope.launchDigest).toBe(fixture.prepared.plan.launchDigest);
      expect(fixture.prepared.capsule.launch.launchDigest).toBe(fixture.prepared.plan.launchDigest);
      const { launchDigest, ...legacyLaunch } = fixture.prepared.capsule.launch;
      const legacyLaunchDigest = graphGenesisDigest({
        ...legacyLaunch,
        args: legacyLaunch.args.filter((argument) => argument !== '--maxsockets=4'),
      });
      expect(legacyLaunchDigest).not.toBe(launchDigest);
      const noSaveProdLaunchDigest = graphGenesisDigest({
        ...legacyLaunch,
        args: legacyLaunch.args.filter((argument) => argument !== '--save-prod'),
      });
      const changedSaveProdLaunchDigest = graphGenesisDigest({
        ...legacyLaunch,
        args: legacyLaunch.args.map((argument) => argument === '--save-prod' ? '--save-dev' : argument),
      });
      const nestedPrefixLaunchDigest = graphGenesisDigest({
        ...legacyLaunch,
        args: legacyLaunch.args.map((argument) => argument === `--prefix=${fixture.workspace.rootRealpath}`
          ? `--prefix=${join(fixture.workspace.rootRealpath, 'prefix')}` : argument),
      });
      expect(noSaveProdLaunchDigest).not.toBe(launchDigest);
      expect(changedSaveProdLaunchDigest).not.toBe(launchDigest);
      expect(nestedPrefixLaunchDigest).not.toBe(launchDigest);
      const { executionEnvelopeHash, ...unsignedEnvelope } = prepared.envelope;
      expect(graphGenesisDigest({ ...unsignedEnvelope, launchDigest: legacyLaunchDigest }))
        .not.toBe(executionEnvelopeHash);
      expect(graphGenesisDigest({ ...unsignedEnvelope, launchDigest: noSaveProdLaunchDigest }))
        .not.toBe(executionEnvelopeHash);
      expect(graphGenesisDigest({ ...unsignedEnvelope, launchDigest: changedSaveProdLaunchDigest }))
        .not.toBe(executionEnvelopeHash);
      expect(graphGenesisDigest({ ...unsignedEnvelope, launchDigest: nestedPrefixLaunchDigest }))
        .not.toBe(executionEnvelopeHash);
      await expect(executionAudit.record('runtime_snapshot_complete', {
        runtimeManifestDigest: '0'.repeat(64),
      })).rejects.toMatchObject({ code: 'stage_audit_incomplete' });
      await executionAudit.record('runtime_snapshot_complete', {
        runtimeManifestDigest: prepared.envelope.runtimeManifestDigest,
      });
      await expect(executionAudit.record('containment_probe_complete', {
        containmentEvidenceDigest: '0'.repeat(64),
      })).rejects.toMatchObject({ code: 'stage_audit_incomplete' });
      await executionAudit.record('containment_probe_complete', {
        containmentEvidenceDigest: prepared.envelope.containmentEvidenceDigest,
      });
      await expect(executionAudit.record('plan_ready', {
        executionEnvelopeHash: '0'.repeat(64),
      })).rejects.toMatchObject({ code: 'stage_audit_incomplete' });
      await executionAudit.record('plan_ready', {
        executionEnvelopeHash: prepared.envelope.executionEnvelopeHash,
      });
      const preparationOrder = database.prepare(`
        SELECT event_type FROM audit_events WHERE tool_call_id = ?
          AND event_type IN (
            'decision_recorded',
            'graph_genesis_session_created',
            'graph_genesis_execution_runtime_snapshot_complete',
            'graph_genesis_execution_containment_probe_complete',
            'graph_genesis_execution_plan_ready'
          ) ORDER BY sequence
      `).all(audit.actionId);
      expect(preparationOrder).toEqual([
        { event_type: 'decision_recorded' },
        { event_type: 'graph_genesis_session_created' },
        { event_type: 'graph_genesis_execution_runtime_snapshot_complete' },
        { event_type: 'graph_genesis_execution_containment_probe_complete' },
        { event_type: 'graph_genesis_execution_plan_ready' },
      ]);
      expect(() => sessions.createExecutionAuditGate(audit, { ...prepared.envelope }))
        .toThrowError(expect.objectContaining({ code: 'approval_invalid' }));
      let monotonic = 1_000;
      const authorization = sessions.authorize({
        ...prepared,
        audit,
        monotonicNow: () => monotonic,
        wallNow: () => NOW,
      });

      const pending = approvals.listPending();
      expect(pending).toHaveLength(1);
      expect(pending[0]).toMatchObject({ kind: 'graph_genesis', graphGenesis: { target: '@modelcontextprotocol/server-filesystem@2026.7.10' } });
      const approvalEvent = database.prepare(`
        SELECT sequence FROM audit_events WHERE tool_call_id = ? AND event_type = 'approval_requested'
      `).get(audit.actionId);
      expect(approvalEvent).toBeDefined();
      expect(JSON.stringify(pending[0])).not.toContain(fixture.routeToken);
      expect(JSON.stringify(pending[0])).toContain('Direct npm/npx commands bypass APG');

      expect(approvals.decide(pending[0]!.id, 'approved')).toBe('approved');
      monotonic = 2_000;
      const result = await authorization;
      expect(result.status).toBe('authorized');
      if (result.status !== 'authorized') throw new Error('expected authorization');
      expect(result.executionAudit).toBe(executionAudit);
      expect(result.executionAudit.events).toEqual([
        'runtime_snapshot_complete', 'containment_probe_complete', 'plan_ready', 'authorization_finalized',
      ]);
      expect(sessions.authenticatesStartLease(result.lease, fixture.prepared.plan.planHash)).toBe(true);
      expect(sessions.consumeStartLease(result.lease, 'broker_arm', 2_001)).toBe(true);
      expect(sessions.consumeStartLease(result.lease, 'broker_arm', 2_002)).toBe(false);
      expect(sessions.consumeStartLease(result.lease, 'process_spawn', 2_003)).toBe(true);
      expect(sessions.consumeStartLease(result.lease, 'process_spawn', 2_004)).toBe(false);

      const receiptRow = database.prepare(`
        SELECT event_json FROM audit_events
        WHERE tool_call_id = ? AND event_type = 'authorization_receipt_finalized'
      `).get(audit.actionId) as { event_json: string };
      const receiptEvent = JSON.parse(receiptRow.event_json) as { details: { receipt: { schema: { minorVersion: number }; coverage: { boundary: string }; action: { executionPlanHash: string } } } };
      expect(receiptEvent.details.receipt).toMatchObject({
        schema: { minorVersion: 2 },
        coverage: { boundary: 'graph_genesis_plan' },
        action: { executionPlanHash: prepared.envelope.executionEnvelopeHash },
      });
      const portable = new PortableReceiptService(database, recorder).exportAction(audit.actionId);
      expect(portable.format.minorVersion).toBe(2);
      expect(verifyPortableReceipt(serializePortableReceipt(portable))).toMatchObject({ valid: true, status: 'incomplete' });
      await result.executionAudit.record('broker_armed');
      await result.executionAudit.record('npm_spawn_intent_recorded');
      await result.executionAudit.record('npm_spawn_started');
      await result.executionAudit.record('metadata_request_started', { sequence: 1, packageName: '@modelcontextprotocol/server-filesystem' });
      await result.executionAudit.record('metadata_response_validated', {
        sequence: 1, packageName: '@modelcontextprotocol/server-filesystem', responseBytes: 128,
      });
      await result.executionAudit.record('npm_terminal_observed', {
        status: 'completed', exitCode: 0, stdoutBytes: 0, stderrBytes: 0,
      });
      audit.finalizeGraphGenesisOutcome({
        metadata: { externalReadStatus: 'validated', requestCount: 1, uniquePackageCount: 1, responseBytes: 128 },
        process: { status: 'completed', exitCode: 0, stdoutBytes: 0, stderrBytes: 0 },
        candidate: {
          lockDigest: `sha256:${'6'.repeat(64)}`,
          candidateDigest: `sha256:${'7'.repeat(64)}`,
          artifactDigest: `sha256:${'8'.repeat(64)}`,
        },
        cleanup: { status: 'complete' },
        terminalAudit: { status: 'complete' },
      }, 'completed');
      const complete = new PortableReceiptService(database, recorder).exportAction(audit.actionId);
      expect(complete.outcome?.receipt.execution.observedResult).toMatchObject({
        kind: 'graph_genesis', externalReadStatus: 'validated', cleanupStatus: 'complete', terminalAuditStatus: 'complete',
      });
      expect(verifyPortableReceipt(serializePortableReceipt(complete))).toMatchObject({ valid: true, status: 'verified_unsigned' });
      const terminalEvents = database.prepare(`
        SELECT event_type FROM audit_events WHERE tool_call_id = ?
          AND event_type IN ('graph_genesis_complete', 'outcome_receipt_finalized') ORDER BY sequence
      `).all(audit.actionId);
      expect(terminalEvents).toEqual([
        { event_type: 'graph_genesis_complete' }, { event_type: 'outcome_receipt_finalized' },
      ]);
      const productionProof = new ProductionGraphGenesisTerminalProofSource({
        canonicalPath: source.canonicalPath,
        fileIdentityDigest: source.fileIdentityDigest,
        schemaDigest: source.schemaDigest,
      });
      expect(() => new ProductionGraphGenesisTerminalProofSource({
        canonicalPath: source.canonicalPath,
        fileIdentityDigest: '0'.repeat(64),
        schemaDigest: source.schemaDigest,
      })).toThrow();
      expect(productionProof.hasCompleteTerminalProof({
        actionId: audit.actionId,
        executionEnvelopeHash: prepared.envelope.executionEnvelopeHash,
        planHash: prepared.envelope.planHash,
        candidateDigest: '7'.repeat(64),
        artifactDigest: '8'.repeat(64),
      })).toBe(true);
      chmodSync(dirname(source.canonicalPath), 0o755);
      expect(productionProof.hasCompleteTerminalProof({
        actionId: audit.actionId,
        executionEnvelopeHash: prepared.envelope.executionEnvelopeHash,
        planHash: prepared.envelope.planHash,
        candidateDigest: '7'.repeat(64),
        artifactDigest: '8'.repeat(64),
      })).toBe(false);
      chmodSync(dirname(source.canonicalPath), 0o700);
      expect(productionProof.hasCompleteTerminalProof({
        actionId: audit.actionId,
        executionEnvelopeHash: prepared.envelope.executionEnvelopeHash,
        planHash: prepared.envelope.planHash,
        candidateDigest: '7'.repeat(64),
        artifactDigest: '9'.repeat(64),
      })).toBe(false);
    } finally {
      approvals.close();
      database.close();
    }
  });

  it('rejects copied or substituted envelope material and records denial without a lease', async () => {
    const fixture = await planFixture();
    const envelopes = new GraphGenesisExecutionEnvelopeAuthority(fixture.plans);
    const source = existingAuditSource();
    const prepared = envelopeFixture(envelopes, fixture, undefined, source);
    expect(envelopes.authenticatesPair({ ...prepared.envelope }, prepared.privateCapsule)).toBe(false);
    expect(envelopes.authenticatesPair(prepared.envelope, { ...prepared.privateCapsule })).toBe(false);

    const database = source.database;
    const approvals = new LocalApprovalService(() => NOW);
    try {
      const sessions = new ProductionGraphGenesisSessionAuthority(fixture.plans, envelopes, approvals);
      expect(() => sessions.createBoundAuditSession(
        { ...source }, prepared.envelope, prepared.privateCapsule, () => NOW,
      )).toThrowError(expect.objectContaining({ code: 'approval_invalid' }));
      const substitutedSource = existingAuditSource();
      expect(() => sessions.createBoundAuditSession(
        substitutedSource, prepared.envelope, prepared.privateCapsule, () => NOW,
      )).toThrowError(expect.objectContaining({ code: 'approval_invalid' }));
      substitutedSource.database.close();
      const { audit } = sessions.createBoundAuditSession(
        source, prepared.envelope, prepared.privateCapsule, () => NOW,
      );
      const pendingResult = sessions.authorize({
        ...prepared, audit, monotonicNow: () => 1_000, wallNow: () => NOW,
      });
      const request = approvals.listPending()[0]!;
      approvals.decide(request.id, 'denied');
      await expect(pendingResult).resolves.toMatchObject({ status: 'denied', actionId: audit.actionId });
      const statuses = database.prepare('SELECT status FROM approvals WHERE tool_call_id = ?').all(audit.actionId);
      expect(statuses).toEqual([{ status: 'denied' }]);
      await expect(sessions.authorize({
        ...prepared, audit, monotonicNow: () => 1_000, wallNow: () => NOW,
      })).rejects.toMatchObject({ code: 'approval_invalid' });
    } finally {
      approvals.close();
      database.close();
    }
  });

  it('keeps a request hidden and issues no authority when durable approval-request recording fails', async () => {
    const fixture = await planFixture();
    const envelopes = new GraphGenesisExecutionEnvelopeAuthority(fixture.plans);
    const source = existingAuditSource();
    const prepared = envelopeFixture(envelopes, fixture, undefined, source);
    const approvals = new LocalApprovalService(() => NOW);
    const sessions = new ProductionGraphGenesisSessionAuthority(fixture.plans, envelopes, approvals);
    const database = source.database;
    try {
      const audit = sessions.createBoundAuditSession(
        source, prepared.envelope, prepared.privateCapsule, () => NOW,
      ).audit;
      database.exec(`
        CREATE TRIGGER reject_graph_approval BEFORE INSERT ON approvals
        BEGIN SELECT RAISE(ABORT, 'synthetic durable audit failure'); END
      `);
      await expect(sessions.authorize({
        ...prepared, audit, monotonicNow: () => 1_000, wallNow: () => NOW,
      })).rejects.toThrow(/durable audit failure/);
      expect(approvals.listPending()).toEqual([]);
      expect(database.prepare('SELECT COUNT(*) AS count FROM approvals').get()).toEqual({ count: 0 });
    } finally {
      approvals.close();
      database.close();
    }
  });

  it('runs the Dashboard in approval/audit-only mode with policy routes disabled', async () => {
    const database = openAuditDatabase(':memory:');
    const approvals = new LocalApprovalService(() => NOW);
    const recorder = new SqliteAuditRecorder(database, () => NOW);
    const dashboard = await startDashboard({
      approvals,
      audit: new AuditQueryService(database, recorder),
      token: 'd'.repeat(48),
      port: 0,
      mode: 'approval_audit_only',
    });
    try {
      const url = new URL(dashboard.url);
      const headers = { Origin: url.origin, Authorization: `Bearer ${'d'.repeat(48)}` };
      const health = await fetch(`${url.origin}/api/health`, { headers });
      await expect(health.json()).resolves.toMatchObject({ capabilities: ['approvals', 'audit'] });
      expect((await fetch(`${url.origin}/api/policy`, { headers })).status).toBe(404);
      expect((await fetch(`${url.origin}/api/policy`, { method: 'PUT', headers })).status).toBe(404);
    } finally {
      approvals.close();
      await dashboard.close();
      database.close();
    }
  });

  it('opens only an existing exact private audit schema and performs no migration', () => {
    const parent = temporaryDirectory('apg-existing-audit-');
    const path = join(parent, 'audit.sqlite');
    const created = openAuditDatabase(path);
    created.close();
    const before = statSync(path);
    const opened = openExistingGraphGenesisAuditDatabase(path);
    try {
      expect(opened).toMatchObject({ canonicalPath: path, initialChainTail: '0'.repeat(64) });
      expect(opened.schemaDigest).toMatch(/^[a-f0-9]{64}$/u);
      expect(opened.fileIdentityDigest).toMatch(/^[a-f0-9]{64}$/u);
      expect(opened.durabilityProfileDigest).toMatch(/^[a-f0-9]{64}$/u);
      expect(opened.database.pragma('journal_mode', { simple: true })).toBe('wal');
      expect(opened.database.pragma('synchronous', { simple: true })).toBe(2);
      expect(opened.database.prepare('SELECT version FROM schema_migrations ORDER BY version').all())
        .toEqual([{ version: 1 }, { version: 2 }]);
    } finally { opened.database.close(); }
    expect(statSync(path).ino).toBe(before.ino);
    chmodSync(path, 0o644);
    expect(() => openExistingGraphGenesisAuditDatabase(path)).toThrow(/private current-user regular file/);
  });

  it('rejects an existing audit source when its captured chain tail has drifted', async () => {
    const fixture = await planFixture();
    const source = existingAuditSource();
    const envelopes = new GraphGenesisExecutionEnvelopeAuthority(fixture.plans);
    const prepared = envelopeFixture(envelopes, fixture, undefined, source);
    const approvals = new LocalApprovalService(() => NOW);
    try {
      new SqliteAuditRecorder(source.database, () => NOW).begin({
        serverId: 'interleaving-fixture', toolName: 'write', arguments: {},
      }, { action: 'forward' });
      const sessions = new ProductionGraphGenesisSessionAuthority(fixture.plans, envelopes, approvals);
      expect(() => sessions.createBoundAuditSession(
        source, prepared.envelope, prepared.privateCapsule, () => NOW,
      )).toThrowError(expect.objectContaining({ code: 'approval_invalid' }));
    } finally {
      approvals.close();
      source.database.close();
    }
  });

  it('composes the broker and inert child under one synthetic abort owner without network access', async () => {
    const fixture = await planFixture();
    const audit = new GraphGenesisAuditGate(fixture.prepared.plan.planHash, new MemoryGraphAuditSink());
    await audit.record('authorization_finalized');
    const leases = new SyntheticGraphGenesisStartLeaseAuthority(fixture.plans);
    const lease = leases.createForTest(fixture.prepared.plan, 10_000);
    const orchestrator = new SyntheticNetworkFreeGraphGenesisOrchestrator(fixture.plans, {
      implementationKind: 'synthetic',
      async fetchPackage(packageName) {
        return {
          status: 200,
          contentType: 'application/json',
          contentEncoding: 'identity',
          finalUrl: `https://registry.npmjs.org/${packageName.replace('/', '%2f')}`,
          redirected: false,
          body: Buffer.from(JSON.stringify({ name: packageName, versions: {} })),
        };
      },
    });
    await expect(orchestrator.run({
      plan: fixture.prepared.plan,
      capsule: fixture.prepared.capsule,
      startLease: lease,
      startLeaseVerifier: leases,
      audit,
      packageNames: ['@modelcontextprotocol/server-filesystem'],
      monotonicNow: () => 1,
    })).resolves.toMatchObject({
      terminalState: 'synthetic_complete',
      ledger: { startedRequestCount: 1, terminalState: 'disarmed_complete' },
      process: { status: 'completed', exitCode: 0, childClosed: true },
    });

    const cancelled = new AbortController();
    cancelled.abort();
    const secondAudit = new GraphGenesisAuditGate(fixture.prepared.plan.planHash, new MemoryGraphAuditSink());
    await secondAudit.record('authorization_finalized');
    const secondLeases = new SyntheticGraphGenesisStartLeaseAuthority(fixture.plans);
    await expect(new SyntheticNetworkFreeGraphGenesisOrchestrator(fixture.plans, {
      implementationKind: 'synthetic',
      async fetchPackage() { throw new Error('transport must not run'); },
    }).run({
      plan: fixture.prepared.plan,
      capsule: fixture.prepared.capsule,
      startLease: secondLeases.createForTest(fixture.prepared.plan, 10_000),
      startLeaseVerifier: secondLeases,
      audit: secondAudit,
      packageNames: ['fixture'],
      monotonicNow: () => 1,
      signal: cancelled.signal,
    })).rejects.toMatchObject({ code: 'artifact_cancelled' });
  });

  it('writes a private exclusive candidate and rejects import without matching terminal proof', async () => {
    const fixture = await planFixture();
    const outputParent = temporaryDirectory('apg-graph-output-');
    const outputPath = join(outputParent, 'candidate.json');
    const envelopes = new GraphGenesisExecutionEnvelopeAuthority(fixture.plans);
    const prepared = envelopeFixture(envelopes, fixture, outputPath);
    const candidates = new ExactGraphCandidateAuthority();
    const candidate = candidates.compile(candidateInput());
    const artifacts = new GraphGenesisCandidateArtifactAuthority(envelopes, candidates);
    const artifact = artifacts.compile({
      ...prepared,
      candidate,
      actionId: randomUUID(),
      brokerLedgerDigest: '8'.repeat(64),
      postStateDigest: '9'.repeat(64),
    });
    const written = await artifacts.writeExclusive({ ...prepared, artifact });
    expect(written.artifactDigest).toBe(artifact.artifactDigest);
    expect(statSync(outputPath).mode & 0o777).toBe(0o600);
    expect(() => JSON.parse(readFileSync(outputPath, 'utf8'))).not.toThrow();
    await expect(artifacts.writeExclusive({ ...prepared, artifact })).rejects.toMatchObject({ code: 'acceptance_incomplete' });

    const importer = new GraphGenesisCandidateArtifactImporter();
    await expect(importer.verify(outputPath, { hasCompleteTerminalProof: () => false }))
      .rejects.toMatchObject({ code: 'acceptance_incomplete' });
    await expect(importer.verify(outputPath, { hasCompleteTerminalProof: (query) => query.artifactDigest === artifact.artifactDigest }))
      .resolves.toMatchObject({ artifactDigest: artifact.artifactDigest, assurance: 'portable_unsigned_local_candidate' });
  });

  it('binds cleanup to an authenticated post-state inventory and quarantines drift', async () => {
    const fixture = await planFixture();
    writeExpectedPostState(fixture.workspace.rootRealpath);
    const postStates = new HardenedGraphGenesisPostStateAuthority(fixture.plans, fixture.workspaces);
    const inspected = await postStates.inspect({
      plan: fixture.prepared.plan,
      executionCapsule: fixture.prepared.capsule,
      workspace: fixture.workspace,
    });
    const cleanups = new PostStateBoundGraphGenesisCleanupAuthority(postStates);
    const inventory = await cleanups.capture(fixture.workspace, inspected.evidence);
    writeFileSync(join(fixture.workspace.rootRealpath, 'logs', 'foreign.log'), 'foreign');
    await expect(cleanups.cleanup(fixture.workspace, inventory)).rejects.toMatchObject({ code: 'artifact_cleanup_incomplete' });
    expect(existsSync(fixture.workspace.rootRealpath)).toBe(true);
    expect(existsSync(join(fixture.workspace.rootRealpath, 'logs', 'foreign.log'))).toBe(true);
    unlinkSync(join(fixture.workspace.rootRealpath, 'logs', 'foreign.log'));
    const acceptedInventory = await cleanups.capture(fixture.workspace, inspected.evidence);
    const result = await cleanups.cleanup(fixture.workspace, acceptedInventory);
    expect(cleanups.authenticates(result)).toBe(true);
    expect(existsSync(fixture.workspace.rootRealpath)).toBe(false);
  });
});

function envelopeFixture(
  envelopes: GraphGenesisExecutionEnvelopeAuthority,
  fixture: Awaited<ReturnType<typeof planFixture>>,
  outputPath = join(fixture.parent, 'output', 'candidate.json'),
  auditSource?: ExistingGraphGenesisAuditDatabase,
) {
  return envelopes.create({
    prepared: fixture.prepared,
    dashboardInstanceId: '11111111-1111-4111-8111-111111111111',
    dashboardPort: 47_831,
    runtimeManifestDigest: '6'.repeat(64),
    bootSessionDigest: '1'.repeat(64),
    audit: {
      path: auditSource?.canonicalPath ?? join(fixture.parent, 'audit.sqlite'),
      schemaDigest: auditSource?.schemaDigest ?? '2'.repeat(64),
      fileIdentityDigest: auditSource?.fileIdentityDigest ?? '3'.repeat(64),
      databaseInstanceId: auditSource?.databaseInstanceId ?? '22222222-2222-4222-8222-222222222222',
      initialChainTail: auditSource?.initialChainTail ?? '4'.repeat(64),
      durabilityProfileDigest: auditSource?.durabilityProfileDigest ?? '5'.repeat(64),
    },
    output: {
      path: outputPath,
      canonicalPathDigest: graphGenesisDigest(outputPath),
      parentIdentityDigest: directoryIdentity(dirname(outputPath)),
    },
    requestedAt: NOW.toISOString(),
    planDeadlineMonotonicMs: 181_000,
  });
}

function existingAuditSource(): ExistingGraphGenesisAuditDatabase {
  const parent = temporaryDirectory('apg-composition-audit-');
  const path = join(parent, 'audit.sqlite');
  const created = openAuditDatabase(path);
  created.close();
  return openExistingGraphGenesisAuditDatabase(path);
}

function directoryIdentity(path: string): string {
  const info = statSync(path);
  return graphGenesisDirectoryIdentityDigest({
    canonicalPath: path,
    device: info.dev,
    inode: info.ino,
    owner: info.uid,
    mode: info.mode & 0o7777,
  });
}

async function planFixture() {
  const parent = temporaryDirectory('apg-composition-');
  mkdirSync(join(parent, 'output'), { mode: 0o700 });
  const files = new RuntimeFileSnapshotAuthority();
  const trees = new RuntimeTreeSnapshotAuthority();
  const versions = new OwnedRuntimeVersionAuthority(files, trees, syntheticVersionExecutor());
  const workspaces = new FinalizedGraphGenesisWorkspaceAuthority(trees);
  const probes = new OwnedContainmentProbeAuthority(files, workspaces, syntheticContainmentExecutor());
  const hosts = new OwnedHostPlatformAuthority(syntheticHostExecutor());
  const plans = new HardenedGraphGenesisPlanAuthority(files, trees, probes, versions, workspaces, hosts);
  const runtime = join(parent, 'runtime');
  mkdirSync(join(runtime, 'npm/bin'), { recursive: true });
  mkdirSync(join(runtime, 'broker'), { recursive: true });
  const paths = {
    node: join(runtime, 'node'), npmCli: join(runtime, 'npm/bin/npm-cli.js'), sandboxExec: join(runtime, 'sandbox-exec'),
    broker: join(runtime, 'broker/broker.js'), probe: join(runtime, 'probe.js'),
  };
  for (const [name, path] of Object.entries(paths)) writeFileSync(path, `synthetic ${name}`);
  writeFileSync(join(runtime, 'npm/package.json'), JSON.stringify({ name: 'npm', version: '11.16.0' }));
  const snapshots = {
    node: await files.capture('node', paths.node),
    npmCli: await files.capture('npm_cli', paths.npmCli),
    sandboxExec: await files.capture('sandbox_exec', paths.sandboxExec),
    brokerRuntime: await files.capture('broker_runtime', paths.broker),
    probeRuntime: await files.capture('probe_runtime', paths.probe),
  };
  const npmTree = await trees.capture(join(runtime, 'npm'));
  const brokerTree = await trees.capture(join(runtime, 'broker'));
  const runtimeVersions = await versions.observe({ node: snapshots.node, npmCli: snapshots.npmCli, npmTree });
  const host = await hosts.observe();
  const brokerPort = 45_454;
  const containment = new SeatbeltLoopbackContainmentAuthority();
  const profile = containment.prepare({ osBuild: '25G83', sandboxExecSha256: snapshots.sandboxExec.sha256, allowedPort: brokerPort });
  const workspace = await workspaces.initialize(join(parent, 'workspace'), profile.profileText);
  const containmentEvidence = await probes.observe({
    osBuild: '25G83', hostEvidenceDigest: host.evidenceDigest, nodeSnapshotDigest: snapshots.node.snapshotDigest,
    probeSnapshotDigest: snapshots.probeRuntime.snapshotDigest, sandboxExecSnapshotDigest: snapshots.sandboxExec.snapshotDigest,
    workspaceBinding: computeWorkspaceBinding(workspace), profileDigest: profile.profileDigest, allowedPort: brokerPort,
  }, profile, { node: snapshots.node, probe: snapshots.probeRuntime, sandboxExec: snapshots.sandboxExec, workspace });
  const routeToken = 'a'.repeat(32);
  const launch = buildGraphGenesisLaunch({
    sandboxExecPath: snapshots.sandboxExec.absolutePath, profilePath: join(workspace.rootRealpath, 'broker-profile.sb'),
    nodePath: snapshots.node.absolutePath, npmCliPath: snapshots.npmCli.absolutePath, npmRuntimeRoot: npmTree.rootRealpath,
    workspaceRoot: workspace.rootRealpath, brokerPort, routeToken,
  });
  const prepared = plans.prepare({
    planId: 'b'.repeat(32), host, ...snapshots, npmTree, brokerTree, runtimeVersions, containmentEvidence,
    workspace, brokerPort, routeToken, launch, limits: limits(), allowSynthetic: true,
  });
  return { parent, plans, workspaces, workspace, routeToken, prepared };
}

function limits() {
  return {
    broker: { uniquePackageNames: 4, totalRequests: 8, concurrentRequests: 2, responseBytes: 4_096, aggregateResponseBytes: 32_768, requestTimeoutMs: 100 },
    completeTimeoutMs: 1_000, stdoutBytes: 1_024, stderrBytes: 1_024,
    packageJsonBytes: 4_096, packageLockBytes: 8_192,
  };
}

function syntheticVersionExecutor(): RuntimeVersionProbeExecutor {
  return { implementationKind: 'synthetic', async observe() { return { nodeVersion: '26.3.1', npmVersion: '11.16.0' }; } };
}

function syntheticContainmentExecutor(): ContainmentProbeExecutor {
  return { implementationKind: 'synthetic', async run() { return {
    approvedLoopbackPortConnected: true, alternateLoopbackPortDenied: true, nonLoopbackLocalAddressDenied: true,
    ipv6LoopbackDenied: true, outsideWorkspaceWriteDenied: true, childProcessDenied: true,
    workerThreadDenied: true, addonGrantAbsent: true, publicNetworkAttempted: false as const,
  }; } };
}

function syntheticHostExecutor(): HostPlatformProbeExecutor {
  return { implementationKind: 'synthetic', async observe() { return {
    platform: 'darwin', architecture: 'arm64', osBuild: '25G83',
    bootSessionId: '00000000-0000-0000-0000-000000000001',
  }; } };
}

function candidateInput() {
  const name = '@modelcontextprotocol/server-filesystem';
  const version = '2026.7.10';
  return {
    profileId: 'filesystem-candidate', profileVersion: 1,
    topPackage: { name, exactVersion: version, exactEntrypointRelativePath: 'dist/index.js' },
    registryOrigin: 'https://registry.npmjs.org/',
    runtimeConstraint: { os: 'darwin' as const, architecture: 'arm64' as const, nodeMajor: 26 as const, nodeVersion: '26.3.1', npmGraphGeneratorVersion: '11.16.0', lockfileVersion: 3 as const },
    materializationRulesVersion: 1, archiveRulesVersion: 1, workerProtocolVersion: 2 as const,
    limits: PACKAGE_STAGE_HARD_CEILINGS,
    packageLock: {
      name: 'apg-graph-genesis', version: '0.0.0', lockfileVersion: 3, requires: true,
      packages: {
        '': { name: 'apg-graph-genesis', version: '0.0.0', dependencies: { [name]: version } },
        [`node_modules/${name}`]: {
          version,
          resolved: `https://registry.npmjs.org/@modelcontextprotocol/server-filesystem/-/server-filesystem-${version}.tgz`,
          integrity: `sha512-${createHash('sha512').update('synthetic').digest('base64')}`,
        },
      },
    },
  };
}

function writeExpectedPostState(root: string): void {
  writeFileSync(join(root, 'package-lock.json'), JSON.stringify(candidateInput().packageLock));
}

function temporaryDirectory(prefix: string): string {
  const path = realpathSync(mkdtempSync(join(tmpdir(), prefix)));
  chmodSync(path, 0o700);
  temporaryPaths.push(path);
  return path;
}

class MemoryGraphAuditSink implements GraphGenesisDurableAuditSink {
  readonly implementationKind = 'synthetic' as const;
  async append(): Promise<void> {}
}
