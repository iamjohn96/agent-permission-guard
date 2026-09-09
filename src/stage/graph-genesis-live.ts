import { createHash, randomBytes } from 'node:crypto';
import { lstat, realpath } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { LocalApprovalService } from '../approval/service.js';
import { AuditQueryService } from '../audit/query-service.js';
import { SqliteAuditRecorder, type AuditCall } from '../audit/recorder.js';
import { assertGraphGenesisLocalInputs, type ExactGraphGenesisArguments } from '../cli/graph-genesis.js';
import { startDashboard, type DashboardHandle } from '../dashboard/server.js';
import { writeExclusiveDashboardStateFile, type DashboardStateFile } from '../dashboard/state-file.js';
import { openExistingGraphGenesisAuditDatabase, type ExistingGraphGenesisAuditDatabase } from '../db/database.js';
import { canonicalJson } from '../audit/canonical-json.js';
import { ExactGraphCandidateAuthority, type ExactGraphCandidate } from './exact-production-graph.js';
import {
  GraphGenesisCandidateArtifactAuthority,
  ProductionGraphGenesisTerminalProofSource,
  type ProductionGraphGenesisAuditProofIdentity,
  type GraphGenesisCandidateArtifactV1,
} from './graph-genesis-candidate-artifact.js';
import { PostStateBoundGraphGenesisCleanupAuthority, type AuthenticatedPostStateCleanup } from './graph-genesis-cleanup.js';
import {
  GraphGenesisExecutionEnvelopeAuthority,
  ProductionGraphGenesisSessionAuthority,
  graphGenesisDigest,
  graphGenesisDirectoryIdentityDigest,
  type GraphGenesisExecutionEnvelopeV1,
} from './graph-genesis-composition.js';
import { SeatbeltLoopbackContainmentAuthority } from './graph-genesis-containment.js';
import { LocalSeatbeltContainmentProbeExecutor } from './graph-genesis-containment-runner.js';
import {
  FinalizedGraphGenesisWorkspaceAuthority,
  GraphGenesisAuditGate,
  HardenedGraphGenesisPlanAuthority,
  NodeHostPlatformProbeExecutor,
  NodeRuntimeVersionProbeExecutor,
  OwnedContainmentProbeAuthority,
  OwnedHostPlatformAuthority,
  OwnedRuntimeVersionAuthority,
  RuntimeFileSnapshotAuthority,
  computeWorkspaceBinding,
  type HardenedGraphGenesisPlan,
} from './graph-genesis-hardening.js';
import { classifyGraphGenesisFailure, GraphGenesisLivePhaseAuthority } from './graph-genesis-live-state.js';
import {
  BoundedNpmPublicMetadataTransport,
  HardenedLoopbackBrokerListener,
  HardenedMetadataBrokerAuthority,
  NodePinnedHttpsClient,
  SystemRegistryAddressResolver,
  type AuthenticatedHardenedBrokerLedger,
} from './graph-genesis-network.js';
import { repositoryRoot, sqliteNativePath } from './graph-genesis-preflight-audit.js';
import { PreflightRoot } from './graph-genesis-preflight-root.js';
import {
  GraphGenesisProcessSupervisor,
  NodeGraphGenesisSpawnAdapter,
  type AuthenticatedGraphGenesisProcessResult,
} from './graph-genesis-supervisor.js';
import {
  HardenedGraphGenesisCandidateCompiler,
  HardenedGraphGenesisPostStateAuthority,
  type AuthenticatedHardenedGraphGenesisPostState,
} from './graph-genesis-workspace.js';
import { RuntimeTreeSnapshotAuthority, buildGraphGenesisLaunch, type GraphGenesisWorkspace } from './graph-genesis.js';
import { PackageStageError, type PackageStageErrorCode } from './profile.js';

const MiB = 1024 * 1024;
const LIMITS = Object.freeze({
  broker: Object.freeze({ uniquePackageNames: 128, totalRequests: 256, concurrentRequests: 4,
    responseBytes: 4 * MiB, aggregateResponseBytes: 64 * MiB, requestTimeoutMs: 10_000 }),
  completeTimeoutMs: 120_000, stdoutBytes: 256 * 1024, stderrBytes: 256 * 1024,
  packageJsonBytes: 64 * 1024, packageLockBytes: 4 * MiB,
});
const FORBIDDEN_ENVIRONMENT_KEYS = /^(?:NODE_OPTIONS|NODE_EXTRA_CA_CERTS|NODE_TLS_REJECT_UNAUTHORIZED|SSL_CERT_FILE|SSL_CERT_DIR|HTTPS?_PROXY|ALL_PROXY|NO_PROXY|NPM_CONFIG_.+)$/iu;

export type ProductionGraphGenesisLiveResult = Readonly<{
  status: 'complete' | 'not_started' | 'failed' | 'incomplete' | 'quarantined' | 'outcome_unknown';
  exitCode: 0 | 2 | 3 | 4 | 5 | 6;
  reasonCode: string;
  externalReadMayHaveOccurred: boolean;
  installationOccurred: false;
  packageDownloadOccurred: false;
  bypassWarning: 'Direct npm/npx commands bypass APG and receive none of this protection or evidence.';
  actionId?: string;
  executionEnvelopeHash?: string;
  planHash?: string;
  candidateDigest?: string;
  artifactDigest?: string;
  metadataRequestCount?: number;
  metadataResponseBytes?: number;
  processStatus?: string;
  cleanupStatus?: string;
  quarantineReferenceDigest?: string;
}>;

/**
 * The only production live owner. Its public inputs are the parsed operator paths/port and AbortSignal.
 * Every runtime, approval, persistence, network, process, output and cleanup collaborator is constructed here.
 */
export async function runExactProductionGraphGenesisLive(
  input: ExactGraphGenesisArguments,
  signal?: AbortSignal,
): Promise<ProductionGraphGenesisLiveResult> {
  const phases = new GraphGenesisLivePhaseAuthority();
  const controller = new AbortController();
  const externalAbort = () => controller.abort();
  signal?.addEventListener('abort', externalAbort, { once: true });
  const deadline = setTimeout(() => controller.abort(), 180_000);
  deadline.unref();
  const preparationDeadline = setTimeout(() => controller.abort(), 60_000);
  preparationDeadline.unref();
  let root: PreflightRoot | undefined;
  let workspace: GraphGenesisWorkspace | undefined;
  let listener: HardenedLoopbackBrokerListener | undefined;
  let dashboard: DashboardHandle | undefined;
  let dashboardState: DashboardStateFile | undefined;
  let approvals: LocalApprovalService | undefined;
  let auditSource: ExistingGraphGenesisAuditDatabase | undefined;
  let auditProofIdentity: ProductionGraphGenesisAuditProofIdentity | undefined;
  let audit: AuditCall | undefined;
  let executionAudit: GraphGenesisAuditGate | undefined;
  let plan: HardenedGraphGenesisPlan | undefined;
  let envelope: GraphGenesisExecutionEnvelopeV1 | undefined;
  let candidate: ExactGraphCandidate | undefined;
  let artifact: GraphGenesisCandidateArtifactV1 | undefined;
  let ledger: AuthenticatedHardenedBrokerLedger | undefined;
  let processResult: AuthenticatedGraphGenesisProcessResult | undefined;
  let postState: AuthenticatedHardenedGraphGenesisPostState | undefined;
  let cleanup: AuthenticatedPostStateCleanup | undefined;
  let postStates: HardenedGraphGenesisPostStateAuthority | undefined;
  let cleanups: PostStateBoundGraphGenesisCleanupAuthority | undefined;
  let spawned = false;
  let terminalCommitted = false;
  let terminalCommitAttempted = false;
  let reconciliationAttempted = false;
  try {
    assertClosedInput(input, controller.signal);
    phases.advance('INPUT_VALIDATED');
    root = await PreflightRoot.create();
    phases.advance('LOCAL_RESOURCES_CREATED');
    throwIfAborted(controller.signal);

    const files = new RuntimeFileSnapshotAuthority();
    const trees = new RuntimeTreeSnapshotAuthority();
    const repo = repositoryRoot();
    const require = createRequire(import.meta.url);
    const sqliteRoot = dirname(require.resolve('better-sqlite3/package.json'));
    const stageRoot = dirname(fileURLToPath(import.meta.url));
    const node = await files.capture('node', process.execPath);
    const npmCli = await files.capture('npm_cli', '/opt/homebrew/lib/node_modules/npm/bin/npm-cli.js');
    const npmTree = await trees.capture(dirname(dirname(npmCli.absolutePath)));
    const sandboxExec = await files.capture('sandbox_exec', '/usr/bin/sandbox-exec');
    const brokerRuntime = await files.capture('broker_runtime', fileURLToPath(import.meta.url));
    const probeRuntime = await files.capture('probe_runtime', join(stageRoot, 'graph-genesis-containment-probe.js'));
    const sourceRuntimeTree = await trees.capture(dirname(stageRoot));
    const sqliteTree = await trees.capture(join(sqliteRoot, 'lib'));
    const migrationTree = await trees.capture(join(repo, 'migrations'));
    const webTree = await trees.capture(join(repo, 'web'));
    const manifestFiles = await Promise.all([
      sqliteNativePath(), join(sqliteRoot, 'package.json'), join(repo, 'package.json'), join(repo, 'package-lock.json'),
      '/usr/bin/sw_vers', '/usr/sbin/sysctl',
    ].map((path) => files.capture('broker_runtime', path)));
    const runtimeManifestDigest = sha256(canonicalJson({
      trees: [npmTree, sourceRuntimeTree, sqliteTree, migrationTree, webTree].map((tree) => tree.treeDigest),
      files: [node, npmCli, sandboxExec, brokerRuntime, probeRuntime, ...manifestFiles].map((file) => file.snapshotDigest),
    }));
    phases.advance('RUNTIME_SNAPSHOTTED');
    throwIfAborted(controller.signal);

    const hosts = new OwnedHostPlatformAuthority(new NodeHostPlatformProbeExecutor(controller.signal));
    const versions = new OwnedRuntimeVersionAuthority(files, trees, new NodeRuntimeVersionProbeExecutor(controller.signal));
    const host = await hosts.observe();
    const runtimeVersions = await versions.observe({ node, npmCli, npmTree });
    throwIfAborted(controller.signal);
    const workspaces = new FinalizedGraphGenesisWorkspaceAuthority(trees);
    const probes = new OwnedContainmentProbeAuthority(files, workspaces, new LocalSeatbeltContainmentProbeExecutor(controller.signal));
    const plans = new HardenedGraphGenesisPlanAuthority(files, trees, probes, versions, workspaces, hosts);
    const broker = new HardenedMetadataBrokerAuthority(plans);
    listener = new HardenedLoopbackBrokerListener(broker);
    const brokerPort = await listener.listen();
    throwIfAborted(controller.signal);
    const containmentProfile = new SeatbeltLoopbackContainmentAuthority().prepare({
      osBuild: host.osBuild, sandboxExecSha256: sandboxExec.sha256, allowedPort: brokerPort,
    });
    workspace = await workspaces.initialize(join(root.path, 'workspace'), containmentProfile.profileText);
    throwIfAborted(controller.signal);
    const containmentEvidence = await probes.observe({
      osBuild: host.osBuild, hostEvidenceDigest: host.evidenceDigest,
      nodeSnapshotDigest: node.snapshotDigest, probeSnapshotDigest: probeRuntime.snapshotDigest,
      sandboxExecSnapshotDigest: sandboxExec.snapshotDigest, workspaceBinding: computeWorkspaceBinding(workspace),
      profileDigest: containmentProfile.profileDigest, allowedPort: brokerPort,
    }, containmentProfile, { node, probe: probeRuntime, sandboxExec, workspace });
    phases.advance('CONTAINMENT_PROBED');
    throwIfAborted(controller.signal);
    const routeToken = randomBytes(16).toString('hex');
    const launch = buildGraphGenesisLaunch({
      sandboxExecPath: sandboxExec.absolutePath, profilePath: join(workspace.rootRealpath, 'broker-profile.sb'),
      nodePath: node.absolutePath, npmCliPath: npmCli.absolutePath, npmRuntimeRoot: npmTree.rootRealpath,
      workspaceRoot: workspace.rootRealpath, brokerPort, routeToken,
    });
    const prepared = plans.prepare({
      host, node, npmCli, sandboxExec, brokerRuntime, probeRuntime, npmTree, brokerTree: sourceRuntimeTree,
      runtimeVersions, containmentEvidence, workspace, brokerPort, routeToken, launch, limits: LIMITS,
    });
    plan = prepared.plan;
    phases.advance('PLAN_READY');
    clearTimeout(preparationDeadline);
    throwIfAborted(controller.signal);

    auditSource = openExistingGraphGenesisAuditDatabase(input.auditDbPath);
    auditProofIdentity = Object.freeze({
      canonicalPath: auditSource.canonicalPath,
      fileIdentityDigest: auditSource.fileIdentityDigest,
      schemaDigest: auditSource.schemaDigest,
    });
    throwIfAborted(controller.signal);
    approvals = new LocalApprovalService();
    const queryRecorder = new SqliteAuditRecorder(auditSource.database, () => new Date(), 'immediate');
    dashboard = await startDashboard({
      approvals, audit: new AuditQueryService(auditSource.database, queryRecorder),
      token: randomBytes(32).toString('base64url'), port: input.dashboardPort, mode: 'graph_run',
    });
    throwIfAborted(controller.signal);
    const dashboardUrl = new URL(dashboard.url);
    const dashboardPort = Number(dashboardUrl.port);
    if (dashboardUrl.protocol !== 'http:' || dashboardUrl.hostname !== '127.0.0.1'
      || !Number.isSafeInteger(dashboardPort) || dashboardPort < 1024 || dashboardPort > 65_535
      || (input.dashboardPort !== 0 && dashboardPort !== input.dashboardPort)) fail('plan_invalid');
    const outputParentPath = await realpath(dirname(input.outputPath));
    const outputParent = await lstat(outputParentPath);
    const envelopes = new GraphGenesisExecutionEnvelopeAuthority(plans);
    const created = envelopes.create({
      prepared, dashboardInstanceId: dashboard.instanceId, bootSessionDigest: host.bootSessionDigest,
      dashboardPort, runtimeManifestDigest,
      audit: {
        path: auditSource.canonicalPath, schemaDigest: auditSource.schemaDigest,
        fileIdentityDigest: auditSource.fileIdentityDigest, databaseInstanceId: auditSource.databaseInstanceId,
        initialChainTail: auditSource.initialChainTail, durabilityProfileDigest: auditSource.durabilityProfileDigest,
      },
      output: {
        path: input.outputPath, canonicalPathDigest: graphGenesisDigest(input.outputPath),
        parentIdentityDigest: graphGenesisDirectoryIdentityDigest({
          canonicalPath: outputParentPath, device: outputParent.dev, inode: outputParent.ino,
          owner: outputParent.uid, mode: outputParent.mode & 0o7777,
        }),
      },
      requestedAt: new Date().toISOString(), planDeadlineMonotonicMs: performance.now() + 180_000,
    });
    envelope = created.envelope;
    const sessions = new ProductionGraphGenesisSessionAuthority(plans, envelopes, approvals);
    const bound = sessions.createBoundAuditSession(auditSource, envelope, created.privateCapsule);
    audit = bound.audit;
    executionAudit = sessions.createExecutionAuditGate(audit, envelope);
    await executionAudit.record('runtime_snapshot_complete', { runtimeManifestDigest });
    throwIfAborted(controller.signal);
    await executionAudit.record('containment_probe_complete', {
      containmentEvidenceDigest: containmentEvidence.evidenceDigest,
    });
    throwIfAborted(controller.signal);
    await executionAudit.record('plan_ready', { executionEnvelopeHash: envelope.executionEnvelopeHash });
    throwIfAborted(controller.signal);
    dashboard.bindGraphAction(audit.actionId);
    if (input.dashboardStatePath !== undefined) {
      dashboardState = writeExclusiveDashboardStateFile(input.dashboardStatePath, dashboard.url, dashboard.instanceId);
    }
    phases.advance('AUDIT_SESSION_READY');
    throwIfAborted(controller.signal);
    process.stderr.write(`[apg] Graph Genesis approval dashboard: ${dashboard.url}\n`);
    const authorizationPromise = sessions.authorize({
      envelope, privateCapsule: created.privateCapsule, audit,
      monotonicNow: () => performance.now(), wallNow: () => new Date(), signal: controller.signal,
    });
    phases.advance('APPROVAL_PENDING');
    const authorization = await authorizationPromise;
    if (authorization.status !== 'authorized') {
      phases.fail();
      await listener.closeAndDrain();
      listener = undefined;
      await shutdownDashboard(approvals, dashboard, dashboardState);
      approvals = undefined; dashboard = undefined; dashboardState = undefined;
      auditSource.database.close();
      auditSource = undefined;
      await root.cleanup();
      root = undefined;
      return safeResult('not_started', 2, `approval_${authorization.status}`, executionAudit, {
        actionId: authorization.actionId, envelope, plan,
      });
    }
    phases.advance('AUTHORIZED');
    throwIfAborted(controller.signal);

    const transport = new BoundedNpmPublicMetadataTransport(
      new SystemRegistryAddressResolver(), new NodePinnedHttpsClient(),
    );
    const brokerSession = broker.prepareSession({
      plan, capsule: prepared.capsule, startLease: authorization.lease, startLeaseVerifier: sessions,
      audit: authorization.executionAudit, transport, onFailure: () => controller.abort(),
      mode: 'production', monotonicNow: () => performance.now(),
    });
    throwIfAborted(controller.signal);
    await broker.arm(brokerSession);
    throwIfAborted(controller.signal);
    listener.arm(brokerSession);
    phases.advance('BROKER_ARMED');
    const supervisor = new GraphGenesisProcessSupervisor(plans, new NodeGraphGenesisSpawnAdapter());
    throwIfAborted(controller.signal);
    spawned = true;
    phases.advance('NPM_RUNNING');
    processResult = await supervisor.run({
      plan, capsule: prepared.capsule, audit: authorization.executionAudit,
      startLease: authorization.lease, startLeaseVerifier: sessions,
      monotonicNow: () => performance.now(), onFailure: () => controller.abort(),
      signal: controller.signal, mode: 'production',
    });
    if (!supervisor.authenticates(processResult) || processResult.planHash !== plan.planHash) fail();
    phases.advance('LISTENER_DRAINING');
    const listenerDrain = await listener.closeAndDrain();
    listener = undefined;
    throwIfAborted(controller.signal);
    await authorization.executionAudit.record('listener_drained', {
      acceptedHandlerCount: listenerDrain.acceptedHandlerCount,
    });
    throwIfAborted(controller.signal);
    if (processResult.status !== 'completed' || processResult.exitCode !== 0) fail('graph_metadata_incomplete');
    ledger = await broker.complete(brokerSession);
    if (!broker.authenticatesLedger(ledger) || ledger.planHash !== plan.planHash) fail();
    phases.advance('BROKER_FINALIZED');
    throwIfAborted(controller.signal);

    const exactCandidates = new ExactGraphCandidateAuthority();
    postStates = new HardenedGraphGenesisPostStateAuthority(plans, workspaces);
    await authorization.executionAudit.record('lock_validation_started');
    const inspected = await postStates.inspect({ plan, executionCapsule: prepared.capsule, workspace });
    postState = inspected.evidence;
    if (!postStates.authenticatesPair(postState, inspected.privateCapsule)
      || postState.planHash !== plan.planHash) fail();
    await authorization.executionAudit.record('post_state_validated', { postStateDigest: postState.evidenceDigest });
    throwIfAborted(controller.signal);
    phases.advance('POST_STATE_VALIDATED');
    const compiler = new HardenedGraphGenesisCandidateCompiler(postStates, exactCandidates);
    candidate = compiler.compile({ plan, postState, privatePostStateCapsule: inspected.privateCapsule });
    if (!compiler.authenticatesPair(candidate, postState)) fail();
    await authorization.executionAudit.record('candidate_compiled');
    phases.advance('CANDIDATE_COMPILED');
    throwIfAborted(controller.signal);
    const artifacts = new GraphGenesisCandidateArtifactAuthority(envelopes, exactCandidates);
    artifact = artifacts.compile({
      envelope, privateCapsule: created.privateCapsule, candidate, actionId: audit.actionId,
      brokerLedgerDigest: ledger.ledgerDigest, postStateDigest: postState.evidenceDigest,
    });
    if (!artifacts.authenticates(artifact)) fail();
    await authorization.executionAudit.record('candidate_output_intent', {
      artifactDigest: artifact.artifactDigest, candidateDigest: candidate.candidateDigest,
    });
    throwIfAborted(controller.signal);
    const output = await artifacts.writeExclusive({ envelope, privateCapsule: created.privateCapsule, artifact });
    throwIfAborted(controller.signal);
    await authorization.executionAudit.record('candidate_output_written', {
      artifactDigest: artifact.artifactDigest, candidateDigest: candidate.candidateDigest, bytes: output.bytes,
    });
    phases.advance('OUTPUT_DURABLE');
    throwIfAborted(controller.signal);
    cleanups = new PostStateBoundGraphGenesisCleanupAuthority(postStates);
    const inventory = await cleanups.capture(workspace, postState);
    cleanup = await cleanups.cleanup(workspace, inventory);
    if (!cleanups.authenticates(cleanup)) fail();
    throwIfAborted(controller.signal);
    await authorization.executionAudit.record('cleanup_complete');
    phases.advance('WORKSPACE_CLEANED');
    throwIfAborted(controller.signal);
    await root.cleanup();
    root = undefined;
    throwIfAborted(controller.signal);
    const terminalPreparation = authorization.executionAudit.prepareAtomicTerminalSuccess();
    if (!authorization.executionAudit.authenticatesTerminalPreparation(terminalPreparation)) fail('stage_audit_incomplete');
    terminalCommitAttempted = true;
    audit.finalizeGraphGenesisOutcome({
      metadata: {
        externalReadStatus: 'validated', requestCount: ledger.startedRequestCount,
        uniquePackageCount: ledger.uniquePackageCount, responseBytes: ledger.aggregateResponseBytes,
      },
      process: {
        status: processResult.status, exitCode: processResult.exitCode,
        stdoutBytes: processResult.stdoutBytes, stderrBytes: processResult.stderrBytes,
      },
      candidate: {
        lockDigest: `sha256:${postState.packageLockSha256}`,
        candidateDigest: `sha256:${candidate.candidateDigest}`,
        artifactDigest: `sha256:${artifact.artifactDigest}`,
      },
      cleanup: { status: 'complete' }, terminalAudit: { status: 'complete' },
    }, 'completed');
    terminalCommitted = true;
    phases.advance('TERMINAL_COMMITTED');
    await shutdownDashboard(approvals, dashboard, dashboardState);
    approvals = undefined; dashboard = undefined; dashboardState = undefined;
    auditSource.database.close();
    auditSource = undefined;
    reconciliationAttempted = true;
    if (auditProofIdentity === undefined) fail('plan_invalid');
    const reconciled = new ProductionGraphGenesisTerminalProofSource(auditProofIdentity).hasCompleteTerminalProof({
      actionId: audit.actionId, executionEnvelopeHash: envelope.executionEnvelopeHash,
      planHash: envelope.planHash, candidateDigest: candidate.candidateDigest, artifactDigest: artifact.artifactDigest,
    });
    if (!reconciled) {
      phases.fail();
      return safeResult('outcome_unknown', 6, 'terminal_proof_not_observed', executionAudit, {
        actionId: audit.actionId, envelope, plan, candidate, artifact, processResult, cleanup,
      });
    }
    phases.advance('COMPLETE');
    return safeResult('complete', 0, 'complete', executionAudit, {
      actionId: audit.actionId, envelope, plan, candidate, artifact, processResult, cleanup,
    });
  } catch (error) {
    phases.fail();
    const metadata = executionAudit?.metadataSummary();
    const externalRead = metadata !== undefined && metadata.externalReadStatus !== 'not_started';
    const quarantineReferenceDigest = root === undefined
      ? undefined : `sha256:${graphGenesisDigest(root.path)}`;
    let cleanupFailed = false;
    await safeShutdown(listener, approvals, dashboard, dashboardState);
    listener = undefined; approvals = undefined; dashboard = undefined; dashboardState = undefined;
    if (spawned && cleanup === undefined && workspace !== undefined && postState !== undefined
      && postStates !== undefined && postStates.authenticates(postState)) {
      try {
        cleanups ??= new PostStateBoundGraphGenesisCleanupAuthority(postStates);
        const inventory = await cleanups.capture(workspace, postState);
        cleanup = await cleanups.cleanup(workspace, inventory);
        if (!cleanups.authenticates(cleanup)) fail();
      } catch { cleanupFailed = true; }
    }
    if ((!spawned || cleanup !== undefined) && root !== undefined) {
      try { await root.cleanup(); root = undefined; } catch { cleanupFailed = true; }
    }
    let terminalUnknown = terminalCommitted || terminalCommitAttempted;
    if (!terminalCommitAttempted && audit !== undefined
      && executionAudit?.events.includes('npm_spawn_started') === true) {
      try {
        audit.finalizeGraphGenesisOutcome({
          metadata: metadata ?? { externalReadStatus: 'not_started', requestCount: 0, uniquePackageCount: 0, responseBytes: 0 },
          process: {
            status: processResult?.status ?? (controller.signal.aborted ? 'cancelled' : 'failed'),
            exitCode: processResult?.exitCode ?? null,
            stdoutBytes: processResult?.stdoutBytes ?? 0, stderrBytes: processResult?.stderrBytes ?? 0,
          },
          cleanup: {
            status: spawned && cleanup === undefined ? 'quarantined'
              : cleanupFailed ? 'incomplete' : cleanup === undefined ? 'not_needed' : 'complete',
            ...(spawned && cleanup === undefined && quarantineReferenceDigest !== undefined
              ? { quarantineReferenceDigest } : {}),
          },
          terminalAudit: { status: 'failed' }, errorCode: safeErrorCode(error),
        }, externalRead ? 'incomplete_external_read' : controller.signal.aborted ? 'cancelled' : 'execution_error');
      } catch { terminalUnknown = true; }
    } else if (!terminalCommitAttempted && audit !== undefined) {
      try { audit.markFailed(safeErrorCode(error)); } catch { terminalUnknown = true; }
    }
    try { auditSource?.database.close(); } catch { terminalUnknown = true; }
    auditSource = undefined;
    if (terminalCommitAttempted && !reconciliationAttempted && audit !== undefined && envelope !== undefined
      && candidate !== undefined && artifact !== undefined) {
      reconciliationAttempted = true;
      try {
        if (auditProofIdentity === undefined) fail('plan_invalid');
        const reconciled = new ProductionGraphGenesisTerminalProofSource(auditProofIdentity).hasCompleteTerminalProof({
          actionId: audit.actionId, executionEnvelopeHash: envelope.executionEnvelopeHash,
          planHash: envelope.planHash, candidateDigest: candidate.candidateDigest,
          artifactDigest: artifact.artifactDigest,
        });
        if (reconciled) {
          return safeResult('complete', 0, 'complete_reconciled', executionAudit, {
            audit, envelope, plan, candidate, artifact, processResult, cleanup,
            quarantineReferenceDigest,
          });
        }
      } catch { /* keep the conservative unknown result */ }
      terminalUnknown = true;
    }
    const disposition = classifyGraphGenesisFailure({
      cancelled: controller.signal.aborted, externalReadMayHaveOccurred: externalRead,
      processSpawned: spawned, cleanupComplete: cleanup !== undefined, cleanupFailed,
      rootPreserved: !spawned && root !== undefined, terminalUnknown,
    });
    return safeResult(disposition.status, disposition.exitCode,
      disposition.reasonCode === 'graph_live_failed' ? safeErrorCode(error) : disposition.reasonCode, executionAudit, {
        audit, envelope, plan, candidate, artifact, processResult, cleanup, quarantineReferenceDigest,
      });
  } finally {
    clearTimeout(deadline);
    clearTimeout(preparationDeadline);
    signal?.removeEventListener('abort', externalAbort);
  }
}

function assertClosedInput(input: ExactGraphGenesisArguments, signal: AbortSignal): void {
  if (input.kind !== 'run' || signal.aborted || process.platform !== 'darwin' || process.arch !== 'arm64'
    || process.version !== 'v26.3.1' || process.execArgv.length !== 0
    || Object.keys(process.env).some((key) => FORBIDDEN_ENVIRONMENT_KEYS.test(key))) fail('plan_invalid');
  try { assertGraphGenesisLocalInputs(input, signal); } catch { fail('plan_invalid'); }
}

async function shutdownDashboard(
  approvals: LocalApprovalService | undefined,
  dashboard: DashboardHandle | undefined,
  state: DashboardStateFile | undefined,
): Promise<void> {
  approvals?.close();
  try { await dashboard?.close(); } finally { state?.remove(); }
}

async function safeShutdown(
  listener: HardenedLoopbackBrokerListener | undefined,
  approvals: LocalApprovalService | undefined,
  dashboard: DashboardHandle | undefined,
  state: DashboardStateFile | undefined,
): Promise<void> {
  approvals?.close();
  await Promise.allSettled([listener?.closeAndDrain(), dashboard?.close()]);
  state?.remove();
}

function safeResult(
  status: ProductionGraphGenesisLiveResult['status'],
  exitCode: ProductionGraphGenesisLiveResult['exitCode'],
  reasonCode: string,
  audit: GraphGenesisAuditGate | undefined,
  evidence: Readonly<{
    actionId?: string | undefined;
    audit?: AuditCall | undefined;
    envelope?: GraphGenesisExecutionEnvelopeV1 | undefined;
    plan?: HardenedGraphGenesisPlan | undefined;
    candidate?: ExactGraphCandidate | undefined;
    artifact?: GraphGenesisCandidateArtifactV1 | undefined;
    processResult?: AuthenticatedGraphGenesisProcessResult | undefined;
    cleanup?: AuthenticatedPostStateCleanup | undefined;
    quarantineReferenceDigest?: string | undefined;
  }>,
): ProductionGraphGenesisLiveResult {
  const metadata = audit?.metadataSummary();
  const actionId = evidence.actionId ?? evidence.audit?.actionId;
  return Object.freeze({
    status, exitCode, reasonCode: safeReason(reasonCode),
    externalReadMayHaveOccurred: metadata !== undefined && metadata.externalReadStatus !== 'not_started',
    installationOccurred: false as const, packageDownloadOccurred: false as const,
    bypassWarning: 'Direct npm/npx commands bypass APG and receive none of this protection or evidence.' as const,
    ...(actionId === undefined ? {} : { actionId }),
    ...(evidence.envelope === undefined ? {} : { executionEnvelopeHash: evidence.envelope.executionEnvelopeHash }),
    ...(evidence.plan === undefined ? {} : { planHash: evidence.plan.planHash }),
    ...(evidence.candidate === undefined ? {} : { candidateDigest: evidence.candidate.candidateDigest }),
    ...(evidence.artifact === undefined ? {} : { artifactDigest: evidence.artifact.artifactDigest }),
    ...(metadata === undefined ? {} : { metadataRequestCount: metadata.requestCount, metadataResponseBytes: metadata.responseBytes }),
    ...(evidence.processResult === undefined ? {} : { processStatus: evidence.processResult.status }),
    ...(evidence.cleanup === undefined ? {} : { cleanupStatus: evidence.cleanup.status }),
    ...(evidence.quarantineReferenceDigest === undefined
      ? {} : { quarantineReferenceDigest: evidence.quarantineReferenceDigest }),
  } as ProductionGraphGenesisLiveResult);
}

function throwIfAborted(signal: AbortSignal): void { if (signal.aborted) fail('artifact_cancelled'); }
function safeErrorCode(error: unknown): string {
  if (error instanceof PackageStageError) return safeReason(error.code);
  return 'graph_live_failed';
}
function safeReason(value: string): string {
  return /^[a-z][a-z0-9_]{0,63}$/u.test(value) ? value : 'graph_live_failed';
}
function sha256(value: string): string { return createHash('sha256').update(value).digest('hex'); }
function fail(code: PackageStageErrorCode = 'acceptance_incomplete'): never { throw new PackageStageError(code); }
