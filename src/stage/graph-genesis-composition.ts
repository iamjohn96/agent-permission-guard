import { createHash, randomBytes } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { isAbsolute } from 'node:path';
import { PassThrough } from 'node:stream';
import type { ChildProcess } from 'node:child_process';

import type { LocalApprovalService } from '../approval/service.js';
import type { ApprovalOutcome, ApprovalRequestView } from '../approval/types.js';
import type { AuditCall, SqliteAuditRecorder } from '../audit/recorder.js';
import { SqliteAuditRecorder as ConcreteSqliteAuditRecorder } from '../audit/recorder.js';
import {
  authenticatesExistingGraphGenesisAuditDatabase,
  revalidatesExistingGraphGenesisAuditDatabase,
  type ExistingGraphGenesisAuditDatabase,
} from '../db/database.js';
import { canonicalReceiptJson, type ReceiptContext } from '../audit/receipt.js';
import { staticPolicyIdentity } from '../policy/identity.js';
import type {
  AuthenticatedGraphGenesisExecutionCapsule,
  AuthenticatedGraphGenesisStartLease,
  GraphGenesisPlanProjection,
  GraphGenesisStartLeaseVerifier,
  HardenedGraphGenesisPlan,
  HardenedGraphGenesisPlanAuthority,
  PreparedHardenedGraphGenesis,
} from './graph-genesis-hardening.js';
import { GraphGenesisAuditGate, type GraphGenesisDurableAuditSink } from './graph-genesis-hardening.js';
import {
  HardenedMetadataBrokerAuthority,
  type AuthenticatedHardenedBrokerLedger,
  type HardenedPublicMetadataTransport,
} from './graph-genesis-network.js';
import {
  GraphGenesisProcessSupervisor,
  type AuthenticatedGraphGenesisProcessResult,
  type GraphGenesisSpawnAdapter,
} from './graph-genesis-supervisor.js';
import { PackageStageError } from './profile.js';

const SHA256 = /^[a-f0-9]{64}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const APPROVAL_TTL_MS = 120_000;
const APPROVED_START_WINDOW_MS = 15_000;
const EXECUTION_TIMEOUT_MS = 120_000;
const TARGET = '@modelcontextprotocol/server-filesystem@2026.7.10' as const;

export const GRAPH_GENESIS_POLICY = Object.freeze({
  schemaVersion: 1,
  evaluatorName: 'graph_genesis_builtin_policy',
  evaluatorVersion: '1',
  decision: 'ask' as const,
  score: 70,
  band: 'high' as const,
  reasonCodes: Object.freeze([
    'public_registry_metadata_disclosure',
    'local_npm_process',
    'persistent_audit_write',
    'candidate_artifact_write',
    'development_only_containment',
  ]),
});

export type GraphGenesisExecutionEnvelopeV1 = Readonly<{
  envelopeVersion: 1;
  sessionId: string;
  planId: string;
  planHash: string;
  safeProjectionDigest: string;
  runtimeManifestDigest: string;
  hostEvidenceDigest: string;
  bootSessionDigest: string;
  workspaceBinding: string;
  containmentProfileDigest: string;
  routeTokenDigest: string;
  launchDigest: string;
  environmentDigest: string;
  executionCapsuleDigest: string;
  policyDigest: string;
  auditSchemaDigest: string;
  auditFileIdentityDigest: string;
  auditDatabaseInstanceId: string;
  initialAuditChainTail: string;
  auditDurabilityProfileDigest: string;
  outputCanonicalPathDigest: string;
  outputParentIdentityDigest: string;
  outputRule: 'exclusive_new_private_file';
  dashboardInstanceId: string;
  requestedAt: string;
  planDeadlineMonotonicMs: number;
  approvalTtlMs: 120000;
  limitsDigest: string;
  consequence: 'bounded_public_metadata_graph_genesis';
  executionEnvelopeHash: string;
}>;

type GraphGenesisEnvelopePrivateCapsule = Readonly<{
  capsuleVersion: 1;
  auditPath: string;
  outputPath: string;
  planCapsule: AuthenticatedGraphGenesisExecutionCapsule;
}>;

export class GraphGenesisExecutionEnvelopeAuthority {
  readonly #envelopes = new WeakSet<object>();
  readonly #capsules = new WeakSet<object>();
  readonly #pairs = new WeakMap<object, object>();
  readonly #plans = new WeakMap<object, HardenedGraphGenesisPlan>();

  constructor(private readonly planAuthority: HardenedGraphGenesisPlanAuthority) {}

  create(input: Readonly<{
    prepared: PreparedHardenedGraphGenesis;
    dashboardInstanceId: string;
    bootSessionDigest: string;
    audit: Readonly<{
      path: string;
      schemaDigest: string;
      fileIdentityDigest: string;
      databaseInstanceId: string;
      initialChainTail: string;
      durabilityProfileDigest: string;
    }>;
    output: Readonly<{
      path: string;
      canonicalPathDigest: string;
      parentIdentityDigest: string;
    }>;
    requestedAt: string;
    planDeadlineMonotonicMs: number;
  }>): Readonly<{ envelope: GraphGenesisExecutionEnvelopeV1; privateCapsule: object }> {
    const { plan, projection, capsule } = input.prepared;
    if (!this.planAuthority.authenticatesPair(plan, capsule)
      || projection.planHash !== plan.planHash || projection.planId !== plan.planId
      || !UUID.test(input.dashboardInstanceId)
      || !isDigest(input.bootSessionDigest) || !isDigest(input.audit.schemaDigest)
      || !isDigest(input.audit.fileIdentityDigest) || !isDigest(input.audit.initialChainTail)
      || !isDigest(input.audit.durabilityProfileDigest)
      || !isDigest(input.output.canonicalPathDigest) || !isDigest(input.output.parentIdentityDigest)
      || input.output.canonicalPathDigest !== digest(input.output.path)
      || !UUID.test(input.audit.databaseInstanceId)
      || !isPrivateAbsolutePath(input.audit.path) || !isPrivateAbsolutePath(input.output.path)
      || !Number.isFinite(Date.parse(input.requestedAt))
      || !Number.isFinite(input.planDeadlineMonotonicMs) || input.planDeadlineMonotonicMs <= 0) failPlan();
    const policyDigest = digest(GRAPH_GENESIS_POLICY);
    const unsigned = deepFreeze({
      envelopeVersion: 1 as const,
      sessionId: randomBytes(16).toString('hex'),
      planId: plan.planId,
      planHash: plan.planHash,
      safeProjectionDigest: digest(projection),
      runtimeManifestDigest: digest(plan.runtimeSnapshots),
      hostEvidenceDigest: plan.hostEvidenceDigest,
      bootSessionDigest: input.bootSessionDigest,
      workspaceBinding: plan.workspaceBinding,
      containmentProfileDigest: plan.containmentProfileDigest,
      routeTokenDigest: plan.routeTokenDigest,
      launchDigest: plan.launchDigest,
      environmentDigest: plan.environmentDigest,
      executionCapsuleDigest: plan.executionCapsuleDigest,
      policyDigest,
      auditSchemaDigest: input.audit.schemaDigest,
      auditFileIdentityDigest: input.audit.fileIdentityDigest,
      auditDatabaseInstanceId: input.audit.databaseInstanceId,
      initialAuditChainTail: input.audit.initialChainTail,
      auditDurabilityProfileDigest: input.audit.durabilityProfileDigest,
      outputCanonicalPathDigest: input.output.canonicalPathDigest,
      outputParentIdentityDigest: input.output.parentIdentityDigest,
      outputRule: 'exclusive_new_private_file' as const,
      dashboardInstanceId: input.dashboardInstanceId,
      requestedAt: input.requestedAt,
      planDeadlineMonotonicMs: input.planDeadlineMonotonicMs,
      approvalTtlMs: APPROVAL_TTL_MS as 120000,
      limitsDigest: digest(plan.limits),
      consequence: plan.consequence,
    });
    const envelope = deepFreeze({ ...unsigned, executionEnvelopeHash: digest(unsigned) });
    const privateCapsule = Object.freeze({
      capsuleVersion: 1 as const,
      auditPath: input.audit.path,
      outputPath: input.output.path,
      planCapsule: capsule,
    });
    this.#envelopes.add(envelope);
    this.#capsules.add(privateCapsule);
    this.#pairs.set(privateCapsule, envelope);
    this.#plans.set(envelope, plan);
    return Object.freeze({ envelope, privateCapsule });
  }

  authenticatesPair(envelope: unknown, privateCapsule: unknown): envelope is GraphGenesisExecutionEnvelopeV1 {
    return typeof envelope === 'object' && envelope !== null && this.#envelopes.has(envelope)
      && typeof privateCapsule === 'object' && privateCapsule !== null && this.#capsules.has(privateCapsule)
      && this.#pairs.get(privateCapsule) === envelope;
  }

  planFor(envelope: GraphGenesisExecutionEnvelopeV1, privateCapsule: object): HardenedGraphGenesisPlan {
    if (!this.authenticatesPair(envelope, privateCapsule)) failPlan();
    const plan = this.#plans.get(envelope);
    if (plan === undefined) failPlan();
    return plan;
  }

  planCapsuleFor(envelope: GraphGenesisExecutionEnvelopeV1, privateCapsule: object): AuthenticatedGraphGenesisExecutionCapsule {
    this.planFor(envelope, privateCapsule);
    return (privateCapsule as GraphGenesisEnvelopePrivateCapsule).planCapsule;
  }

  outputPathFor(envelope: GraphGenesisExecutionEnvelopeV1, privateCapsule: object): string {
    this.planFor(envelope, privateCapsule);
    return (privateCapsule as GraphGenesisEnvelopePrivateCapsule).outputPath;
  }

  approvalView(envelope: GraphGenesisExecutionEnvelopeV1, privateCapsule: object): NonNullable<ApprovalRequestView['graphGenesis']> {
    const plan = this.planFor(envelope, privateCapsule);
    const paths = privateCapsule as GraphGenesisEnvelopePrivateCapsule;
    return deepFreeze({
      target: TARGET,
      registryOrigin: plan.registryOrigin,
      executionEnvelopeHash: envelope.executionEnvelopeHash,
      planHash: plan.planHash,
      host: { platform: plan.platform, architecture: plan.architecture, osBuild: plan.osBuild },
      runtime: { nodeVersion: plan.nodeVersion, npmVersion: plan.npmVersion },
      auditPath: paths.auditPath,
      outputPath: paths.outputPath,
      limits: plan.limits,
      consequences: [
        'Package names are disclosed to the public npm registry.',
        'The exact pinned npm CLI runs locally with lockfile-only and ignore-scripts controls.',
        'Private temporary files, persistent audit rows, and one candidate file may be written.',
      ],
      exclusions: [
        'No tarball download, installation, node_modules, lifecycle or package code execution.',
        'No materialization, profile registration, MCP startup, or MCP action.',
        'Containment is development-only and does not defend against a hostile same-user process.',
      ],
      bypassWarning: 'Direct npm/npx commands bypass APG and receive none of this protection or evidence.',
    });
  }
}

export type GraphGenesisAuthorizationResult =
  | Readonly<{
    status: 'authorized';
    lease: AuthenticatedGraphGenesisStartLease;
    executionAudit: GraphGenesisAuditGate;
    actionId: string;
  }>
  | Readonly<{ status: Exclude<ApprovalOutcome, 'approved'>; actionId: string }>;

/**
 * Network-free composition authority. It has no transport, DNS, registry, spawn, or output adapter.
 * A later production entry point may own this authority, but cannot inject execution collaborators here.
 */
export class ProductionGraphGenesisSessionAuthority implements GraphGenesisStartLeaseVerifier {
  readonly #leases = new WeakSet<object>();
  readonly #usedEnvelopes = new WeakSet<object>();
  readonly #consumed = new WeakMap<object, Set<'broker_arm' | 'process_spawn'>>();
  readonly #auditBindings = new WeakMap<object, GraphGenesisExecutionEnvelopeV1>();
  readonly #executionAudits = new WeakMap<object, GraphGenesisAuditGate>();

  constructor(
    private readonly plans: HardenedGraphGenesisPlanAuthority,
    private readonly envelopes: GraphGenesisExecutionEnvelopeAuthority,
    private readonly approvals: LocalApprovalService,
  ) {}

  createBoundAuditSession(
    source: ExistingGraphGenesisAuditDatabase,
    envelope: GraphGenesisExecutionEnvelopeV1,
    privateCapsule: object,
    now?: () => Date,
  ): Readonly<{ audit: AuditCall; recorder: SqliteAuditRecorder }> {
    this.envelopes.planFor(envelope, privateCapsule);
    if (!authenticatesExistingGraphGenesisAuditDatabase(source)
      || source.canonicalPath !== (privateCapsule as GraphGenesisEnvelopePrivateCapsule).auditPath
      || source.schemaDigest !== envelope.auditSchemaDigest
      || source.fileIdentityDigest !== envelope.auditFileIdentityDigest
      || source.databaseInstanceId !== envelope.auditDatabaseInstanceId
      || source.initialChainTail !== envelope.initialAuditChainTail
      || source.durabilityProfileDigest !== envelope.auditDurabilityProfileDigest) failApproval();
    const recorder = new ConcreteSqliteAuditRecorder(source.database, now, 'immediate');
    const audit = source.database.transaction(() => {
      if (!revalidatesExistingGraphGenesisAuditDatabase(source)) failApproval();
      return recorder.begin({
        serverId: 'apg-graph-genesis',
        toolName: 'filesystem_metadata_graph',
        arguments: { executionEnvelopeHash: envelope.executionEnvelopeHash, planHash: envelope.planHash },
      }, {
        action: 'ask',
        evaluation: {
          baseDecision: 'ask', effectiveDecision: 'ask', matchedRuleId: 'graph_genesis_builtin_ask_v1',
          reasonCodes: GRAPH_GENESIS_POLICY.reasonCodes,
          risk: { score: GRAPH_GENESIS_POLICY.score, band: GRAPH_GENESIS_POLICY.band, signals: [] },
        },
        receipt: graphGenesisReceiptContext(envelope),
      });
    }).immediate();
    this.#auditBindings.set(audit, envelope);
    this.#executionAudits.set(audit, new GraphGenesisAuditGate(
      envelope.planHash,
      new BoundAuditCallSink(audit, envelope),
    ));
    return Object.freeze({ audit, recorder });
  }

  createExecutionAuditGate(audit: AuditCall, envelope: GraphGenesisExecutionEnvelopeV1): GraphGenesisAuditGate {
    if (this.#auditBindings.get(audit) !== envelope) failApproval();
    const gate = this.#executionAudits.get(audit);
    if (gate === undefined) failApproval();
    return gate;
  }

  async authorize(input: Readonly<{
    envelope: GraphGenesisExecutionEnvelopeV1;
    privateCapsule: object;
    audit: AuditCall;
    monotonicNow: () => number;
    wallNow?: () => Date;
    signal?: AbortSignal;
  }>): Promise<GraphGenesisAuthorizationResult> {
    if (!this.envelopes.authenticatesPair(input.envelope, input.privateCapsule)
      || this.#auditBindings.get(input.audit) !== input.envelope
      || this.#usedEnvelopes.has(input.envelope)) failApproval();
    const wallNow = input.wallNow ?? (() => new Date());
    const requestedMonotonicMs = input.monotonicNow();
    const requestedWallMs = Date.parse(input.envelope.requestedAt);
    const observedWallMs = wallNow().getTime();
    if (!Number.isFinite(requestedMonotonicMs)
      || requestedMonotonicMs >= input.envelope.planDeadlineMonotonicMs
      || observedWallMs < requestedWallMs || observedWallMs - requestedWallMs > 180_000) failApproval();
    this.#usedEnvelopes.add(input.envelope);
    input.audit.appendEvidence('graph_genesis_session_created', {
      executionEnvelopeHash: input.envelope.executionEnvelopeHash,
      planHash: input.envelope.planHash,
    });
    const graphGenesis = this.envelopes.approvalView(input.envelope, input.privateCapsule);
    const ticket = this.approvals.requestHidden({
      kind: 'graph_genesis',
      serverId: 'apg-graph-genesis',
      toolName: 'filesystem_metadata_graph',
      arguments: { executionEnvelopeHash: input.envelope.executionEnvelopeHash, planHash: input.envelope.planHash },
      graphGenesis,
      risk: { score: GRAPH_GENESIS_POLICY.score, band: GRAPH_GENESIS_POLICY.band, signals: [] },
      reasonCodes: GRAPH_GENESIS_POLICY.reasonCodes,
    }, APPROVAL_TTL_MS);
    try { input.audit.markApprovalRequested(ticket.request); } catch (error) {
      ticket.cancel();
      throw error;
    }
    this.approvals.publish(ticket.request.id);
    const cancel = () => ticket.cancel();
    input.signal?.addEventListener('abort', cancel, { once: true });
    let outcome: ApprovalOutcome;
    try { outcome = await ticket.outcome; } finally { input.signal?.removeEventListener('abort', cancel); }
    input.audit.markApprovalResolved(ticket.request.id, outcome);
    if (outcome !== 'approved') {
      input.audit.markBlocked(`approval_${outcome}`);
      return Object.freeze({ status: outcome, actionId: input.audit.actionId });
    }
    const decisionMonotonicMs = input.monotonicNow();
    if (!Number.isFinite(decisionMonotonicMs) || decisionMonotonicMs < requestedMonotonicMs
      || Date.parse(ticket.request.expiresAt) <= wallNow().getTime()
      || decisionMonotonicMs >= input.envelope.planDeadlineMonotonicMs) {
      input.audit.markFailed('approval_expired_before_revalidation');
      failApproval();
    }
    const plan = this.envelopes.planFor(input.envelope, input.privateCapsule);
    const capsule = this.envelopes.planCapsuleFor(input.envelope, input.privateCapsule);
    await this.plans.revalidatePair(plan, capsule);
    if (input.signal?.aborted === true) {
      input.audit.markFailed('approval_cancelled_after_revalidation');
      failApproval();
    }
    input.audit.appendEvidence('graph_genesis_approved_revalidation_complete', {
      executionEnvelopeHash: input.envelope.executionEnvelopeHash,
    });
    input.audit.markAuthorized();
    input.audit.appendEvidence('graph_genesis_authorization_finalized', {
      executionEnvelopeHash: input.envelope.executionEnvelopeHash,
      approvalId: ticket.request.id,
    });
    const executionAudit = this.#executionAudits.get(input.audit);
    if (executionAudit === undefined) failApproval();
    await executionAudit.record('authorization_finalized');
    const startByMonotonicMs = Math.min(
      input.envelope.planDeadlineMonotonicMs,
      requestedMonotonicMs + APPROVAL_TTL_MS,
      decisionMonotonicMs + APPROVED_START_WINDOW_MS,
    );
    const unsigned = Object.freeze({
      leaseVersion: 1 as const,
      planHash: input.envelope.planHash,
      executionEnvelopeHash: input.envelope.executionEnvelopeHash,
      approvalId: ticket.request.id,
      startByMonotonicMs,
      executionDeadlineMonotonicMs: startByMonotonicMs + EXECUTION_TIMEOUT_MS,
    });
    const lease = Object.freeze({ ...unsigned, leaseDigest: digest(unsigned) });
    this.#leases.add(lease);
    this.#consumed.set(lease, new Set());
    return Object.freeze({ status: 'authorized', lease, executionAudit, actionId: input.audit.actionId });
  }

  authenticatesStartLease(value: unknown, planHash: string): value is AuthenticatedGraphGenesisStartLease {
    return typeof value === 'object' && value !== null && this.#leases.has(value)
      && (value as AuthenticatedGraphGenesisStartLease).planHash === planHash;
  }

  consumeStartLease(
    value: AuthenticatedGraphGenesisStartLease,
    phase: 'broker_arm' | 'process_spawn',
    monotonicNowMs: number,
  ): boolean {
    if (!this.authenticatesStartLease(value, value.planHash) || !Number.isFinite(monotonicNowMs)
      || monotonicNowMs > value.startByMonotonicMs) return false;
    const phases = this.#consumed.get(value);
    if (phases === undefined || phases.has(phase)) return false;
    phases.add(phase);
    return true;
  }
}

class BoundAuditCallSink implements GraphGenesisDurableAuditSink {
  readonly implementationKind = 'production' as const;
  constructor(
    private readonly audit: AuditCall,
    private readonly envelope: GraphGenesisExecutionEnvelopeV1,
  ) {}

  async append(event: Parameters<GraphGenesisDurableAuditSink['append']>[0], payload: Readonly<Record<string, string | number | boolean>>): Promise<void> {
    if (payload.planHash !== this.envelope.planHash) failApproval();
    if (event === 'npm_spawn_started') this.audit.markExecutionStarted();
    this.audit.appendEvidence(`graph_genesis_execution_${event}`, {
      ...payload,
      executionEnvelopeHash: this.envelope.executionEnvelopeHash,
    });
  }
}

/** Test-only lease authority; it cannot create production approvals or use the Dashboard. */
export class SyntheticGraphGenesisStartLeaseAuthority implements GraphGenesisStartLeaseVerifier {
  readonly #leases = new WeakSet<object>();
  readonly #consumed = new WeakMap<object, Set<'broker_arm' | 'process_spawn'>>();

  createForTest(plan: HardenedGraphGenesisPlan, startByMonotonicMs: number): AuthenticatedGraphGenesisStartLease {
    if (!this.plans.authenticatesPlan(plan) || !Number.isFinite(startByMonotonicMs) || startByMonotonicMs <= 0) failApproval();
    const unsigned = Object.freeze({
      leaseVersion: 1 as const,
      planHash: plan.planHash,
      executionEnvelopeHash: digest({ synthetic: true, planHash: plan.planHash, startByMonotonicMs }),
      approvalId: '00000000-0000-4000-8000-000000000001',
      startByMonotonicMs,
      executionDeadlineMonotonicMs: startByMonotonicMs + EXECUTION_TIMEOUT_MS,
    });
    const lease = Object.freeze({ ...unsigned, leaseDigest: digest(unsigned) });
    this.#leases.add(lease);
    this.#consumed.set(lease, new Set());
    return lease;
  }

  constructor(private readonly plans: HardenedGraphGenesisPlanAuthority) {}

  authenticatesStartLease(value: unknown, planHash: string): value is AuthenticatedGraphGenesisStartLease {
    return typeof value === 'object' && value !== null && this.#leases.has(value)
      && (value as AuthenticatedGraphGenesisStartLease).planHash === planHash;
  }

  consumeStartLease(
    value: AuthenticatedGraphGenesisStartLease,
    phase: 'broker_arm' | 'process_spawn',
    monotonicNowMs: number,
  ): boolean {
    if (!this.authenticatesStartLease(value, value.planHash) || monotonicNowMs > value.startByMonotonicMs) return false;
    const phases = this.#consumed.get(value);
    if (phases === undefined || phases.has(phase)) return false;
    phases.add(phase);
    return true;
  }
}

export type NetworkFreeGraphGenesisCompositionResult = Readonly<{
  ledger: AuthenticatedHardenedBrokerLedger;
  process: AuthenticatedGraphGenesisProcessResult;
  terminalState: 'synthetic_complete';
}>;

export class GraphGenesisAbortOwner {
  readonly controller = new AbortController();
  readonly #aborters: Array<() => void | Promise<void>> = [];
  #failure: unknown;
  #aborting: Promise<void> | undefined;

  register(aborter: () => void | Promise<void>): void {
    if (this.#failure !== undefined) failApproval();
    this.#aborters.push(aborter);
  }

  throwIfAborted(): void {
    if (this.#failure !== undefined || this.controller.signal.aborted) throw this.#failure ?? new PackageStageError('artifact_cancelled');
  }

  async abort(reason: unknown): Promise<void> {
    if (this.#aborting !== undefined) return await this.#aborting;
    this.#failure = reason;
    this.controller.abort();
    this.#aborting = Promise.allSettled([...this.#aborters].reverse().map(async (aborter) => await aborter())).then(() => undefined);
    await this.#aborting;
  }
}

/**
 * Closed test composition: synthetic transport plus an in-memory child only.
 * It contains no system resolver, HTTPS client, Node spawn adapter, output writer, or product DB handle.
 */
export class SyntheticNetworkFreeGraphGenesisOrchestrator {
  readonly #broker: HardenedMetadataBrokerAuthority;
  readonly #child = new InertChildSpawnAdapter();
  readonly #supervisor: GraphGenesisProcessSupervisor;
  #used = false;

  constructor(
    private readonly plans: HardenedGraphGenesisPlanAuthority,
    private readonly transport: HardenedPublicMetadataTransport,
  ) {
    if (transport.implementationKind !== 'synthetic') failPlan();
    this.#broker = new HardenedMetadataBrokerAuthority(plans);
    this.#supervisor = new GraphGenesisProcessSupervisor(plans, this.#child);
  }

  async run(input: Readonly<{
    plan: HardenedGraphGenesisPlan;
    capsule: AuthenticatedGraphGenesisExecutionCapsule;
    startLease: AuthenticatedGraphGenesisStartLease;
    startLeaseVerifier: GraphGenesisStartLeaseVerifier;
    audit: GraphGenesisAuditGate;
    packageNames: readonly string[];
    monotonicNow: () => number;
    signal?: AbortSignal;
  }>): Promise<NetworkFreeGraphGenesisCompositionResult> {
    if (this.#used || input.packageNames.length < 1 || input.packageNames.length > input.plan.limits.broker.totalRequests) failPlan();
    this.#used = true;
    const abort = new GraphGenesisAbortOwner();
    const externalAbort = () => { void abort.abort(new PackageStageError('artifact_cancelled')); };
    input.signal?.addEventListener('abort', externalAbort, { once: true });
    let brokerSession: object | undefined;
    abort.register(async () => {
      if (brokerSession !== undefined) await this.#broker.abort(brokerSession);
    });
    abort.register(() => this.#child.abort());
    if (input.signal?.aborted === true) externalAbort();
    try {
      abort.throwIfAborted();
      brokerSession = this.#broker.prepareSession({
        plan: input.plan,
        capsule: input.capsule,
        startLease: input.startLease,
        startLeaseVerifier: input.startLeaseVerifier,
        audit: input.audit,
        transport: this.transport,
        onFailure: () => abort.abort(new PackageStageError('graph_metadata_incomplete')),
        mode: 'synthetic',
        monotonicNow: input.monotonicNow,
      });
      await this.#broker.arm(brokerSession);
      abort.throwIfAborted();
      const processPromise = this.#supervisor.run({
        plan: input.plan,
        capsule: input.capsule,
        audit: input.audit,
        startLease: input.startLease,
        startLeaseVerifier: input.startLeaseVerifier,
        monotonicNow: input.monotonicNow,
        onFailure: () => abort.abort(new PackageStageError('graph_metadata_incomplete')),
        signal: abort.controller.signal,
        mode: 'synthetic',
      });
      await waitFor(() => input.audit.events.includes('npm_spawn_started'), abort.controller.signal);
      for (const packageName of input.packageNames) {
        abort.throwIfAborted();
        await this.#broker.handle(
          brokerSession,
          'GET',
          `/${input.capsule.routeToken}/${packageName.startsWith('@') ? packageName.replace('/', '%2f') : packageName}`,
          {},
        );
        abort.throwIfAborted();
      }
      const ledger = await this.#broker.complete(brokerSession);
      this.#child.complete();
      const process = await processPromise;
      abort.throwIfAborted();
      if (process.status !== 'completed' || process.exitCode !== 0) failApproval();
      return Object.freeze({ ledger, process, terminalState: 'synthetic_complete' as const });
    } catch (error) {
      await abort.abort(error);
      throw error;
    } finally {
      input.signal?.removeEventListener('abort', externalAbort);
    }
  }
}

class InertChildSpawnAdapter implements GraphGenesisSpawnAdapter {
  readonly implementationKind = 'synthetic' as const;
  #close: ((code: number | null, signal: NodeJS.Signals | null) => void) | undefined;

  spawn(): ChildProcess {
    if (this.#close !== undefined) failPlan();
    const child = new EventEmitter() as EventEmitter & {
      pid: number;
      stdout: PassThrough;
      stderr: PassThrough;
      kill(signal?: NodeJS.Signals): boolean;
    };
    child.pid = 99_999_997;
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    let closed = false;
    this.#close = (code, signal) => {
      if (closed) return;
      closed = true;
      queueMicrotask(() => child.emit('close', code, signal));
    };
    child.kill = (signal = 'SIGTERM') => { this.#close?.(null, signal); return true; };
    return child as unknown as ChildProcess;
  }

  complete(): void { this.#close?.(0, null); }
  abort(): void { this.#close?.(null, 'SIGTERM'); }
}

async function waitFor(predicate: () => boolean, signal: AbortSignal): Promise<void> {
  for (let attempt = 0; attempt < 1_000; attempt += 1) {
    if (predicate()) return;
    if (signal.aborted) throw new PackageStageError('artifact_cancelled');
    await new Promise<void>((resolvePromise) => setTimeout(resolvePromise, 1));
  }
  throw new PackageStageError('graph_metadata_incomplete');
}

export function graphGenesisReceiptContext(envelope: GraphGenesisExecutionEnvelopeV1): ReceiptContext {
  return {
    adapter: 'graph_genesis',
    adapterVersion: '1',
    operation: 'filesystem_metadata_graph',
    boundary: 'graph_genesis_plan',
    identityAssurance: 'execution_plan_exact',
    identityMaterial: {
      executionEnvelopeHash: envelope.executionEnvelopeHash,
      planHash: envelope.planHash,
      policyDigest: envelope.policyDigest,
      auditFileIdentityDigest: envelope.auditFileIdentityDigest,
      auditDurabilityProfileDigest: envelope.auditDurabilityProfileDigest,
      outputCanonicalPathDigest: envelope.outputCanonicalPathDigest,
    },
    subject: TARGET,
    executionPlanHash: envelope.executionEnvelopeHash,
    policy: staticPolicyIdentity(
      GRAPH_GENESIS_POLICY.schemaVersion,
      GRAPH_GENESIS_POLICY.evaluatorName,
      GRAPH_GENESIS_POLICY.evaluatorVersion,
      GRAPH_GENESIS_POLICY,
    ),
  };
}

export function graphGenesisDigest(value: unknown): string { return digest(value); }

export function graphGenesisDirectoryIdentityDigest(input: Readonly<{
  canonicalPath: string;
  device: number;
  inode: number;
  owner: number;
  mode: number;
}>): string {
  return digest(input);
}

function isDigest(value: string): boolean { return SHA256.test(value); }

function isPrivateAbsolutePath(value: string): boolean {
  return isAbsolute(value) && value.length <= 4_096 && !/[\u0000-\u001f\u007f]/u.test(value);
}

function digest(value: unknown): string {
  return createHash('sha256').update(canonicalReceiptJson(value)).digest('hex');
}

function deepFreeze<T>(input: T): T {
  if (typeof input !== 'object' || input === null || Object.isFrozen(input)) return input;
  for (const value of Object.values(input)) deepFreeze(value);
  return Object.freeze(input);
}

function failPlan(): never { throw new PackageStageError('artifact_plan_invalid'); }
function failApproval(): never { throw new PackageStageError('approval_invalid'); }
