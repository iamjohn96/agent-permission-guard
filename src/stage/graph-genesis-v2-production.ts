import { createHash, randomBytes } from 'node:crypto';
import { spawn, type ChildProcess } from 'node:child_process';
import { constants, existsSync, lstatSync, realpathSync, openSync, closeSync, fstatSync, readSync } from 'node:fs';
import { lstat, open, realpath, type FileHandle } from 'node:fs/promises';
import { createServer, type Server } from 'node:http';
import { performance } from 'node:perf_hooks';
import { basename, dirname, join, relative, resolve, sep } from 'node:path';

import { LocalApprovalService } from '../approval/service.js';
import type { ApprovalOutcome, ApprovalTicket } from '../approval/types.js';
import { AuditQueryService } from '../audit/query-service.js';
import { SqliteAuditRecorder, type AuditCall, type GraphGenesisExecutionSummary } from '../audit/recorder.js';
import { AuthorizationReceiptSchema, OutcomeReceiptSchema, receiptDigest, type ReceiptContext } from '../audit/receipt.js';
import { canonicalJson } from '../audit/canonical-json.js';
import {
  authenticatesExistingGraphGenesisAuditDatabase,
  openAuditDatabaseReadOnly,
  type AuditDatabase,
  revalidatesExistingGraphGenesisAuditDatabase,
  type ExistingGraphGenesisAuditDatabase,
} from '../db/database.js';
import { startDashboard, type DashboardHandle } from '../dashboard/server.js';
import { staticPolicyIdentity } from '../policy/identity.js';
import type {
  AuthenticatedRuntimeTreeSnapshot,
  GraphGenesisLaunch,
  GraphGenesisLimits,
  GraphGenesisWorkspace,
  RuntimeTreeSnapshotAuthority,
} from './graph-genesis.js';
import { buildGraphGenesisLaunch } from './graph-genesis.js';
import type { SeatbeltLoopbackProfile } from './graph-genesis-containment.js';
import { SeatbeltLoopbackContainmentAuthority } from './graph-genesis-containment.js';
import { GRAPH_GENESIS_POLICY } from './graph-genesis-composition.js';
import { ExactGraphCandidateV2Authority, PEER_SEMANTICS_V2_CONTRACT } from './exact-production-graph-v2.js';
import {
  createGraphGenesisCandidateArtifactV2,
  decodeGraphGenesisCandidateArtifactV2,
  encodeGraphGenesisCandidateArtifactV2,
  syntheticUnavailableEvidenceV2,
  type GraphGenesisCandidateArtifactV2,
  type GraphGenesisCandidateArtifactV2Binding,
} from './graph-genesis-candidate-artifact-v2.js';
import { SyntheticPostStateV2Authority, type SyntheticPostStateV2 } from './graph-genesis-v2-post-state.js';
import type { DormantV2ConcreteExecution, DormantV2ConcreteTerminalProof, DormantV2MockedExecution, DormantV2MockedTerminalProof } from './graph-genesis-v2-execution-production.js';
import {
  SyntheticGraphGenesisV2ExecutionAuthority,
  type SyntheticGraphGenesisV2Run,
} from './graph-genesis-v2-execution.js';
import { parseStrictJsonDocument } from './graph-genesis-broker.js';
import {
  COMPILATION_CONTRACT_DIGEST,
  EXACT_COMPILATION_CONTRACT_V1,
  GRAPH_GENESIS_V2_POLICY,
  GRAPH_GENESIS_V2_POLICY_DIGEST,
  GraphGenesisV2BindingAuthority,
  SEMANTIC_CONTRACT_DIGEST,
  type GraphGenesisExecutionEnvelopeV2,
  type GraphGenesisPlanV3,
  type GraphGenesisProjectionV3,
  type PreparedGraphGenesisV2Binding,
} from './graph-genesis-v2-binding.js';
import {
  type AuthenticatedHostPlatformEvidence,
  type AuthenticatedOwnedContainmentEvidence,
  type AuthenticatedRuntimeFileSnapshot,
  type AuthenticatedRuntimeVersionEvidence,
  type FinalizedGraphGenesisWorkspaceAuthority,
  type OwnedContainmentProbeAuthority,
  type OwnedHostPlatformAuthority,
  type OwnedRuntimeVersionAuthority,
  type RuntimeFileSnapshotAuthority,
  computeWorkspaceBinding,
} from './graph-genesis-hardening.js';

const REQUIRED_ROLES = [
  'node', 'npmCli', 'sandboxExec', 'brokerRuntime', 'probeRuntime',
  'npmTree', 'distRuntimeTree', 'sqliteLib', 'migrations', 'webAssets',
  'sqlitePackage', 'sqliteNative', 'repositoryPackageJson', 'repositoryPackageLock', 'swVers', 'sysctl',
] as const;
type RuntimeRole = (typeof REQUIRED_ROLES)[number];
type RuntimeKind = 'file' | 'tree';

const TOP_LEVEL_KEYS = [
  'files', 'trees', 'runtimeVersions', 'host', 'workspace', 'containmentProfile', 'containment',
] as const;
const FILE_KEYS = [
  'node', 'npmCli', 'sandboxExec', 'brokerRuntime', 'probeRuntime',
  'sqlitePackage', 'sqliteNative', 'repositoryPackageJson', 'repositoryPackageLock', 'swVers', 'sysctl',
] as const;
const TREE_KEYS = ['npmTree', 'distRuntimeTree', 'sqliteLib', 'migrations', 'webAssets'] as const;
const DASHBOARD_KEYS = ['url', 'instanceId', 'close', 'bindGraphAction'] as const;
const OUTPUT_NAME = 'candidate.json';
const CONCRETE_WORKSPACE_NAME = '.apg-graph-genesis-v2-workspace';
const TARGET = '@modelcontextprotocol/server-filesystem@2026.7.10' as const;
const PREPARATION_WINDOW_MS = 120_000;
const APPROVAL_TTL_MS = 120_000;
const APPROVED_START_WINDOW_MS = 15_000;
const EXECUTION_WINDOW_MS = 120_000;
const MiB = 1024 * 1024;
const GRAPH_GENESIS_V2_LIMITS = Object.freeze({
  broker: Object.freeze({
    uniquePackageNames: 128,
    totalRequests: 256,
    concurrentRequests: 4,
    responseBytes: 4 * MiB,
    aggregateResponseBytes: 64 * MiB,
    requestTimeoutMs: 10_000,
  }),
  completeTimeoutMs: 120_000,
  stdoutBytes: 256 * 1024,
  stderrBytes: 256 * 1024,
  packageJsonBytes: 64 * 1024,
  packageLockBytes: 4 * MiB,
} satisfies GraphGenesisLimits);

/** Closed production bridge input: every value is branded by an existing low-level authority. */
export type GraphGenesisV2ConcreteProductionBundle = Readonly<{
  files: Readonly<{
    node: AuthenticatedRuntimeFileSnapshot;
    npmCli: AuthenticatedRuntimeFileSnapshot;
    sandboxExec: AuthenticatedRuntimeFileSnapshot;
    brokerRuntime: AuthenticatedRuntimeFileSnapshot;
    probeRuntime: AuthenticatedRuntimeFileSnapshot;
    sqlitePackage: AuthenticatedRuntimeFileSnapshot;
    sqliteNative: AuthenticatedRuntimeFileSnapshot;
    repositoryPackageJson: AuthenticatedRuntimeFileSnapshot;
    repositoryPackageLock: AuthenticatedRuntimeFileSnapshot;
    swVers: AuthenticatedRuntimeFileSnapshot;
    sysctl: AuthenticatedRuntimeFileSnapshot;
  }>;
  trees: Readonly<{
    npmTree: AuthenticatedRuntimeTreeSnapshot;
    distRuntimeTree: AuthenticatedRuntimeTreeSnapshot;
    sqliteLib: AuthenticatedRuntimeTreeSnapshot;
    migrations: AuthenticatedRuntimeTreeSnapshot;
    webAssets: AuthenticatedRuntimeTreeSnapshot;
  }>;
  runtimeVersions: AuthenticatedRuntimeVersionEvidence;
  host: AuthenticatedHostPlatformEvidence;
  workspace: GraphGenesisWorkspace;
  containmentProfile: SeatbeltLoopbackProfile;
  containment: AuthenticatedOwnedContainmentEvidence;
}>;

export type GraphGenesisV2RuntimeSeedInput = Readonly<Pick<GraphGenesisV2ConcreteProductionBundle,
  'files' | 'trees' | 'host' | 'runtimeVersions'>>;
export type AuthenticatedGraphGenesisV2RuntimeSeed = Readonly<{ runtimeSeedVersion: 1 }>;
type OwnedProductionBundle = GraphGenesisV2ConcreteProductionBundle;
const snapshotBundles = new WeakMap<object, OwnedProductionBundle>();

export type GraphGenesisV2RuntimeSnapshot = Readonly<{
  role: RuntimeRole;
  kind: RuntimeKind;
  identityDigest: string;
}>;

export type AuthenticatedGraphGenesisV2ProductionSnapshot = Readonly<{
  snapshotVersion: 1;
  runtimeManifestVersion: 2;
  runtimeManifestDigest: string;
  snapshots: readonly GraphGenesisV2RuntimeSnapshot[];
  hostEvidenceDigest: string;
  runtimeVersionEvidenceDigest: string;
  workspaceBinding: string;
  containmentProfileDigest: string;
  containmentEvidenceDigest: string;
}>;

export type GraphGenesisV2RevalidationOptions = Readonly<{
  signal?: AbortSignal;
  monotonicNow: () => number;
  deadline: number;
}>;

export type AuthenticatedGraphGenesisV2SessionContext = Readonly<{
  contextVersion: 1;
}>;

export type AuthenticatedGraphGenesisV2OutputIntent = Readonly<{
  outputIntentVersion: 1;
}>;

export type PreparedGraphGenesisV2Production = Readonly<{
  plan: GraphGenesisPlanV3;
  projection: GraphGenesisProjectionV3;
  envelope: GraphGenesisExecutionEnvelopeV2;
  approval: GraphGenesisV2ApprovalView;
  receipt: ReceiptContext;
  privateCapsule: object;
}>;

export type AuthenticatedGraphGenesisV2SealedAuthorization = Readonly<{
  sealedAuthorizationVersion: 2;
}>;
export type PreparedGraphGenesisV2ConcreteRoot = Readonly<{ rootVersion: 2; brokerPort: number }>;

export type GraphGenesisV2AuthorizationResult =
  | Readonly<{
    status: 'authorized';
    actionId: string;
    sealedAuthorization: AuthenticatedGraphGenesisV2SealedAuthorization;
  }>
  | Readonly<{
    status: Exclude<ApprovalOutcome, 'approved'>;
    actionId: string;
  }>;

export type GraphGenesisV2AuthorizationOptions = Readonly<{
  signal?: AbortSignal;
}>;

type OwnedPreparedProduction = Readonly<{
  prepared: PreparedGraphGenesisV2Production;
  snapshot: AuthenticatedGraphGenesisV2ProductionSnapshot;
  context: AuthenticatedGraphGenesisV2SessionContext;
  output: AuthenticatedGraphGenesisV2OutputIntent;
  privateBinding: object;
  privateExecution: GraphGenesisV2PrivateExecution;
  originalListener?: OwnedConcreteV2Listener;
  construction?: OwnedConcretePreparation;
}>;

type OwnedSealedAuthorization = Readonly<{
  sealed: AuthenticatedGraphGenesisV2SealedAuthorization;
  audit: AuditCall;
  prepared: PreparedGraphGenesisV2Production;
  context: AuthenticatedGraphGenesisV2SessionContext;
  output: AuthenticatedGraphGenesisV2OutputIntent;
  actionId: string;
  approvalId: string;
  startByMonotonicMs: number;
  sealedAtMonotonicMs: number;
  executionDeadlineMonotonicMs: number;
  privateExecution: GraphGenesisV2PrivateExecution;
  callerSignal?: AbortSignal;
  concreteAudit?: ConcreteAuditSnapshot;
}>;

type AuditCheckpoint = Readonly<{
  sequence: number;
  tail: string;
}>;

type OwnedSessionContext = Readonly<{
  source: ExistingGraphGenesisAuditDatabase;
  approvals: LocalApprovalService;
  recorder: SqliteAuditRecorder;
  query: AuditQueryService;
  dashboard: DashboardHandle;
  dashboardPort: number;
  controller: AbortController;
  outputs: Set<OwnedOutputIntent>;
  listeners: Set<OwnedConcreteV2Listener>;
}>;

type OwnedOutputIntent = Readonly<{
  publicIntent: AuthenticatedGraphGenesisV2OutputIntent;
  preparations: Set<OwnedConcretePreparation>;
  context: AuthenticatedGraphGenesisV2SessionContext;
  canonicalPath: string;
  parentCanonicalPath: string;
  parentDevice: number;
  parentInode: number;
  parentOwner: number;
  parentMode: number;
  parentIdentityDigest: string;
  canonicalPathDigest: string;
  descriptor: FileHandle;
  controller: AbortController;
}>;

type SyntheticQuiescedRunV2 = Readonly<{ actionId: string; approvalId: string; planHash: string; executionEnvelopeHash: string }>;
type SyntheticArtifactOutputV2 = Readonly<{ artifactDigest: string; outputDigest: string }>;

const COMPLETION_OWNER = Symbol('session-owned-synthetic-completion');
type CompletionProof = Readonly<{ actionId: string; artifactDigest: string; evidenceOrigin: 'synthetic_fixture'; terminalStatus: 'incomplete_external_read' }>;
type ProofRow = Record<string, unknown>;
type OwnedEvent = Readonly<{ type: string; details: unknown }>;
type GraphGenesisV2PrivateExecution = Readonly<{
  capsuleVersion: 2; planId: string; sessionId: string; routeToken: string;
  launch: GraphGenesisLaunch; runtimePaths: Readonly<Record<string, string>>; dashboardInstanceId: string;
  originalListenerIdentityDigest?: string;
}>;
type OwnedConcreteV2Listener = {
  readonly server: Server;
  port: number;
  identityDigest: string;
  state: 'disarmed' | 'armed' | 'drained' | 'closed';
  readonly controller: AbortController;
  readonly context: OwnedSessionContext;
  readonly deadline: number;
  lastNow: number;
  executionOwned: boolean;
  closePromise: Promise<boolean> | undefined;
  lifetime: ReturnType<typeof setTimeout> | undefined;
  detached: () => void;
};


/** No exported constructor, runtime raw fields, caller-selected DB or injected proof. */
class SessionOwnedSyntheticCompletion {
  readonly #sealed: OwnedSealedAuthorization;
  readonly #context: OwnedSessionContext;
  readonly #output: OwnedOutputIntent;
  readonly #workspace: GraphGenesisWorkspace;
  readonly #candidates: ExactGraphCandidateV2Authority;
  readonly #active: () => boolean;
  readonly #parentIdentity: string;
  readonly #initialEvents: readonly ProofRow[];
  readonly #initialCall: ProofRow;
  readonly #initialApproval: ProofRow;
  readonly #journal: OwnedEvent[] = [];
  readonly #dispose: Array<() => void> = [];
  readonly #runs = new WeakSet<object>();
  readonly #artifacts = new WeakMap<object, Readonly<{run: SyntheticQuiescedRunV2; state: SyntheticPostStateV2}>>();
  readonly #reservations = new WeakMap<object, SyntheticQuiescedRunV2>();
  readonly #outputs = new WeakMap<object, GraphGenesisCandidateArtifactV2>();
  readonly #postStates = new SyntheticPostStateV2Authority();
  readonly #execution = new SyntheticGraphGenesisV2ExecutionAuthority();
  readonly #executionRuns = new WeakMap<object, SyntheticGraphGenesisV2Run>();
  readonly #privateExecutionDigest: string;
  #runValue: SyntheticQuiescedRunV2 | undefined;
  #lastNow: number | undefined;
  #phase: 'new' | 'issued' | 'captured' | 'compiled' | 'reserved' | 'written' | 'terminal' = 'new';
  #busy = false;
  #started = false;
  #writtenIdentity: string | undefined;
  #terminalAttempted = false;
  #proofAttempted = false;
  #terminalEvents: readonly ProofRow[] | undefined;
  #terminalProofState: 'unattempted' | 'proven' | 'unknown' = 'unattempted';

  constructor(token: symbol, sealed: OwnedSealedAuthorization, context: OwnedSessionContext,
    output: OwnedOutputIntent, workspace: GraphGenesisWorkspace, candidates: ExactGraphCandidateV2Authority,
    privateExecution: object, active: () => boolean) {
    if (token !== COMPLETION_OWNER) fail();
    this.#sealed = sealed; this.#context = context; this.#output = output;
    this.#workspace = workspace; this.#candidates = candidates; this.#active = active;
    this.#privateExecutionDigest = digest(privateExecution);
    if (this.#privateExecutionDigest !== sealed.prepared.plan.executionCapsuleDigest) fail();
    this.#parentIdentity = proofIdentity(lstatSync(dirname(context.source.canonicalPath)));
    this.#checkSourcePath();
    // Snapshot the already durable owner-created authorization, not caller-supplied rows.
    this.#initialEvents = boundedProofEvents(context.source.database).filter((row) => row.tool_call_id === sealed.actionId);
    this.#initialCall = boundedProofRow(context.source.database, 'tool_calls', sealed.actionId);
    this.#initialApproval = boundedProofRow(context.source.database, 'approvals', sealed.approvalId);
    if (this.#initialEvents.length !== 8) fail();
    for (const signal of [context.controller.signal, output.controller.signal, sealed.callerSignal]) {
      if (signal === undefined) continue;
      const revoke = () => this.#failure();
      signal.addEventListener('abort', revoke, { once: true });
      this.#dispose.push(() => signal.removeEventListener('abort', revoke));
    }
    Object.freeze(this);
  }

  issueSyntheticQuiescedRun(now: () => number): SyntheticQuiescedRunV2 {
    return this.#sync(() => {
      const at = this.#fence(now); if (this.#phase !== 'new') fail();
      const run = Object.freeze({ actionId: this.#sealed.actionId, approvalId: this.#sealed.approvalId,
        planHash: this.#sealed.prepared.plan.planHash, executionEnvelopeHash: this.#sealed.prepared.envelope.executionEnvelopeHash });
      const binding = Object.freeze({
        actionId: run.actionId, approvalId: run.approvalId, planHash: run.planHash,
        executionEnvelopeHash: run.executionEnvelopeHash,
        listenerProfileDigest: this.#sealed.prepared.plan.containmentProfileDigest,
        routeDigest: this.#sealed.prepared.plan.routeTokenDigest,
        capsuleDigest: this.#privateExecutionDigest,
      });
      const listener = this.#execution.prepareListener(binding, this.#sealed.prepared.plan.brokerPort);
      const executionRun = this.#execution.reserve(binding, listener, at, this.#sealed.startByMonotonicMs,
        this.#sealed.executionDeadlineMonotonicMs);
      // Durable dispatch is recorded before this fixture models broker/child ordering.
      this.#started = true;
      this.#sealed.audit.markExecutionStarted();
      this.#execution.markExecutionStarted(executionRun, at);
      this.#execution.recordBrokerIntent(executionRun, at);
      this.#execution.commitBrokerArm(executionRun, at);
      this.#execution.recordSpawnAttempt(executionRun, at);
      this.#execution.observeChildClose(executionRun, at, 0);
      this.#execution.observeListenerQuiesced(executionRun, listener, at);
      const quiescence = this.#execution.quiesce(executionRun, at);
      this.#append('graph_genesis_v2_synthetic_quiesced_fixture', {
        evidenceOrigin: 'synthetic_fixture', planHash: run.planHash, executionEnvelopeHash: run.executionEnvelopeHash,
        quiescence: { childCloseObserved: quiescence.childCloseObserved, exitCode: quiescence.exitCode,
          requestCount: quiescence.requestCount, responseBytes: quiescence.responseBytes },
        unavailableEvidence: syntheticUnavailableEvidenceV2(run.actionId),
      });
      this.#runs.add(run); this.#executionRuns.set(run, executionRun); this.#runValue = run; this.#phase = 'issued';
      return run;
    });
  }

  async captureSyntheticPostState(run: SyntheticQuiescedRunV2, now: () => number): Promise<SyntheticPostStateV2> {
    return this.#async(async () => {
      this.#run(run, now); if (this.#phase !== 'issued') fail();
      const state = await this.#postStates.capture({ evidenceOrigin: 'synthetic_fixture', ...run,
        workspaceBinding: this.#sealed.prepared.plan.workspaceBinding, workspace: this.#workspace,
        checkpoint: () => this.#run(run, now) });
      this.#run(run, now);
      this.#append('graph_genesis_v2_post_state_validated', { evidenceOrigin: 'synthetic_fixture', postStateDigest: state.postStateDigest });
      this.#phase = 'captured'; return state;
    });
  }

  compileSyntheticArtifact(run: SyntheticQuiescedRunV2, state: SyntheticPostStateV2, now: () => number): GraphGenesisCandidateArtifactV2 {
    return this.#sync(() => {
      this.#run(run, now);
      if (this.#phase !== 'captured' || !this.#postStates.matches(state, run)) fail();
      const candidate = this.#postStates.compileCandidate(state, this.#candidates, this.#sealed.prepared.plan.compilationContract);
      if (!this.#candidates.authenticates(candidate)) fail();
      const artifact = createGraphGenesisCandidateArtifactV2({ evidenceOrigin: 'synthetic_fixture', candidate, binding: this.#binding(run, state) });
      this.#append('graph_genesis_v2_candidate_compiled', { evidenceOrigin: 'synthetic_fixture', candidateDigest: candidate.candidateDigest, postStateDigest: state.postStateDigest });
      this.#artifacts.set(artifact, { run, state }); this.#phase = 'compiled'; return artifact;
    });
  }

  async reserveOutput(run: SyntheticQuiescedRunV2, now: () => number): Promise<object> {
    return this.#async(async () => {
      this.#run(run, now); if (this.#phase !== 'compiled') fail();
      await this.#parent(run, now);
      await assertAbsentV2(this.#output.canonicalPath); this.#run(run, now);
      this.#append('graph_genesis_v2_candidate_output_intent', { evidenceOrigin: 'synthetic_fixture',
        outputCanonicalPathDigest: this.#sealed.prepared.envelope.outputCanonicalPathDigest });
      const reservation = Object.freeze({ reservationVersion: 2 as const });
      this.#reservations.set(reservation, run); this.#phase = 'reserved'; return reservation;
    });
  }

  async writeReservedArtifact(run: SyntheticQuiescedRunV2, reservation: object, artifact: GraphGenesisCandidateArtifactV2, now: () => number): Promise<SyntheticArtifactOutputV2> {
    return this.#async(async () => {
      this.#run(run, now);
      const owned = this.#artifacts.get(artifact);
      if (this.#phase !== 'reserved' || this.#reservations.get(reservation) !== run || owned?.run !== run) fail();
      this.#reservations.delete(reservation);
      await this.#postStates.revalidate(owned.state, () => this.#run(run, now)); this.#run(run, now);
      await this.#parent(run, now);
      await assertAbsentV2(this.#output.canonicalPath); this.#run(run, now);
      const bytes = encodeGraphGenesisCandidateArtifactV2(artifact);
      let file: FileHandle | undefined;
      try {
        file = await open(this.#output.canonicalPath, constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW | constants.O_RDWR, 0o600);
        this.#run(run, now);
        await this.#parent(run, now);
        const write = await file.write(bytes, 0, bytes.byteLength, 0); this.#run(run, now);
        if (write.bytesWritten !== bytes.byteLength) fail();
        await file.sync(); this.#run(run, now);
        const info = await file.stat(); this.#run(run, now);
        if (!info.isFile() || info.nlink !== 1 || info.uid !== currentUserV2(info.uid) || (Number(info.mode) & 0o7777) !== 0o600 || info.size !== bytes.byteLength) fail();
        const buffer = Buffer.alloc(bytes.byteLength + 1);
        const read = await file.read(buffer, 0, buffer.byteLength, 0); this.#run(run, now);
        if (read.bytesRead !== bytes.byteLength || !buffer.subarray(0, bytes.byteLength).equals(Buffer.from(bytes))) fail();
        if (decodeGraphGenesisCandidateArtifactV2(buffer.subarray(0, read.bytesRead)).artifactDigest !== artifact.artifactDigest) fail();
        const after = await file.stat(); this.#run(run, now);
        const linked = await lstat(this.#output.canonicalPath); this.#run(run, now);
        if (!sameV2File(info, after) || !sameV2File(info, linked)) fail();
        this.#writtenIdentity = proofFileIdentity(after);
        await this.#output.descriptor.sync(); this.#run(run, now);
        await this.#parent(run, now);
        await this.#postStates.revalidate(owned.state, () => this.#run(run, now)); this.#run(run, now);
      } finally { if (file !== undefined) await file.close(); }
      this.#run(run, now);
      const result = Object.freeze({ artifactDigest: artifact.artifactDigest, outputDigest: createHash('sha256').update(bytes).digest('hex') });
      // Never issue an output capability before the output event is durable.
      this.#append('graph_genesis_v2_candidate_output_written', { evidenceOrigin: 'synthetic_fixture', artifactDigest: artifact.artifactDigest, outputDigest: result.outputDigest });
      this.#outputs.set(result, artifact); this.#phase = 'written'; return result;
    });
  }

  finalizeSyntheticIncomplete(run: SyntheticQuiescedRunV2, output: SyntheticArtifactOutputV2, now: () => number): CompletionProof {
    return this.#sync(() => {
      this.#run(run, now);
      const artifact = this.#outputs.get(output);
      if (this.#phase !== 'written' || artifact === undefined || this.#artifacts.get(artifact)?.run !== run) fail();
      this.#verifyOutput(artifact);
      this.#run(run, now);
      const proof = this.#terminal('incomplete_external_read', artifact);
      if (proof === undefined) fail();
      return proof;
    });
  }

  async #parent(run: SyntheticQuiescedRunV2, now: () => number): Promise<void> {
    this.#run(run, now);
    const descriptor = await this.#output.descriptor.stat(); this.#run(run, now);
    const linked = await lstat(this.#output.parentCanonicalPath); this.#run(run, now);
    const canonical = await realpath(this.#output.parentCanonicalPath); this.#run(run, now);
    if (canonical !== this.#output.parentCanonicalPath || !descriptor.isDirectory() || !linked.isDirectory()
      || linked.isSymbolicLink() || descriptor.dev !== this.#output.parentDevice || descriptor.ino !== this.#output.parentInode
      || descriptor.uid !== this.#output.parentOwner || (descriptor.mode & 0o7777) !== this.#output.parentMode
      || descriptor.dev !== linked.dev || descriptor.ino !== linked.ino || descriptor.uid !== linked.uid
      || (linked.mode & 0o7777) !== this.#output.parentMode) fail();
  }

  #sync<T>(operation: () => T): T {
    if (this.#terminalAttempted) fail();
    if (this.#busy) { this.#failure(); fail(); }
    this.#busy = true;
    try { return operation(); } catch (error) { this.#failure(); throw error; } finally { this.#busy = false; }
  }
  async #async<T>(operation: () => Promise<T>): Promise<T> {
    if (this.#terminalAttempted) fail();
    if (this.#busy) { this.#failure(); fail(); }
    this.#busy = true;
    try { return await operation(); } catch (error) { this.#failure(); throw error; } finally { this.#busy = false; }
  }
  #failure(): void {
    if (!this.#started || this.#terminalAttempted) return;
    // Preserve-only: a partially created file is an orphan, never retried or promoted.
    try { this.#terminal('failed'); } catch { /* terminal/proof remains unknown; no fallback writer */ }
  }
  #append(type: string, details: unknown): void {
    this.#sealed.audit.appendEvidence(type, details);
    this.#journal.push(Object.freeze({ type, details: parseStrictJsonDocument(canonicalJson(details)) }));
  }
  #terminal(status: 'failed' | 'incomplete_external_read', artifact?: GraphGenesisCandidateArtifactV2): CompletionProof | undefined {
    if (this.#terminalAttempted) fail();
    this.#terminalAttempted = true; this.#phase = 'terminal';
    for (const dispose of this.#dispose.splice(0)) dispose();
    const summary: GraphGenesisExecutionSummary = {
      metadata: { externalReadStatus: status === 'failed' ? 'not_started' : 'incomplete', requestCount: 0, uniquePackageCount: 0, responseBytes: 0 },
      process: { status: 'failed', exitCode: null, stdoutBytes: 0, stderrBytes: 0 },
      ...(artifact === undefined ? {} : { candidate: { lockDigest: 'sha256:' + artifact.binding.lockBytesDigest, candidateDigest: 'sha256:' + artifact.candidate.candidateDigest, artifactDigest: 'sha256:' + artifact.artifactDigest } }),
      cleanup: { status: 'incomplete' }, terminalAudit: { status: 'unknown' },
      errorCode: status === 'failed' ? 'synthetic_fixture_completion_failed_preserve_only' : 'synthetic_fixture_not_production_evidence',
    };
    // One write attempt, then one independent reconciliation even if that write throws.
    try { this.#sealed.audit.finalizeGraphGenesisOutcome(summary, status); } catch { /* possibly committed */ }
    try {
      this.#terminalEvents = boundedProofEvents(this.#context.source.database)
        .filter((row) => row.tool_call_id === this.#sealed.actionId).slice(-3);
    } catch { /* independent proof is still attempted; exact receipt identity remains unavailable */ }
    try {
      this.#prove(summary, status);
      if (artifact !== undefined) this.#verifyOutput(artifact);
      this.#terminalProofState = 'proven';
      if (artifact !== undefined && status === 'incomplete_external_read') return Object.freeze({
        actionId: this.#sealed.actionId, artifactDigest: artifact.artifactDigest, evidenceOrigin: 'synthetic_fixture', terminalStatus: status,
      });
      return undefined;
    } catch { this.#terminalProofState = 'unknown'; fail(); }
  }

  #verifyOutput(artifact: GraphGenesisCandidateArtifactV2): void {
    if (!this.#active() || this.#context.controller.signal.aborted || this.#output.controller.signal.aborted || this.#sealed.callerSignal?.aborted) fail();
    const parent = lstatSync(this.#output.parentCanonicalPath);
    if (!parent.isDirectory() || parent.isSymbolicLink() || realpathSync(this.#output.parentCanonicalPath) !== this.#output.parentCanonicalPath
      || parent.dev !== this.#output.parentDevice || parent.ino !== this.#output.parentInode || parent.uid !== this.#output.parentOwner
      || (parent.mode & 0o7777) !== this.#output.parentMode) fail();
    const expected = Buffer.from(encodeGraphGenesisCandidateArtifactV2(artifact));
    const fd = openSync(this.#output.canonicalPath, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const before = fstatSync(fd);
      if (!before.isFile() || before.nlink !== 1 || proofFileIdentity(before) !== this.#writtenIdentity) fail();
      const bytes = Buffer.alloc(expected.byteLength + 1); let offset = 0;
      while (offset < bytes.byteLength) {
        const count = readSync(fd, bytes, offset, bytes.byteLength - offset, offset);
        if (count === 0) break; offset += count;
      }
      if (offset !== expected.byteLength || !bytes.subarray(0, offset).equals(expected)
        || proofFileIdentity(fstatSync(fd)) !== this.#writtenIdentity
        || proofFileIdentity(lstatSync(this.#output.canonicalPath)) !== this.#writtenIdentity
        || decodeGraphGenesisCandidateArtifactV2(bytes.subarray(0, offset)).artifactDigest !== artifact.artifactDigest) fail();
    } finally { closeSync(fd); }
  }

  #run(run: SyntheticQuiescedRunV2, now: () => number): void {
    if (run !== this.#runValue || !this.#runs.has(run) || this.#executionRuns.get(run) === undefined) fail(); this.#fence(now);
  }
  #fence(now: () => number): number {
    if (this.#terminalAttempted || !this.#active() || this.#context.controller.signal.aborted || this.#output.controller.signal.aborted || this.#sealed.callerSignal?.aborted) fail();
    const value = now();
    // The caller's clock may synchronously revoke/re-enter the owner.
    if (this.#terminalAttempted || !this.#active() || this.#context.controller.signal.aborted || this.#output.controller.signal.aborted || this.#sealed.callerSignal?.aborted) fail();
    if (!Number.isFinite(value) || value < 0 || value >= this.#sealed.executionDeadlineMonotonicMs
      || (this.#phase === 'new' && value >= this.#sealed.startByMonotonicMs)
      || (this.#lastNow !== undefined && value < this.#lastNow)) fail();
    this.#lastNow = value;
    return value;
  }
  #binding(run: SyntheticQuiescedRunV2, post: SyntheticPostStateV2): GraphGenesisCandidateArtifactV2Binding {
    const plan = this.#sealed.prepared.plan; const envelope = this.#sealed.prepared.envelope;
    const unavailable = syntheticUnavailableEvidenceV2(run.actionId);
    return Object.freeze({ bindingVersion: 2, actionId: run.actionId, approvalId: run.approvalId, planId: plan.planId, sessionId: envelope.sessionId, planHash: plan.planHash, executionEnvelopeHash: envelope.executionEnvelopeHash, projectionDigest: envelope.projectionDigest, semanticContractDigest: plan.semanticContractDigest, compilationContractDigest: plan.compilationContractDigest, runtimeManifestDigest: plan.runtimeManifestDigest, workspaceBinding: plan.workspaceBinding, lockBytesDigest: post.lockBytesDigest, lockDocumentDigest: post.lockDocumentDigest, postStateDigest: post.postStateDigest, inventoryDigest: post.inventoryDigest, brokerLedgerDigest: unavailable.brokerLedgerDigest, processResultDigest: unavailable.processResultDigest, listenerDrainDigest: unavailable.listenerDrainDigest, hostEvidenceDigest: plan.hostEvidenceDigest, containmentProfileDigest: plan.containmentProfileDigest, containmentEvidenceDigest: plan.containmentEvidenceDigest, policyDigest: envelope.policyDigest, auditFileIdentityDigest: envelope.auditFileIdentityDigest, auditDurabilityProfileDigest: envelope.auditDurabilityProfileDigest, outputCanonicalPathDigest: envelope.outputCanonicalPathDigest, outputParentIdentityDigest: envelope.outputParentIdentityDigest });
  }
  #checkSourcePath(): void {
    const source = this.#context.source;
    const file = lstatSync(source.canonicalPath); const parent = lstatSync(dirname(source.canonicalPath));
    if (realpathSync(source.canonicalPath) !== source.canonicalPath || !file.isFile() || file.isSymbolicLink()
      || file.nlink !== 1 || proofIdentity(file) !== source.fileIdentityDigest || !parent.isDirectory()
      || parent.isSymbolicLink() || proofIdentity(parent) !== this.#parentIdentity) fail();
  }
  #prove(summary: GraphGenesisExecutionSummary, status: 'failed' | 'incomplete_external_read'): void {
    if (this.#proofAttempted) fail();
    this.#proofAttempted = true;
    this.#checkSourcePath();
    const db = openAuditDatabaseReadOnly(this.#context.source.canonicalPath);
    try {
      if (!db.readonly || db === this.#context.source.database || db.pragma('query_only', { simple: true }) !== 1) fail();
      db.transaction(() => {
        this.#checkSourcePath();
        const schemaBytes = db.prepare("SELECT coalesce(sum(length(CAST(sql AS BLOB))),0) AS bytes FROM sqlite_schema WHERE type='table' AND name IN ('approvals','audit_events','schema_migrations','tool_calls')").get() as { bytes: number };
        if (schemaBytes.bytes > 512 * 1024 || db.prepare('SELECT count(*) FROM schema_migrations').pluck().get() !== 2) fail();
        const tables = db.prepare("SELECT name, sql FROM sqlite_schema WHERE type='table' AND name IN ('approvals','audit_events','schema_migrations','tool_calls') ORDER BY name").all();
        if (digest({ migrations: [1, 2], tables }) !== this.#context.source.schemaDigest) fail();
        const migrations = db.prepare('SELECT version FROM schema_migrations ORDER BY version').pluck().all();
        if (canonicalJson(migrations) !== '[1,2]') fail();
        const events = boundedProofEvents(db);
        let tail = '0'.repeat(64); let sequence = 0;
        const ids = new Set<string>();
        for (const row of events) {
          const event = proofRecord(proofJson(row.event_json));
          if (typeof row.sequence !== 'number' || !Number.isSafeInteger(row.sequence) || row.sequence <= sequence || typeof row.event_id !== 'string'
            || ids.has(row.event_id) || canonicalJson(Object.keys(event).sort()) !== canonicalJson(['createdAt','details','eventId','eventType','toolCallId'].sort())
            || event.eventId !== row.event_id || event.eventType !== row.event_type || event.toolCallId !== row.tool_call_id
            || event.createdAt !== row.created_at || canonicalJson(event) !== row.event_json || row.previous_hash !== tail
            || row.event_hash !== createHash('sha256').update(tail + '\n' + String(row.event_json)).digest('hex')) fail();
          ids.add(row.event_id); sequence = row.sequence; tail = String(row.event_hash);
        }
        const own = events.filter((row) => row.tool_call_id === this.#sealed.actionId);
        const prefix = ['decision_recorded','graph_genesis_v2_session_created','approval_requested','approval_approved',
          'graph_genesis_v2_approved_revalidation_complete','authorization_receipt_finalized','graph_genesis_authorization_ready','graph_genesis_v2_authorization_finalized'];
        const types = [...prefix, 'execution_start_recorded', ...this.#journal.map((entry) => entry.type),
          'graph_genesis_incomplete','execution_completed','outcome_receipt_finalized'];
        if (own.length > 1024 || canonicalJson(own.map((row) => row.event_type)) !== canonicalJson(types)
          || canonicalJson(own.slice(0, 8)) !== canonicalJson(this.#initialEvents)
          || this.#terminalEvents === undefined || canonicalJson(own.slice(-3)) !== canonicalJson(this.#terminalEvents)) fail();
        const details = own.map((row) => proofRecord(proofRecord(proofJson(row.event_json)).details));
        for (let i = 0; i < this.#journal.length; i += 1) {
          if (canonicalJson(details[9 + i]) !== canonicalJson(this.#journal[i]!.details)) fail();
        }
        const authDetails = details[5]!;
        const auth = AuthorizationReceiptSchema.parse(authDetails.receipt);
        const receiptContext = this.#sealed.prepared.receipt;
        const expectedAction = { id: this.#sealed.actionId, adapter: receiptContext.adapter,
          adapterVersion: receiptContext.adapterVersion, operation: receiptContext.operation,
          identityAssurance: receiptContext.identityAssurance,
          intentDigest: 'sha256:' + digest({ format: 'apg-portable-intent-v1', adapter: receiptContext.adapter,
            adapterVersion: receiptContext.adapterVersion, operation: receiptContext.operation, material: receiptContext.identityMaterial }),
          subject: receiptContext.subject, executionPlanHash: receiptContext.executionPlanHash };
        if (canonicalJson(auth.action) !== canonicalJson(expectedAction) || auth.schema.minorVersion !== 2
          || auth.coverage.boundary !== 'graph_genesis_plan' || auth.authorization.status !== 'authorized'
          || canonicalJson(auth.policy) !== canonicalJson({ ...receiptContext.policy, matchedRuleId: 'graph_genesis_builtin_ask_v2' })
          || canonicalJson(auth.decision) !== canonicalJson({ base: 'ask', effective: 'ask', reasonCodes: [...GRAPH_GENESIS_POLICY.reasonCodes], riskScore: GRAPH_GENESIS_POLICY.score, riskBand: GRAPH_GENESIS_POLICY.band })
          || authDetails.receiptDigest !== receiptDigest(auth) || details[8]!.receiptDigest !== receiptDigest(auth)) fail();
        const approval = boundedProofRow(db, 'approvals', this.#sealed.approvalId);
        if (canonicalJson(approval) !== canonicalJson(this.#initialApproval) || approval.status !== 'approved'
          || approval.tool_call_id !== this.#sealed.actionId || auth.approval.requestId !== approval.id
          || !auth.approval.required || auth.approval.outcome !== 'approved'
          || auth.approval.principalAssurance !== 'local_dashboard_session'
          || auth.approval.requestedAt !== approval.requested_at || auth.approval.decidedAt !== approval.decided_at
          || auth.approval.expiresAt !== approval.expires_at) fail();
        const call = boundedProofRow(db, 'tool_calls', this.#sealed.actionId);
        for (const key of Object.keys(this.#initialCall).filter((key) => !['status','completed_at','latency_ms','result_summary_json','error_code'].includes(key))) {
          if (canonicalJson(call[key]) !== canonicalJson(this.#initialCall[key])) fail();
        }
        const args = { executionEnvelopeHash: this.#sealed.prepared.envelope.executionEnvelopeHash, planHash: this.#sealed.prepared.plan.planHash };
        if (call.status !== status || call.server_id !== 'apg-graph-genesis' || call.tool_name !== 'filesystem_metadata_graph'
          || call.arguments_json !== canonicalJson(args) || call.request_hash !== digest({ serverId: call.server_id, toolName: call.tool_name, arguments: args })
          || call.result_summary_json !== canonicalJson(summary) || call.error_code !== summary.errorCode) fail();
        const terminal = details[details.length - 3]!;
        const executed = details[details.length - 2]!;
        const outcomeDetails = details[details.length - 1]!;
        const outcome = OutcomeReceiptSchema.parse(outcomeDetails.receipt);
        const expectedObserved = { kind: 'graph_genesis', isError: true, externalReadStatus: summary.metadata.externalReadStatus,
          metadataRequestCount: 0, metadataUniquePackageCount: 0, metadataResponseBytes: 0,
          executionStatus: 'failed', exitCode: null, stdoutBytes: 0, stderrBytes: 0,
          ...(summary.candidate === undefined ? {} : { lockDigest: summary.candidate.lockDigest,
            candidateDigest: summary.candidate.candidateDigest, candidateArtifactDigest: summary.candidate.artifactDigest }),
          cleanupStatus: 'incomplete', terminalAuditStatus: 'unknown', errorCode: summary.errorCode };
        if (canonicalJson(executed) !== canonicalJson(summary) || outcome.schema.minorVersion !== 2
          || canonicalJson(outcome.action) !== canonicalJson(auth.action) || canonicalJson(outcome.coverage) !== canonicalJson(auth.coverage)
          || outcome.authorizationReceiptDigest !== receiptDigest(auth) || outcomeDetails.receiptDigest !== receiptDigest(outcome)
          || outcome.execution.terminalStatus !== status || outcome.execution.completedAt !== call.completed_at
          || outcome.receipt.issuedAt !== call.completed_at
          || outcome.execution.startedAt < auth.receipt.issuedAt || outcome.execution.startedAt > String(own[8]!.created_at)
          || canonicalJson(outcome.execution.observedResult) !== canonicalJson(expectedObserved)
          || terminal.executionPlanHash !== args.executionEnvelopeHash || terminal.terminalStatus !== status
          || terminal.outcomeReceiptDigest !== receiptDigest(outcome)) fail();
        this.#checkSourcePath();
      })();
      this.#checkSourcePath();
    } finally { db.close(); }
  }
}


const CONCRETE_OWNER = Symbol('session-owned-concrete-v2');
const AUTHORIZED_V2_EVENTS = [
  'decision_recorded', 'graph_genesis_v2_session_created', 'approval_requested', 'approval_approved',
  'graph_genesis_v2_approved_revalidation_complete', 'authorization_receipt_finalized',
  'graph_genesis_authorization_ready', 'graph_genesis_v2_authorization_finalized',
] as const;
type ConcreteAuditSnapshot = Readonly<{
  events: readonly ProofRow[]; call: ProofRow; approval: ProofRow; parentIdentity: string;
}>;
function concreteEventDetails(row: ProofRow): ProofRow {
  return proofRecord(proofRecord(proofJson(row.event_json)).details);
}
function concreteDBIdentity(source: ExistingGraphGenesisAuditDatabase, parentIdentity: string, db: AuditDatabase): void {
  if (!authenticatesExistingGraphGenesisAuditDatabase(source)) fail();
  const file = lstatSync(source.canonicalPath), parent = lstatSync(dirname(source.canonicalPath));
  if (realpathSync(source.canonicalPath) !== source.canonicalPath || !file.isFile() || file.isSymbolicLink()
    || file.nlink !== 1 || proofIdentity(file) !== source.fileIdentityDigest || !parent.isDirectory()
    || parent.isSymbolicLink() || proofIdentity(parent) !== parentIdentity) fail();
  const sidecars: string[] = [];
  for (const suffix of ['-wal', '-shm']) {
    const path = source.canonicalPath + suffix;
    if (!existsSync(path)) continue;
    const info = lstatSync(path);
    if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.uid !== file.uid || (info.mode & 0o077) !== 0) fail();
    sidecars.push(suffix);
  }
  // Durability is a property of the retained writer; query-only is independently checked on the proof connection.
  const profile = {
    journalMode: String(source.database.pragma('journal_mode', { simple: true })).toLowerCase(),
    synchronous: Number(source.database.pragma('synchronous', { simple: true })),
    busyTimeoutMs: Number(source.database.pragma('busy_timeout', { simple: true })),
    integrity: 'ok', sidecars,
  };
  if (profile.journalMode !== 'wal' || profile.synchronous !== 2 || profile.busyTimeoutMs !== 5000
    || digest(profile) !== source.durabilityProfileDigest) fail();
  const bytes = db.prepare("SELECT coalesce(sum(length(CAST(sql AS BLOB))),0) FROM sqlite_schema WHERE type='table' AND name IN ('approvals','audit_events','schema_migrations','tool_calls')").pluck().get();
  if (typeof bytes !== 'number' || bytes > 512 * 1024
    || db.prepare('SELECT count(*) FROM schema_migrations').pluck().get() !== 2) fail();
  const migrations = db.prepare('SELECT version FROM schema_migrations ORDER BY version').pluck().all();
  const tables = db.prepare("SELECT name,sql FROM sqlite_schema WHERE type='table' AND name IN ('approvals','audit_events','schema_migrations','tool_calls') ORDER BY name").all();
  if (canonicalJson(migrations) !== '[1,2]' || digest({ migrations, tables }) !== source.schemaDigest) fail();
}
function concreteChain(db: AuditDatabase): ProofRow[] {
  const events = boundedProofEvents(db);
  let tail = '0'.repeat(64), sequence = 0;
  const ids = new Set<string>();
  for (const row of events) {
    const event = proofRecord(proofJson(row.event_json));
    if (!Number.isSafeInteger(row.sequence) || Number(row.sequence) <= sequence || typeof row.event_id !== 'string'
      || ids.has(row.event_id) || canonicalJson(Object.keys(event).sort()) !== canonicalJson(['createdAt','details','eventId','eventType','toolCallId'].sort())
      || event.eventId !== row.event_id || event.eventType !== row.event_type || event.toolCallId !== row.tool_call_id
      || event.createdAt !== row.created_at || canonicalJson(event) !== row.event_json || row.previous_hash !== tail
      || row.event_hash !== digestBytes(tail + '\n' + row.event_json)) fail();
    sequence = Number(row.sequence); tail = String(row.event_hash); ids.add(row.event_id);
  }
  return events;
}
function captureConcreteAuditSnapshot(source: ExistingGraphGenesisAuditDatabase, actionId: string, approvalId: string): ConcreteAuditSnapshot {
  const parentIdentity = proofIdentity(lstatSync(dirname(source.canonicalPath)));
  concreteDBIdentity(source, parentIdentity, source.database);
  const events = concreteChain(source.database);
  // The enclosing authorize method has just verified the exact eight owner-created events.
  const last = events.at(-1); if (last === undefined || typeof last.tool_call_id !== 'string') fail();
  if (last.tool_call_id !== actionId) fail();
  const own = events.filter(row => row.tool_call_id === actionId);
  if (canonicalJson(own.map(row => row.event_type)) !== canonicalJson(AUTHORIZED_V2_EVENTS)) fail();
  if (concreteEventDetails(own[7]!).approvalId !== approvalId
    || own[0]!.previous_hash !== source.initialChainTail) fail();
  return Object.freeze({
    events: Object.freeze(events.map(row => Object.freeze({ ...row }))),
    call: Object.freeze(boundedProofRow(source.database, 'tool_calls', actionId)),
    approval: Object.freeze(boundedProofRow(source.database, 'approvals', approvalId)), parentIdentity,
  });
}

/** Owner-held append expectations; neither input rows nor a supplied proof can create this journal. */
class ConcreteAuditJournal {
  readonly #sealed: OwnedSealedAuthorization;
  readonly #source: ExistingGraphGenesisAuditDatabase;
  readonly #snapshot: ConcreteAuditSnapshot;
  #expected: readonly ProofRow[];
  #startAttempted = false;
  #started = false;
  #pending: OwnedEvent | undefined;
  #terminal: Readonly<{ summary: GraphGenesisExecutionSummary; status: 'execution_error' | 'outcome_unknown_after_interruption' }> | undefined;
  #reconciled = false;

  constructor(token: symbol, sealed: OwnedSealedAuthorization, context: OwnedSessionContext) {
    if (token !== CONCRETE_OWNER || sealed.concreteAudit === undefined) fail();
    this.#sealed = sealed; this.#source = context.source; this.#snapshot = sealed.concreteAudit;
    this.#expected = this.#snapshot.events;
    Object.freeze(this);
  }
  verify(): void { this.#check(this.#source.database, []); }
  start(): void {
    this.verify();
    if (this.#startAttempted) fail();
    this.#startAttempted = true;
    this.#pending = { type: 'execution_start_recorded', details: { receiptDigest: this.#authDigest() } };
    this.#sealed.audit.markExecutionStarted();
    this.#acceptPending(); this.#started = true;
  }
  append(type: string, details: unknown): void {
    this.verify();
    if (!this.#started || this.#pending !== undefined) fail();
    this.#pending = Object.freeze({ type, details: parseStrictJsonDocument(canonicalJson(details)) });
    this.#sealed.audit.appendEvidence(type, details);
    this.#acceptPending();
  }
  finalize(summary: GraphGenesisExecutionSummary, status: 'execution_error' | 'outcome_unknown_after_interruption'): void {
    this.verify();
    if (!this.#started || this.#terminal !== undefined) fail();
    this.#terminal = Object.freeze({ summary, status });
    // May commit then throw. The caller must reconcile; never call a fallback writer.
    this.#sealed.audit.finalizeGraphGenesisOutcome(summary, status);
  }
  reconcile(requireTerminal: boolean): boolean {
    if (this.#reconciled) fail(); this.#reconciled = true;
    let db: AuditDatabase | undefined;
    let proven = false;
    try {
      concreteDBIdentity(this.#source, this.#snapshot.parentIdentity, this.#source.database);
      db = openAuditDatabaseReadOnly(this.#source.canonicalPath);
      if (!db.readonly || db === this.#source.database || db.pragma('query_only', { simple: true }) !== 1) fail();
      const proofDB = db;
      proofDB.transaction(() => {
        if (requireTerminal && this.#terminal === undefined) fail();
        const events = concreteChain(proofDB);
        const suffix = events.slice(this.#expected.length);
        if (this.#terminal !== undefined) this.#check(proofDB, suffix, true);
        else if (this.#pending !== undefined && suffix.length === 1) this.#check(proofDB, suffix);
        else this.#check(proofDB, []);
      })();
      proven = true;
    } catch { proven = false; }
    finally { try { db?.close(); } catch { proven = false; } }
    return proven;
  }
  #authDigest(): string {
    const own = this.#snapshot.events.filter(row => row.tool_call_id === this.#sealed.actionId);
    if (own.length !== 8) fail();
    return receiptDigest(AuthorizationReceiptSchema.parse(concreteEventDetails(own[5]!).receipt));
  }
  #acceptPending(): void {
    const events = this.#check(this.#source.database, [this.#pending!]);
    this.#expected = Object.freeze(events); this.#pending = undefined;
  }
  #check(db: AuditDatabase, extra: readonly (ProofRow | OwnedEvent)[], terminal = false): ProofRow[] {
    concreteDBIdentity(this.#source, this.#snapshot.parentIdentity, db);
    const events = concreteChain(db);
    if (events.length !== this.#expected.length + extra.length
      || canonicalJson(events.slice(0, this.#expected.length)) !== canonicalJson(this.#expected)) fail();
    const suffix = events.slice(this.#expected.length);
    if (!terminal) for (const row of suffix) {
      if (this.#pending === undefined || row.tool_call_id !== this.#sealed.actionId
        || row.event_type !== this.#pending.type || canonicalJson(concreteEventDetails(row)) !== canonicalJson(this.#pending.details)) fail();
    }
    const initialOwn = this.#snapshot.events.filter(row => row.tool_call_id === this.#sealed.actionId);
    if (initialOwn.length !== 8 || canonicalJson(initialOwn.map(row => row.event_type)) !== canonicalJson(AUTHORIZED_V2_EVENTS)) fail();
    const authDetails = concreteEventDetails(initialOwn[5]!);
    const auth = AuthorizationReceiptSchema.parse(authDetails.receipt);
    const prepared = this.#sealed.prepared, receipt = prepared.receipt, envelope = prepared.envelope;
    const expectedAction = { id: this.#sealed.actionId, adapter: receipt.adapter, adapterVersion: receipt.adapterVersion,
      operation: receipt.operation, identityAssurance: receipt.identityAssurance,
      intentDigest: 'sha256:' + digest({ format: 'apg-portable-intent-v1', adapter: receipt.adapter,
        adapterVersion: receipt.adapterVersion, operation: receipt.operation, material: receipt.identityMaterial }),
      subject: receipt.subject, executionPlanHash: receipt.executionPlanHash };
    if (canonicalJson(auth.action) !== canonicalJson(expectedAction) || auth.schema.minorVersion !== 2
      || auth.coverage.boundary !== 'graph_genesis_plan' || auth.authorization.status !== 'authorized'
      || canonicalJson(auth.policy) !== canonicalJson({ ...receipt.policy, matchedRuleId: 'graph_genesis_builtin_ask_v2' })
      || canonicalJson(auth.decision) !== canonicalJson({ base: 'ask', effective: 'ask', reasonCodes: [...GRAPH_GENESIS_POLICY.reasonCodes],
        riskScore: GRAPH_GENESIS_POLICY.score, riskBand: GRAPH_GENESIS_POLICY.band })
      || authDetails.receiptDigest !== receiptDigest(auth)
      || envelope.auditFileIdentityDigest !== this.#source.fileIdentityDigest
      || envelope.auditSchemaDigest !== this.#source.schemaDigest
      || envelope.auditDatabaseInstanceId !== this.#source.databaseInstanceId
      || envelope.auditDurabilityProfileDigest !== this.#source.durabilityProfileDigest
      || envelope.initialAuditChainTail !== this.#source.initialChainTail
      || concreteEventDetails(initialOwn[1]!).planHash !== prepared.plan.planHash
      || concreteEventDetails(initialOwn[1]!).executionEnvelopeHash !== envelope.executionEnvelopeHash
      || concreteEventDetails(initialOwn[7]!).approvalId !== this.#sealed.approvalId
      || concreteEventDetails(initialOwn[7]!).executionEnvelopeHash !== envelope.executionEnvelopeHash) fail();
    const approval = boundedProofRow(db, 'approvals', this.#sealed.approvalId);
    if (canonicalJson(approval) !== canonicalJson(this.#snapshot.approval) || approval.tool_call_id !== this.#sealed.actionId
      || approval.status !== 'approved' || auth.approval.requestId !== approval.id || auth.approval.outcome !== 'approved'
      || !auth.approval.required || auth.approval.principalAssurance !== 'local_dashboard_session'
      || auth.approval.requestedAt !== approval.requested_at || auth.approval.decidedAt !== approval.decided_at
      || auth.approval.expiresAt !== approval.expires_at) fail();
    const call = boundedProofRow(db, 'tool_calls', this.#sealed.actionId);
    const mutable = new Set(['status','completed_at','latency_ms','result_summary_json','error_code']);
    for (const key of Object.keys(this.#snapshot.call)) if (!mutable.has(key)
      && canonicalJson(call[key]) !== canonicalJson(this.#snapshot.call[key])) fail();
    const args = { executionEnvelopeHash: envelope.executionEnvelopeHash, planHash: prepared.plan.planHash };
    if (call.arguments_json !== canonicalJson(args) || call.server_id !== 'apg-graph-genesis' || call.tool_name !== 'filesystem_metadata_graph'
      || call.request_hash !== digest({ serverId: call.server_id, toolName: call.tool_name, arguments: args })) fail();
    const started = events.some(row => row.tool_call_id === this.#sealed.actionId && row.event_type === 'execution_start_recorded');
    if (!terminal) {
      if (call.status !== (started ? 'forwarding' : this.#snapshot.call.status) || call.completed_at !== this.#snapshot.call.completed_at
        || call.result_summary_json !== this.#snapshot.call.result_summary_json || call.error_code !== this.#snapshot.call.error_code) fail();
    } else {
      const expected = this.#terminal; if (expected === undefined || suffix.length !== 3) fail();
      if (canonicalJson(suffix.map(row => row.event_type)) !== canonicalJson(['graph_genesis_incomplete','execution_completed','outcome_receipt_finalized'])
        || suffix.some(row => row.tool_call_id !== this.#sealed.actionId)) fail();
      const outcomeDetails = concreteEventDetails(suffix[2]!);
      const outcome = OutcomeReceiptSchema.parse(outcomeDetails.receipt);
      const start = events.find(row => row.tool_call_id === this.#sealed.actionId && row.event_type === 'execution_start_recorded');
      if (start === undefined || concreteEventDetails(start).receiptDigest !== receiptDigest(auth)) fail();
      const summary = expected.summary;
      const observed = { kind: 'graph_genesis', isError: true, externalReadStatus: summary.metadata.externalReadStatus,
        metadataRequestCount: summary.metadata.requestCount, metadataUniquePackageCount: summary.metadata.uniquePackageCount,
        metadataResponseBytes: summary.metadata.responseBytes, executionStatus: summary.process.status, exitCode: summary.process.exitCode,
        stdoutBytes: summary.process.stdoutBytes, stderrBytes: summary.process.stderrBytes,
        cleanupStatus: summary.cleanup.status, terminalAuditStatus: summary.terminalAudit.status, errorCode: summary.errorCode };
      if (canonicalJson(concreteEventDetails(suffix[1]!)) !== canonicalJson(summary)
        || call.status !== expected.status || call.result_summary_json !== canonicalJson(summary) || call.error_code !== summary.errorCode
        || outcome.schema.minorVersion !== 2
        || canonicalJson(outcome.action) !== canonicalJson(auth.action) || canonicalJson(outcome.coverage) !== canonicalJson(auth.coverage)
        || outcome.authorizationReceiptDigest !== receiptDigest(auth) || outcomeDetails.receiptDigest !== receiptDigest(outcome)
        || outcome.execution.terminalStatus !== expected.status || outcome.execution.completedAt !== call.completed_at
        || outcome.receipt.issuedAt !== call.completed_at || outcome.execution.startedAt < auth.receipt.issuedAt
        || outcome.execution.startedAt > String(start.created_at)
        || canonicalJson(outcome.execution.observedResult) !== canonicalJson(observed)
        || canonicalJson(concreteEventDetails(suffix[0]!)) !== canonicalJson({ executionPlanHash: envelope.executionEnvelopeHash,
          terminalStatus: expected.status, outcomeReceiptDigest: receiptDigest(outcome) })) fail();
    }
    concreteDBIdentity(this.#source, this.#snapshot.parentIdentity, db);
    return events;
  }
}


type ConcreteFailure = 'cancelled' | 'deadline' | 'clock_invalid' | 'audit_invalid' | 'spawn_failed'
  | 'process_error' | 'output_overflow' | 'listener_failed' | 'revalidation_failed' | 'completion_unavailable';
type ConcretePhase = 'reserved' | 'validated' | 'started' | 'armed' | 'spawn-intent' | 'running' | 'stopping' | 'terminal';

class SessionOwnedDormantConcreteExecution {
  readonly #sealed: OwnedSealedAuthorization;
  readonly #prepared: OwnedPreparedProduction;
  readonly #snapshots: ProductionGraphGenesisV2SnapshotAuthority;
  readonly #listener: OwnedConcreteV2Listener;
  readonly #context: OwnedSessionContext;
  readonly #output: OwnedOutputIntent;
  readonly #active: () => boolean;
  readonly #journal: ConcreteAuditJournal;
  readonly #abort = new AbortController();
  readonly #dispose: Array<() => void> = [];
  readonly #wake: Promise<void>;
  #wakeResolve!: () => void;
  readonly #closed: Promise<void>;
  #closeResolve!: () => void;
  #phase: ConcretePhase = 'reserved';
  #claimed = false;
  #result: Promise<DormantV2ConcreteTerminalProof> | undefined;
  #failure: ConcreteFailure | undefined;
  #startReturned = false;
  #startUncertain = false;
  #childAttempted = false;
  #child: ChildProcess | undefined;
  #childCreated = false;
  #childCloseObserved = false;
  #exitCode: number | null = null;
  #stdoutBytes = 0;
  #stderrBytes = 0;
  #stop: Promise<boolean> | undefined;
  #lastNow: number;
  #executionTimer: ReturnType<typeof setTimeout> | undefined;
  readonly #pendingReads = new Set<Promise<unknown>>();

  constructor(token: symbol, sealed: OwnedSealedAuthorization, prepared: OwnedPreparedProduction,
    snapshots: ProductionGraphGenesisV2SnapshotAuthority, context: OwnedSessionContext,
    output: OwnedOutputIntent, active: () => boolean) {
    if (token !== CONCRETE_OWNER || prepared.originalListener === undefined
      || prepared.originalListener.state !== 'disarmed' || prepared.prepared !== sealed.prepared
      || sealed.privateExecution !== prepared.privateExecution) fail();
    this.#sealed = sealed; this.#prepared = prepared; this.#snapshots = snapshots;
    this.#listener = prepared.originalListener; this.#context = context; this.#output = output; this.#active = active;
    this.#journal = new ConcreteAuditJournal(CONCRETE_OWNER, sealed, context);
    this.#lastNow = sealed.sealedAtMonotonicMs;
    this.#wake = new Promise(resolve => { this.#wakeResolve = resolve; });
    this.#closed = new Promise(resolve => { this.#closeResolve = resolve; });
    for (const signal of [context.controller.signal, output.controller.signal, sealed.callerSignal, this.#listener.controller.signal]) {
      if (signal === undefined) continue;
      const abort = () => this.#latch('cancelled');
      signal.addEventListener('abort', abort, { once: true });
      this.#dispose.push(() => signal.removeEventListener('abort', abort));
      if (signal.aborted) this.#latch('cancelled');
    }
    this.#listener.executionOwned = true;
    if (this.#listener.lifetime !== undefined) clearTimeout(this.#listener.lifetime);
    Object.freeze(this);
  }

  execute(): Promise<DormantV2ConcreteTerminalProof> {
    if (arguments.length !== 0 || this.#claimed) return Promise.reject(new Error('graph_genesis_v2_production_invalid'));
    // Claim before the first await; duplicate calls cannot start or finalize a second run.
    this.#claimed = true;
    this.#result = this.#run();
    return this.#result;
  }
  stopForRevocation(token: symbol): Promise<DormantV2ConcreteTerminalProof> {
    if (token !== CONCRETE_OWNER) fail();
    this.#latch('cancelled');
    if (!this.#claimed) { this.#claimed = true; this.#result = this.#run(); }
    return this.#result!;
  }
  custodyDrained(token: symbol): Promise<unknown> {
    if (token !== CONCRETE_OWNER) fail();
    return Promise.allSettled([...this.#pendingReads]);
  }

  async #run(): Promise<DormantV2ConcreteTerminalProof> {
    try {
      await this.#revalidateBeforeSpawn();
      this.#phase = 'validated';
      try { this.#journal.start(); this.#startReturned = true; }
      catch { this.#startUncertain = true; this.#latch('audit_invalid'); throw new Error('graph_genesis_v2_production_invalid'); }
      this.#phase = 'started';
      this.#fence(true);
      this.#journal.append('graph_genesis_v2_broker_arm_intent', { listenerIdentityDigest: this.#listener.identityDigest });
      this.#fence(true);
      if (this.#phase !== 'started' || this.#listener.state !== 'disarmed') fail();
      this.#listener.state = 'armed'; this.#phase = 'armed';
      this.#journal.append('graph_genesis_v2_broker_armed', { listenerIdentityDigest: this.#listener.identityDigest });
      await this.#revalidateBeforeSpawn();
      this.#journal.append('graph_genesis_v2_spawn_intent', { launchDigest: this.#sealed.privateExecution.launch.launchDigest });
      this.#fence(true);
      if (this.#phase !== 'armed') fail();
      this.#phase = 'spawn-intent'; this.#childAttempted = true;
      const launch = this.#sealed.privateExecution.launch;
      try {
        // No public launch parameters. This exact object was retained in the authenticated private capsule.
        this.#child = spawn(launch.executable, launch.args, {
          cwd: launch.cwd, env: { ...launch.env }, shell: false, stdio: ['ignore', 'pipe', 'pipe'], detached: false,
        });
      } catch { this.#latch('spawn_failed'); throw new Error('graph_genesis_v2_production_invalid'); }
      this.#observeChild(this.#child);
      this.#phase = 'running';
      if (this.#failure !== undefined) this.#wakeResolve();
      else {
        const now = this.#fence(false);
        this.#executionTimer = setTimeout(() => this.#latch('deadline'), Math.max(1, this.#sealed.executionDeadlineMonotonicMs - now));
      }
      await this.#wake;
      if (this.#failure === undefined) {
        // Initial empty-workspace/probe validation is deliberately not used after the child.
        await this.#revalidateAfterChild();
        this.#latch('completion_unavailable');
      }
    } catch { this.#latch('revalidation_failed'); }

    const drained = await this.#stopAndDrain();
    let status: DormantV2ConcreteTerminalProof['terminalStatus'] =
      this.#startReturned && (!this.#child || this.#childCloseObserved) && drained
        ? 'execution_error' : 'outcome_unknown_after_interruption';
    const summary = Object.freeze<GraphGenesisExecutionSummary>({
      metadata: { externalReadStatus: 'not_started', requestCount: 0, uniquePackageCount: 0, responseBytes: 0 },
      process: { status: this.#failure === 'deadline' ? 'timed_out' : this.#failure === 'cancelled' ? 'cancelled'
        : this.#failure === 'output_overflow' ? 'output_overflow'
        : this.#childCreated && this.#childCloseObserved && this.#exitCode === 0 ? 'completed' : 'failed',
        exitCode: this.#childCloseObserved ? this.#exitCode : null, stdoutBytes: this.#stdoutBytes, stderrBytes: this.#stderrBytes },
      cleanup: { status: 'incomplete' }, terminalAudit: { status: 'unknown' },
      errorCode: 'graph_genesis_v2_' + (this.#failure ?? 'completion_unavailable'),
    });
    // Uncertain start is reconcile-only, even if SQLite actually committed it.
    if (this.#startReturned && !this.#startUncertain) {
      try { this.#journal.finalize(summary, status); }
      catch { /* one attempt only; exact committed receipt may still be independently proven */ }
    }
    const journalProven = this.#journal.reconcile(this.#startReturned);
    const proven = journalProven && this.#pendingReads.size === 0;
    if (!proven || !this.#startReturned || this.#startUncertain) status = 'outcome_unknown_after_interruption';
    this.#phase = 'terminal';
    if (this.#executionTimer !== undefined) clearTimeout(this.#executionTimer);
    for (const dispose of this.#dispose.splice(0)) dispose();
    return Object.freeze({
      terminalStatus: status, actionId: this.#sealed.actionId, childAttempted: this.#childAttempted,
      childCreated: this.#childCreated, childCloseObserved: this.#childCloseObserved,
      exitCode: this.#childCloseObserved ? this.#exitCode : null, stdoutBytes: this.#stdoutBytes, stderrBytes: this.#stderrBytes,
      listenerClosed: drained, reconciliation: proven ? 'proven' : 'unknown',
    });
  }

  #latch(code: ConcreteFailure): void {
    if (this.#failure !== undefined || this.#phase === 'terminal') return;
    this.#failure = code; this.#abort.abort();
    // Revoke the output capability now; its descriptor and namespace remain under session custody until settlement.
    this.#output.controller.abort();
    this.#wakeResolve();
  }
  #fence(startWindow: boolean): number {
    const now = performance.now();
    if (!Number.isFinite(now) || Object.is(now, -0) || now < 0 || now > Number.MAX_SAFE_INTEGER || now < this.#lastNow) {
      this.#latch('clock_invalid'); fail();
    }
    this.#lastNow = now;
    if (now >= this.#sealed.executionDeadlineMonotonicMs || (startWindow && now >= this.#sealed.startByMonotonicMs)) {
      this.#latch('deadline'); fail();
    }
    if (this.#failure !== undefined || this.#abort.signal.aborted || !this.#active()
      || this.#sealed.callerSignal?.aborted || this.#context.controller.signal.aborted || this.#output.controller.signal.aborted) {
      this.#latch('cancelled'); fail();
    }
    return now;
  }
  async #revalidateBeforeSpawn(): Promise<void> {
    this.#fence(true); this.#journal.verify();
    const execution = this.#sealed.privateExecution, prepared = this.#sealed.prepared;
    if (execution !== this.#prepared.privateExecution || digest(execution) !== prepared.plan.executionCapsuleDigest
      || execution.launch.launchDigest !== prepared.plan.launchDigest || digest(execution.launch.env) !== prepared.plan.environmentDigest
      || execution.originalListenerIdentityDigest !== this.#listener.identityDigest
      || prepared.plan.brokerPort !== this.#listener.port) fail();
    const operation = this.#snapshots.revalidate(this.#prepared.snapshot, {
      signal: this.#abort.signal, monotonicNow: () => this.#fence(true), deadline: this.#sealed.startByMonotonicMs,
    });
    await this.#read(operation, this.#sealed.startByMonotonicMs);
    this.#fence(true);
    await this.#read(concreteOutputParent(this.#output), this.#sealed.startByMonotonicMs);
    this.#fence(true);
    await this.#read(assertAbsentV2(this.#output.canonicalPath), this.#sealed.startByMonotonicMs);
    this.#fence(true);
    this.#journal.verify();
  }
  async #revalidateAfterChild(): Promise<void> {
    this.#fence(false);
    await this.#read(this.#snapshots.revalidateConcreteImmutable(CONCRETE_OWNER, this.#prepared.snapshot, {
      signal: this.#abort.signal, monotonicNow: () => this.#fence(false), deadline: this.#sealed.executionDeadlineMonotonicMs,
    }), this.#sealed.executionDeadlineMonotonicMs);
    this.#fence(false);
    await this.#read(concreteOutputParent(this.#output), this.#sealed.executionDeadlineMonotonicMs);
    this.#fence(false);
    this.#journal.verify();
  }
  #read<T>(operation: Promise<T>, deadline: number): Promise<T> {
    this.#pendingReads.add(operation);
    // Cancellation fences forward progress; it cannot cancel an already-issued Node fs read.
    void operation.then(() => this.#pendingReads.delete(operation), () => this.#pendingReads.delete(operation));
    return concreteAwait(operation, deadline, this.#abort.signal);
  }
  #observeChild(child: ChildProcess): void {
    child.once('spawn', () => { this.#childCreated = true; });
    child.on('error', () => this.#latch('process_error'));
    const count = (stream: 'stdout' | 'stderr', chunk: Buffer | string) => {
      if (this.#phase === 'terminal') return;
      const bytes = typeof chunk === 'string' ? Buffer.byteLength(chunk) : chunk.byteLength;
      const maximum = stream === 'stdout' ? this.#sealed.prepared.plan.limits.stdoutBytes : this.#sealed.prepared.plan.limits.stderrBytes;
      const total = (stream === 'stdout' ? this.#stdoutBytes : this.#stderrBytes) + bytes;
      if (stream === 'stdout') this.#stdoutBytes = Math.min(total, maximum); else this.#stderrBytes = Math.min(total, maximum);
      if (total > maximum) this.#latch('output_overflow');
    };
    child.stdout?.on('data', chunk => count('stdout', chunk));
    child.stderr?.on('data', chunk => count('stderr', chunk));
    child.once('close', (exitCode: number | null) => {
      if (this.#childCloseObserved || this.#phase === 'terminal') return;
      this.#childCloseObserved = true;
      this.#exitCode = Number.isInteger(exitCode) ? exitCode : null;
      if (!this.#childCreated || exitCode !== 0) this.#latch('process_error');
      this.#closeResolve(); this.#wakeResolve();
    });
  }
  #stopAndDrain(): Promise<boolean> {
    if (this.#stop !== undefined) return this.#stop;
    this.#phase = 'stopping';
    if (this.#executionTimer !== undefined) clearTimeout(this.#executionTimer);
    const stopAt = performance.now();
    // The grace window is for observation only; it never reopens forward execution.
    const stopDeadline = Number.isFinite(stopAt) && stopAt >= 0 ? stopAt + 5_000 : 5_000;
    this.#stop = (async () => {
      let killTimer: ReturnType<typeof setTimeout> | undefined;
      const child = this.#child;
      if (child !== undefined && !this.#childCloseObserved) {
        try { child.kill('SIGTERM'); } catch { /* retain missing-close uncertainty */ }
        killTimer = setTimeout(() => {
          if (!this.#childCloseObserved) try { child.kill('SIGKILL'); } catch { /* observed failure remains unknown */ }
        }, 2_000);
      }
      const drain = closeOriginalListener(this.#listener, stopDeadline);
      if (child !== undefined && !this.#childCloseObserved) await concreteSettlesWithin(this.#closed, 4_000);
      if (killTimer !== undefined) clearTimeout(killTimer);
      return await drain;
    })();
    return this.#stop;
  }
}

class SessionOwnedDormantMockedExecution {
  readonly #completion: SessionOwnedSyntheticCompletion;
  #terminal = false;

  constructor(token: symbol, completion: SessionOwnedSyntheticCompletion) {
    if (token !== COMPLETION_OWNER) fail();
    this.#completion = completion;
    Object.freeze(this);
  }

  async execute(): Promise<DormantV2MockedTerminalProof> {
    if (this.#terminal) fail();
    try {
      const now = (): number => performance.now();
      const run = this.#completion.issueSyntheticQuiescedRun(now);
      const postState = await this.#completion.captureSyntheticPostState(run, now);
      const artifact = this.#completion.compileSyntheticArtifact(run, postState, now);
      const reservation = await this.#completion.reserveOutput(run, now);
      const output = await this.#completion.writeReservedArtifact(run, reservation, artifact, now);
      const proof = this.#completion.finalizeSyntheticIncomplete(run, output, now);
      this.#terminal = true;
      return Object.freeze({ evidenceOrigin: proof.evidenceOrigin, terminalStatus: proof.terminalStatus,
        actionId: proof.actionId, artifactDigest: proof.artifactDigest });
    } catch (error) {
      this.#terminal = true;
      throw error;
    }
  }
}

function proofIdentity(info: ReturnType<typeof lstatSync>): string {
  if (info === undefined) fail();
  return digest({ device: info.dev, inode: info.ino, owner: info.uid, mode: Number(info.mode) & 0o7777 });
}
function proofFileIdentity(info: ReturnType<typeof lstatSync>): string {
  if (info === undefined) fail();
  return digest({ identity: proofIdentity(info), size: info.size, nlink: info.nlink, mtimeMs: info.mtimeMs, ctimeMs: info.ctimeMs });
}
function proofRecord(value: unknown): ProofRow {
  if (!object(value) || Array.isArray(value)) fail(); return value as ProofRow;
}
function proofJson(value: unknown): unknown {
  if (typeof value !== 'string' || Buffer.byteLength(value) > 512 * 1024) fail();
  return parseStrictJsonDocument(value);
}
function boundedProofEvents(db: AuditDatabase): ProofRow[] {
  const count = db.prepare('SELECT count(*) FROM (SELECT 1 FROM audit_events LIMIT 16385)').pluck().get();
  if (typeof count !== 'number' || count > 16384) fail();
  const fields = ['event_id','tool_call_id','event_type','event_json','previous_hash','event_hash','created_at'];
  const rowBytes = fields.map((field) => 'coalesce(length(CAST(' + field + ' AS BLOB)),0)').join('+');
  const limits = db.prepare('SELECT count(*) AS n, coalesce(sum(' + rowBytes + '),0) AS bytes, coalesce(max(' + rowBytes + '),0) AS largest FROM audit_events').get() as { n: number; bytes: number; largest: number };
  if (limits.n > 16384 || limits.bytes > 16 * MiB || limits.largest > 512 * 1024) fail();
  return db.prepare('SELECT sequence,event_id,tool_call_id,event_type,event_json,previous_hash,event_hash,created_at FROM audit_events ORDER BY sequence LIMIT 16385').all() as ProofRow[];
}
function boundedProofRow(db: AuditDatabase, table: 'tool_calls' | 'approvals', id: string): ProofRow {
  const columns = table === 'tool_calls'
    ? ['id','server_id','tool_name','arguments_json','request_hash','base_decision','effective_decision','matched_rule_id','reason_codes_json','risk_signals_json','risk_band','status','started_at','completed_at','result_summary_json','error_code']
    : ['id','tool_call_id','status','requested_at','expires_at','decided_at'];
  const size = db.prepare('SELECT ' + columns.map((column) => 'coalesce(length(CAST(' + column + ' AS BLOB)),0)').join('+') + ' AS bytes FROM ' + table + ' WHERE id=?').get(id) as {bytes: number} | undefined;
  if (size === undefined || size.bytes > 512 * 1024) fail();
  return proofRecord(db.prepare('SELECT * FROM ' + table + ' WHERE id=?').get(id));
}


/** Lexical construction owner; no public path, callback, clock or proof creates this capability. */
class OwnedConcretePreparation {
  readonly #root: PreparedGraphGenesisV2ConcreteRoot;
  readonly #seed: AuthenticatedGraphGenesisV2RuntimeSeed;
  readonly #runtime: GraphGenesisV2RuntimeSeedInput;
  readonly #context: OwnedSessionContext;
  readonly #output: OwnedOutputIntent;
  readonly #listener: OwnedConcreteV2Listener;
  readonly #controller = new AbortController();
  readonly #pending = new Set<Promise<unknown>>();
  readonly #dispose: Array<() => void> = [];
  readonly #destination: string;
  #lastNow: number;
  #revoked = false;
  #preparing = true;
  #association: Readonly<{ snapshot: AuthenticatedGraphGenesisV2ProductionSnapshot; bundle: OwnedProductionBundle }> | undefined;

  constructor(token: symbol, root: PreparedGraphGenesisV2ConcreteRoot, seed: AuthenticatedGraphGenesisV2RuntimeSeed,
    runtime: GraphGenesisV2RuntimeSeedInput, context: OwnedSessionContext, output: OwnedOutputIntent,
    listener: OwnedConcreteV2Listener, destination: string) {
    if (token !== CONCRETE_OWNER || listener.context !== context || destination !== join(output.parentCanonicalPath, CONCRETE_WORKSPACE_NAME)) fail();
    this.#root = root; this.#seed = seed; this.#runtime = runtime; this.#context = context;
    this.#output = output; this.#listener = listener; this.#destination = destination; this.#lastNow = listener.lastNow;
    for (const signal of [context.controller.signal, output.controller.signal, listener.controller.signal]) {
      const revoke = () => this.revoke(CONCRETE_OWNER);
      signal.addEventListener('abort', revoke, { once: true });
      this.#dispose.push(() => signal.removeEventListener('abort', revoke));
      if (signal.aborted) this.#revoked = true;
    }
    if (this.#revoked) this.#controller.abort();
    Object.freeze(this);
  }
  runtime(token: symbol): GraphGenesisV2RuntimeSeedInput { this.#token(token); return this.#runtime; }
  destination(token: symbol): string { this.#token(token); return this.#destination; }
  port(token: symbol): number { this.#token(token); return this.#listener.port; }
  signal(token: symbol): AbortSignal { this.#token(token); return this.#controller.signal; }
  checkpoint(token: symbol): void {
    this.#token(token);
    const now = performance.now();
    if (this.#revoked || this.#controller.signal.aborted || this.#context.controller.signal.aborted
      || this.#output.controller.signal.aborted || this.#listener.controller.signal.aborted || this.#listener.state !== 'disarmed'
      || !Number.isFinite(now) || Object.is(now, -0) || now < 0 || now > Number.MAX_SAFE_INTEGER
      || now < this.#lastNow || now >= this.#listener.deadline
      || (this.#preparing && !revalidatesExistingGraphGenesisAuditDatabase(this.#context.source))) { this.revoke(token); fail(); }
    this.#lastNow = now; this.#listener.lastNow = now;
  }
  async step<T>(token: symbol, operation: () => Promise<T>): Promise<T> {
    this.checkpoint(token);
    // Register the operation synchronously; rejection is observed even after the public await has been cancelled.
    const promise = operation();
    this.#pending.add(promise);
    void promise.then(() => this.#pending.delete(promise), () => this.#pending.delete(promise));
    const result = await concreteAwait(promise, this.#listener.deadline, this.#controller.signal);
    this.checkpoint(token); return result;
  }
  async checkParent(token: symbol): Promise<void> {
    await this.step(token, () => concreteOutputParent(this.#output));
  }
  async checkDestination(token: symbol): Promise<void> {
    await this.checkParent(token);
    const protectedPaths = [
      ...FILE_KEYS.map(key => this.#runtime.files[key].absolutePath),
      ...TREE_KEYS.map(key => this.#runtime.trees[key].rootRealpath),
      this.#context.source.canonicalPath, this.#output.canonicalPath,
    ];
    if (protectedPaths.some(path => pathsOverlapConcrete(this.#destination, path))) fail();
    await this.step(token, () => assertAbsentV2(this.#destination));
    await this.step(token, () => assertAbsentV2(this.#output.canonicalPath));
    await this.checkParent(token);
  }
  associate(token: symbol, snapshot: AuthenticatedGraphGenesisV2ProductionSnapshot, bundle: OwnedProductionBundle): void {
    this.checkpoint(token);
    if (this.#association !== undefined || bundle.workspace.rootRealpath !== this.#destination
      || bundle.containmentProfile.allowedPort !== this.#listener.port || snapshotBundles.get(snapshot) !== bundle) fail();
    this.#association = Object.freeze({ snapshot, bundle });
  }
  matches(token: symbol, snapshot: AuthenticatedGraphGenesisV2ProductionSnapshot, listener: OwnedConcreteV2Listener,
    context: OwnedSessionContext, output: OwnedOutputIntent): boolean {
    this.#token(token);
    const association = this.#association;
    return !this.#revoked && !this.#controller.signal.aborted && !context.controller.signal.aborted
      && !output.controller.signal.aborted && !listener.controller.signal.aborted
      && this.#listener === listener && this.#context === context && this.#output === output
      && this.#root.brokerPort === listener.port && object(this.#seed) && association?.snapshot === snapshot
      && snapshotBundles.get(snapshot) === association.bundle
      && association.bundle.workspace.rootRealpath === this.#destination
      && association.bundle.containmentProfile.allowedPort === listener.port;
  }
  revoke(token: symbol): void {
    this.#token(token);
    if (this.#revoked) return;
    this.#revoked = true; this.#controller.abort(); this.#association = undefined;
    for (const dispose of this.#dispose.splice(0)) dispose();
    this.#output.controller.abort(); this.#listener.controller.abort();
    if (!this.#listener.executionOwned) void closeOriginalListener(this.#listener, performance.now() + 5_000);
  }
  custodyDrained(token: symbol): Promise<unknown> {
    this.#token(token); return Promise.allSettled([...this.#pending]);
  }
  prepared(token: symbol): void {
    this.checkpoint(token);
    if (this.#association === undefined || !this.#preparing) fail();
    this.#preparing = false;
  }
  #token(token: symbol): void { if (token !== CONCRETE_OWNER) fail(); }
}
function pathsOverlapConcrete(left: string, right: string): boolean {
  const nested = (parent: string, child: string) => {
    const part = relative(parent, child);
    return part === '' || (!part.startsWith('..' + sep) && part !== '..' && !part.startsWith(sep));
  };
  return nested(left, right) || nested(right, left);
}

/** Production-only bridge: it has no raw-digest capture API. */
export class ProductionGraphGenesisV2SnapshotAuthority {
  readonly #owned = new WeakMap<object, OwnedProductionBundle>();
  readonly #runtimeSeeds = new WeakMap<object, GraphGenesisV2RuntimeSeedInput>();
  readonly #claimedSeeds = new WeakSet<object>();

  constructor(
    private readonly files: RuntimeFileSnapshotAuthority,
    private readonly trees: RuntimeTreeSnapshotAuthority,
    private readonly versions: OwnedRuntimeVersionAuthority,
    private readonly hosts: OwnedHostPlatformAuthority,
    private readonly workspaces: FinalizedGraphGenesisWorkspaceAuthority,
    private readonly containment: OwnedContainmentProbeAuthority,
    private readonly profiles: SeatbeltLoopbackContainmentAuthority,
  ) {}


  captureConcreteRuntimeSeed(input: GraphGenesisV2RuntimeSeedInput): AuthenticatedGraphGenesisV2RuntimeSeed {
    try {
      const top = closedRecord(input, ['files', 'trees', 'host', 'runtimeVersions'] as const);
      const runtime = Object.freeze({
        files: closedRecord(top.files, FILE_KEYS) as GraphGenesisV2RuntimeSeedInput['files'],
        trees: closedRecord(top.trees, TREE_KEYS) as GraphGenesisV2RuntimeSeedInput['trees'],
        host: top.host as AuthenticatedHostPlatformEvidence,
        runtimeVersions: top.runtimeVersions as AuthenticatedRuntimeVersionEvidence,
      });
      this.#assertRuntimeSeed(runtime);
      const seed = Object.freeze({ runtimeSeedVersion: 1 as const });
      this.#runtimeSeeds.set(seed, runtime);
      return seed;
    } catch { fail(); }
  }

  claimConcreteRuntimeSeed(token: symbol, seed: AuthenticatedGraphGenesisV2RuntimeSeed): GraphGenesisV2RuntimeSeedInput {
    if (token !== CONCRETE_OWNER) fail();
    const runtime = this.#runtimeSeeds.get(seed);
    if (runtime === undefined || this.#claimedSeeds.has(seed)) fail();
    this.#assertRuntimeSeed(runtime);
    this.#claimedSeeds.add(seed);
    return runtime;
  }

  async constructConcreteSnapshot(token: symbol, construction: OwnedConcretePreparation): Promise<AuthenticatedGraphGenesisV2ProductionSnapshot> {
    if (token !== CONCRETE_OWNER || !(construction instanceof OwnedConcretePreparation)) fail();
    const runtime = construction.runtime(token);
    const step = <T>(operation: () => Promise<T>) => construction.step(token, operation);
    this.#assertRuntimeSeed(runtime);
    await construction.checkDestination(token);
    for (const key of FILE_KEYS) await step(() => this.files.revalidate(runtime.files[key]));
    for (const key of TREE_KEYS) await step(() => this.trees.revalidate(runtime.trees[key]));
    const host = await step(() => this.hosts.observe());
    if (host.evidenceDigest !== runtime.host.evidenceDigest) fail();
    const versions = await step(() => this.versions.observe({
      node: runtime.files.node, npmCli: runtime.files.npmCli, npmTree: runtime.trees.npmTree,
    }));
    if (versions.evidenceDigest !== runtime.runtimeVersions.evidenceDigest) fail();
    await construction.checkDestination(token);
    construction.checkpoint(token);
    const profile = this.profiles.prepare({
      osBuild: runtime.host.osBuild, sandboxExecSha256: runtime.files.sandboxExec.sha256,
      allowedPort: construction.port(token),
    });
    construction.checkpoint(token);
    const workspace = await step(() => this.workspaces.initialize(construction.destination(token), profile.profileText));
    await construction.checkParent(token);
    const containment = await step(() => this.containment.observe({
      osBuild: runtime.host.osBuild, hostEvidenceDigest: runtime.host.evidenceDigest,
      nodeSnapshotDigest: runtime.files.node.snapshotDigest, probeSnapshotDigest: runtime.files.probeRuntime.snapshotDigest,
      sandboxExecSnapshotDigest: runtime.files.sandboxExec.snapshotDigest, workspaceBinding: computeWorkspaceBinding(workspace),
      profileDigest: profile.profileDigest, allowedPort: construction.port(token),
    }, profile, { node: runtime.files.node, probe: runtime.files.probeRuntime, sandboxExec: runtime.files.sandboxExec, workspace }));
    await construction.checkParent(token);
    construction.checkpoint(token);
    const snapshot = this.prepare({ ...runtime, workspace, containmentProfile: profile, containment });
    const bundle = this.#owned.get(snapshot); if (bundle === undefined) fail();
    construction.associate(token, snapshot, bundle);
    return snapshot;
  }

  #assertRuntimeSeed(runtime: GraphGenesisV2RuntimeSeedInput): void {
    assertFileOwnership(this.files, runtime.files);
    assertTreeOwnership(this.trees, runtime.trees);
    assertDistinctRoles(runtime);
    if (!this.hosts.authenticates(runtime.host, 'local_observed')
      || !this.versions.authenticates(runtime.runtimeVersions, 'local_observed')) fail();
    assertStructuralRelationships(runtime);
    if (runtime.runtimeVersions.nodeSnapshotDigest !== runtime.files.node.snapshotDigest
      || runtime.runtimeVersions.npmCliSnapshotDigest !== runtime.files.npmCli.snapshotDigest
      || runtime.runtimeVersions.npmTreeDigest !== runtime.trees.npmTree.treeDigest) fail();
  }

  prepare(input: GraphGenesisV2ConcreteProductionBundle): AuthenticatedGraphGenesisV2ProductionSnapshot {
    try {
      const owned = ownClosedBundle(input);
      this.#assertOwnedRelationships(owned);
      const snapshots = createManifest(owned);
      const identity = Object.freeze({
        runtimeManifestVersion: 2 as const,
        snapshots,
        hostEvidenceDigest: owned.host.evidenceDigest,
        runtimeVersionEvidenceDigest: owned.runtimeVersions.evidenceDigest,
        workspaceBinding: computeWorkspaceBinding(owned.workspace),
        containmentProfileDigest: owned.containmentProfile.profileDigest,
        containmentEvidenceDigest: owned.containment.evidenceDigest,
      });
      const snapshot = Object.freeze({
        snapshotVersion: 1 as const,
        ...identity,
        runtimeManifestDigest: digest(identity),
      });
      this.#owned.set(snapshot, owned);
      snapshotBundles.set(snapshot, owned);
      return snapshot;
    } catch {
      fail();
    }
  }

  authenticates(value: unknown): value is AuthenticatedGraphGenesisV2ProductionSnapshot {
    return object(value) && this.#owned.has(value);
  }

  /** Token-gated post-child identity check; mutable npm output is not an initial-empty workspace. */
  async revalidateConcreteImmutable(token: symbol, value: AuthenticatedGraphGenesisV2ProductionSnapshot,
    options: GraphGenesisV2RevalidationOptions): Promise<void> {
    if (token !== CONCRETE_OWNER) fail();
    const owned = this.#owned.get(value); if (owned === undefined) fail();
    const guarded = createGuardedAwait(options);
    for (const key of FILE_KEYS) await guarded(() => this.files.revalidate(owned.files[key]));
    for (const key of TREE_KEYS) await guarded(() => this.trees.revalidate(owned.trees[key]));
    await guarded(async () => concreteProtected(owned.workspace));
  }

  async revalidate(
    value: AuthenticatedGraphGenesisV2ProductionSnapshot,
    options: GraphGenesisV2RevalidationOptions,
  ): Promise<void> {
    try {
      const owned = this.#owned.get(value);
      if (owned === undefined) fail();
      const guarded = createGuardedAwait(options);

      for (const key of FILE_KEYS) {
        await guarded(() => this.files.revalidate(owned.files[key]));
      }
      for (const key of TREE_KEYS) {
        await guarded(() => this.trees.revalidate(owned.trees[key]));
      }
      await guarded(() => this.workspaces.revalidateInitial(owned.workspace));

      const host = await guarded(() => this.hosts.observe());
      if (host.evidenceDigest !== owned.host.evidenceDigest) fail();

      const runtimeVersions = await guarded(() => this.versions.observe({
        node: owned.files.node,
        npmCli: owned.files.npmCli,
        npmTree: owned.trees.npmTree,
      }));
      if (runtimeVersions.evidenceDigest !== owned.runtimeVersions.evidenceDigest) fail();

      const containment = await guarded(() => this.containment.observe(
        owned.containment.binding,
        owned.containmentProfile,
        {
          node: owned.files.node,
          probe: owned.files.probeRuntime,
          sandboxExec: owned.files.sandboxExec,
          workspace: owned.workspace,
        },
      ));
      if (containment.evidenceDigest !== owned.containment.evidenceDigest) fail();
      this.#assertOwnedRelationships(Object.freeze({
        ...owned,
        host,
        runtimeVersions,
        containment,
      }));
    } catch {
      fail();
    }
  }

  #assertOwnedRelationships(input: OwnedProductionBundle): void {
    assertFileOwnership(this.files, input.files);
    assertTreeOwnership(this.trees, input.trees);
    assertDistinctRoles(input);
    if (!this.versions.authenticates(input.runtimeVersions, 'local_observed')
      || !this.hosts.authenticates(input.host, 'local_observed')
      || !this.workspaces.authenticates(input.workspace)
      || !this.profiles.authenticatesProfile(input.containmentProfile)
      || !this.containment.authenticates(input.containment, 'local_observed')) fail();
    assertStructuralRelationships(input);
    assertEvidenceRelationships(input);
  }
}

export type GraphGenesisV2ApprovalView = Readonly<{
  approvalIdentityVersion: 2;
  target: '@modelcontextprotocol/server-filesystem@2026.7.10';
  registryOrigin: 'https://registry.npmjs.org/';
  executionEnvelopeHash: string;
  planHash: string;
  projectionDigest: string;
  runtimeManifestDigest: string;
  candidateSchemaVersion: 2;
  peerSemanticsVersion: 1;
  compilationContractVersion: 1;
  semanticContractDigest: string;
  compilationContractDigest: string;
  maxCandidateOutputs: 1;
  effect: 'metadata_only_lock_only_local';
  containment: 'development_only';
  host: Readonly<{ platform: 'darwin'; architecture: 'arm64'; osBuild: string }>;
  runtime: Readonly<{ nodeVersion: '26.3.1'; npmVersion: '11.16.0' }>;
  auditPath: string;
  outputPath: string;
  limits: GraphGenesisLimits;
  consequences: readonly string[];
  exclusions: readonly string[];
  bypassWarning: 'Direct npm/npx commands bypass APG and receive none of this protection or evidence.';
}>;

/**
 * Dormant session bridge for production composition.
 *
 * The bridge deliberately exposes no raw session factories. It authenticates a
 * caller-owned existing audit database, owns the local approval/Dashboard
 * channel and output-parent descriptor, and can mint only a same-authority
 * memory-only seal. Only the explicitly synthetic dormant continuation can
 * create fixture artifacts; production execution consumers remain unavailable.
 */
export class ProductionGraphGenesisV2SessionAuthority {
  readonly #contexts = new WeakMap<object, OwnedSessionContext>();
  readonly #outputs = new WeakMap<object, OwnedOutputIntent>();
  readonly #seenDashboardHandles = new WeakSet<object>();
  readonly #activeDashboardInstanceIds = new Set<string>();
  readonly #activeDashboardPorts = new Set<number>();
  readonly #activeOutputPaths = new Set<string>();
  readonly #prepared = new WeakMap<object, OwnedPreparedProduction>();
  readonly #usedPrepared = new WeakSet<object>();
  readonly #usedContexts = new WeakSet<object>();
  readonly #sealed = new WeakMap<object, OwnedSealedAuthorization>();
  readonly #consumedSealed = new WeakSet<object>();
  readonly #concreteRoots = new WeakMap<object, OwnedConcreteV2Listener>();
  readonly #concreteExecutions = new WeakMap<object, SessionOwnedDormantConcreteExecution>();
  readonly #outputReleases = new WeakMap<object, Promise<void>>();
  readonly #constructionContexts = new WeakSet<object>();
  readonly #constructionOutputs = new WeakSet<object>();
  readonly #constructionDestinations = new Set<string>();
  // Binding and dormant completion share this owner; no live route consumes it.
  readonly #candidates = new ExactGraphCandidateV2Authority();
  readonly #bindings = new GraphGenesisV2BindingAuthority(this.#candidates);

  constructor(private readonly snapshots: ProductionGraphGenesisV2SnapshotAuthority) {}

  authenticatesSnapshot(value: unknown): value is AuthenticatedGraphGenesisV2ProductionSnapshot {
    return this.snapshots.authenticates(value);
  }

  async createContext(
    source: ExistingGraphGenesisAuditDatabase,
  ): Promise<AuthenticatedGraphGenesisV2SessionContext> {
    if (!authenticatesExistingGraphGenesisAuditDatabase(source)
      || !revalidatesExistingGraphGenesisAuditDatabase(source)) fail();
    const approvals = new LocalApprovalService();
    const recorder = new SqliteAuditRecorder(source.database, () => new Date(), 'immediate');
    const query = new AuditQueryService(source.database, recorder);
    const controller = new AbortController();
    let dashboard: DashboardHandle | undefined;
    try {
      const token = randomBytes(32).toString('base64url');
      dashboard = await startDashboard({
        approvals,
        audit: query,
        auditRecorder: recorder,
        token,
        port: 0,
        mode: 'graph_run',
      });
      if (this.#seenDashboardHandles.has(dashboard)) {
        dashboard = undefined;
        fail();
      }
      const dashboardPort = authenticateDashboardHandle(dashboard, token);
      if (this.#activeDashboardInstanceIds.has(dashboard.instanceId)
        || this.#activeDashboardPorts.has(dashboardPort)) fail();
      if (!revalidatesExistingGraphGenesisAuditDatabase(source)) fail();
      const context = Object.freeze({ contextVersion: 1 as const });
      const owned = Object.freeze({
        source,
        approvals,
        recorder,
        query,
        dashboard,
        dashboardPort,
        controller,
        outputs: new Set<OwnedOutputIntent>(),
        listeners: new Set<OwnedConcreteV2Listener>(),
      });
      this.#seenDashboardHandles.add(dashboard);
      this.#activeDashboardInstanceIds.add(dashboard.instanceId);
      this.#activeDashboardPorts.add(dashboardPort);
      this.#contexts.set(context, owned);
      return context;
    } catch {
      controller.abort();
      approvals.close();
      if (dashboard !== undefined) await closeDashboardAfterFailure(dashboard);
      fail();
    }
  }

  async captureOutputIntent(
    context: AuthenticatedGraphGenesisV2SessionContext,
    requestedPath: string,
  ): Promise<AuthenticatedGraphGenesisV2OutputIntent> {
    const ownedContext = this.#contexts.get(context);
    if (ownedContext === undefined || ownedContext.controller.signal.aborted
      || !revalidatesExistingGraphGenesisAuditDatabase(ownedContext.source)) fail();
    let descriptor: FileHandle | undefined;
    try {
      if (typeof requestedPath !== 'string' || requestedPath !== resolve(requestedPath)
        || basename(requestedPath) !== OUTPUT_NAME) fail();
      if (this.#activeOutputPaths.has(requestedPath)) fail();
      const parentCanonicalPath = await realpath(dirname(requestedPath));
      if (parentCanonicalPath !== dirname(requestedPath)) fail();
      const linked = await lstat(parentCanonicalPath);
      assertPrivateDirectory(linked);
      descriptor = await open(parentCanonicalPath, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
      const opened = await descriptor.stat();
      if (!sameDirectory(linked, opened)) fail();
      await assertTargetAbsent(requestedPath);
      const current = await lstat(parentCanonicalPath);
      if (!sameDirectory(opened, current)) fail();
      const parentMode = opened.mode & 0o7777;
      const parentIdentityDigest = digest({
        canonicalPath: parentCanonicalPath,
        device: opened.dev,
        inode: opened.ino,
        owner: opened.uid,
        mode: parentMode,
      });
      const publicIntent = Object.freeze({ outputIntentVersion: 1 as const });
      const owned = Object.freeze({
        publicIntent,
        preparations: new Set<OwnedConcretePreparation>(),
        context,
        canonicalPath: requestedPath,
        parentCanonicalPath,
        parentDevice: opened.dev,
        parentInode: opened.ino,
        parentOwner: opened.uid,
        parentMode,
        parentIdentityDigest,
        canonicalPathDigest: digest(requestedPath),
        descriptor,
        controller: new AbortController(),
      });
      ownedContext.outputs.add(owned);
      this.#activeOutputPaths.add(requestedPath);
      this.#outputs.set(publicIntent, owned);
      return publicIntent;
    } catch {
      if (descriptor !== undefined) await closeDescriptorAfterFailure(descriptor);
      fail();
    }
  }

  async prepare(
    snapshot: AuthenticatedGraphGenesisV2ProductionSnapshot,
    context: AuthenticatedGraphGenesisV2SessionContext,
    output: AuthenticatedGraphGenesisV2OutputIntent,
  ): Promise<PreparedGraphGenesisV2Production> {
    return this.#prepare(snapshot, context, output);
  }

  async #prepare(
    snapshot: AuthenticatedGraphGenesisV2ProductionSnapshot,
    context: AuthenticatedGraphGenesisV2SessionContext,
    output: AuthenticatedGraphGenesisV2OutputIntent,
    originalListener?: OwnedConcreteV2Listener,
    construction?: OwnedConcretePreparation,
  ): Promise<PreparedGraphGenesisV2Production> {
    const bundle = this.#snapshotBundle(snapshot);
    const ownedContext = this.#contexts.get(context);
    const ownedOutput = this.#outputs.get(output);
    if (ownedContext === undefined || ownedOutput === undefined || ownedOutput.context !== context
      || ownedContext.controller.signal.aborted || !ownedContext.outputs.has(ownedOutput)) fail();
    this.#assertPolicyIdentity();
    const requestedAt = new Date().toISOString();
    const deadline = originalListener?.deadline ?? performance.now() + PREPARATION_WINDOW_MS;
    if (!Number.isFinite(deadline) || deadline <= 0 || deadline > Number.MAX_SAFE_INTEGER) fail();

    const revalidate = () => this.snapshots.revalidate(snapshot, {
      signal: construction?.signal(CONCRETE_OWNER) ?? ownedContext.controller.signal,
      monotonicNow: () => performance.now(), deadline,
    });
    if (construction === undefined) {
      await revalidate(); await this.#revalidateOutput(ownedOutput);
    } else {
      if (originalListener === undefined || !construction.matches(CONCRETE_OWNER, snapshot, originalListener, ownedContext, ownedOutput)) fail();
      await construction.step(CONCRETE_OWNER, revalidate);
      await construction.step(CONCRETE_OWNER, () => this.#revalidateOutput(ownedOutput));
      construction.checkpoint(CONCRETE_OWNER);
    }
    if (this.#contexts.get(context) !== ownedContext || this.#outputs.get(output) !== ownedOutput
      || ownedContext.controller.signal.aborted
      || !revalidatesExistingGraphGenesisAuditDatabase(ownedContext.source)) fail();

    const planId = randomBytes(16).toString('hex');
    const sessionId = randomBytes(16).toString('hex');
    const routeToken = randomBytes(16).toString('hex');
    const launch = buildGraphGenesisLaunch({
      sandboxExecPath: bundle.files.sandboxExec.absolutePath,
      profilePath: join(bundle.workspace.rootRealpath, 'broker-profile.sb'),
      nodePath: bundle.files.node.absolutePath,
      npmCliPath: bundle.files.npmCli.absolutePath,
      npmRuntimeRoot: bundle.trees.npmTree.rootRealpath,
      workspaceRoot: bundle.workspace.rootRealpath,
      brokerPort: bundle.containmentProfile.allowedPort,
      routeToken,
    });
    const runtimePaths = Object.freeze({
      node: bundle.files.node.absolutePath,
      npmCli: bundle.files.npmCli.absolutePath,
      sandboxExec: bundle.files.sandboxExec.absolutePath,
      brokerRuntime: bundle.files.brokerRuntime.absolutePath,
      probeRuntime: bundle.files.probeRuntime.absolutePath,
      npmTree: bundle.trees.npmTree.rootRealpath,
      distRuntimeTree: bundle.trees.distRuntimeTree.rootRealpath,
      workspace: bundle.workspace.rootRealpath,
      audit: ownedContext.source.canonicalPath,
      output: ownedOutput.canonicalPath,
    });
    const privateExecution = Object.freeze({
      capsuleVersion: 2 as const,
      planId,
      sessionId,
      routeToken,
      launch,
      runtimePaths,
      dashboardInstanceId: ownedContext.dashboard.instanceId,
      ...(originalListener === undefined ? {} : { originalListenerIdentityDigest: originalListener.identityDigest }),
    });
    const bound = this.#bindings.prepare({
      plan: {
        planVersion: 3,
        candidateSchemaVersion: 2,
        peerSemanticsVersion: 1,
        compilationContractVersion: 1,
        semanticContract: PEER_SEMANTICS_V2_CONTRACT,
        semanticContractDigest: SEMANTIC_CONTRACT_DIGEST,
        compilationContract: EXACT_COMPILATION_CONTRACT_V1,
        compilationContractDigest: COMPILATION_CONTRACT_DIGEST,
        planId,
        targetName: '@modelcontextprotocol/server-filesystem',
        exactTargetVersion: '2026.7.10',
        registryOrigin: 'https://registry.npmjs.org/',
        platform: bundle.host.platform,
        architecture: bundle.host.architecture,
        osBuild: bundle.host.osBuild,
        nodeVersion: bundle.runtimeVersions.nodeVersion,
        npmVersion: bundle.runtimeVersions.npmVersion,
        hostEvidenceDigest: bundle.host.evidenceDigest,
        runtimeVersionEvidenceDigest: bundle.runtimeVersions.evidenceDigest,
        runtimeSnapshots: {
          node: bundle.files.node.snapshotDigest,
          npmCli: bundle.files.npmCli.snapshotDigest,
          sandboxExec: bundle.files.sandboxExec.snapshotDigest,
          brokerRuntime: bundle.files.brokerRuntime.snapshotDigest,
          probeRuntime: bundle.files.probeRuntime.snapshotDigest,
          npmTree: bundle.trees.npmTree.treeDigest,
          brokerTree: bundle.trees.distRuntimeTree.treeDigest,
        },
        runtimeManifestDigest: snapshot.runtimeManifestDigest,
        containmentEvidenceDigest: bundle.containment.evidenceDigest,
        containmentProfileDigest: bundle.containmentProfile.profileDigest,
        containmentProviderId: bundle.containmentProfile.providerId,
        workspaceBinding: snapshot.workspaceBinding,
        brokerAddress: '127.0.0.1',
        brokerPort: bundle.containmentProfile.allowedPort,
        routeTokenDigest: digestBytes(routeToken),
        privatePathSetDigest: digest(runtimePaths),
        launchDigest: launch.launchDigest,
        environmentDigest: digest(launch.env),
        executionCapsuleDigest: digest(privateExecution),
        limits: GRAPH_GENESIS_V2_LIMITS,
        maxCandidateOutputs: 1,
        consequence: 'bounded_public_metadata_graph_genesis',
      },
      envelope: {
        envelopeVersion: 2,
        sessionId,
        bootSessionDigest: bundle.host.bootSessionDigest,
        auditSchemaDigest: ownedContext.source.schemaDigest,
        auditFileIdentityDigest: ownedContext.source.fileIdentityDigest,
        auditDatabaseInstanceId: ownedContext.source.databaseInstanceId,
        initialAuditChainTail: ownedContext.source.initialChainTail,
        auditDurabilityProfileDigest: ownedContext.source.durabilityProfileDigest,
        outputCanonicalPathDigest: ownedOutput.canonicalPathDigest,
        outputParentIdentityDigest: ownedOutput.parentIdentityDigest,
        outputRule: 'exclusive_new_private_file',
        dashboardInstanceId: ownedContext.dashboard.instanceId,
        dashboardPort: ownedContext.dashboardPort,
        requestedAt,
        planDeadlineMonotonicMs: deadline,
      },
    });
    const privateCapsule = Object.freeze({ capsuleVersion: 2 as const });
    const approval = createApprovalView(bound, ownedContext.source.canonicalPath, ownedOutput.canonicalPath);
    const receipt = createReceiptContext(bound);
    const prepared = Object.freeze({
      plan: bound.plan,
      projection: bound.projection,
      envelope: bound.envelope,
      approval,
      receipt,
      privateCapsule,
    });
    this.#prepared.set(privateCapsule, Object.freeze({
      prepared,
      snapshot,
      context,
      output,
      privateBinding: bound.privateBinding,
      privateExecution,
      ...(originalListener === undefined ? {} : { originalListener }),
      ...(construction === undefined ? {} : { construction }),
    }));
    return prepared;
  }

  async prepareConcreteRoot(context: AuthenticatedGraphGenesisV2SessionContext): Promise<PreparedGraphGenesisV2ConcreteRoot> {
    const owned = this.#contexts.get(context);
    if (owned === undefined || owned.controller.signal.aborted) fail();
    const listener = await prepareOriginalListener(owned);
    if (this.#contexts.get(context) !== owned || owned.controller.signal.aborted) {
      await closeOriginalListener(listener, performance.now() + 5_000); fail();
    }
    const root = Object.freeze({ rootVersion: 2 as const, brokerPort: listener.port });
    this.#concreteRoots.set(root, listener); return root;
  }

  async prepareConcrete(
    root: PreparedGraphGenesisV2ConcreteRoot,
    seed: AuthenticatedGraphGenesisV2RuntimeSeed,
    context: AuthenticatedGraphGenesisV2SessionContext,
    output: AuthenticatedGraphGenesisV2OutputIntent,
  ): Promise<PreparedGraphGenesisV2Production> {
    const listener = this.#concreteRoots.get(root);
    if (listener === undefined) fail();
    this.#concreteRoots.delete(root);
    let construction: OwnedConcretePreparation | undefined;
    try {
      const ownedContext = this.#contexts.get(context), intent = this.#outputs.get(output);
      if (arguments.length !== 4 || listener.state !== 'disarmed' || listener.controller.signal.aborted
        || ownedContext === undefined || intent === undefined || intent.context !== context
        || ownedContext.controller.signal.aborted || intent.controller.signal.aborted
        || listener.context !== ownedContext || !ownedContext.outputs.has(intent) || listener.port !== root.brokerPort
        || this.#constructionContexts.has(context) || this.#constructionOutputs.has(output)
        || this.#usedContexts.has(context)) fail();
      const destination = join(intent.parentCanonicalPath, CONCRETE_WORKSPACE_NAME);
      if (this.#constructionDestinations.has(destination)) fail();
      const runtime = this.snapshots.claimConcreteRuntimeSeed(CONCRETE_OWNER, seed);
      // These claims precede every await and construction effect. They are never reset or retried.
      this.#constructionContexts.add(context); this.#constructionOutputs.add(output);
      this.#constructionDestinations.add(destination);
      construction = new OwnedConcretePreparation(CONCRETE_OWNER, root, seed, runtime, ownedContext, intent, listener, destination);
      intent.preparations.add(construction);
      const snapshot = await this.snapshots.constructConcreteSnapshot(CONCRETE_OWNER, construction);
      construction.checkpoint(CONCRETE_OWNER);
      const prepared = await this.#prepare(snapshot, context, output, listener, construction);
      construction.checkpoint(CONCRETE_OWNER);
      if (!this.authenticatesPrepared(prepared)) fail();
      construction.prepared(CONCRETE_OWNER);
      return prepared;
    } catch {
      construction?.revoke(CONCRETE_OWNER);
      await closeOriginalListener(listener, performance.now() + 5_000); fail();
    }
  }

  #authenticatesConstruction(owned: OwnedPreparedProduction): boolean {
    if (owned.originalListener === undefined) return owned.construction === undefined;
    const context = this.#contexts.get(owned.context), output = this.#outputs.get(owned.output);
    return context !== undefined && output !== undefined && owned.construction !== undefined
      && owned.construction.matches(CONCRETE_OWNER, owned.snapshot, owned.originalListener, context, output);
  }

  authenticatesPrepared(value: unknown): value is PreparedGraphGenesisV2Production {
    if (!object(value)) return false;
    const privateCapsule = (value as Partial<PreparedGraphGenesisV2Production>).privateCapsule;
    if (!object(privateCapsule)) return false;
    const owned = this.#prepared.get(privateCapsule);
    return owned?.prepared === value
      && this.#contexts.has(owned.context)
      && this.#outputs.has(owned.output)
      && this.snapshots.authenticates(owned.snapshot)
      && this.#authenticatesConstruction(owned)
      && this.#bindings.authenticatesPair(
        owned.prepared.plan,
        owned.prepared.projection,
        owned.prepared.envelope,
        owned.privateBinding,
      );
  }

  async authorize(
    prepared: PreparedGraphGenesisV2Production,
    options: GraphGenesisV2AuthorizationOptions = Object.freeze({}),
  ): Promise<GraphGenesisV2AuthorizationResult> {
    let audit: AuditCall | undefined;
    let ticket: ApprovalTicket | undefined;
    let approvalRecorded = false;
    let approvalResolved = false;
    let signalLink: LinkedAuthorizationSignal | undefined;
    let listenerLink: LinkedAuthorizationSignal | undefined;
    let originalListener: OwnedConcreteV2Listener | undefined;
    try {
      const callerSignal = authorizationSignal(options);
      const owned = this.#ownedPrepared(prepared);
      originalListener = owned.originalListener;
      if (this.#usedPrepared.has(prepared) || this.#usedContexts.has(owned.context)) fail();
      const context = this.#contexts.get(owned.context);
      const output = this.#outputs.get(owned.output);
      if (context === undefined || output === undefined || output.context !== owned.context
        || !context.outputs.has(output)) fail();
      this.#usedPrepared.add(prepared);
      this.#usedContexts.add(owned.context);
      listenerLink = originalListener === undefined ? undefined
        : linkAuthorizationSignals(originalListener.controller.signal, callerSignal);
      signalLink = linkAuthorizationSignals(context.controller.signal, listenerLink?.signal ?? callerSignal);
      const lifecycleFence = createLifecycleFence(prepared.envelope, signalLink.signal);
      const fence = (expiresAt?: string) => {
        if (!this.#authenticatesConstruction(owned)) fail();
        owned.construction?.checkpoint(CONCRETE_OWNER);
        return lifecycleFence(expiresAt);
      };
      fence();
      if (!revalidatesExistingGraphGenesisAuditDatabase(context.source)) fail();
      const checkpoint = captureInitialAuditCheckpoint(context.source);

      audit = context.recorder.begin({
        serverId: 'apg-graph-genesis',
        toolName: 'filesystem_metadata_graph',
        arguments: {
          executionEnvelopeHash: prepared.envelope.executionEnvelopeHash,
          planHash: prepared.plan.planHash,
        },
      }, {
        action: 'ask',
        evaluation: {
          baseDecision: 'ask',
          effectiveDecision: 'ask',
          matchedRuleId: 'graph_genesis_builtin_ask_v2',
          reasonCodes: GRAPH_GENESIS_POLICY.reasonCodes,
          risk: {
            score: GRAPH_GENESIS_POLICY.score,
            band: GRAPH_GENESIS_POLICY.band,
            signals: [],
          },
        },
        receipt: prepared.receipt,
      });
      audit.appendEvidence('graph_genesis_v2_session_created', {
        executionEnvelopeHash: prepared.envelope.executionEnvelopeHash,
        planHash: prepared.plan.planHash,
      });
      await assertAdvancedAuditSource(context.source, context.recorder, checkpoint, audit.actionId, [
        'decision_recorded',
        'graph_genesis_v2_session_created',
      ]);
      const requestTtlMs = boundedApprovalTtlMs(
        fence(),
        prepared.envelope.planDeadlineMonotonicMs,
      );
      ticket = context.approvals.requestHidden({
        kind: 'graph_genesis',
        serverId: 'apg-graph-genesis',
        toolName: 'filesystem_metadata_graph',
        arguments: {
          executionEnvelopeHash: prepared.envelope.executionEnvelopeHash,
          planHash: prepared.plan.planHash,
        },
        graphGenesis: prepared.approval,
        risk: {
          score: GRAPH_GENESIS_POLICY.score,
          band: GRAPH_GENESIS_POLICY.band,
          signals: [],
        },
        reasonCodes: GRAPH_GENESIS_POLICY.reasonCodes,
      }, requestTtlMs);
      const activeTicket = ticket;
      try {
        audit.markApprovalRequested(activeTicket.request);
        approvalRecorded = true;
      } catch (error) {
        activeTicket.cancel();
        throw error;
      }
      await assertAdvancedAuditSource(context.source, context.recorder, checkpoint, audit.actionId, [
        'decision_recorded',
        'graph_genesis_v2_session_created',
        'approval_requested',
      ]);
      fence();
      context.dashboard.bindGraphAction(audit.actionId);
      context.approvals.publish(activeTicket.request.id);

      const cancelApproval = () => activeTicket.cancel();
      signalLink.signal.addEventListener('abort', cancelApproval, { once: true });
      let outcome: ApprovalOutcome;
      try {
        outcome = await activeTicket.outcome;
      } finally {
        signalLink.signal.removeEventListener('abort', cancelApproval);
      }
      audit.markApprovalResolved(activeTicket.request.id, outcome);
      approvalResolved = true;
      if (outcome !== 'approved') {
        const blocked = blockedStatus(outcome);
        audit.markBlocked(blocked);
        await assertAdvancedAuditSource(context.source, context.recorder, checkpoint, audit.actionId, [
          'decision_recorded',
          'graph_genesis_v2_session_created',
          'approval_requested',
          `approval_${outcome}`,
          blocked,
          'authorization_receipt_finalized',
        ]);
        if (originalListener !== undefined) await closeOriginalListener(originalListener, performance.now() + 5_000);
        return Object.freeze({ status: outcome, actionId: audit.actionId });
      }

      const decisionMonotonicMs = fence(activeTicket.request.expiresAt);
      await this.snapshots.revalidate(owned.snapshot, {
        signal: signalLink.signal,
        monotonicNow: () => performance.now(),
        deadline: prepared.envelope.planDeadlineMonotonicMs,
      });
      fence(activeTicket.request.expiresAt);
      await this.#revalidateOutput(output);
      fence(activeTicket.request.expiresAt);
      await assertAdvancedAuditSource(context.source, context.recorder, checkpoint, audit.actionId, [
        'decision_recorded',
        'graph_genesis_v2_session_created',
        'approval_requested',
        'approval_approved',
      ]);
      fence(activeTicket.request.expiresAt);

      audit.appendEvidence('graph_genesis_v2_approved_revalidation_complete', {
        executionEnvelopeHash: prepared.envelope.executionEnvelopeHash,
      });
      audit.markAuthorized();
      audit.appendEvidence('graph_genesis_v2_authorization_finalized', {
        executionEnvelopeHash: prepared.envelope.executionEnvelopeHash,
        approvalId: activeTicket.request.id,
      });
      const authorizedEvents = [
        'decision_recorded',
        'graph_genesis_v2_session_created',
        'approval_requested',
        'approval_approved',
        'graph_genesis_v2_approved_revalidation_complete',
        'authorization_receipt_finalized',
        'graph_genesis_authorization_ready',
        'graph_genesis_v2_authorization_finalized',
      ] as const;
      await assertAdvancedAuditSource(
        context.source,
        context.recorder,
        checkpoint,
        audit.actionId,
        authorizedEvents,
      );
      fence(activeTicket.request.expiresAt);

      await this.snapshots.revalidate(owned.snapshot, {
        signal: signalLink.signal,
        monotonicNow: () => performance.now(),
        deadline: prepared.envelope.planDeadlineMonotonicMs,
      });
      fence(activeTicket.request.expiresAt);
      await this.#revalidateOutput(output);
      fence(activeTicket.request.expiresAt);
      await assertAdvancedAuditSource(
        context.source,
        context.recorder,
        checkpoint,
        audit.actionId,
        authorizedEvents,
      );
      const sealedAtMonotonicMs = fence(activeTicket.request.expiresAt);
      const startByMonotonicMs = Math.min(
        prepared.envelope.planDeadlineMonotonicMs,
        decisionMonotonicMs + APPROVED_START_WINDOW_MS,
      );
      if (startByMonotonicMs <= sealedAtMonotonicMs) fail();
      const sealed = Object.freeze({ sealedAuthorizationVersion: 2 as const });
      this.#sealed.set(sealed, Object.freeze({
        sealed,
        audit,
        prepared,
        context: owned.context,
        output: owned.output,
        actionId: audit.actionId,
        approvalId: activeTicket.request.id,
        startByMonotonicMs,
        sealedAtMonotonicMs,
        executionDeadlineMonotonicMs: originalListener === undefined ? startByMonotonicMs + EXECUTION_WINDOW_MS
          : decisionMonotonicMs + EXECUTION_WINDOW_MS,
        privateExecution: owned.privateExecution,
        ...(callerSignal === undefined ? {} : { callerSignal }),
        ...(originalListener === undefined ? {} : { concreteAudit: captureConcreteAuditSnapshot(context.source, audit.actionId, activeTicket.request.id) }),
      }));
      return Object.freeze({ status: 'authorized' as const, actionId: audit.actionId, sealedAuthorization: sealed });
    } catch {
      if (ticket !== undefined) {
        ticket.cancel();
        if (audit !== undefined && approvalRecorded && !approvalResolved) {
          try {
            const outcome = await ticket.outcome;
            audit.markApprovalResolved(ticket.request.id, outcome);
            approvalResolved = true;
          } catch {
            // The failure remains terminal and cannot mint sealed evidence.
          }
        }
      }
      if (audit !== undefined) {
        try {
          audit.markFailed('graph_genesis_v2_authorization_failed');
        } catch {
          // A failed audit sink cannot be repaired or treated as authorization.
        }
      }
      if (originalListener !== undefined) await closeOriginalListener(originalListener, performance.now() + 5_000);
      return fail();
    } finally {
      listenerLink?.dispose();
      signalLink?.dispose();
    }
  }

  authenticatesSealed(
    value: unknown,
    prepared: PreparedGraphGenesisV2Production,
  ): value is AuthenticatedGraphGenesisV2SealedAuthorization {
    if (!object(value)) return false;
    const owned = this.#sealed.get(value);
    return owned?.sealed === value
      && owned.prepared === prepared
      && this.#contexts.has(owned.context)
      && this.#outputs.has(owned.output)
      && !this.#contexts.get(owned.context)!.controller.signal.aborted
      && !this.#outputs.get(owned.output)!.controller.signal.aborted
      && !owned.callerSignal?.aborted
      && this.#usedPrepared.has(prepared)
      && this.#usedContexts.has(owned.context);
  }

  /**
   * Fixture-only dormant handoff. It consumes the exact in-memory seal once
   * and passes no caller-selected identity, raw approval token, or database
   * handle to the public API. Production issuers/routes remain absent.
   */
  createSyntheticCompletion(
    prepared: PreparedGraphGenesisV2Production,
    sealed: AuthenticatedGraphGenesisV2SealedAuthorization,
  ): SessionOwnedSyntheticCompletion {
    const owned = this.#sealed.get(sealed);
    const preparedOwned = this.#ownedPrepared(prepared);
    const context = owned === undefined ? undefined : this.#contexts.get(owned.context);
    const output = owned === undefined ? undefined : this.#outputs.get(owned.output);
    const bundle = this.#snapshotBundle(preparedOwned.snapshot);
    if (owned === undefined || owned.prepared !== prepared || digest(owned.privateExecution) !== prepared.plan.executionCapsuleDigest
      || this.#consumedSealed.has(sealed)
      || context === undefined || output === undefined || output.context !== owned.context
      || context.controller.signal.aborted || !context.outputs.has(output)) fail();
    this.#consumedSealed.add(sealed);
    return new SessionOwnedSyntheticCompletion(COMPLETION_OWNER, owned, context, output, bundle.workspace, this.#candidates,
      owned.privateExecution, () =>
      this.#contexts.get(owned.context) === context
      && this.#outputs.get(owned.output) === output
      && context.outputs.has(output),
    );
  }

  /** Closed test-only handoff: callers receive one opaque terminal operation. */
  createDormantMockedExecution(
    prepared: PreparedGraphGenesisV2Production,
    sealed: AuthenticatedGraphGenesisV2SealedAuthorization,
  ): DormantV2MockedExecution {
    const owned = this.#sealed.get(sealed);
    const preparedOwned = this.#ownedPrepared(prepared);
    const context = owned === undefined ? undefined : this.#contexts.get(owned.context);
    const output = owned === undefined ? undefined : this.#outputs.get(owned.output);
    if (owned === undefined || owned.prepared !== prepared || this.#consumedSealed.has(sealed)
      || context === undefined || output === undefined || output.context !== owned.context
      || context.controller.signal.aborted || !context.outputs.has(output)
      || digest(owned.privateExecution) !== prepared.plan.executionCapsuleDigest) fail();
    this.#consumedSealed.add(sealed);
    return new SessionOwnedDormantMockedExecution(COMPLETION_OWNER,
      new SessionOwnedSyntheticCompletion(COMPLETION_OWNER, owned, context, output,
        this.#snapshotBundle(preparedOwned.snapshot).workspace, this.#candidates, owned.privateExecution, () =>
          this.#contexts.get(owned.context) === context
          && this.#outputs.get(owned.output) === output
          && context.outputs.has(output)));
  }

  createDormantConcreteExecution(
    prepared: PreparedGraphGenesisV2Production,
    sealed: AuthenticatedGraphGenesisV2SealedAuthorization,
  ): DormantV2ConcreteExecution {
    const owned = this.#sealed.get(sealed);
    const preparedOwned = this.#ownedPrepared(prepared);
    const context = owned === undefined ? undefined : this.#contexts.get(owned.context);
    const output = owned === undefined ? undefined : this.#outputs.get(owned.output);
    const listener = preparedOwned.originalListener;
    if (owned === undefined || owned.prepared !== prepared || this.#consumedSealed.has(sealed)
      || context === undefined || output === undefined || listener === undefined || listener.state !== 'disarmed'
      || listener.port !== prepared.plan.brokerPort || listener.controller.signal.aborted
      || owned.privateExecution.originalListenerIdentityDigest !== listener.identityDigest
      || output.controller.signal.aborted || output.context !== owned.context
      || context.controller.signal.aborted || !context.outputs.has(output)
      || digest(owned.privateExecution) !== prepared.plan.executionCapsuleDigest) fail();
    this.#consumedSealed.add(sealed);
    const execution = new SessionOwnedDormantConcreteExecution(CONCRETE_OWNER, owned, preparedOwned, this.snapshots, context, output, () =>
      this.#contexts.get(owned.context) === context && this.#outputs.get(owned.output) === output
      && context.outputs.has(output));
    this.#concreteExecutions.set(output.publicIntent, execution);
    return execution;
  }

  async revalidateSnapshot(
    snapshot: AuthenticatedGraphGenesisV2ProductionSnapshot,
    options: GraphGenesisV2RevalidationOptions,
  ): Promise<void> {
    if (!this.snapshots.authenticates(snapshot)) fail();
    await this.snapshots.revalidate(snapshot, options);
  }

  async closeOutputIntent(output: AuthenticatedGraphGenesisV2OutputIntent): Promise<void> {
    const owned = this.#outputs.get(output);
    if (owned === undefined) fail();
    this.#outputs.delete(output);
    owned.controller.abort();
    // Keep namespace and descriptor custody until the single concrete owner has stopped and reconciled.
    await this.#concreteExecutions.get(output)?.stopForRevocation(CONCRETE_OWNER);
    const context = this.#contexts.get(owned.context);
    const listeners = [...(context?.listeners ?? [])].filter(listener => !listener.executionOwned);
    await Promise.all(listeners.map(listener => closeOriginalListener(listener, performance.now() + 5_000)));
    context?.outputs.delete(owned);
    if (!await concreteSettlesWithin(this.#releaseOutputCustody(owned), 5_000)) fail();
  }

  async closeContext(context: AuthenticatedGraphGenesisV2SessionContext): Promise<void> {
    const owned = this.#contexts.get(context);
    if (owned === undefined) fail();
    this.#contexts.delete(context);
    owned.controller.abort();
    const descriptors = [...owned.outputs];
    for (const output of descriptors) {
      this.#outputs.delete(output.publicIntent);
      output.controller.abort();
    }
    owned.approvals.close();
    await Promise.all(descriptors.map(output => this.#concreteExecutions.get(output.publicIntent)?.stopForRevocation(CONCRETE_OWNER)));
    await Promise.all([...owned.listeners].map(listener => closeOriginalListener(listener, performance.now() + 5_000)));
    const results = await Promise.allSettled([
      ...descriptors.map(async output => {
        if (!await concreteSettlesWithin(this.#releaseOutputCustody(output), 5_000)) fail();
      }),
      owned.dashboard.close(),
    ]);
    owned.outputs.clear();
    this.#activeDashboardInstanceIds.delete(owned.dashboard.instanceId);
    this.#activeDashboardPorts.delete(owned.dashboardPort);
    if (results.some(result => result.status === 'rejected')) fail();
  }

  #releaseOutputCustody(output: OwnedOutputIntent): Promise<void> {
    const existing = this.#outputReleases.get(output.publicIntent);
    if (existing !== undefined) return existing;
    const release = Promise.resolve().then(async () => {
      await Promise.all([...output.preparations].map(preparation => preparation.custodyDrained(CONCRETE_OWNER)));
      await this.#concreteExecutions.get(output.publicIntent)?.custodyDrained(CONCRETE_OWNER);
      await output.descriptor.close();
      this.#activeOutputPaths.delete(output.canonicalPath);
    });
    this.#outputReleases.set(output.publicIntent, release);
    void release.catch(() => {});
    return release;
  }

  #snapshotBundle(snapshot: AuthenticatedGraphGenesisV2ProductionSnapshot): OwnedProductionBundle {
    const bundle = snapshotBundles.get(snapshot);
    if (bundle === undefined) fail();
    return bundle;
  }

  #ownedPrepared(prepared: PreparedGraphGenesisV2Production): OwnedPreparedProduction {
    if (!this.authenticatesPrepared(prepared)) fail();
    const owned = this.#prepared.get(prepared.privateCapsule);
    if (owned === undefined || owned.prepared !== prepared) fail();
    return owned;
  }

  #assertPolicyIdentity(): void {
    if (canonicalJson(GRAPH_GENESIS_V2_POLICY) !== canonicalJson(GRAPH_GENESIS_POLICY)
      || GRAPH_GENESIS_V2_POLICY_DIGEST !== digest(GRAPH_GENESIS_POLICY)) fail();
  }

  async #revalidateOutput(output: OwnedOutputIntent): Promise<void> {
    const opened = await output.descriptor.stat();
    if (!matchesOwnedDirectory(opened, output)) fail();
    const linked = await lstat(output.parentCanonicalPath);
    if (!matchesOwnedDirectory(linked, output)) fail();
    if (await realpath(output.parentCanonicalPath) !== output.parentCanonicalPath) fail();
    await assertTargetAbsent(output.canonicalPath);
    const current = await lstat(output.parentCanonicalPath);
    if (!matchesOwnedDirectory(current, output)) fail();
  }
}

function createApprovalView(
  bound: PreparedGraphGenesisV2Binding,
  auditPath: string,
  outputPath: string,
): GraphGenesisV2ApprovalView {
  return Object.freeze({
    approvalIdentityVersion: 2 as const,
    target: TARGET,
    registryOrigin: bound.plan.registryOrigin,
    executionEnvelopeHash: bound.envelope.executionEnvelopeHash,
    planHash: bound.plan.planHash,
    projectionDigest: bound.envelope.projectionDigest,
    runtimeManifestDigest: bound.plan.runtimeManifestDigest,
    candidateSchemaVersion: 2 as const,
    peerSemanticsVersion: 1 as const,
    compilationContractVersion: 1 as const,
    semanticContractDigest: bound.plan.semanticContractDigest,
    compilationContractDigest: bound.plan.compilationContractDigest,
    maxCandidateOutputs: 1 as const,
    effect: 'metadata_only_lock_only_local' as const,
    containment: 'development_only' as const,
    host: Object.freeze({
      platform: bound.plan.platform,
      architecture: bound.plan.architecture,
      osBuild: bound.plan.osBuild,
    }),
    runtime: Object.freeze({
      nodeVersion: bound.plan.nodeVersion,
      npmVersion: bound.plan.npmVersion,
    }),
    auditPath,
    outputPath,
    limits: bound.plan.limits,
    consequences: Object.freeze([
      'Public registry package metadata may be disclosed after a separate exact approval.',
      'A later authorized run may write one candidate.json file in the displayed private output directory.',
    ]),
    exclusions: Object.freeze([
      'No package download, installation, node_modules, lifecycle script, or package execution.',
      'No current capability can start a broker, npm process, candidate writer, or live run.',
    ]),
    bypassWarning: 'Direct npm/npx commands bypass APG and receive none of this protection or evidence.' as const,
  });
}

function createReceiptContext(bound: PreparedGraphGenesisV2Binding): ReceiptContext {
  return Object.freeze({
    adapter: 'graph_genesis',
    adapterVersion: '2',
    operation: 'filesystem_metadata_graph',
    boundary: 'graph_genesis_plan' as const,
    identityAssurance: 'execution_plan_exact' as const,
    identityMaterial: Object.freeze({
      executionEnvelopeHash: bound.envelope.executionEnvelopeHash,
      planHash: bound.plan.planHash,
      projectionDigest: bound.envelope.projectionDigest,
      semanticContractDigest: bound.plan.semanticContractDigest,
      compilationContractDigest: bound.plan.compilationContractDigest,
      runtimeManifestDigest: bound.plan.runtimeManifestDigest,
      hostEvidenceDigest: bound.plan.hostEvidenceDigest,
      workspaceBinding: bound.plan.workspaceBinding,
      containmentProfileDigest: bound.plan.containmentProfileDigest,
      containmentEvidenceDigest: bound.plan.containmentEvidenceDigest,
      policyDigest: bound.envelope.policyDigest,
      auditFileIdentityDigest: bound.envelope.auditFileIdentityDigest,
      auditDurabilityProfileDigest: bound.envelope.auditDurabilityProfileDigest,
      outputCanonicalPathDigest: bound.envelope.outputCanonicalPathDigest,
      outputParentIdentityDigest: bound.envelope.outputParentIdentityDigest,
    }),
    subject: TARGET,
    executionPlanHash: bound.envelope.executionEnvelopeHash,
    policy: staticPolicyIdentity(
      GRAPH_GENESIS_POLICY.schemaVersion,
      GRAPH_GENESIS_POLICY.evaluatorName,
      GRAPH_GENESIS_POLICY.evaluatorVersion,
      GRAPH_GENESIS_POLICY,
    ),
  });
}

function authenticateDashboardHandle(handle: DashboardHandle, token: string): number {
  const record = closedRecord(handle, DASHBOARD_KEYS);
  if (typeof record.url !== 'string' || typeof record.instanceId !== 'string'
    || typeof record.close !== 'function' || typeof record.bindGraphAction !== 'function'
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(record.instanceId)) fail();
  const url = new URL(record.url);
  const fragment = new URLSearchParams(url.hash.slice(1));
  const port = Number(url.port);
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || url.pathname !== '/'
    || url.username !== '' || url.password !== '' || url.search !== ''
    || fragment.size !== 1 || fragment.get('token') !== token
    || !Number.isSafeInteger(port) || port < 1024 || port > 65_535) fail();
  return port;
}

async function closeDashboardAfterFailure(handle: DashboardHandle): Promise<void> {
  try {
    if (typeof handle.close === 'function') await handle.close();
  } catch {
    // Failure remains terminal; cleanup is best-effort and never transfers ownership.
  }
}

async function closeDescriptorAfterFailure(descriptor: FileHandle): Promise<void> {
  try {
    await descriptor.close();
  } catch {
    // Failure remains terminal; the descriptor is not registered as an owned intent.
  }
}

type DirectoryStat = Awaited<ReturnType<typeof lstat>>;

function assertPrivateDirectory(info: DirectoryStat): void {
  const owner = Number(info.uid);
  const currentUser = typeof process.geteuid === 'function' ? process.geteuid() : owner;
  if (!info.isDirectory() || info.isSymbolicLink() || owner !== currentUser
    || (Number(info.mode) & 0o077) !== 0) fail();
}

function sameDirectory(left: DirectoryStat, right: DirectoryStat): boolean {
  return left.isDirectory() && right.isDirectory() && !left.isSymbolicLink() && !right.isSymbolicLink()
    && Number(left.dev) === Number(right.dev) && Number(left.ino) === Number(right.ino)
    && Number(left.uid) === Number(right.uid)
    && (Number(left.mode) & 0o7777) === (Number(right.mode) & 0o7777);
}

function matchesOwnedDirectory(info: DirectoryStat, output: OwnedOutputIntent): boolean {
  return info.isDirectory() && !info.isSymbolicLink()
    && Number(info.dev) === output.parentDevice
    && Number(info.ino) === output.parentInode
    && Number(info.uid) === output.parentOwner
    && (Number(info.mode) & 0o7777) === output.parentMode;
}

async function assertTargetAbsent(path: string): Promise<void> {
  try {
    await lstat(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return;
    fail();
  }
  fail();
}

type LinkedAuthorizationSignal = Readonly<{
  signal: AbortSignal;
  dispose(): void;
}>;

function authorizationSignal(options: GraphGenesisV2AuthorizationOptions): AbortSignal | undefined {
  const keys = Object.prototype.hasOwnProperty.call(options, 'signal') ? ['signal'] as const : [] as const;
  const owned = closedRecord(options, keys);
  if (!('signal' in owned)) return undefined;
  const signal = owned.signal;
  if (!object(signal) || typeof (signal as AbortSignal).aborted !== 'boolean'
    || typeof (signal as AbortSignal).addEventListener !== 'function'
    || typeof (signal as AbortSignal).removeEventListener !== 'function') fail();
  return signal as AbortSignal;
}

function linkAuthorizationSignals(
  contextSignal: AbortSignal,
  callerSignal: AbortSignal | undefined,
): LinkedAuthorizationSignal {
  const controller = new AbortController();
  const abort = () => controller.abort();
  contextSignal.addEventListener('abort', abort, { once: true });
  callerSignal?.addEventListener('abort', abort, { once: true });
  if (contextSignal.aborted || callerSignal?.aborted) controller.abort();
  return Object.freeze({
    signal: controller.signal,
    dispose: () => {
      contextSignal.removeEventListener('abort', abort);
      callerSignal?.removeEventListener('abort', abort);
    },
  });
}

function createLifecycleFence(
  envelope: GraphGenesisExecutionEnvelopeV2,
  signal: AbortSignal,
): (expiresAt?: string) => number {
  const requestedAtMs = Date.parse(envelope.requestedAt);
  if (!Number.isFinite(requestedAtMs)) fail();
  let previousMonotonic: number | undefined;
  return (expiresAt?: string): number => {
    if (signal.aborted) fail();
    const monotonic = performance.now();
    const wallNow = Date.now();
    if (!Number.isFinite(monotonic) || monotonic < 0 || Math.abs(monotonic) > Number.MAX_SAFE_INTEGER
      || Object.is(monotonic, -0) || monotonic >= envelope.planDeadlineMonotonicMs
      || (previousMonotonic !== undefined && monotonic < previousMonotonic)
      || !Number.isFinite(wallNow) || wallNow < requestedAtMs || wallNow - requestedAtMs > APPROVAL_TTL_MS) fail();
    if (expiresAt !== undefined) {
      const expiresAtMs = Date.parse(expiresAt);
      if (!Number.isFinite(expiresAtMs) || wallNow >= expiresAtMs) fail();
    }
    previousMonotonic = monotonic;
    return monotonic;
  };
}

function boundedApprovalTtlMs(monotonicNow: number, deadline: number): number {
  if (!Number.isFinite(monotonicNow) || !Number.isFinite(deadline)
    || monotonicNow < 0 || deadline <= monotonicNow) fail();
  const ttlMs = Math.floor(Math.min(APPROVAL_TTL_MS, deadline - monotonicNow));
  if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0) fail();
  return ttlMs;
}

function blockedStatus(outcome: Exclude<ApprovalOutcome, 'approved'>):
  'approval_denied' | 'approval_expired' | 'approval_cancelled' {
  switch (outcome) {
    case 'denied': return 'approval_denied';
    case 'expired': return 'approval_expired';
    case 'cancelled': return 'approval_cancelled';
  }
  fail();
}

function captureInitialAuditCheckpoint(source: ExistingGraphGenesisAuditDatabase): AuditCheckpoint {
  const row = source.database.prepare(`
    SELECT sequence, event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1
  `).get() as { sequence: number; event_hash: string } | undefined;
  const checkpoint = Object.freeze({
    sequence: row?.sequence ?? 0,
    tail: row?.event_hash ?? '0'.repeat(64),
  });
  if (!Number.isSafeInteger(checkpoint.sequence) || checkpoint.sequence < 0
    || checkpoint.tail !== source.initialChainTail) fail();
  return checkpoint;
}

async function assertAdvancedAuditSource(
  source: ExistingGraphGenesisAuditDatabase,
  recorder: SqliteAuditRecorder,
  checkpoint: AuditCheckpoint,
  actionId: string,
  expectedEventTypes: readonly string[],
): Promise<void> {
  if (!authenticatesExistingGraphGenesisAuditDatabase(source)
    || !recorder.verifyHashChain()) fail();
  const parent = await lstat(dirname(source.canonicalPath));
  const file = await lstat(source.canonicalPath);
  const currentUser = typeof process.geteuid === 'function' ? process.geteuid() : file.uid;
  if (await realpath(source.canonicalPath) !== source.canonicalPath
    || !parent.isDirectory() || parent.isSymbolicLink() || parent.uid !== currentUser || (parent.mode & 0o077) !== 0
    || !file.isFile() || file.isSymbolicLink() || file.nlink !== 1 || file.uid !== currentUser
    || (file.mode & 0o777) !== 0o600
    || digest({ device: file.dev, inode: file.ino, owner: file.uid, mode: file.mode & 0o7777 })
      !== source.fileIdentityDigest) fail();

  const journalMode = String(source.database.pragma('journal_mode', { simple: true })).toLowerCase();
  const synchronous = Number(source.database.pragma('synchronous', { simple: true }));
  const busyTimeoutMs = Number(source.database.pragma('busy_timeout', { simple: true }));
  const integrity = String(source.database.pragma('integrity_check', { simple: true })).toLowerCase();
  const sidecars = [`${source.canonicalPath}-wal`, `${source.canonicalPath}-shm`]
    .filter((path) => existsSync(path));
  for (const sidecar of sidecars) {
    const info = await lstat(sidecar);
    if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.uid !== currentUser
      || (info.mode & 0o077) !== 0) fail();
  }
  const durabilityProfile = {
    journalMode,
    synchronous,
    busyTimeoutMs,
    integrity,
    sidecars: sidecars.map((path) => path.slice(source.canonicalPath.length)),
  };
  if (journalMode !== 'wal' || synchronous !== 2 || busyTimeoutMs !== 5000 || integrity !== 'ok'
    || digest(durabilityProfile) !== source.durabilityProfileDigest) fail();

  const migrations = source.database.prepare('SELECT version FROM schema_migrations ORDER BY version')
    .all() as Array<{ version: number }>;
  const tables = source.database.prepare(`
    SELECT name, sql FROM sqlite_schema
    WHERE type = 'table' AND name IN ('approvals', 'audit_events', 'schema_migrations', 'tool_calls')
    ORDER BY name
  `).all() as Array<{ name: string; sql: string }>;
  if (canonicalJson(migrations.map((row) => row.version)) !== '[1,2]'
    || canonicalJson(tables.map((row) => row.name))
      !== canonicalJson(['approvals', 'audit_events', 'schema_migrations', 'tool_calls'])
    || digest({ migrations: [1, 2], tables }) !== source.schemaDigest) fail();

  const events = source.database.prepare(`
    SELECT sequence, tool_call_id, event_type, event_json, previous_hash, event_hash
    FROM audit_events ORDER BY sequence
  `).all() as Array<{
    sequence: number;
    tool_call_id: string;
    event_type: string;
    event_json: string;
    previous_hash: string;
    event_hash: string;
  }>;
  let tail = '0'.repeat(64);
  let foundCheckpoint = checkpoint.sequence === 0;
  const advanced: typeof events = [];
  for (const event of events) {
    if (!Number.isSafeInteger(event.sequence) || event.sequence <= 0
      || event.previous_hash !== tail || digestBytes(`${event.previous_hash}\n${event.event_json}`) !== event.event_hash) fail();
    const parsed = JSON.parse(event.event_json) as { toolCallId?: unknown; eventType?: unknown };
    if (parsed.toolCallId !== event.tool_call_id || parsed.eventType !== event.event_type) fail();
    tail = event.event_hash;
    if (event.sequence === checkpoint.sequence) {
      if (event.event_hash !== checkpoint.tail) fail();
      foundCheckpoint = true;
    }
    if (event.sequence > checkpoint.sequence) advanced.push(event);
  }
  if (!foundCheckpoint || advanced.length !== expectedEventTypes.length
    || tail === checkpoint.tail) fail();
  for (let index = 0; index < expectedEventTypes.length; index += 1) {
    const event = advanced[index]!;
    if (event.tool_call_id !== actionId || event.event_type !== expectedEventTypes[index]) fail();
  }
}

function ownClosedBundle(input: GraphGenesisV2ConcreteProductionBundle): OwnedProductionBundle {
  const top = closedRecord(input, TOP_LEVEL_KEYS);
  const files = closedRecord(top.files, FILE_KEYS) as GraphGenesisV2ConcreteProductionBundle['files'];
  const trees = closedRecord(top.trees, TREE_KEYS) as GraphGenesisV2ConcreteProductionBundle['trees'];
  return Object.freeze({
    files,
    trees,
    runtimeVersions: top.runtimeVersions as AuthenticatedRuntimeVersionEvidence,
    host: top.host as AuthenticatedHostPlatformEvidence,
    workspace: top.workspace as GraphGenesisWorkspace,
    containmentProfile: top.containmentProfile as SeatbeltLoopbackProfile,
    containment: top.containment as AuthenticatedOwnedContainmentEvidence,
  });
}

function closedRecord<const Keys extends readonly string[]>(
  value: unknown,
  expectedKeys: Keys,
): Readonly<Record<Keys[number], unknown>> {
  if (!object(value) || Array.isArray(value)) fail();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((key) => typeof key !== 'string')) fail();
  const actualKeys = (ownKeys as string[]).sort();
  const wantedKeys = [...expectedKeys].sort();
  if (canonicalJson(actualKeys) !== canonicalJson(wantedKeys)) fail();
  const clone: Record<string, unknown> = {};
  for (const key of expectedKeys) {
    const descriptor = descriptors[key];
    if (descriptor === undefined || !descriptor.enumerable || !('value' in descriptor)) fail();
    clone[key] = descriptor.value;
  }
  return Object.freeze(clone) as Readonly<Record<Keys[number], unknown>>;
}

function assertFileOwnership(
  authority: RuntimeFileSnapshotAuthority,
  files: GraphGenesisV2ConcreteProductionBundle['files'],
): void {
  if (!authority.authenticates(files.node, 'node')
    || !authority.authenticates(files.npmCli, 'npm_cli')
    || !authority.authenticates(files.sandboxExec, 'sandbox_exec')
    || !authority.authenticates(files.brokerRuntime, 'broker_runtime')
    || !authority.authenticates(files.probeRuntime, 'probe_runtime')) fail();
  for (const key of [
    'sqlitePackage', 'sqliteNative', 'repositoryPackageJson', 'repositoryPackageLock', 'swVers', 'sysctl',
  ] as const) {
    if (!authority.authenticates(files[key], 'broker_runtime')) fail();
  }
}

function assertTreeOwnership(
  authority: RuntimeTreeSnapshotAuthority,
  trees: GraphGenesisV2ConcreteProductionBundle['trees'],
): void {
  for (const key of TREE_KEYS) {
    if (!authority.authenticates(trees[key])) fail();
  }
}

function assertDistinctRoles(input: GraphGenesisV2RuntimeSeedInput): void {
  const values: object[] = [
    ...FILE_KEYS.map((key) => input.files[key]),
    ...TREE_KEYS.map((key) => input.trees[key]),
  ];
  if (values.length !== REQUIRED_ROLES.length || new Set(values).size !== REQUIRED_ROLES.length) fail();
  const fileIdentities = FILE_KEYS.map((key) => {
    const file = input.files[key];
    return `${file.device}:${file.inode}`;
  });
  const filePaths = FILE_KEYS.map((key) => input.files[key].absolutePath);
  const treeRoots = TREE_KEYS.map((key) => input.trees[key].rootRealpath);
  if (new Set(filePaths).size !== filePaths.length
    || new Set(fileIdentities).size !== fileIdentities.length
    || new Set(treeRoots).size !== treeRoots.length) fail();
}

function assertStructuralRelationships(input: GraphGenesisV2RuntimeSeedInput): void {
  if (input.files.npmCli.absolutePath !== join(input.trees.npmTree.rootRealpath, 'bin', 'npm-cli.js')
    || !treeHasRelativeFile(input.trees.npmTree, 'package.json')
    || !treeBindsFile(input.trees.npmTree, input.files.npmCli)
    || basename(input.files.brokerRuntime.absolutePath) !== 'graph-genesis-live.js'
    || basename(input.files.probeRuntime.absolutePath) !== 'graph-genesis-containment-probe.js'
    || !treeBindsFile(input.trees.distRuntimeTree, input.files.brokerRuntime)
    || !treeBindsFile(input.trees.distRuntimeTree, input.files.probeRuntime)) fail();

  const repositoryRoot = dirname(input.trees.migrations.rootRealpath);
  if (input.trees.migrations.rootRealpath !== join(repositoryRoot, 'migrations')
    || input.trees.webAssets.rootRealpath !== join(repositoryRoot, 'web')
    || input.trees.distRuntimeTree.rootRealpath !== join(repositoryRoot, 'dist', 'src')
    || input.files.repositoryPackageJson.absolutePath !== join(repositoryRoot, 'package.json')
    || input.files.repositoryPackageLock.absolutePath !== join(repositoryRoot, 'package-lock.json')) fail();

  const sqliteRoot = dirname(input.trees.sqliteLib.rootRealpath);
  if (input.trees.sqliteLib.rootRealpath !== join(sqliteRoot, 'lib')
    || input.files.sqlitePackage.absolutePath !== join(sqliteRoot, 'package.json')
    || dirname(dirname(input.files.sqliteNative.absolutePath)) !== sqliteRoot
    || basename(dirname(input.files.sqliteNative.absolutePath)) !== 'prebuilds'
    || basename(input.files.sqliteNative.absolutePath) !== `${input.host.platform}-${input.host.architecture}.node`
    || input.files.swVers.absolutePath !== '/usr/bin/sw_vers'
    || input.files.sysctl.absolutePath !== '/usr/sbin/sysctl') fail();
}

function assertEvidenceRelationships(input: OwnedProductionBundle): void {
  const workspaceBinding = computeWorkspaceBinding(input.workspace);
  if (input.runtimeVersions.nodeSnapshotDigest !== input.files.node.snapshotDigest
    || input.runtimeVersions.npmCliSnapshotDigest !== input.files.npmCli.snapshotDigest
    || input.runtimeVersions.npmTreeDigest !== input.trees.npmTree.treeDigest
    || input.host.osBuild !== input.containment.binding.osBuild
    || input.host.evidenceDigest !== input.containment.binding.hostEvidenceDigest
    || input.files.node.snapshotDigest !== input.containment.binding.nodeSnapshotDigest
    || input.files.probeRuntime.snapshotDigest !== input.containment.binding.probeSnapshotDigest
    || input.files.sandboxExec.snapshotDigest !== input.containment.binding.sandboxExecSnapshotDigest
    || workspaceBinding !== input.containment.binding.workspaceBinding
    || input.containmentProfile.profileDigest !== input.containment.binding.profileDigest
    || input.containmentProfile.allowedPort !== input.containment.binding.allowedPort
    || input.containmentProfile.osBuild !== input.host.osBuild
    || input.containmentProfile.sandboxExecSha256 !== input.files.sandboxExec.sha256) fail();

  const protectedProfiles = input.workspace.protectedFiles.filter((file) => file.name === 'broker-profile.sb');
  if (protectedProfiles.length !== 1) fail();
  const protectedProfile = protectedProfiles[0]!;
  if (protectedProfile.size !== Buffer.byteLength(input.containmentProfile.profileText)
    || protectedProfile.sha256 !== digestBytes(input.containmentProfile.profileText)) fail();
}

function treeBindsFile(
  tree: AuthenticatedRuntimeTreeSnapshot,
  file: AuthenticatedRuntimeFileSnapshot,
): boolean {
  const relativePath = relative(tree.rootRealpath, file.absolutePath).split(sep).join('/');
  if (relativePath === '' || relativePath === '..' || relativePath.startsWith('../')) return false;
  return tree.entries.some((entry) => entry.type === 'file'
    && entry.relativePath === relativePath
    && entry.device === file.device
    && entry.inode === file.inode
    && entry.mode === file.mode
    && entry.size === file.size
    && entry.mtimeMs === file.mtimeMs
    && entry.ctimeMs === file.ctimeMs
    && entry.sha256 === file.sha256);
}

function treeHasRelativeFile(tree: AuthenticatedRuntimeTreeSnapshot, relativePath: string): boolean {
  return tree.entries.some((entry) => entry.type === 'file' && entry.relativePath === relativePath);
}

function createManifest(input: OwnedProductionBundle): readonly GraphGenesisV2RuntimeSnapshot[] {
  const snapshots: GraphGenesisV2RuntimeSnapshot[] = [
    manifestEntry('node', 'file', input.files.node.snapshotDigest),
    manifestEntry('npmCli', 'file', input.files.npmCli.snapshotDigest),
    manifestEntry('sandboxExec', 'file', input.files.sandboxExec.snapshotDigest),
    manifestEntry('brokerRuntime', 'file', input.files.brokerRuntime.snapshotDigest),
    manifestEntry('probeRuntime', 'file', input.files.probeRuntime.snapshotDigest),
    manifestEntry('npmTree', 'tree', input.trees.npmTree.treeDigest),
    manifestEntry('distRuntimeTree', 'tree', input.trees.distRuntimeTree.treeDigest),
    manifestEntry('sqliteLib', 'tree', input.trees.sqliteLib.treeDigest),
    manifestEntry('migrations', 'tree', input.trees.migrations.treeDigest),
    manifestEntry('webAssets', 'tree', input.trees.webAssets.treeDigest),
    manifestEntry('sqlitePackage', 'file', input.files.sqlitePackage.snapshotDigest),
    manifestEntry('sqliteNative', 'file', input.files.sqliteNative.snapshotDigest),
    manifestEntry('repositoryPackageJson', 'file', input.files.repositoryPackageJson.snapshotDigest),
    manifestEntry('repositoryPackageLock', 'file', input.files.repositoryPackageLock.snapshotDigest),
    manifestEntry('swVers', 'file', input.files.swVers.snapshotDigest),
    manifestEntry('sysctl', 'file', input.files.sysctl.snapshotDigest),
  ];
  if (canonicalJson(snapshots.map(({ role }) => role)) !== canonicalJson(REQUIRED_ROLES)) fail();
  return Object.freeze(snapshots);
}

function manifestEntry(role: RuntimeRole, kind: RuntimeKind, identityDigest: string): GraphGenesisV2RuntimeSnapshot {
  return Object.freeze({ role, kind, identityDigest });
}

function createGuardedAwait(options: GraphGenesisV2RevalidationOptions) {
  const keys = Object.prototype.hasOwnProperty.call(options, 'signal')
    ? ['signal', 'monotonicNow', 'deadline'] as const
    : ['monotonicNow', 'deadline'] as const;
  const owned = closedRecord(options, keys);
  const monotonicNow = owned.monotonicNow;
  const deadline = owned.deadline;
  const signal = 'signal' in owned ? owned.signal : undefined;
  if (typeof monotonicNow !== 'function' || typeof deadline !== 'number' || !Number.isFinite(deadline)
    || deadline <= 0 || Math.abs(deadline) > Number.MAX_SAFE_INTEGER || Object.is(deadline, -0)
    || (signal !== undefined && (!object(signal) || typeof (signal as AbortSignal).aborted !== 'boolean'))) fail();
  let previous: number | undefined;
  const checkpoint = (): void => {
    if ((signal as AbortSignal | undefined)?.aborted) fail();
    const now = (monotonicNow as () => number)();
    if (!Number.isFinite(now) || now < 0 || Math.abs(now) > Number.MAX_SAFE_INTEGER
      || Object.is(now, -0) || (previous !== undefined && now < previous) || now >= deadline) fail();
    previous = now;
  };
  return async <T>(operation: () => Promise<T>): Promise<T> => {
    checkpoint();
    const result = await operation();
    checkpoint();
    return result;
  };
}

function digest(value: unknown): string {
  return createHash('sha256').update(canonicalJson(value)).digest('hex');
}

function digestBytes(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

async function assertAbsentV2(path: string): Promise<void> {
  try {
    await lstat(path);
    fail();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
}

function sameV2File(
  left: Awaited<ReturnType<typeof lstat>>,
  right: Awaited<ReturnType<typeof lstat>>,
): boolean {
  return left.isFile() && right.isFile() && left.nlink === 1 && right.nlink === 1
    && left.dev === right.dev && left.ino === right.ino && left.uid === right.uid
    && (Number(left.mode) & 0o777) === (Number(right.mode) & 0o777) && left.size === right.size;
}

function currentUserV2(fallback: number): number {
  return typeof process.geteuid === 'function' ? process.geteuid() : fallback;
}


/** A cooperative timer fence observes rejection immediately and removes its own timer/listener on every path. */
function concreteAwait<T>(operation: Promise<T>, deadline: number, signal?: AbortSignal): Promise<T> {
  return new Promise<T>((resolveValue, rejectValue) => {
    let settled = false;
    const finish = (error: boolean, value?: T) => {
      if (settled) return; settled = true; clearTimeout(timer); signal?.removeEventListener('abort', aborted);
      if (error) rejectValue(new Error('graph_genesis_v2_production_invalid')); else resolveValue(value!);
    };
    const aborted = () => finish(true);
    const now = performance.now();
    const remaining = Math.max(0, deadline - now);
    const timer = setTimeout(() => finish(true), Number.isFinite(remaining) ? remaining : 0);
    operation.then(value => finish(false, value), () => finish(true));
    signal?.addEventListener('abort', aborted, { once: true });
    if (signal?.aborted || !Number.isFinite(now) || now < 0 || now >= deadline) finish(true);
  });
}
function concreteSettlesWithin(operation: Promise<unknown>, timeoutMs: number): Promise<boolean> {
  return new Promise(resolveValue => {
    let settled = false;
    const finish = (value: boolean) => { if (settled) return; settled = true; clearTimeout(timer); resolveValue(value); };
    const timer = setTimeout(() => finish(false), Number.isFinite(timeoutMs) ? Math.max(0, timeoutMs) : 0);
    operation.then(() => finish(true), () => finish(false));
  });
}
async function concreteOutputParent(output: OwnedOutputIntent): Promise<void> {
  const descriptor = await output.descriptor.stat(), linked = await lstat(output.parentCanonicalPath);
  if (!matchesOwnedDirectory(descriptor, output) || !matchesOwnedDirectory(linked, output)
    || await realpath(output.parentCanonicalPath) !== output.parentCanonicalPath) fail();
}
function concreteProtected(workspace: GraphGenesisWorkspace): void {
  const root = lstatSync(workspace.rootRealpath);
  if (!root.isDirectory() || root.isSymbolicLink() || root.dev !== workspace.device || root.ino !== workspace.inode
    || root.uid !== workspace.owner || (root.mode & 0o7777) !== workspace.mode) fail();
  for (const item of workspace.protectedFiles) {
    const path = join(workspace.rootRealpath, item.name);
    const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const before = fstatSync(fd);
      if (!before.isFile() || before.nlink !== 1 || before.uid !== workspace.owner || before.dev !== item.device
        || before.ino !== item.inode || (before.mode & 0o7777) !== item.mode || before.size !== item.size
        || item.size > 64 * 1024) fail();
      const bytes = Buffer.alloc(item.size + 1); let offset = 0;
      while (offset < bytes.length) { const n = readSync(fd, bytes, offset, bytes.length - offset, offset); if (!n) break; offset += n; }
      if (offset !== item.size || createHash('sha256').update(bytes.subarray(0, offset)).digest('hex') !== item.sha256
        || proofFileIdentity(fstatSync(fd)) !== proofFileIdentity(before)
        || proofFileIdentity(lstatSync(path)) !== proofFileIdentity(before)) fail();
    } finally { closeSync(fd); }
  }
}

async function prepareOriginalListener(context: OwnedSessionContext): Promise<OwnedConcreteV2Listener> {
  const createdAt = performance.now();
  if (!Number.isFinite(createdAt) || Object.is(createdAt, -0) || createdAt < 0 || createdAt > Number.MAX_SAFE_INTEGER - PREPARATION_WINDOW_MS
    || context.controller.signal.aborted) fail();
  let listener!: OwnedConcreteV2Listener;
  const server = createServer((_request, response) => {
    // Metadata transport is not connected in the failure-lifecycle unit. An armed request fails the run closed.
    if (listener.state === 'armed') listener.controller.abort();
    response.statusCode = 503; response.end();
  });
  listener = {
    server, port: 0, identityDigest: '', state: 'disarmed', controller: new AbortController(), context,
    deadline: createdAt + PREPARATION_WINDOW_MS, lastNow: createdAt,
    executionOwned: false, closePromise: undefined, lifetime: undefined, detached: () => {},
  };
  const revoke = () => {
    listener.controller.abort();
    if (!listener.executionOwned) void closeOriginalListener(listener, performance.now() + 5_000);
  };
  context.listeners.add(listener);
  context.controller.signal.addEventListener('abort', revoke, { once: true });
  server.on('error', revoke);
  listener.detached = () => context.controller.signal.removeEventListener('abort', revoke);
  listener.lifetime = setTimeout(revoke, PREPARATION_WINDOW_MS);
  try {
    await concreteAwait(new Promise<void>((resolveListen, rejectListen) => {
      server.once('error', rejectListen);
      server.listen(0, '127.0.0.1', () => { server.removeListener('error', rejectListen); resolveListen(); });
    }), listener.deadline, context.controller.signal);
    const address = server.address();
    if (context.controller.signal.aborted || listener.controller.signal.aborted || listener.state !== 'disarmed'
      || address === null || typeof address === 'string' || address.address !== '127.0.0.1'
      || !Number.isSafeInteger(address.port) || address.port < 1024 || address.port > 65_535) fail();
    listener.port = address.port;
    // This nonce identifies this server instance; equal ports never authenticate a replacement.
    listener.identityDigest = digest({ nonce: randomBytes(32).toString('hex'), address: address.address, port: address.port });
    return listener;
  } catch {
    await closeOriginalListener(listener, performance.now() + 5_000);
    fail();
  }
}

function closeOriginalListener(listener: OwnedConcreteV2Listener, deadline: number): Promise<boolean> {
  if (listener.closePromise !== undefined) return listener.closePromise;
  listener.state = 'drained';
  if (listener.lifetime !== undefined) clearTimeout(listener.lifetime);
  listener.detached();
  // Publish the one shared promise before invoking callbacks that can reenter.
  listener.closePromise = Promise.resolve().then(async () => {
    const remaining = () => {
      const left = deadline - performance.now();
      return Number.isFinite(left) ? Math.max(0, Math.min(5_000, left)) : 0;
    };
    let connections = -1;
    const counted = await concreteSettlesWithin(new Promise<void>((resolveCount, rejectCount) => {
      try {
        listener.server.getConnections((error, count) => { if (error) rejectCount(error); else { connections = count; resolveCount(); } });
      } catch (error) { rejectCount(error); }
    }), Math.min(1_000, remaining()));
    const closed = await concreteSettlesWithin(new Promise<void>((resolveClose, rejectClose) => {
      try {
        listener.server.close(error => {
          if (error !== undefined && (error as NodeJS.ErrnoException).code !== 'ERR_SERVER_NOT_RUNNING') rejectClose(error);
          else resolveClose();
        });
        if (connections > 0 || !counted) listener.server.closeAllConnections();
      } catch (error) { rejectClose(error); }
    }), remaining());
    listener.state = closed ? 'closed' : 'drained';
    listener.context.listeners.delete(listener);
    return counted && connections === 0 && closed;
  });
  return listener.closePromise;
}

function object(value: unknown): value is object {
  return typeof value === 'object' && value !== null;
}

function fail(): never { throw new Error('graph_genesis_v2_production_invalid'); }
