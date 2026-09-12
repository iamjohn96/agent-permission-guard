import { createHash, randomBytes } from 'node:crypto';
import { constants, existsSync } from 'node:fs';
import { lstat, open, realpath, type FileHandle } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';
import { basename, dirname, join, relative, resolve, sep } from 'node:path';

import { LocalApprovalService } from '../approval/service.js';
import type { ApprovalOutcome, ApprovalTicket } from '../approval/types.js';
import { AuditQueryService } from '../audit/query-service.js';
import { SqliteAuditRecorder, type AuditCall } from '../audit/recorder.js';
import type { ReceiptContext } from '../audit/receipt.js';
import { canonicalJson } from '../audit/canonical-json.js';
import {
  authenticatesExistingGraphGenesisAuditDatabase,
  revalidatesExistingGraphGenesisAuditDatabase,
  type ExistingGraphGenesisAuditDatabase,
} from '../db/database.js';
import { startDashboard, type DashboardHandle } from '../dashboard/server.js';
import { staticPolicyIdentity } from '../policy/identity.js';
import type {
  AuthenticatedRuntimeTreeSnapshot,
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
}>;

type OwnedSealedAuthorization = Readonly<{
  sealed: AuthenticatedGraphGenesisV2SealedAuthorization;
  prepared: PreparedGraphGenesisV2Production;
  context: AuthenticatedGraphGenesisV2SessionContext;
  output: AuthenticatedGraphGenesisV2OutputIntent;
  actionId: string;
  approvalId: string;
  startByMonotonicMs: number;
  executionDeadlineMonotonicMs: number;
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
}>;

type OwnedOutputIntent = Readonly<{
  publicIntent: AuthenticatedGraphGenesisV2OutputIntent;
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
}>;

/** Production-only bridge: it has no raw-digest capture API. */
export class ProductionGraphGenesisV2SnapshotAuthority {
  readonly #owned = new WeakMap<object, OwnedProductionBundle>();

  constructor(
    private readonly files: RuntimeFileSnapshotAuthority,
    private readonly trees: RuntimeTreeSnapshotAuthority,
    private readonly versions: OwnedRuntimeVersionAuthority,
    private readonly hosts: OwnedHostPlatformAuthority,
    private readonly workspaces: FinalizedGraphGenesisWorkspaceAuthority,
    private readonly containment: OwnedContainmentProbeAuthority,
    private readonly profiles: SeatbeltLoopbackContainmentAuthority,
  ) {}

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
 * memory-only seal. Candidate creation and every execution consumer remain
 * unavailable.
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
  readonly #bindings = new GraphGenesisV2BindingAuthority(new ExactGraphCandidateV2Authority());

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
    const bundle = this.#snapshotBundle(snapshot);
    const ownedContext = this.#contexts.get(context);
    const ownedOutput = this.#outputs.get(output);
    if (ownedContext === undefined || ownedOutput === undefined || ownedOutput.context !== context
      || ownedContext.controller.signal.aborted || !ownedContext.outputs.has(ownedOutput)) fail();
    this.#assertPolicyIdentity();
    const requestedAt = new Date().toISOString();
    const deadline = performance.now() + PREPARATION_WINDOW_MS;
    if (!Number.isFinite(deadline) || deadline <= 0 || deadline > Number.MAX_SAFE_INTEGER) fail();

    await this.snapshots.revalidate(snapshot, {
      signal: ownedContext.controller.signal,
      monotonicNow: () => performance.now(),
      deadline,
    });
    await this.#revalidateOutput(ownedOutput);
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
    }));
    return prepared;
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
    try {
      const callerSignal = authorizationSignal(options);
      const owned = this.#ownedPrepared(prepared);
      if (this.#usedPrepared.has(prepared) || this.#usedContexts.has(owned.context)) fail();
      const context = this.#contexts.get(owned.context);
      const output = this.#outputs.get(owned.output);
      if (context === undefined || output === undefined || output.context !== owned.context
        || !context.outputs.has(output)) fail();
      this.#usedPrepared.add(prepared);
      this.#usedContexts.add(owned.context);
      signalLink = linkAuthorizationSignals(context.controller.signal, callerSignal);
      const fence = createLifecycleFence(prepared.envelope, signalLink.signal);
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
        prepared,
        context: owned.context,
        output: owned.output,
        actionId: audit.actionId,
        approvalId: activeTicket.request.id,
        startByMonotonicMs,
        executionDeadlineMonotonicMs: startByMonotonicMs + EXECUTION_WINDOW_MS,
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
      return fail();
    } finally {
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
      && this.#usedPrepared.has(prepared)
      && this.#usedContexts.has(owned.context);
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
    this.#contexts.get(owned.context)?.outputs.delete(owned);
    this.#activeOutputPaths.delete(owned.canonicalPath);
    try {
      await owned.descriptor.close();
    } catch {
      fail();
    }
  }

  async closeContext(context: AuthenticatedGraphGenesisV2SessionContext): Promise<void> {
    const owned = this.#contexts.get(context);
    if (owned === undefined) fail();
    this.#contexts.delete(context);
    owned.controller.abort();
    const descriptors = [...owned.outputs];
    owned.outputs.clear();
    for (const output of descriptors) {
      this.#outputs.delete(output.publicIntent);
      this.#activeOutputPaths.delete(output.canonicalPath);
    }
    this.#activeDashboardInstanceIds.delete(owned.dashboard.instanceId);
    this.#activeDashboardPorts.delete(owned.dashboardPort);
    owned.approvals.close();
    const results = await Promise.allSettled([
      ...descriptors.map((output) => output.descriptor.close()),
      owned.dashboard.close(),
    ]);
    if (results.some((result) => result.status === 'rejected')) fail();
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

function assertDistinctRoles(input: OwnedProductionBundle): void {
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

function assertStructuralRelationships(input: OwnedProductionBundle): void {
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

function object(value: unknown): value is object {
  return typeof value === 'object' && value !== null;
}

function fail(): never { throw new Error('graph_genesis_v2_production_invalid'); }
