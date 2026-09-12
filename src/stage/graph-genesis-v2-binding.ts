import { createHash } from 'node:crypto';

import { canonicalJson } from '../audit/canonical-json.js';
import { ARCHIVE_WORKER_PROTOCOL_VERSION } from './archive-worker-protocol.js';
import {
  PEER_SEMANTICS_V2_CONTRACT,
  type ExactGraphCandidateV2,
  type ExactGraphCandidateV2Authority,
} from './exact-production-graph-v2.js';
import { PACKAGE_STAGE_HARD_CEILINGS } from './profile.js';
import type { GraphGenesisLimits } from './graph-genesis.js';

const MiB = 1024 * 1024;
const SHA256 = /^[a-f0-9]{64}$/u;
const ID = /^[a-f0-9]{32}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const MAX_CLOSED_BYTES = MiB;
const MAX_CLOSED_DEPTH = 24;
const MAX_CLOSED_VALUES = 10_000;
const MAX_TEXT_BYTES = 4_096;
const GRAPH_GENESIS_V2_LIMIT_CEILINGS = deepFreeze({
  broker: {
    uniquePackageNames: 128,
    totalRequests: 256,
    concurrentRequests: 4,
    responseBytes: 4 * MiB,
    aggregateResponseBytes: 64 * MiB,
    requestTimeoutMs: 10_000,
  },
  completeTimeoutMs: 120_000,
  stdoutBytes: 256 * 1024,
  stderrBytes: 256 * 1024,
  packageJsonBytes: 64 * 1024,
  packageLockBytes: 4 * MiB,
} satisfies GraphGenesisLimits);

export const GRAPH_GENESIS_V2_POLICY = deepFreeze({
  schemaVersion: 1 as const,
  evaluatorName: 'graph_genesis_builtin_policy',
  evaluatorVersion: '1',
  decision: 'ask' as const,
  score: 70 as const,
  band: 'high' as const,
  reasonCodes: [
    'public_registry_metadata_disclosure',
    'local_npm_process',
    'persistent_audit_write',
    'candidate_artifact_write',
    'development_only_containment',
  ] as const,
});

export const SEMANTIC_CONTRACT_DIGEST = digest(PEER_SEMANTICS_V2_CONTRACT);

export const EXACT_COMPILATION_CONTRACT_V1 = deepFreeze({
  compilationContractVersion: 1 as const,
  semanticContract: PEER_SEMANTICS_V2_CONTRACT,
  semanticContractDigest: SEMANTIC_CONTRACT_DIGEST,
  profileId: 'filesystem-2026-7-10-candidate' as const,
  profileVersion: 1 as const,
  topPackage: {
    name: '@modelcontextprotocol/server-filesystem' as const,
    exactVersion: '2026.7.10' as const,
    exactEntrypointRelativePath: 'dist/index.js' as const,
  },
  registryOrigin: 'https://registry.npmjs.org/' as const,
  runtimeConstraint: {
    os: 'darwin' as const,
    architecture: 'arm64' as const,
    nodeMajor: 26 as const,
    nodeVersion: '26.3.1' as const,
    npmGraphGeneratorVersion: '11.16.0' as const,
    lockfileVersion: 3 as const,
  },
  materializationRulesVersion: 1 as const,
  archiveRulesVersion: 1 as const,
  workerProtocolVersion: ARCHIVE_WORKER_PROTOCOL_VERSION,
  limits: { ...PACKAGE_STAGE_HARD_CEILINGS },
  effectiveLockBytes: 4 * MiB,
  effectiveCandidateBytes: PEER_SEMANTICS_V2_CONTRACT.limits.candidateBytes,
  maxCandidateOutputs: 1 as const,
  candidateOutputRule: 'exclusive_new_private_file' as const,
});

export const COMPILATION_CONTRACT_DIGEST = digest(EXACT_COMPILATION_CONTRACT_V1);
export const GRAPH_GENESIS_V2_POLICY_DIGEST = digest(GRAPH_GENESIS_V2_POLICY);

export type ExactCompilationContractV1 = typeof EXACT_COMPILATION_CONTRACT_V1;

export type GraphGenesisPlanV3Input = Readonly<{
  planVersion: 3;
  candidateSchemaVersion: 2;
  peerSemanticsVersion: 1;
  compilationContractVersion: 1;
  semanticContract: typeof PEER_SEMANTICS_V2_CONTRACT;
  semanticContractDigest: string;
  compilationContract: ExactCompilationContractV1;
  compilationContractDigest: string;
  planId: string;
  targetName: '@modelcontextprotocol/server-filesystem';
  exactTargetVersion: '2026.7.10';
  registryOrigin: 'https://registry.npmjs.org/';
  platform: 'darwin';
  architecture: 'arm64';
  osBuild: string;
  nodeVersion: '26.3.1';
  npmVersion: '11.16.0';
  hostEvidenceDigest: string;
  runtimeVersionEvidenceDigest: string;
  runtimeSnapshots: Readonly<{
    node: string;
    npmCli: string;
    sandboxExec: string;
    brokerRuntime: string;
    probeRuntime: string;
    npmTree: string;
    brokerTree: string;
  }>;
  runtimeManifestDigest: string;
  containmentEvidenceDigest: string;
  containmentProfileDigest: string;
  containmentProviderId: 'macos-seatbelt-loopback-development-v0';
  workspaceBinding: string;
  brokerAddress: '127.0.0.1';
  brokerPort: number;
  routeTokenDigest: string;
  privatePathSetDigest: string;
  launchDigest: string;
  environmentDigest: string;
  executionCapsuleDigest: string;
  limits: GraphGenesisLimits;
  maxCandidateOutputs: 1;
  consequence: 'bounded_public_metadata_graph_genesis';
}>;

export type GraphGenesisPlanV3 = GraphGenesisPlanV3Input & Readonly<{
  planHash: string;
}>;

export type GraphGenesisProjectionV3 = Readonly<{
  projectionVersion: 3;
  planVersion: 3;
  planId: string;
  planHash: string;
  candidateSchemaVersion: 2;
  peerSemanticsVersion: 1;
  compilationContractVersion: 1;
  semanticContractDigest: string;
  compilationContractDigest: string;
  runtimeManifestDigest: string;
  target: '@modelcontextprotocol/server-filesystem@2026.7.10';
  registryOrigin: 'https://registry.npmjs.org/';
  host: Readonly<{ platform: 'darwin'; architecture: 'arm64'; osBuild: string }>;
  runtime: Readonly<{
    nodeVersion: '26.3.1';
    npmVersion: '11.16.0';
    containmentProviderId: 'macos-seatbelt-loopback-development-v0';
  }>;
  limits: GraphGenesisLimits;
  maxCandidateOutputs: 1;
  consequence: 'bounded_public_metadata_graph_genesis';
  statements: readonly [
    'metadata_only_no_artifact_install_or_package_execution',
    'private_disposable_workspace_writes',
    'development_only_containment',
    'direct_npm_npx_outside_apg_protection',
  ];
}>;

export type GraphGenesisEnvelopeV2Input = Readonly<{
  envelopeVersion: 2;
  sessionId: string;
  bootSessionDigest: string;
  auditSchemaDigest: string;
  auditFileIdentityDigest: string;
  auditDatabaseInstanceId: string;
  initialAuditChainTail: string;
  auditDurabilityProfileDigest: string;
  outputCanonicalPathDigest: string;
  outputParentIdentityDigest: string;
  outputRule: 'exclusive_new_private_file';
  dashboardInstanceId: string;
  dashboardPort: number;
  requestedAt: string;
  planDeadlineMonotonicMs: number;
}>;

export type GraphGenesisExecutionEnvelopeV2 = GraphGenesisEnvelopeV2Input & Readonly<{
  planVersion: 3;
  projectionVersion: 3;
  candidateSchemaVersion: 2;
  peerSemanticsVersion: 1;
  compilationContractVersion: 1;
  planId: string;
  planHash: string;
  projectionDigest: string;
  semanticContractDigest: string;
  compilationContractDigest: string;
  runtimeManifestDigest: string;
  hostEvidenceDigest: string;
  workspaceBinding: string;
  containmentProfileDigest: string;
  containmentEvidenceDigest: string;
  routeTokenDigest: string;
  launchDigest: string;
  environmentDigest: string;
  executionCapsuleDigest: string;
  policy: typeof GRAPH_GENESIS_V2_POLICY;
  policyDigest: string;
  approvalTtlMs: 120000;
  limitsDigest: string;
  consequence: 'bounded_public_metadata_graph_genesis';
  executionEnvelopeHash: string;
}>;

export type PreparedGraphGenesisV2Binding = Readonly<{
  plan: GraphGenesisPlanV3;
  projection: GraphGenesisProjectionV3;
  envelope: GraphGenesisExecutionEnvelopeV2;
  privateBinding: object;
}>;

const PLAN_KEYS = [
  'planVersion', 'candidateSchemaVersion', 'peerSemanticsVersion',
  'compilationContractVersion', 'semanticContract', 'semanticContractDigest',
  'compilationContract', 'compilationContractDigest', 'planId', 'targetName',
  'exactTargetVersion', 'registryOrigin', 'platform', 'architecture', 'osBuild',
  'nodeVersion', 'npmVersion', 'hostEvidenceDigest', 'runtimeVersionEvidenceDigest',
  'runtimeSnapshots', 'runtimeManifestDigest', 'containmentEvidenceDigest',
  'containmentProfileDigest', 'containmentProviderId', 'workspaceBinding',
  'brokerAddress', 'brokerPort', 'routeTokenDigest', 'privatePathSetDigest',
  'launchDigest', 'environmentDigest', 'executionCapsuleDigest', 'limits',
  'maxCandidateOutputs', 'consequence',
] as const;
const ENVELOPE_KEYS = [
  'envelopeVersion', 'sessionId', 'bootSessionDigest', 'auditSchemaDigest',
  'auditFileIdentityDigest', 'auditDatabaseInstanceId', 'initialAuditChainTail',
  'auditDurabilityProfileDigest', 'outputCanonicalPathDigest',
  'outputParentIdentityDigest', 'outputRule', 'dashboardInstanceId', 'dashboardPort',
  'requestedAt', 'planDeadlineMonotonicMs',
] as const;
const SNAPSHOT_KEYS = [
  'node', 'npmCli', 'sandboxExec', 'brokerRuntime', 'probeRuntime', 'npmTree', 'brokerTree',
] as const;
const LIMIT_KEYS = [
  'broker', 'completeTimeoutMs', 'stdoutBytes', 'stderrBytes',
  'packageJsonBytes', 'packageLockBytes',
] as const;
const BROKER_LIMIT_KEYS = [
  'uniquePackageNames', 'totalRequests', 'concurrentRequests', 'responseBytes',
  'aggregateResponseBytes', 'requestTimeoutMs',
] as const;

type OwnedBinding = Readonly<{
  plan: GraphGenesisPlanV3;
  projection: GraphGenesisProjectionV3;
  envelope: GraphGenesisExecutionEnvelopeV2;
}>;

export class GraphGenesisV2BindingAuthority {
  readonly #plans = new WeakSet<object>();
  readonly #projections = new WeakSet<object>();
  readonly #envelopes = new WeakSet<object>();
  readonly #privateBindings = new WeakSet<object>();
  readonly #pairs = new WeakMap<object, OwnedBinding>();

  constructor(private readonly candidates: ExactGraphCandidateV2Authority) {}

  prepare(input: Readonly<{
    plan: GraphGenesisPlanV3Input;
    envelope: GraphGenesisEnvelopeV2Input;
  }>): PreparedGraphGenesisV2Binding {
    const clonedInput = record(cloneClosedJson(input));
    exactKeys(clonedInput, ['plan', 'envelope']);
    const plan = this.#createPlan(clonedInput.plan);
    const projection = this.#createProjection(plan);
    const envelope = this.#createEnvelope(plan, projection, clonedInput.envelope);
    const privateBinding = deepFreeze({ bindingVersion: 1 as const });
    const pair = Object.freeze({ plan, projection, envelope });
    this.#plans.add(plan);
    this.#projections.add(projection);
    this.#envelopes.add(envelope);
    this.#privateBindings.add(privateBinding);
    this.#pairs.set(privateBinding, pair);
    return Object.freeze({ plan, projection, envelope, privateBinding });
  }

  authenticatesPair(
    plan: unknown,
    projection: unknown,
    envelope: unknown,
    privateBinding: unknown,
  ): plan is GraphGenesisPlanV3 {
    if (!isObject(privateBinding)) return false;
    const pair = this.#pairs.get(privateBinding);
    return isObject(plan) && this.#plans.has(plan)
      && isObject(projection) && this.#projections.has(projection)
      && isObject(envelope) && this.#envelopes.has(envelope)
      && this.#privateBindings.has(privateBinding)
      && pair?.plan === plan && pair.projection === projection && pair.envelope === envelope;
  }

  authenticatesCandidate(
    plan: unknown,
    projection: unknown,
    envelope: unknown,
    privateBinding: unknown,
    candidate: unknown,
  ): candidate is ExactGraphCandidateV2 {
    if (!this.authenticatesPair(plan, projection, envelope, privateBinding)
      || !this.candidates.authenticates(candidate)) return false;
    return candidateMatchesContract(candidate, plan.compilationContract);
  }

  #createPlan(value: unknown): GraphGenesisPlanV3 {
    const input = record(value);
    exactKeys(input, PLAN_KEYS);
    if (input.planVersion !== 3 || input.candidateSchemaVersion !== 2
      || input.peerSemanticsVersion !== 1 || input.compilationContractVersion !== 1
      || canonicalJson(input.semanticContract) !== canonicalJson(PEER_SEMANTICS_V2_CONTRACT)
      || input.semanticContractDigest !== SEMANTIC_CONTRACT_DIGEST
      || canonicalJson(input.compilationContract) !== canonicalJson(EXACT_COMPILATION_CONTRACT_V1)
      || input.compilationContractDigest !== COMPILATION_CONTRACT_DIGEST
      || !ID.test(input.planId as string)
      || input.targetName !== EXACT_COMPILATION_CONTRACT_V1.topPackage.name
      || input.exactTargetVersion !== EXACT_COMPILATION_CONTRACT_V1.topPackage.exactVersion
      || input.registryOrigin !== EXACT_COMPILATION_CONTRACT_V1.registryOrigin
      || input.platform !== 'darwin' || input.architecture !== 'arm64'
      || input.nodeVersion !== '26.3.1' || input.npmVersion !== '11.16.0'
      || !safeText(input.osBuild)
      || input.containmentProviderId !== 'macos-seatbelt-loopback-development-v0'
      || input.brokerAddress !== '127.0.0.1'
      || !integer(input.brokerPort, 1024, 65_535)
      || input.maxCandidateOutputs !== 1
      || input.consequence !== 'bounded_public_metadata_graph_genesis') fail();
    for (const key of [
      'hostEvidenceDigest', 'runtimeVersionEvidenceDigest', 'runtimeManifestDigest',
      'containmentEvidenceDigest', 'containmentProfileDigest', 'workspaceBinding',
      'routeTokenDigest', 'privatePathSetDigest', 'launchDigest', 'environmentDigest',
      'executionCapsuleDigest',
    ]) if (!isDigest(input[key])) fail();
    const snapshots = normalizeSnapshots(input.runtimeSnapshots);
    const limits = normalizeGraphGenesisLimits(input.limits);
    const unsigned = deepFreeze({
      ...(input as unknown as GraphGenesisPlanV3Input),
      semanticContract: PEER_SEMANTICS_V2_CONTRACT,
      compilationContract: EXACT_COMPILATION_CONTRACT_V1,
      runtimeSnapshots: snapshots,
      limits,
    });
    return deepFreeze({ ...unsigned, planHash: digest(unsigned) });
  }

  #createProjection(plan: GraphGenesisPlanV3): GraphGenesisProjectionV3 {
    return deepFreeze({
      projectionVersion: 3 as const,
      planVersion: 3 as const,
      planId: plan.planId,
      planHash: plan.planHash,
      candidateSchemaVersion: 2 as const,
      peerSemanticsVersion: 1 as const,
      compilationContractVersion: 1 as const,
      semanticContractDigest: plan.semanticContractDigest,
      compilationContractDigest: plan.compilationContractDigest,
      runtimeManifestDigest: plan.runtimeManifestDigest,
      target: '@modelcontextprotocol/server-filesystem@2026.7.10' as const,
      registryOrigin: 'https://registry.npmjs.org/' as const,
      host: {
        platform: 'darwin' as const,
        architecture: 'arm64' as const,
        osBuild: plan.osBuild,
      },
      runtime: {
        nodeVersion: '26.3.1' as const,
        npmVersion: '11.16.0' as const,
        containmentProviderId: 'macos-seatbelt-loopback-development-v0' as const,
      },
      limits: plan.limits,
      maxCandidateOutputs: 1 as const,
      consequence: 'bounded_public_metadata_graph_genesis' as const,
      statements: [
        'metadata_only_no_artifact_install_or_package_execution',
        'private_disposable_workspace_writes',
        'development_only_containment',
        'direct_npm_npx_outside_apg_protection',
      ] as const,
    });
  }

  #createEnvelope(
    plan: GraphGenesisPlanV3,
    projection: GraphGenesisProjectionV3,
    value: unknown,
  ): GraphGenesisExecutionEnvelopeV2 {
    const input = record(value);
    exactKeys(input, ENVELOPE_KEYS);
    if (input.envelopeVersion !== 2 || !ID.test(input.sessionId as string)
      || !UUID.test(input.auditDatabaseInstanceId as string)
      || !UUID.test(input.dashboardInstanceId as string)
      || input.outputRule !== 'exclusive_new_private_file'
      || !integer(input.dashboardPort, 1024, 65_535)
      || !canonicalTimestamp(input.requestedAt)
      || !jsonNumber(input.planDeadlineMonotonicMs)
      || (input.planDeadlineMonotonicMs as number) <= 0) fail();
    for (const key of [
      'bootSessionDigest', 'auditSchemaDigest', 'auditFileIdentityDigest',
      'initialAuditChainTail', 'auditDurabilityProfileDigest',
      'outputCanonicalPathDigest', 'outputParentIdentityDigest',
    ]) if (!isDigest(input[key])) fail();
    const projectionDigest = digest(projection);
    const unsigned = deepFreeze({
      ...(input as unknown as GraphGenesisEnvelopeV2Input),
      planVersion: 3 as const,
      projectionVersion: 3 as const,
      candidateSchemaVersion: 2 as const,
      peerSemanticsVersion: 1 as const,
      compilationContractVersion: 1 as const,
      planId: plan.planId,
      planHash: plan.planHash,
      projectionDigest,
      semanticContractDigest: plan.semanticContractDigest,
      compilationContractDigest: plan.compilationContractDigest,
      runtimeManifestDigest: plan.runtimeManifestDigest,
      hostEvidenceDigest: plan.hostEvidenceDigest,
      workspaceBinding: plan.workspaceBinding,
      containmentProfileDigest: plan.containmentProfileDigest,
      containmentEvidenceDigest: plan.containmentEvidenceDigest,
      routeTokenDigest: plan.routeTokenDigest,
      launchDigest: plan.launchDigest,
      environmentDigest: plan.environmentDigest,
      executionCapsuleDigest: plan.executionCapsuleDigest,
      policy: GRAPH_GENESIS_V2_POLICY,
      policyDigest: GRAPH_GENESIS_V2_POLICY_DIGEST,
      approvalTtlMs: 120_000 as const,
      limitsDigest: digest(plan.limits),
      consequence: plan.consequence,
    });
    return deepFreeze({ ...unsigned, executionEnvelopeHash: digest(unsigned) });
  }
}

function candidateMatchesContract(
  candidate: ExactGraphCandidateV2,
  contract: ExactCompilationContractV1,
): boolean {
  return candidate.candidateSchemaVersion === 2
    && canonicalJson(candidate.semanticContract) === canonicalJson(contract.semanticContract)
    && candidate.profileId === contract.profileId
    && candidate.profileVersion === contract.profileVersion
    && canonicalJson(candidate.topPackage) === canonicalJson(contract.topPackage)
    && candidate.registryOrigin === contract.registryOrigin
    && canonicalJson(candidate.runtimeConstraint) === canonicalJson(contract.runtimeConstraint)
    && candidate.materializationRulesVersion === contract.materializationRulesVersion
    && candidate.archiveRulesVersion === contract.archiveRulesVersion
    && candidate.workerProtocolVersion === contract.workerProtocolVersion
    && canonicalJson(candidate.limits) === canonicalJson(contract.limits)
    && Buffer.byteLength(canonicalJson(candidate)) <= contract.effectiveCandidateBytes;
}

function normalizeSnapshots(value: unknown): GraphGenesisPlanV3Input['runtimeSnapshots'] {
  const input = record(value);
  exactKeys(input, SNAPSHOT_KEYS);
  const output = Object.create(null) as Record<(typeof SNAPSHOT_KEYS)[number], string>;
  for (const key of SNAPSHOT_KEYS) {
    if (!isDigest(input[key])) fail();
    output[key] = input[key] as string;
  }
  return deepFreeze(output);
}

function normalizeGraphGenesisLimits(value: unknown): GraphGenesisLimits {
  const input = record(value);
  exactKeys(input, LIMIT_KEYS);
  const broker = record(input.broker);
  exactKeys(broker, BROKER_LIMIT_KEYS);
  const brokerCeilings = GRAPH_GENESIS_V2_LIMIT_CEILINGS.broker;
  if (!integer(broker.uniquePackageNames, 1, brokerCeilings.uniquePackageNames)
    || !integer(broker.totalRequests, broker.uniquePackageNames as number, brokerCeilings.totalRequests)
    || !integer(broker.concurrentRequests, 1, brokerCeilings.concurrentRequests)
    || !integer(broker.responseBytes, 1, brokerCeilings.responseBytes)
    || !integer(broker.aggregateResponseBytes, broker.responseBytes as number, brokerCeilings.aggregateResponseBytes)
    || !integer(broker.requestTimeoutMs, 1, brokerCeilings.requestTimeoutMs)
    || !integer(input.completeTimeoutMs, 1, GRAPH_GENESIS_V2_LIMIT_CEILINGS.completeTimeoutMs)
    || !integer(input.stdoutBytes, 1, GRAPH_GENESIS_V2_LIMIT_CEILINGS.stdoutBytes)
    || !integer(input.stderrBytes, 1, GRAPH_GENESIS_V2_LIMIT_CEILINGS.stderrBytes)
    || !integer(input.packageJsonBytes, 1, GRAPH_GENESIS_V2_LIMIT_CEILINGS.packageJsonBytes)
    || !integer(input.packageLockBytes, 1, GRAPH_GENESIS_V2_LIMIT_CEILINGS.packageLockBytes)) fail();
  return deepFreeze({
    broker: {
      uniquePackageNames: broker.uniquePackageNames as number,
      totalRequests: broker.totalRequests as number,
      concurrentRequests: broker.concurrentRequests as number,
      responseBytes: broker.responseBytes as number,
      aggregateResponseBytes: broker.aggregateResponseBytes as number,
      requestTimeoutMs: broker.requestTimeoutMs as number,
    },
    completeTimeoutMs: input.completeTimeoutMs as number,
    stdoutBytes: input.stdoutBytes as number,
    stderrBytes: input.stderrBytes as number,
    packageJsonBytes: input.packageJsonBytes as number,
    packageLockBytes: input.packageLockBytes as number,
  });
}

function cloneClosedJson(value: unknown): unknown {
  let visits = 0;
  const active = new WeakSet<object>();
  const clone = (item: unknown, depth: number): unknown => {
    visits += 1;
    if (visits > MAX_CLOSED_VALUES || depth > MAX_CLOSED_DEPTH) fail();
    if (item === null || typeof item === 'boolean') return item;
    if (typeof item === 'string') {
      if (Buffer.byteLength(item) > MAX_TEXT_BYTES) fail();
      return item;
    }
    if (typeof item === 'number') {
      if (!jsonNumber(item)) fail();
      return item;
    }
    if (!isObject(item) || active.has(item)) fail();
    active.add(item);
    try {
      if (Array.isArray(item)) {
        if (Object.getPrototypeOf(item) !== Array.prototype) fail();
        const keys = Reflect.ownKeys(item);
        for (const key of keys) {
          if (key === 'length') continue;
          if (typeof key !== 'string' || !/^(?:0|[1-9]\d*)$/u.test(key)) fail();
          const descriptor = Object.getOwnPropertyDescriptor(item, key);
          if (!descriptor || !descriptor.enumerable || !('value' in descriptor)
            || descriptor.value === undefined) fail();
        }
        if (Object.keys(item).length !== item.length) fail();
        return item.map((child) => clone(child, depth + 1));
      }
      const input = record(item);
      const output: Record<string, unknown> = Object.create(null);
      for (const key of Object.keys(input)) output[key] = clone(input[key], depth + 1);
      return output;
    } finally {
      active.delete(item);
    }
  };
  const cloned = clone(value, 0);
  if (Buffer.byteLength(canonicalJson(cloned)) > MAX_CLOSED_BYTES) fail();
  return cloned;
}

function record(value: unknown): Record<string, unknown> {
  if (!isObject(value) || Array.isArray(value)
    || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) fail();
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') fail();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !('value' in descriptor)
      || descriptor.value === undefined) fail();
  }
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): void {
  const actual = Object.keys(value).sort(compareText);
  const required = [...expected].sort(compareText);
  if (canonicalJson(actual) !== canonicalJson(required)) fail();
}

function safeText(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0
    && Buffer.byteLength(value) <= 256 && /^[\x20-\x7e]+$/u.test(value);
}

function isDigest(value: unknown): value is string {
  return typeof value === 'string' && SHA256.test(value);
}

function integer(value: unknown, minimum: number, maximum: number): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value)
    && !Object.is(value, -0) && value >= minimum && value <= maximum;
}

function jsonNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value)
    && Math.abs(value) <= Number.MAX_SAFE_INTEGER && !Object.is(value, -0);
}

function canonicalTimestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value;
}

function digest(value: unknown): string {
  return createHash('sha256').update(canonicalJson(value)).digest('hex');
}

function deepFreeze<T>(value: T): T {
  if (isObject(value) && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isObject(value: unknown): value is object {
  return typeof value === 'object' && value !== null;
}

function fail(): never {
  throw new Error('graph_genesis_v2_binding_invalid');
}
