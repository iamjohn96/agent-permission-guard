import { createHash, randomBytes } from 'node:crypto';

import { canonicalJson } from '../audit/canonical-json.js';
import {
  ARCHIVE_WORKER_PROTOCOL_VERSION,
} from './archive-worker-protocol.js';
import {
  PACKAGE_STAGE_HARD_CEILINGS,
  PackageStageError,
  parseSha512Integrity,
  validatePortableRelativePath,
} from './profile.js';
import type { PackageDependencyEdge, PackageStageLimits } from './types.js';

const SHA256 = /^[a-f0-9]{64}$/u;
const EXACT_VERSION = /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/u;
const PACKAGE_NAME = /^(?:@[a-z0-9][a-z0-9._-]*\/[a-z0-9][a-z0-9._-]*|[a-z0-9][a-z0-9._-]*)$/u;
const IDENTIFIER = /^[a-z0-9][a-z0-9._-]{0,127}$/u;

export type ExactGraphRuntimeConstraint = Readonly<{
  os: 'darwin';
  architecture: 'arm64';
  nodeMajor: 26;
  nodeVersion: string;
  npmGraphGeneratorVersion: string;
  lockfileVersion: 3;
}>;

export type ExactGraphCandidateNode = Readonly<{
  installPath: string;
  packageName: string;
  exactVersion: string;
  tarballUrl: string;
  sha512Integrity: string;
  dependencyEdges: readonly PackageDependencyEdge[];
  expectedLifecycleScriptNames: readonly string[];
}>;

export type ExactGraphCandidate = Readonly<{
  candidateSchemaVersion: 1;
  profileId: string;
  profileVersion: number;
  topPackage: Readonly<{
    name: string;
    exactVersion: string;
    exactEntrypointRelativePath: string;
  }>;
  registryOrigin: string;
  runtimeConstraint: ExactGraphRuntimeConstraint;
  graphNodes: readonly ExactGraphCandidateNode[];
  materializationRulesVersion: number;
  archiveRulesVersion: number;
  workerProtocolVersion: typeof ARCHIVE_WORKER_PROTOCOL_VERSION;
  limits: PackageStageLimits;
  candidateDigest: string;
}>;

export type ExactGraphCandidateInput = Readonly<{
  profileId: string;
  profileVersion: number;
  topPackage: ExactGraphCandidate['topPackage'];
  registryOrigin: string;
  runtimeConstraint: ExactGraphRuntimeConstraint;
  materializationRulesVersion: number;
  archiveRulesVersion: number;
  workerProtocolVersion: typeof ARCHIVE_WORKER_PROTOCOL_VERSION;
  limits: PackageStageLimits;
  packageLock: unknown;
}>;

export type GraphMetadataObservation = Readonly<{
  packageName: string;
  exactVersion: string;
  tarballUrl: string;
  sha512Integrity: string;
  responseBytes: number;
}>;

export type GraphMetadataObservationSet = Readonly<{
  observationSchemaVersion: 1;
  candidateDigest: string;
  registryOrigin: string;
  observedAt: string;
  expiresAt: string;
  observations: readonly GraphMetadataObservation[];
  observationDigest: string;
}>;

export type GraphMetadataRequest = Readonly<{
  registryOrigin: string;
  packageName: string;
  exactVersion: string;
  headers: Readonly<{ accept: 'application/json' }>;
}>;

export type GraphMetadataResponse = Readonly<{
  status: number;
  contentType: string;
  responseBytes: number;
  redirected: boolean;
  finalUrl: string;
  packageName: string;
  exactVersion: string;
  tarballUrl: string;
  sha512Integrity: string;
}>;

export interface ExactGraphMetadataTransport {
  fetch(request: GraphMetadataRequest, signal?: AbortSignal): Promise<GraphMetadataResponse>;
}

export type GraphMetadataLimits = Readonly<{
  responseBytes: number;
  aggregateBytes: number;
  freshnessMs: number;
  requestTimeoutMs: number;
  totalTimeoutMs: number;
}>;

export type ReadOnlyArtifactIdentity = Readonly<{
  installPaths: readonly string[];
  packageName: string;
  exactVersion: string;
  tarballUrl: string;
  sha512Integrity: string;
}>;

export type ReadOnlyArtifactAcceptancePlan = Readonly<{
  planVersion: 1;
  acceptanceSessionId: string;
  candidateDigest: string;
  metadataObservationDigest: string;
  metadataExpiresAt: string;
  registryOrigin: string;
  artifacts: readonly ReadOnlyArtifactIdentity[];
  limits: PackageStageLimits;
  runtimeDigest: string;
  workerProtocolVersion: typeof ARCHIVE_WORKER_PROTOCOL_VERSION;
  quarantineRootBinding: string;
  artifactRequestTimeoutMs: number;
  totalArtifactTimeoutMs: number;
  consequence: 'exact_artifact_download_and_read_only_inspection';
  planHash: string;
}>;

export type SyntheticReadOnlyArtifactApproval = Readonly<{
  approvalVersion: 1;
  approvalId: string;
  planHash: string;
  consequence: 'exact_artifact_download_and_read_only_inspection';
  expiresAt: string;
}>;

export type AcceptedArtifactEvidence = Readonly<{
  installPaths: readonly string[];
  packageName: string;
  exactVersion: string;
  tarballUrl: string;
  sha512Integrity: string;
  compressedBytes: number;
  expandedBytes: number;
  archiveEntryCount: number;
  archiveTranscriptDigest: string;
  packageJsonBodySha256: string;
  packageManifestProjectionDigest: string;
}>;

export type CompleteReadOnlyAcceptanceEvidence = Readonly<{
  evidenceVersion: 1;
  candidateDigest: string;
  planHash: string;
  artifacts: readonly AcceptedArtifactEvidence[];
  cleanupComplete: true;
  evidenceDigest: string;
}>;

export type AcceptedProductionGraphProfile = Readonly<{
  productionProfileSchemaVersion: 1;
  candidate: ExactGraphCandidate;
  artifactAcceptance: readonly AcceptedArtifactEvidence[];
  productionProfileDigest: string;
}>;

export class ExactGraphCandidateAuthority {
  readonly #authenticated = new WeakSet<object>();

  compile(input: ExactGraphCandidateInput): ExactGraphCandidate {
    const normalized = normalizeCandidateInput(input);
    const graphNodes = compileLockGraph(input.packageLock, normalized);
    const unsigned = deepFreeze({
      candidateSchemaVersion: 1 as const,
      ...normalized,
      graphNodes,
    });
    const candidate = deepFreeze({ ...unsigned, candidateDigest: sha256(canonicalJson(unsigned)) });
    this.#authenticated.add(candidate);
    return candidate;
  }

  authenticates(candidate: unknown): candidate is ExactGraphCandidate {
    return typeof candidate === 'object' && candidate !== null && this.#authenticated.has(candidate);
  }

  assertAuthenticates(candidate: unknown): asserts candidate is ExactGraphCandidate {
    if (!this.authenticates(candidate)) throw new PackageStageError('profile_not_authenticated');
  }
}

export class ExactGraphMetadataAuthority {
  readonly #authenticated = new WeakSet<object>();

  constructor(private readonly candidateAuthority: ExactGraphCandidateAuthority) {}

  async confirm(
    candidate: ExactGraphCandidate,
    transport: ExactGraphMetadataTransport,
    limits: GraphMetadataLimits,
    now = new Date(),
    signal?: AbortSignal,
  ): Promise<GraphMetadataObservationSet> {
    this.candidateAuthority.assertAuthenticates(candidate);
    assertMetadataLimits(limits);
    if (!Number.isFinite(now.getTime())) throw new PackageStageError('graph_metadata_invalid');
    const expected = uniqueArtifactIdentities(candidate.graphNodes);
    const observations: GraphMetadataObservation[] = [];
    let aggregateBytes = 0;
    const startedAt = Date.now();
    for (const item of expected) {
      if (signal?.aborted === true) throw new PackageStageError('artifact_cancelled');
      const remainingMs = limits.totalTimeoutMs - (Date.now() - startedAt);
      if (remainingMs <= 0) throw new PackageStageError('graph_metadata_incomplete');
      const response = await fetchMetadataWithTimeout(transport, Object.freeze({
        registryOrigin: candidate.registryOrigin,
        packageName: item.packageName,
        exactVersion: item.exactVersion,
        headers: Object.freeze({ accept: 'application/json' as const }),
      }), Math.min(limits.requestTimeoutMs, remainingMs), signal);
      aggregateBytes += response.responseBytes;
      if (
        response.status !== 200
        || response.contentType.toLowerCase().split(';', 1)[0] !== 'application/json'
        || !Number.isSafeInteger(response.responseBytes)
        || response.responseBytes <= 0
        || response.responseBytes > limits.responseBytes
        || aggregateBytes > limits.aggregateBytes
        || response.redirected
        || response.finalUrl !== metadataUrl(candidate.registryOrigin, item.packageName, item.exactVersion)
        || response.packageName !== item.packageName
        || response.exactVersion !== item.exactVersion
        || response.tarballUrl !== item.tarballUrl
        || response.sha512Integrity !== item.sha512Integrity
      ) {
        throw new PackageStageError('graph_metadata_invalid');
      }
      observations.push(Object.freeze({
        packageName: item.packageName,
        exactVersion: item.exactVersion,
        tarballUrl: item.tarballUrl,
        sha512Integrity: item.sha512Integrity,
        responseBytes: response.responseBytes,
      }));
    }
    if (observations.length !== expected.length) throw new PackageStageError('graph_metadata_incomplete');
    observations.sort(compareArtifactIdentity);
    const observedAt = now.toISOString();
    const expiresAt = new Date(now.getTime() + limits.freshnessMs).toISOString();
    const unsigned = deepFreeze({
      observationSchemaVersion: 1 as const,
      candidateDigest: candidate.candidateDigest,
      registryOrigin: candidate.registryOrigin,
      observedAt,
      expiresAt,
      observations: Object.freeze(observations),
    });
    const result = deepFreeze({ ...unsigned, observationDigest: sha256(canonicalJson(unsigned)) });
    this.#authenticated.add(result);
    return result;
  }

  authenticates(candidate: unknown): candidate is GraphMetadataObservationSet {
    return typeof candidate === 'object' && candidate !== null && this.#authenticated.has(candidate);
  }

  assertAuthenticates(candidate: unknown): asserts candidate is GraphMetadataObservationSet {
    if (!this.authenticates(candidate)) throw new PackageStageError('graph_metadata_incomplete');
  }
}

export class ReadOnlyArtifactAcceptancePlanAuthority {
  readonly #authenticated = new WeakSet<object>();

  constructor(
    private readonly candidateAuthority: ExactGraphCandidateAuthority,
    private readonly metadataAuthority: ExactGraphMetadataAuthority,
  ) {}

  create(
    candidate: ExactGraphCandidate,
    metadata: GraphMetadataObservationSet,
    input: Readonly<{
      acceptanceSessionId?: string;
      runtimeDigest: string;
      quarantineRootBinding: string;
      artifactRequestTimeoutMs: number;
      totalArtifactTimeoutMs: number;
      now?: Date;
    }>,
  ): ReadOnlyArtifactAcceptancePlan {
    this.candidateAuthority.assertAuthenticates(candidate);
    this.metadataAuthority.assertAuthenticates(metadata);
    const now = input.now ?? new Date();
    if (
      metadata.candidateDigest !== candidate.candidateDigest
      || new Date(metadata.expiresAt).getTime() <= now.getTime()
      || !SHA256.test(input.runtimeDigest)
      || !SHA256.test(input.quarantineRootBinding)
      || !isBoundedInteger(input.artifactRequestTimeoutMs, 100, 120_000)
      || !isBoundedInteger(input.totalArtifactTimeoutMs, input.artifactRequestTimeoutMs, 30 * 60 * 1000)
    ) {
      throw new PackageStageError(new Date(metadata.expiresAt).getTime() <= now.getTime()
        ? 'metadata_expired'
        : 'artifact_plan_invalid');
    }
    const acceptanceSessionId = input.acceptanceSessionId ?? randomBytes(16).toString('hex');
    if (!/^[a-f0-9]{32}$/u.test(acceptanceSessionId)) throw new PackageStageError('artifact_plan_invalid');
    const artifacts = uniqueArtifactIdentities(candidate.graphNodes).map((identity) => Object.freeze({
      ...identity,
      installPaths: Object.freeze(candidate.graphNodes
        .filter((node) => sameArtifact(node, identity))
        .map((node) => node.installPath)
        .sort(compareText)),
    }));
    const unsigned = deepFreeze({
      planVersion: 1 as const,
      acceptanceSessionId,
      candidateDigest: candidate.candidateDigest,
      metadataObservationDigest: metadata.observationDigest,
      metadataExpiresAt: metadata.expiresAt,
      registryOrigin: candidate.registryOrigin,
      artifacts: Object.freeze(artifacts),
      limits: candidate.limits,
      runtimeDigest: input.runtimeDigest,
      workerProtocolVersion: candidate.workerProtocolVersion,
      quarantineRootBinding: input.quarantineRootBinding,
      artifactRequestTimeoutMs: input.artifactRequestTimeoutMs,
      totalArtifactTimeoutMs: input.totalArtifactTimeoutMs,
      consequence: 'exact_artifact_download_and_read_only_inspection' as const,
    });
    const plan = deepFreeze({ ...unsigned, planHash: sha256(canonicalJson(unsigned)) });
    this.#authenticated.add(plan);
    return plan;
  }

  authenticates(candidate: unknown): candidate is ReadOnlyArtifactAcceptancePlan {
    return typeof candidate === 'object' && candidate !== null && this.#authenticated.has(candidate);
  }

  assertAuthenticates(candidate: unknown): asserts candidate is ReadOnlyArtifactAcceptancePlan {
    if (!this.authenticates(candidate)) throw new PackageStageError('plan_not_authenticated');
  }
}

/** Network-free test boundary. It is not a product or persistent approval provider. */
export class SyntheticReadOnlyArtifactApprovalAuthority {
  readonly #issued = new WeakSet<object>();
  readonly #consumed = new WeakSet<object>();

  constructor(private readonly planAuthority: ReadOnlyArtifactAcceptancePlanAuthority) {}

  issueForTest(
    plan: ReadOnlyArtifactAcceptancePlan,
    input: Readonly<{ approvalId?: string; expiresAt: string }>,
  ): SyntheticReadOnlyArtifactApproval {
    this.planAuthority.assertAuthenticates(plan);
    const approvalId = input.approvalId ?? randomBytes(16).toString('hex');
    if (!/^[a-f0-9]{32}$/u.test(approvalId) || !Number.isFinite(new Date(input.expiresAt).getTime())) {
      throw new PackageStageError('approval_invalid');
    }
    const approval = Object.freeze({
      approvalVersion: 1 as const,
      approvalId,
      planHash: plan.planHash,
      consequence: plan.consequence,
      expiresAt: input.expiresAt,
    });
    this.#issued.add(approval);
    return approval;
  }

  consume(
    approval: SyntheticReadOnlyArtifactApproval,
    plan: ReadOnlyArtifactAcceptancePlan,
    now = new Date(),
  ): void {
    this.planAuthority.assertAuthenticates(plan);
    if (!this.#issued.has(approval) || approval.planHash !== plan.planHash || approval.consequence !== plan.consequence) {
      throw new PackageStageError('approval_invalid');
    }
    if (this.#consumed.has(approval)) throw new PackageStageError('approval_consumed');
    if (
      new Date(approval.expiresAt).getTime() <= now.getTime()
      || new Date(plan.metadataExpiresAt).getTime() <= now.getTime()
    ) {
      throw new PackageStageError('metadata_expired');
    }
    this.#consumed.add(approval);
  }
}

/** Test-only stand-in for a later human-reviewed repository registration. */
export class SyntheticProductionProfileReviewAuthority {
  readonly #authenticated = new WeakSet<object>();

  constructor(private readonly candidateAuthority: ExactGraphCandidateAuthority) {}

  acceptForTest(
    candidate: ExactGraphCandidate,
    evidence: CompleteReadOnlyAcceptanceEvidence,
    evidenceAuthority: Readonly<{ authenticates(value: unknown): value is CompleteReadOnlyAcceptanceEvidence }>,
  ): AcceptedProductionGraphProfile {
    this.candidateAuthority.assertAuthenticates(candidate);
    if (
      !evidenceAuthority.authenticates(evidence)
      || evidence.candidateDigest !== candidate.candidateDigest
      || !evidence.cleanupComplete
      || evidence.artifacts.length !== uniqueArtifactIdentities(candidate.graphNodes).length
    ) {
      throw new PackageStageError('acceptance_incomplete');
    }
    const unsigned = deepFreeze({
      productionProfileSchemaVersion: 1 as const,
      candidate,
      artifactAcceptance: evidence.artifacts,
    });
    const profile = deepFreeze({ ...unsigned, productionProfileDigest: sha256(canonicalJson(unsigned)) });
    this.#authenticated.add(profile);
    return profile;
  }

  authenticates(candidate: unknown): candidate is AcceptedProductionGraphProfile {
    return typeof candidate === 'object' && candidate !== null && this.#authenticated.has(candidate);
  }
}

function normalizeCandidateInput(input: ExactGraphCandidateInput): Omit<ExactGraphCandidate, 'candidateSchemaVersion' | 'graphNodes' | 'candidateDigest'> {
  assertRecord(input);
  assertExactKeys(input, [
    'profileId', 'profileVersion', 'topPackage', 'registryOrigin', 'runtimeConstraint',
    'materializationRulesVersion', 'archiveRulesVersion', 'workerProtocolVersion', 'limits', 'packageLock',
  ]);
  if (!IDENTIFIER.test(input.profileId) || !isPositiveInteger(input.profileVersion)) failLock();
  assertRecord(input.topPackage);
  assertExactKeys(input.topPackage, ['name', 'exactVersion', 'exactEntrypointRelativePath']);
  if (!isPackageName(input.topPackage.name) || !isExactVersion(input.topPackage.exactVersion)) failLock();
  const limits = normalizeLimits(input.limits);
  validatePortableRelativePath(input.topPackage.exactEntrypointRelativePath, limits);
  const registryOrigin = normalizeRegistryOrigin(input.registryOrigin);
  assertRecord(input.runtimeConstraint);
  assertExactKeys(input.runtimeConstraint, [
    'os', 'architecture', 'nodeMajor', 'nodeVersion', 'npmGraphGeneratorVersion', 'lockfileVersion',
  ]);
  if (
    input.runtimeConstraint.os !== 'darwin'
    || input.runtimeConstraint.architecture !== 'arm64'
    || input.runtimeConstraint.nodeMajor !== 26
    || !isExactVersion(input.runtimeConstraint.nodeVersion)
    || !isExactVersion(input.runtimeConstraint.npmGraphGeneratorVersion)
    || input.runtimeConstraint.lockfileVersion !== 3
    || input.workerProtocolVersion !== ARCHIVE_WORKER_PROTOCOL_VERSION
    || !isPositiveInteger(input.materializationRulesVersion)
    || !isPositiveInteger(input.archiveRulesVersion)
  ) failLock();
  return deepFreeze({
    profileId: input.profileId,
    profileVersion: input.profileVersion,
    topPackage: { ...input.topPackage },
    registryOrigin,
    runtimeConstraint: { ...input.runtimeConstraint },
    materializationRulesVersion: input.materializationRulesVersion,
    archiveRulesVersion: input.archiveRulesVersion,
    workerProtocolVersion: input.workerProtocolVersion,
    limits,
  });
}

function compileLockGraph(
  input: unknown,
  candidate: Omit<ExactGraphCandidate, 'candidateSchemaVersion' | 'graphNodes' | 'candidateDigest'>,
): readonly ExactGraphCandidateNode[] {
  assertRecord(input);
  assertExactKeys(input, ['name', 'version', 'lockfileVersion', 'requires', 'packages']);
  if (
    typeof input.name !== 'string'
    || typeof input.version !== 'string'
    || input.lockfileVersion !== 3
    || input.requires !== true
  ) failLock();
  assertRecord(input.packages);
  const packageRecords = input.packages;
  const root = packageRecords[''];
  assertRecord(root);
  assertAllowedKeys(root, ['name', 'version', 'dependencies', 'engines']);
  if (typeof root.name !== 'string' || typeof root.version !== 'string') failLock();
  const rootDependencies = parseDependencies(root.dependencies);
  if (rootDependencies.size !== 1 || rootDependencies.get(candidate.topPackage.name) !== candidate.topPackage.exactVersion) failLock();

  const paths = Object.keys(packageRecords).filter((path) => path !== '').sort(compareText);
  if (paths.length === 0 || paths.length > candidate.limits.graphNodes) failLock();
  const byPath = new Map<string, ExactGraphCandidateNode>();
  const portablePaths = new Set<string>();
  for (const installPath of paths) {
    validatePortableRelativePath(installPath, candidate.limits);
    if (!installPath.startsWith('node_modules/')) failLock();
    const portable = installPath.toLocaleLowerCase('en-US');
    if (portablePaths.has(portable)) failLock();
    portablePaths.add(portable);
    const record = packageRecords[installPath];
    assertRecord(record);
    assertAllowedKeys(record, [
      'version', 'resolved', 'integrity', 'dependencies', 'bin', 'engines', 'license', 'funding',
      'dev', 'optional', 'peer', 'devOptional', 'peerDependencies', 'peerDependenciesMeta',
      'optionalDependencies', 'bundleDependencies', 'bundledDependencies', 'hasInstallScript',
      'link', 'inBundle', 'os', 'cpu',
    ]);
    if (
      record.dev === true || record.optional === true || record.peer === true || record.devOptional === true
      || record.hasInstallScript === true || record.link === true || record.inBundle === true
      || record.peerDependencies !== undefined || record.peerDependenciesMeta !== undefined
      || record.optionalDependencies !== undefined || record.bundleDependencies !== undefined
      || record.bundledDependencies !== undefined || record.os !== undefined || record.cpu !== undefined
      || !isExactVersion(record.version) || typeof record.resolved !== 'string' || typeof record.integrity !== 'string'
    ) failLock();
    validateTarballUrl(record.resolved, candidate.registryOrigin);
    parseSha512Integrity(record.integrity);
    const packageName = packageNameFromInstallPath(installPath);
    const dependencies = parseDependencies(record.dependencies);
    byPath.set(installPath, deepFreeze({
      installPath,
      packageName,
      exactVersion: record.version,
      tarballUrl: record.resolved,
      sha512Integrity: record.integrity,
      dependencyEdges: Object.freeze([...dependencies].map(([name, declaredSpecifier]) => ({
        packageName: name,
        declaredSpecifier,
        installPath: '',
      }))),
      expectedLifecycleScriptNames: Object.freeze([]),
    }));
  }

  const nodes = [...byPath.values()].map((node) => deepFreeze({
    ...node,
    dependencyEdges: Object.freeze(node.dependencyEdges.map((edge) => {
      const targetPath = resolveNodeDependency(node.installPath, edge.packageName, byPath);
      const target = byPath.get(targetPath);
      if (target?.packageName !== edge.packageName) failLock();
      return Object.freeze({ ...edge, installPath: targetPath });
    }).sort((left, right) => compareText(left.packageName, right.packageName))),
  })).sort((left, right) => compareText(left.installPath, right.installPath));

  const topPath = `node_modules/${candidate.topPackage.name}`;
  const top = byPath.get(topPath);
  if (top?.packageName !== candidate.topPackage.name || top.exactVersion !== candidate.topPackage.exactVersion) failLock();
  assertConnectedAcyclic(nodes, topPath);
  return Object.freeze(nodes);
}

function assertConnectedAcyclic(nodes: readonly ExactGraphCandidateNode[], topPath: string): void {
  const byPath = new Map(nodes.map((node) => [node.installPath, node]));
  const visiting = new Set<string>();
  const visited = new Set<string>();
  const visit = (path: string): void => {
    if (visiting.has(path)) failLock();
    if (visited.has(path)) return;
    const node = byPath.get(path);
    if (node === undefined) failLock();
    visiting.add(path);
    for (const edge of node.dependencyEdges) visit(edge.installPath);
    visiting.delete(path);
    visited.add(path);
  };
  visit(topPath);
  if (visited.size !== nodes.length) failLock();
}

function resolveNodeDependency(
  declaringPath: string,
  dependencyName: string,
  byPath: ReadonlyMap<string, ExactGraphCandidateNode>,
): string {
  let cursor = declaringPath;
  while (true) {
    const local = `${cursor}/node_modules/${dependencyName}`;
    if (byPath.has(local)) return local;
    const boundary = cursor.lastIndexOf('/node_modules/');
    if (boundary < 0) break;
    cursor = cursor.slice(0, boundary);
  }
  const root = `node_modules/${dependencyName}`;
  if (byPath.has(root)) return root;
  failLock();
}

function packageNameFromInstallPath(path: string): string {
  const segments = path.split('/');
  let index = 0;
  let lastName: string | undefined;
  while (index < segments.length) {
    if (segments[index] !== 'node_modules') failLock();
    index += 1;
    const first = segments[index];
    if (first === undefined) failLock();
    if (first.startsWith('@')) {
      const second = segments[index + 1];
      if (second === undefined) failLock();
      lastName = `${first}/${second}`;
      index += 2;
    } else {
      lastName = first;
      index += 1;
    }
  }
  if (lastName === undefined || !isPackageName(lastName)) failLock();
  return lastName;
}

function parseDependencies(input: unknown): Map<string, string> {
  if (input === undefined) return new Map();
  assertRecord(input);
  const output = new Map<string, string>();
  for (const [name, specifier] of Object.entries(input)) {
    if (
      !isPackageName(name)
      || typeof specifier !== 'string'
      || !isSafeText(specifier, 256)
      || /^(?:file:|git(?:\+|:)|https?:|workspace:|npm:)/u.test(specifier)
    ) failLock();
    output.set(name, specifier);
  }
  return output;
}

function uniqueArtifactIdentities(nodes: readonly ExactGraphCandidateNode[]): readonly Omit<ReadOnlyArtifactIdentity, 'installPaths'>[] {
  const identities = new Map<string, Omit<ReadOnlyArtifactIdentity, 'installPaths'>>();
  for (const node of nodes) {
    const identity = Object.freeze({
      packageName: node.packageName,
      exactVersion: node.exactVersion,
      tarballUrl: node.tarballUrl,
      sha512Integrity: node.sha512Integrity,
    });
    const key = canonicalJson(identity);
    identities.set(key, identity);
  }
  return Object.freeze([...identities.values()].sort(compareArtifactIdentity));
}

function sameArtifact(
  node: ExactGraphCandidateNode,
  identity: Omit<ReadOnlyArtifactIdentity, 'installPaths'>,
): boolean {
  return node.packageName === identity.packageName
    && node.exactVersion === identity.exactVersion
    && node.tarballUrl === identity.tarballUrl
    && node.sha512Integrity === identity.sha512Integrity;
}

function compareArtifactIdentity(
  left: Pick<GraphMetadataObservation, 'packageName' | 'exactVersion' | 'tarballUrl'>,
  right: Pick<GraphMetadataObservation, 'packageName' | 'exactVersion' | 'tarballUrl'>,
): number {
  return compareText(
    `${left.packageName}\u0000${left.exactVersion}\u0000${left.tarballUrl}`,
    `${right.packageName}\u0000${right.exactVersion}\u0000${right.tarballUrl}`,
  );
}

function metadataUrl(registryOrigin: string, packageName: string, exactVersion: string): string {
  return `${registryOrigin}${packageName.replace('/', '%2f')}/${exactVersion}`;
}

function normalizeLimits(input: PackageStageLimits): PackageStageLimits {
  assertRecord(input);
  const keys = Object.keys(PACKAGE_STAGE_HARD_CEILINGS) as (keyof PackageStageLimits)[];
  assertExactKeys(input, keys);
  const output = {} as Record<keyof PackageStageLimits, number>;
  for (const key of keys) {
    const value = input[key];
    if (!isPositiveInteger(value) || value > PACKAGE_STAGE_HARD_CEILINGS[key]) failLock();
    output[key] = value;
  }
  if (
    output.compressedArtifactBytes > output.totalCompressedBytes
    || output.uncompressedArtifactBytes > output.totalUncompressedBytes
    || output.regularFileBytes > output.uncompressedArtifactBytes
  ) failLock();
  return Object.freeze(output as PackageStageLimits);
}

function assertMetadataLimits(input: GraphMetadataLimits): void {
  if (
    !isBoundedInteger(input.responseBytes, 1, 16 * 1024 * 1024)
    || !isBoundedInteger(input.aggregateBytes, input.responseBytes, 128 * 1024 * 1024)
    || !isBoundedInteger(input.freshnessMs, 1, 24 * 60 * 60 * 1000)
    || !isBoundedInteger(input.requestTimeoutMs, 1, 30_000)
    || !isBoundedInteger(input.totalTimeoutMs, input.requestTimeoutMs, 5 * 60 * 1000)
  ) throw new PackageStageError('graph_metadata_invalid');
}

async function fetchMetadataWithTimeout(
  transport: ExactGraphMetadataTransport,
  request: GraphMetadataRequest,
  timeoutMs: number,
  outerSignal?: AbortSignal,
): Promise<GraphMetadataResponse> {
  const controller = new AbortController();
  const forwardAbort = () => controller.abort();
  outerSignal?.addEventListener('abort', forwardAbort, { once: true });
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await Promise.race([
      transport.fetch(request, controller.signal),
      new Promise<never>((_resolve, reject) => {
        controller.signal.addEventListener('abort', () => reject(new PackageStageError(
          outerSignal?.aborted === true ? 'artifact_cancelled' : 'graph_metadata_incomplete',
        )), { once: true });
      }),
    ]);
  } catch (error) {
    if (error instanceof PackageStageError) throw error;
    throw new PackageStageError(outerSignal?.aborted === true ? 'artifact_cancelled' : 'graph_metadata_incomplete');
  } finally {
    clearTimeout(timeout);
    outerSignal?.removeEventListener('abort', forwardAbort);
  }
}

function normalizeRegistryOrigin(value: string): string {
  let url: URL;
  try { url = new URL(value); } catch { failLock(); }
  if (
    url.protocol !== 'https:' || url.username !== '' || url.password !== '' || url.pathname !== '/'
    || url.search !== '' || url.hash !== ''
  ) failLock();
  return `${url.origin}/`;
}

function validateTarballUrl(value: string, registryOrigin: string): void {
  let url: URL;
  try { url = new URL(value); } catch { failLock(); }
  if (
    url.protocol !== 'https:' || url.origin !== new URL(registryOrigin).origin
    || url.username !== '' || url.password !== '' || url.search !== '' || url.hash !== ''
    || !url.pathname.endsWith('.tgz')
  ) failLock();
}

function assertAllowedKeys(input: Record<string, unknown>, allowed: readonly string[]): void {
  if (Object.keys(input).some((key) => !allowed.includes(key))) failLock();
}

function assertExactKeys(input: object, expected: readonly string[]): void {
  const actual = Object.keys(input).sort(compareText);
  const wanted = [...expected].sort(compareText);
  if (canonicalJson(actual) !== canonicalJson(wanted)) failLock();
}

function assertRecord(input: unknown): asserts input is Record<string, unknown> {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) failLock();
}

function isPackageName(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 214 && PACKAGE_NAME.test(value);
}

function isExactVersion(value: unknown): value is string {
  return typeof value === 'string' && EXACT_VERSION.test(value);
}

function isSafeText(value: unknown, maxLength: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= maxLength
    && !/[\u0000-\u001f\u007f]/u.test(value);
}

function isPositiveInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

function isBoundedInteger(value: unknown, min: number, max: number): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= min && value <= max;
}

function failLock(): never {
  throw new PackageStageError('graph_lock_invalid');
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function deepFreeze<T>(input: T): T {
  if (typeof input !== 'object' || input === null || Object.isFrozen(input)) return input;
  for (const value of Object.values(input)) deepFreeze(value);
  return Object.freeze(input);
}
