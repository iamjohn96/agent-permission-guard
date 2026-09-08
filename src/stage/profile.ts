import { createHash } from 'node:crypto';

import { canonicalJson } from '../audit/canonical-json.js';
import type {
  AuthenticatedVerifiedMcpGraphProfile,
  PackageDependencyEdge,
  PackageGraphNode,
  PackageStageLimits,
  UnsignedVerifiedMcpGraphProfile,
  VerifiedMcpGraphProfileDefinition,
} from './types.js';

export const PACKAGE_STAGE_HARD_CEILINGS: PackageStageLimits = Object.freeze({
  graphNodes: 256,
  compressedArtifactBytes: 50 * 1024 * 1024,
  totalCompressedBytes: 512 * 1024 * 1024,
  uncompressedArtifactBytes: 256 * 1024 * 1024,
  totalUncompressedBytes: 1024 * 1024 * 1024,
  regularFileBytes: 64 * 1024 * 1024,
  archiveEntries: 100_000,
  relativePathBytes: 512,
  pathDepth: 32,
});

export type PackageStageErrorCode =
  | 'profile_unknown'
  | 'profile_invalid'
  | 'profile_digest_mismatch'
  | 'profile_not_authenticated'
  | 'plan_invalid'
  | 'plan_not_authenticated'
  | 'approval_invalid'
  | 'approval_consumed'
  | 'integrity_invalid'
  | 'integrity_mismatch'
  | 'artifact_too_large'
  | 'artifact_cancelled'
  | 'archive_invalid'
  | 'archive_limit_exceeded'
  | 'archive_worker_failed'
  | 'archive_worker_timeout'
  | 'archive_protocol_invalid'
  | 'materialization_failed'
  | 'stage_seal_invalid'
  | 'tree_invalid'
  | 'tree_changed'
  | 'state_transition_invalid'
  | 'stage_not_authenticated'
  | 'stage_audit_incomplete'
  | 'graph_lock_invalid'
  | 'graph_metadata_invalid'
  | 'graph_metadata_incomplete'
  | 'metadata_expired'
  | 'artifact_plan_invalid'
  | 'artifact_file_invalid'
  | 'artifact_cleanup_incomplete'
  | 'manifest_invalid'
  | 'manifest_mismatch'
  | 'acceptance_incomplete';

export class PackageStageError extends Error {
  readonly code: PackageStageErrorCode;

  constructor(code: PackageStageErrorCode) {
    super(`Package stage failed: ${code}`);
    this.name = 'PackageStageError';
    this.code = code;
  }
}

const PROFILE_KEYS = [
  'profileId',
  'profileVersion',
  'topPackage',
  'registryOrigin',
  'runtimeConstraint',
  'graphNodes',
  'materializationRulesVersion',
  'archiveRulesVersion',
  'limits',
] as const;

export function computeGraphProfileDigest(input: UnsignedVerifiedMcpGraphProfile): string {
  const normalized = normalizeUnsignedProfile(input);
  return sha256(canonicalJson(normalized));
}

export class VerifiedMcpGraphProfileAuthority {
  readonly #profiles: ReadonlyMap<string, AuthenticatedVerifiedMcpGraphProfile>;
  readonly #authenticatedProfiles = new WeakSet<object>();

  constructor(definitions: readonly VerifiedMcpGraphProfileDefinition[]) {
    const profiles = new Map<string, AuthenticatedVerifiedMcpGraphProfile>();
    for (const definition of definitions) {
      assertExactKeys(definition, [...PROFILE_KEYS, 'manifestDigest']);
      const { manifestDigest, ...unsigned } = definition;
      const normalized = normalizeUnsignedProfile(unsigned);
      if (!isSha256(manifestDigest)) throw new PackageStageError('profile_invalid');
      const digest = sha256(canonicalJson(normalized));
      if (digest !== manifestDigest) {
        throw new PackageStageError('profile_digest_mismatch');
      }
      if (profiles.has(normalized.profileId)) throw new PackageStageError('profile_invalid');
      const profile = deepFreeze({ ...normalized, manifestDigest: digest });
      profiles.set(profile.profileId, profile);
      this.#authenticatedProfiles.add(profile);
    }
    this.#profiles = profiles;
  }

  select(profileId: string): AuthenticatedVerifiedMcpGraphProfile {
    const profile = this.#profiles.get(profileId);
    if (profile === undefined) throw new PackageStageError('profile_unknown');
    return profile;
  }

  authenticates(candidate: unknown): candidate is AuthenticatedVerifiedMcpGraphProfile {
    return typeof candidate === 'object'
      && candidate !== null
      && this.#authenticatedProfiles.has(candidate);
  }

  assertAuthenticates(candidate: unknown): asserts candidate is AuthenticatedVerifiedMcpGraphProfile {
    if (!this.authenticates(candidate)) throw new PackageStageError('profile_not_authenticated');
  }
}

export function validatePortableRelativePath(path: string, limits: Pick<PackageStageLimits, 'relativePathBytes' | 'pathDepth'>): readonly string[] {
  if (
    typeof path !== 'string'
    || path.length === 0
    || path.startsWith('/')
    || path.includes('\\')
    || path.includes('\0')
    || /[\u0000-\u001f\u007f]/u.test(path)
    || path.normalize('NFC') !== path
    || Buffer.byteLength(path, 'utf8') > limits.relativePathBytes
  ) {
    throw new PackageStageError('profile_invalid');
  }
  const segments = path.split('/');
  if (
    segments.length > limits.pathDepth
    || segments.some((segment) => segment.length === 0 || segment === '.' || segment === '..')
  ) {
    throw new PackageStageError('profile_invalid');
  }
  return segments;
}

export function parseSha512Integrity(integrity: string): Buffer {
  if (typeof integrity !== 'string' || !integrity.startsWith('sha512-')) {
    throw new PackageStageError('integrity_invalid');
  }
  const encoded = integrity.slice('sha512-'.length);
  if (!/^[A-Za-z0-9+/]+={0,2}$/u.test(encoded)) {
    throw new PackageStageError('integrity_invalid');
  }
  const decoded = Buffer.from(encoded, 'base64');
  if (decoded.length !== 64 || decoded.toString('base64') !== encoded) {
    throw new PackageStageError('integrity_invalid');
  }
  return decoded;
}

function normalizeUnsignedProfile(input: UnsignedVerifiedMcpGraphProfile): UnsignedVerifiedMcpGraphProfile {
  assertRecord(input);
  assertExactKeys(input, PROFILE_KEYS);
  if (!isIdentifier(input.profileId) || !isPositiveInteger(input.profileVersion)) {
    throw new PackageStageError('profile_invalid');
  }

  assertRecord(input.topPackage);
  assertExactKeys(input.topPackage, ['name', 'exactVersion', 'exactEntrypointRelativePath']);
  if (!isPackageName(input.topPackage.name) || !isExactVersion(input.topPackage.exactVersion)) {
    throw new PackageStageError('profile_invalid');
  }

  assertRecord(input.runtimeConstraint);
  assertExactKeys(input.runtimeConstraint, ['os', 'architecture', 'nodeMajor', 'npmGraphGeneratorVersion']);
  if (
    !['darwin', 'linux'].includes(input.runtimeConstraint.os)
    || !['arm64', 'x64'].includes(input.runtimeConstraint.architecture)
    || !isPositiveInteger(input.runtimeConstraint.nodeMajor)
    || !isExactVersion(input.runtimeConstraint.npmGraphGeneratorVersion)
  ) {
    throw new PackageStageError('profile_invalid');
  }

  const registryOrigin = normalizeRegistryOrigin(input.registryOrigin);
  const limits = normalizeLimits(input.limits);
  validatePortableRelativePath(input.topPackage.exactEntrypointRelativePath, limits);
  if (!isPositiveInteger(input.materializationRulesVersion) || !isPositiveInteger(input.archiveRulesVersion)) {
    throw new PackageStageError('profile_invalid');
  }
  if (!Array.isArray(input.graphNodes) || input.graphNodes.length === 0 || input.graphNodes.length > limits.graphNodes) {
    throw new PackageStageError('profile_invalid');
  }

  const graphNodes = input.graphNodes.map((node) => normalizeNode(node, registryOrigin, limits))
    .sort((left, right) => compareText(left.installPath, right.installPath));
  validateGraph(graphNodes, input.topPackage.name, input.topPackage.exactVersion);

  return deepFreeze({
    profileId: input.profileId,
    profileVersion: input.profileVersion,
    topPackage: {
      name: input.topPackage.name,
      exactVersion: input.topPackage.exactVersion,
      exactEntrypointRelativePath: input.topPackage.exactEntrypointRelativePath,
    },
    registryOrigin,
    runtimeConstraint: {
      os: input.runtimeConstraint.os,
      architecture: input.runtimeConstraint.architecture,
      nodeMajor: input.runtimeConstraint.nodeMajor,
      npmGraphGeneratorVersion: input.runtimeConstraint.npmGraphGeneratorVersion,
    },
    graphNodes,
    materializationRulesVersion: input.materializationRulesVersion,
    archiveRulesVersion: input.archiveRulesVersion,
    limits,
  });
}

function normalizeNode(
  input: PackageGraphNode,
  registryOrigin: string,
  limits: PackageStageLimits,
): PackageGraphNode {
  assertRecord(input);
  assertExactKeys(input, [
    'installPath',
    'packageName',
    'exactVersion',
    'tarballUrl',
    'sha512Integrity',
    'dependencyEdges',
    'expectedLifecycleScriptNames',
  ]);
  validatePortableRelativePath(input.installPath, limits);
  if (
    !input.installPath.startsWith('node_modules/')
    || !isPackageName(input.packageName)
    || !isExactVersion(input.exactVersion)
  ) {
    throw new PackageStageError('profile_invalid');
  }
  validateTarballUrl(input.tarballUrl, registryOrigin);
  parseSha512Integrity(input.sha512Integrity);
  if (!Array.isArray(input.dependencyEdges) || !Array.isArray(input.expectedLifecycleScriptNames)) {
    throw new PackageStageError('profile_invalid');
  }
  const dependencyEdges = input.dependencyEdges.map((edge) => normalizeEdge(edge, limits))
    .sort((left, right) => compareText(left.packageName, right.packageName));
  const lifecycleNames = [...input.expectedLifecycleScriptNames];
  if (lifecycleNames.some((name) => !isScriptName(name))) throw new PackageStageError('profile_invalid');
  lifecycleNames.sort(compareText);
  assertNoDuplicateStrings(lifecycleNames);
  assertNoDuplicateStrings(dependencyEdges.map((edge) => edge.packageName));
  return deepFreeze({
    installPath: input.installPath,
    packageName: input.packageName,
    exactVersion: input.exactVersion,
    tarballUrl: input.tarballUrl,
    sha512Integrity: input.sha512Integrity,
    dependencyEdges,
    expectedLifecycleScriptNames: lifecycleNames,
  });
}

function normalizeEdge(input: PackageDependencyEdge, limits: PackageStageLimits): PackageDependencyEdge {
  assertRecord(input);
  assertExactKeys(input, ['packageName', 'installPath', 'declaredSpecifier']);
  validatePortableRelativePath(input.installPath, limits);
  if (!isPackageName(input.packageName) || !isSafeText(input.declaredSpecifier, 256)) {
    throw new PackageStageError('profile_invalid');
  }
  return deepFreeze({ ...input });
}

function validateGraph(nodes: readonly PackageGraphNode[], topName: string, topVersion: string): void {
  const byPath = new Map(nodes.map((node) => [node.installPath, node]));
  if (byPath.size !== nodes.length) throw new PackageStageError('profile_invalid');
  const portablePaths = nodes.map((node) => node.installPath.toLocaleLowerCase('en-US'));
  assertNoDuplicateStrings(portablePaths);

  const topPath = `node_modules/${topName}`;
  const top = byPath.get(topPath);
  if (top?.packageName !== topName || top.exactVersion !== topVersion) {
    throw new PackageStageError('profile_invalid');
  }
  for (const node of nodes) {
    for (const edge of node.dependencyEdges) {
      const target = byPath.get(edge.installPath);
      if (target?.packageName !== edge.packageName) throw new PackageStageError('profile_invalid');
    }
  }

  const visiting = new Set<string>();
  const visited = new Set<string>();
  const visit = (path: string): void => {
    if (visiting.has(path)) throw new PackageStageError('profile_invalid');
    if (visited.has(path)) return;
    visiting.add(path);
    const node = byPath.get(path);
    if (node === undefined) throw new PackageStageError('profile_invalid');
    for (const edge of node.dependencyEdges) visit(edge.installPath);
    visiting.delete(path);
    visited.add(path);
  };
  visit(topPath);
  if (visited.size !== nodes.length) throw new PackageStageError('profile_invalid');
}

function normalizeLimits(input: PackageStageLimits): PackageStageLimits {
  assertRecord(input);
  const keys = Object.keys(PACKAGE_STAGE_HARD_CEILINGS) as (keyof PackageStageLimits)[];
  assertExactKeys(input, keys);
  const output = {} as Record<keyof PackageStageLimits, number>;
  for (const key of keys) {
    const value = input[key];
    if (!isPositiveInteger(value) || value > PACKAGE_STAGE_HARD_CEILINGS[key]) {
      throw new PackageStageError('profile_invalid');
    }
    output[key] = value;
  }
  if (
    output.compressedArtifactBytes > output.totalCompressedBytes
    || output.uncompressedArtifactBytes > output.totalUncompressedBytes
    || output.regularFileBytes > output.uncompressedArtifactBytes
  ) {
    throw new PackageStageError('profile_invalid');
  }
  return deepFreeze(output as PackageStageLimits);
}

function normalizeRegistryOrigin(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new PackageStageError('profile_invalid');
  }
  if (
    url.protocol !== 'https:'
    || url.username.length > 0
    || url.password.length > 0
    || url.search.length > 0
    || url.hash.length > 0
    || url.pathname !== '/'
  ) {
    throw new PackageStageError('profile_invalid');
  }
  return `${url.origin}/`;
}

function validateTarballUrl(value: string, registryOrigin: string): void {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new PackageStageError('profile_invalid');
  }
  if (
    url.protocol !== 'https:'
    || url.origin !== new URL(registryOrigin).origin
    || url.username.length > 0
    || url.password.length > 0
    || url.search.length > 0
    || url.hash.length > 0
    || !url.pathname.endsWith('.tgz')
  ) {
    throw new PackageStageError('profile_invalid');
  }
}

function assertExactKeys(input: object, keys: readonly string[]): void {
  const actual = Object.keys(input).sort(compareText);
  const expected = [...keys].sort(compareText);
  if (canonicalJson(actual) !== canonicalJson(expected)) throw new PackageStageError('profile_invalid');
}

function assertRecord(input: unknown): asserts input is Record<string, unknown> {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw new PackageStageError('profile_invalid');
  }
}

function assertNoDuplicateStrings(values: readonly string[]): void {
  if (new Set(values).size !== values.length) throw new PackageStageError('profile_invalid');
}

function isIdentifier(value: unknown): value is string {
  return typeof value === 'string' && /^[a-z0-9][a-z0-9._-]{0,127}$/u.test(value);
}

function isPackageName(value: unknown): value is string {
  return typeof value === 'string'
    && value.length <= 214
    && /^(?:@[a-z0-9][a-z0-9._-]*\/[a-z0-9][a-z0-9._-]*|[a-z0-9][a-z0-9._-]*)$/u.test(value);
}

function isExactVersion(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/u.test(value);
}

function isPositiveInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

function isScriptName(value: unknown): value is string {
  return typeof value === 'string' && isSafeText(value, 128) && !value.includes('/');
}

function isSafeText(value: unknown, maxLength: number): value is string {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= maxLength
    && !/[\u0000-\u001f\u007f]/u.test(value);
}

function isSha256(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value);
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
