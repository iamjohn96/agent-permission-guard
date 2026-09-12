import { createHash } from 'node:crypto';

import { canonicalJson } from '../audit/canonical-json.js';
import { ARCHIVE_WORKER_PROTOCOL_VERSION } from './archive-worker-protocol.js';
import {
  analyzePeerDependencySemantics,
  type PeerSemanticsInput,
} from './peer-dependency-semantics.js';
import {
  PACKAGE_STAGE_HARD_CEILINGS,
  parseSha512Integrity,
  validatePortableRelativePath,
} from './profile.js';
import type { PackageDependencyEdge, PackageStageLimits } from './types.js';

export const PEER_SEMANTICS_V2_CONTRACT = deepFreeze({
  candidateSchemaVersion: 2 as const,
  peerSemanticsVersion: 1 as const,
  grammar: 'stable-triplet-multi-u0020-v1',
  resolver: 'nearest-ancestor-v1',
  closure: 'ordinary-required-peer-fixed-point-v1',
  limits: {
    candidateBytes: 4 * 1024 * 1024,
    rangeBytes: 256,
    branches: 8,
    atoms: 16,
    comparisons: 32,
    nodes: 256,
    pathBytes: 512,
    pathSegments: 32,
    peersPerNode: 64,
    peers: 2048,
    combinedRequirements: 4096,
  },
});

export type ExactGraphCandidateV2Input = Readonly<{
  profileId: string;
  profileVersion: number;
  topPackage: Readonly<{
    name: string;
    exactVersion: string;
    exactEntrypointRelativePath: string;
  }>;
  registryOrigin: string;
  runtimeConstraint: Readonly<{
    os: 'darwin';
    architecture: 'arm64';
    nodeMajor: 26;
    nodeVersion: string;
    npmGraphGeneratorVersion: string;
    lockfileVersion: 3;
  }>;
  materializationRulesVersion: number;
  archiveRulesVersion: number;
  workerProtocolVersion: typeof ARCHIVE_WORKER_PROTOCOL_VERSION;
  limits: PackageStageLimits;
  packageLock: unknown;
  lowerCandidateByteLimit?: number;
}>;

export type PeerResolutionV2 =
  | Readonly<{ kind: 'absent' }>
  | Readonly<{ kind: 'present'; installPath: string; exactVersion: string }>;

export type PeerRequirementV2 = Readonly<{
  packageName: string;
  declaredSpecifier: string;
  optional: boolean;
  resolution: PeerResolutionV2;
}>;

export type ExactGraphCandidateNodeV2 = Readonly<{
  installPath: string;
  packageName: string;
  exactVersion: string;
  tarballUrl: string;
  sha512Integrity: string;
  expectedLifecycleScriptNames: readonly string[];
  dependenciesPresent: boolean;
  dependencyDeclarations: Readonly<Record<string, string>>;
  dependencyEdges: readonly PackageDependencyEdge[];
  peerDependenciesPresent: boolean;
  peerDependencyDeclarations: Readonly<Record<string, string>>;
  peerDependenciesMetaPresent: boolean;
  peerDependenciesMeta: Readonly<Record<string, Readonly<Record<string, boolean>>>>;
  peerFlagPresent: boolean;
  peerFlag?: boolean;
  peerRequirements: readonly PeerRequirementV2[];
}>;

export type ExactGraphCandidateV2 = Readonly<{
  candidateSchemaVersion: 2;
  semanticContract: typeof PEER_SEMANTICS_V2_CONTRACT;
  profileId: string;
  profileVersion: number;
  topPackage: ExactGraphCandidateV2Input['topPackage'];
  registryOrigin: string;
  runtimeConstraint: ExactGraphCandidateV2Input['runtimeConstraint'];
  materializationRulesVersion: number;
  archiveRulesVersion: number;
  workerProtocolVersion: typeof ARCHIVE_WORKER_PROTOCOL_VERSION;
  limits: PackageStageLimits;
  rootDependencies: Readonly<Record<string, string>>;
  graphNodes: readonly ExactGraphCandidateNodeV2[];
  candidateDigest: string;
}>;
type Unsigned = Omit<ExactGraphCandidateV2, 'candidateDigest'>;
type RawNode = Readonly<{
  path: string;
  packageName: string;
  exactVersion: string;
  tarballUrl: string;
  integrity: string;
  dependenciesPresent: boolean;
  dependencies: Record<string, string>;
  peersPresent: boolean;
  peers: Record<string, string>;
  metaPresent: boolean;
  meta: Record<string, Readonly<Record<string, boolean>>>;
  peerFlagPresent: boolean;
  peerFlag?: boolean;
}>;

const SHA256 = /^[a-f0-9]{64}$/u;
const CANDIDATE_KEYS = [
  'candidateSchemaVersion', 'semanticContract', 'profileId', 'profileVersion',
  'topPackage', 'registryOrigin', 'runtimeConstraint', 'materializationRulesVersion',
  'archiveRulesVersion', 'workerProtocolVersion', 'limits', 'rootDependencies',
  'graphNodes', 'candidateDigest',
] as const;
const NODE_KEYS = [
  'installPath', 'packageName', 'exactVersion', 'tarballUrl', 'sha512Integrity',
  'expectedLifecycleScriptNames', 'dependenciesPresent', 'dependencyDeclarations',
  'dependencyEdges', 'peerDependenciesPresent', 'peerDependencyDeclarations',
  'peerDependenciesMetaPresent', 'peerDependenciesMeta', 'peerFlagPresent',
  'peerRequirements',
] as const;

export class ExactGraphCandidateV2Authority {
  readonly #owned = new WeakSet<object>();

  compile(input: ExactGraphCandidateV2Input): ExactGraphCandidateV2 {
    const unsigned = compileUnsignedCandidateV2(input);
    const candidate = deepFreeze({ ...unsigned, candidateDigest: digest(unsigned) });
    if (Buffer.byteLength(canonicalJson(candidate)) > candidateByteLimit(input.lowerCandidateByteLimit)) fail();
    this.#owned.add(candidate);
    return candidate;
  }

  authenticates(value: unknown): value is ExactGraphCandidateV2 {
    return isObject(value) && this.#owned.has(value);
  }
}

/**
 * Validates transferable evidence. The returned value is deliberately not
 * authenticated by any compiler authority: only the creating authority owns
 * that provenance. Validation reconstructs the retained raw lock declarations
 * and recompiles them so derived edges and peer outcomes cannot be asserted by
 * a payload.
 */
export function validateCandidateV2Payload(value: unknown): ExactGraphCandidateV2 {
  const cloned = cloneJsonEvidence(value, PEER_SEMANTICS_V2_CONTRACT.limits.candidateBytes);
  const candidate = ownRecord(cloned);
  exactKeys(candidate, CANDIDATE_KEYS);
  if (typeof candidate.candidateDigest !== 'string' || !SHA256.test(candidate.candidateDigest)) {
    fail();
  }
  if (canonicalJson(candidate.semanticContract) !== canonicalJson(PEER_SEMANTICS_V2_CONTRACT)) {
    fail();
  }
  if (!Array.isArray(candidate.graphNodes)) fail();

  const packages: Record<string, unknown> = Object.create(null);
  packages[''] = {
    name: 'candidate-v2',
    version: '0.0.0',
    dependencies: candidate.rootDependencies,
  };
  for (const item of candidate.graphNodes) {
    const node = ownRecord(item);
    exactKeys(node, NODE_KEYS, ['peerFlag']);
    if (typeof node.installPath !== 'string' || Object.hasOwn(packages, node.installPath)) {
      fail();
    }
    const record: Record<string, unknown> = {
      version: node.exactVersion,
      resolved: node.tarballUrl,
      integrity: node.sha512Integrity,
    };
    if (node.dependenciesPresent === true) {
      record.dependencies = node.dependencyDeclarations;
    } else if (node.dependenciesPresent !== false) {
      fail();
    }
    if (node.peerDependenciesPresent === true) {
      record.peerDependencies = node.peerDependencyDeclarations;
    } else if (node.peerDependenciesPresent !== false) {
      fail();
    }
    if (node.peerDependenciesMetaPresent === true) {
      record.peerDependenciesMeta = node.peerDependenciesMeta;
    } else if (node.peerDependenciesMetaPresent !== false) {
      fail();
    }
    if (node.peerFlagPresent === true) {
      record.peer = node.peerFlag;
    } else if (node.peerFlagPresent !== false) {
      fail();
    }
    packages[node.installPath] = record;
  }

  const unsigned = compileUnsignedCandidateV2({
    profileId: candidate.profileId as string,
    profileVersion: candidate.profileVersion as number,
    topPackage: candidate.topPackage as ExactGraphCandidateV2Input['topPackage'],
    registryOrigin: candidate.registryOrigin as string,
    runtimeConstraint: candidate.runtimeConstraint as ExactGraphCandidateV2Input['runtimeConstraint'],
    materializationRulesVersion: candidate.materializationRulesVersion as number,
    archiveRulesVersion: candidate.archiveRulesVersion as number,
    workerProtocolVersion: candidate.workerProtocolVersion as typeof ARCHIVE_WORKER_PROTOCOL_VERSION,
    limits: candidate.limits as PackageStageLimits,
    packageLock: {
      name: 'candidate-v2',
      version: '0.0.0',
      lockfileVersion: 3,
      requires: true,
      packages,
    },
  });
  const claimedUnsigned = Object.fromEntries(
    Object.entries(candidate).filter(([key]) => key !== 'candidateDigest'),
  );
  if (canonicalJson(claimedUnsigned) !== canonicalJson(unsigned)) fail();
  if (candidate.candidateDigest !== digest(unsigned)) fail();
  return deepFreeze({ ...unsigned, candidateDigest: candidate.candidateDigest as string });
}

export function compileUnsignedCandidateV2(input: ExactGraphCandidateV2Input): Unsigned {
  const source = ownRecord(input);
  exactKeys(source, [
    'profileId', 'profileVersion', 'topPackage', 'registryOrigin', 'runtimeConstraint',
    'materializationRulesVersion', 'archiveRulesVersion', 'workerProtocolVersion',
    'limits', 'packageLock',
  ], ['lowerCandidateByteLimit']);
  if (!identifier(source.profileId) || !positive(source.profileVersion)) fail();
  const limits = normalizeLimits(source.limits);
  const top = ownRecord(source.topPackage);
  exactKeys(top, ['name', 'exactVersion', 'exactEntrypointRelativePath']);
  if (
    !packageName(top.name)
    || !version(top.exactVersion)
    || typeof top.exactEntrypointRelativePath !== 'string'
  ) fail();
  try {
    validatePortableRelativePath(top.exactEntrypointRelativePath, limits);
  } catch {
    fail();
  }
  const registryOrigin = normalizeRegistry(source.registryOrigin);
  const runtime = ownRecord(source.runtimeConstraint);
  exactKeys(runtime, [
    'os', 'architecture', 'nodeMajor', 'nodeVersion',
    'npmGraphGeneratorVersion', 'lockfileVersion',
  ]);
  if (
    runtime.os !== 'darwin'
    || runtime.architecture !== 'arm64'
    || runtime.nodeMajor !== 26
    || runtime.lockfileVersion !== 3
    || !version(runtime.nodeVersion)
    || !version(runtime.npmGraphGeneratorVersion)
  ) fail();
  if (
    !positive(source.materializationRulesVersion)
    || !positive(source.archiveRulesVersion)
    || source.workerProtocolVersion !== ARCHIVE_WORKER_PROTOCOL_VERSION
  ) fail();
  const byteLimit = candidateByteLimit(source.lowerCandidateByteLimit);
  const packageLock = cloneJsonEvidence(source.packageLock, byteLimit);
  const { rootDependencies, rawNodes } = parseLock(
    packageLock,
    top.name,
    top.exactVersion,
    registryOrigin,
    limits,
  );
  const peerInput: PeerSemanticsInput = deepFreeze({
    rootDependencies,
    nodes: rawNodes.map((node) => ({
      installPath: node.path,
      packageName: node.packageName,
      version: node.exactVersion,
      ...(node.dependenciesPresent ? { dependencies: node.dependencies } : {}),
      ...(node.peersPresent ? { peerDependencies: node.peers } : {}),
      ...(node.metaPresent ? { peerDependenciesMeta: node.meta } : {}),
      ...(node.peerFlagPresent ? { peer: node.peerFlag } : {}),
    })),
  });
  let analysis: ReturnType<typeof analyzePeerDependencySemantics>;
  try {
    analysis = analyzePeerDependencySemantics(peerInput);
  } catch {
    fail();
  }

  const byPath = new Map(rawNodes.map((node) => [node.path, node]));
  const peerByFrom = new Map<string, PeerRequirementV2[]>();
  for (const result of analysis.peerRequirements) {
    const owner = byPath.get(result.from);
    if (!owner) fail();
    const declaredSpecifier = owner.peers[result.name];
    if (declaredSpecifier === undefined) fail();
    const target = result.targetPath === undefined ? undefined : byPath.get(result.targetPath);
    if (result.targetPath !== undefined && !target) fail();
    const requirement = deepFreeze({
      packageName: result.name,
      declaredSpecifier,
      optional: result.optional,
      resolution: target === undefined
        ? { kind: 'absent' as const }
        : {
            kind: 'present' as const,
            installPath: target.path,
            exactVersion: target.exactVersion,
          },
    });
    const list = peerByFrom.get(result.from) ?? [];
    list.push(requirement);
    peerByFrom.set(result.from, list);
  }

  const graphNodes = rawNodes.map((node) => {
    const dependencyEdges = Object.keys(node.dependencies).sort(compareText).map((name) => {
      const target = resolveNearest(node.path, name, byPath);
      if (!target) fail();
      return deepFreeze({
        packageName: name,
        declaredSpecifier: node.dependencies[name]!,
        installPath: target.path,
      });
    });
    return deepFreeze({
      installPath: node.path,
      packageName: node.packageName,
      exactVersion: node.exactVersion,
      tarballUrl: node.tarballUrl,
      sha512Integrity: node.integrity,
      expectedLifecycleScriptNames: [],
      dependenciesPresent: node.dependenciesPresent,
      dependencyDeclarations: node.dependencies,
      dependencyEdges,
      peerDependenciesPresent: node.peersPresent,
      peerDependencyDeclarations: node.peers,
      peerDependenciesMetaPresent: node.metaPresent,
      peerDependenciesMeta: node.meta,
      peerFlagPresent: node.peerFlagPresent,
      ...(node.peerFlagPresent ? { peerFlag: node.peerFlag } : {}),
      peerRequirements: (peerByFrom.get(node.path) ?? [])
        .sort((a, b) => compareText(a.packageName, b.packageName)),
    });
  }).sort((a, b) => compareText(a.installPath, b.installPath));

  const unsigned = deepFreeze({
    candidateSchemaVersion: 2 as const,
    semanticContract: PEER_SEMANTICS_V2_CONTRACT,
    profileId: source.profileId as string,
    profileVersion: source.profileVersion as number,
    topPackage: {
      name: top.name as string,
      exactVersion: top.exactVersion as string,
      exactEntrypointRelativePath: top.exactEntrypointRelativePath as string,
    },
    registryOrigin,
    runtimeConstraint: {
      os: 'darwin' as const,
      architecture: 'arm64' as const,
      nodeMajor: 26 as const,
      nodeVersion: runtime.nodeVersion as string,
      npmGraphGeneratorVersion: runtime.npmGraphGeneratorVersion as string,
      lockfileVersion: 3 as const,
    },
    materializationRulesVersion: source.materializationRulesVersion as number,
    archiveRulesVersion: source.archiveRulesVersion as number,
    workerProtocolVersion: ARCHIVE_WORKER_PROTOCOL_VERSION,
    limits,
    rootDependencies,
    graphNodes,
  });
  if (Buffer.byteLength(canonicalJson(unsigned)) > byteLimit) fail();
  return unsigned;
}

function parseLock(
  value: unknown,
  topName: string,
  topVersion: string,
  registry: string,
  limits: PackageStageLimits,
): { rootDependencies: Record<string, string>; rawNodes: RawNode[] } {
  const lock = ownRecord(value);
  exactKeys(lock, ['name', 'version', 'lockfileVersion', 'requires', 'packages']);
  if (
    typeof lock.name !== 'string'
    || typeof lock.version !== 'string'
    || lock.lockfileVersion !== 3
    || lock.requires !== true
  ) fail();

  const packages = ownRecord(lock.packages);
  const root = ownRecord(packages['']);
  allowedKeys(root, ['name', 'version', 'dependencies', 'engines']);
  if (typeof root.name !== 'string' || typeof root.version !== 'string') fail();
  const rootDependencies = stringMap(root.dependencies);
  if (Object.keys(rootDependencies).length !== 1 || rootDependencies[topName] !== topVersion) fail();
  const paths = Object.keys(packages).filter((path) => path !== '').sort(compareText);
  if (paths.length === 0 || paths.length > limits.graphNodes) fail();

  const rawNodes: RawNode[] = [];
  const portable = new Set<string>();
  for (const path of paths) {
    try {
      validatePortableRelativePath(path, limits);
    } catch {
      fail();
    }
    if (!path.startsWith('node_modules/') || portable.has(path.toLowerCase())) fail();
    portable.add(path.toLowerCase());

    const raw = ownRecord(packages[path]);
    allowedKeys(raw, [
      'version', 'resolved', 'integrity', 'dependencies', 'bin', 'engines',
      'license', 'funding', 'dev', 'optional', 'peer', 'devOptional',
      'peerDependencies', 'peerDependenciesMeta', 'optionalDependencies',
      'bundleDependencies', 'bundledDependencies', 'hasInstallScript',
      'link', 'inBundle', 'os', 'cpu',
    ]);
    for (const flag of ['dev', 'optional', 'devOptional', 'hasInstallScript', 'link', 'inBundle']) {
      if (raw[flag] === true) fail();
    }
    for (const field of [
      'optionalDependencies', 'bundleDependencies', 'bundledDependencies', 'os', 'cpu',
    ]) {
      if (Object.hasOwn(raw, field)) fail();
    }
    if (
      !version(raw.version)
      || typeof raw.resolved !== 'string'
      || typeof raw.integrity !== 'string'
    ) fail();
    validateTarball(raw.resolved, registry);
    try {
      parseSha512Integrity(raw.integrity);
    } catch {
      fail();
    }

    const name = nameFromPath(path);
    const dependenciesPresent = Object.hasOwn(raw, 'dependencies');
    const peersPresent = Object.hasOwn(raw, 'peerDependencies');
    const metaPresent = Object.hasOwn(raw, 'peerDependenciesMeta');
    const peerFlagPresent = Object.hasOwn(raw, 'peer');
    const dependencies = stringMap(raw.dependencies);
    const peers = stringMap(raw.peerDependencies);
    const meta = normalizeMeta(raw.peerDependenciesMeta, peers);
    rawNodes.push(deepFreeze({
      path,
      packageName: name,
      exactVersion: raw.version,
      tarballUrl: raw.resolved,
      integrity: raw.integrity,
      dependenciesPresent,
      dependencies,
      peersPresent,
      peers,
      metaPresent,
      meta,
      peerFlagPresent,
      ...(peerFlagPresent ? { peerFlag: raw.peer } : {}),
    } as RawNode));
  }
  return { rootDependencies: deepFreeze(rootDependencies), rawNodes };
}

function normalizeLimits(value: unknown): PackageStageLimits {
  const raw = ownRecord(value);
  const keys = Object.keys(PACKAGE_STAGE_HARD_CEILINGS) as (keyof PackageStageLimits)[];
  exactKeys(raw, keys);
  const out = {} as Record<keyof PackageStageLimits, number>;
  for (const key of keys) {
    const item = raw[key];
    if (!positive(item) || item > PACKAGE_STAGE_HARD_CEILINGS[key]) fail();
    out[key] = item;
  }
  if (
    out.compressedArtifactBytes > out.totalCompressedBytes
    || out.uncompressedArtifactBytes > out.totalUncompressedBytes
    || out.regularFileBytes > out.uncompressedArtifactBytes
  ) fail();
  return deepFreeze(out as PackageStageLimits);
}

function normalizeMeta(
  value: unknown,
  peers: Record<string, string>,
): Record<string, Readonly<Record<string, boolean>>> {
  if (value === undefined) return deepFreeze({});
  const raw = ownRecord(value);
  const out: Record<string, Readonly<Record<string, boolean>>> = Object.create(null);
  for (const key of Object.keys(raw).sort(compareText)) {
    if (peers[key] === undefined) fail();
    const entry = ownRecord(raw[key]);
    exactKeys(entry, [], ['optional']);
    if (Object.hasOwn(entry, 'optional') && typeof entry.optional !== 'boolean') fail();
    out[key] = deepFreeze(
      Object.hasOwn(entry, 'optional') ? { optional: entry.optional as boolean } : {},
    );
  }
  return deepFreeze(out);
}

function stringMap(value: unknown): Record<string, string> {
  if (value === undefined) return deepFreeze({});
  const raw = ownRecord(value);
  const out: Record<string, string> = Object.create(null);
  for (const key of Object.keys(raw).sort(compareText)) {
    if (
      !packageName(key)
      || typeof raw[key] !== 'string'
      || Buffer.byteLength(raw[key] as string) > 256
    ) fail();
    out[key] = raw[key] as string;
  }
  return deepFreeze(out);
}

function resolveNearest(path: string, name: string, nodes: Map<string, RawNode>): RawNode | undefined {
  let cursor = path;
  while (true) {
    const local = nodes.get(`${cursor}/node_modules/${name}`);
    if (local) return local;
    const boundary = cursor.lastIndexOf('/node_modules/');
    if (boundary < 0) return nodes.get(`node_modules/${name}`);
    cursor = cursor.slice(0, boundary);
  }
}

function nameFromPath(path: string): string {
  const segments = path.split('/');
  const last = segments.at(-1)!;
  const previous = segments.at(-2)!;
  const name = previous.startsWith('@') ? `${previous}/${last}` : last;
  if (!packageName(name)) fail();
  return name;
}

function normalizeRegistry(value: unknown): string {
  if (typeof value !== 'string') fail();
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    fail();
  }
  if (
    url.protocol !== 'https:'
    || url.username
    || url.password
    || url.pathname !== '/'
    || url.search
    || url.hash
  ) fail();
  return `${url.origin}/`;
}

function validateTarball(value: string, registry: string): void {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    fail();
  }
  if (
    url.protocol !== 'https:'
    || url.origin !== new URL(registry).origin
    || url.username
    || url.password
    || url.search
    || url.hash
    || !url.pathname.endsWith('.tgz')
  ) fail();
}

function ownRecord(value: unknown): Record<string, unknown> {
  if (
    !isObject(value)
    || Array.isArray(value)
    || (
      Object.getPrototypeOf(value) !== Object.prototype
      && Object.getPrototypeOf(value) !== null
    )
  ) fail();
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') fail();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      !descriptor
      || !descriptor.enumerable
      || !('value' in descriptor)
      || descriptor.value === undefined
    ) fail();
  }
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): void {
  const actual = Object.keys(value);
  if (
    required.some((key) => !actual.includes(key))
    || actual.some((key) => !required.includes(key) && !optional.includes(key))
  ) fail();
}

function allowedKeys(value: Record<string, unknown>, allowed: readonly string[]): void {
  if (Object.keys(value).some((key) => !allowed.includes(key))) fail();
}

function identifier(value: unknown): value is string {
  return typeof value === 'string'
    && value.length <= 128
    && /^[a-z0-9][a-z0-9._-]*$/u.test(value);
}

function packageName(value: unknown): value is string {
  return typeof value === 'string'
    && value.length <= 214
    && /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/u.test(value);
}

function version(value: unknown): value is string {
  return typeof value === 'string'
    && /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u.test(value);
}

function positive(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

function candidateByteLimit(value: unknown): number {
  if (value === undefined) return PEER_SEMANTICS_V2_CONTRACT.limits.candidateBytes;
  if (!positive(value) || value > PEER_SEMANTICS_V2_CONTRACT.limits.candidateBytes) fail();
  return value;
}

function digest(value: unknown): string {
  return createHash('sha256').update(canonicalJson(value)).digest('hex');
}

function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function isObject(value: unknown): value is object {
  return typeof value === 'object' && value !== null;
}

function deepFreeze<T>(value: T): T {
  if (isObject(value) && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function cloneJsonEvidence(value: unknown, byteLimit: number): unknown {
  let visits = 0;
  let minimumBytes = 0;
  const active = new WeakSet<object>();
  const clone = (item: unknown, depth: number): unknown => {
    visits += 1;
    if (visits > 50_000 || depth > 64) fail();
    if (item === null || typeof item === 'boolean') {
      minimumBytes += 1;
      if (minimumBytes > byteLimit) fail();
      return item;
    }
    if (typeof item === 'string') {
      minimumBytes += Buffer.byteLength(item);
      if (minimumBytes > byteLimit) fail();
      return item;
    }
    if (typeof item === 'number') {
      if (!Number.isSafeInteger(item)) fail();
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
          if (
            !descriptor
            || !descriptor.enumerable
            || !('value' in descriptor)
            || descriptor.value === undefined
          ) fail();
        }
        if (Object.keys(item).length !== item.length) fail();
        return item.map((child) => clone(child, depth + 1));
      }
      const record = ownRecord(item);
      const output: Record<string, unknown> = Object.create(null);
      for (const key of Object.keys(record)) {
        minimumBytes += Buffer.byteLength(key);
        if (minimumBytes > byteLimit) fail();
        output[key] = clone(record[key], depth + 1);
      }
      return output;
    } finally {
      active.delete(item);
    }
  };
  const cloned = clone(value, 0);
  if (Buffer.byteLength(canonicalJson(cloned)) > byteLimit) fail();
  return cloned;
}

function fail(): never {
  throw new Error('exact_candidate_v2_invalid');
}
