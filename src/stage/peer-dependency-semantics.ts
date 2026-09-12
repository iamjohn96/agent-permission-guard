/**
 * Deliberately internal, pure peer-dependency analysis.  It is not wired into
 * Graph Genesis and has no authority over candidates, approvals, or artifacts.
 */
export type PeerSemanticsNode = Readonly<{
  installPath: string;
  packageName: string;
  version: string;
  dependencies?: unknown;
  peerDependencies?: unknown;
  peerDependenciesMeta?: unknown;
  dev?: unknown;
  optional?: unknown;
  peer?: unknown;
  devOptional?: unknown;
  link?: unknown;
  inBundle?: unknown;
  hasInstallScript?: unknown;
  optionalDependencies?: unknown;
  bundleDependencies?: unknown;
  bundledDependencies?: unknown;
  os?: unknown;
  cpu?: unknown;
}>;

export type PeerSemanticsInput = Readonly<{
  rootDependencies: unknown;
  nodes: unknown;
}>;

export type PeerRequirementOutcome = Readonly<{
  from: string;
  name: string;
  optional: boolean;
  targetPath?: string;
}>;

export type PeerSemanticsAnalysis = Readonly<{
  /** Internal analysis data only; never a diagnostic or production export. */
  productionPaths: readonly string[];
  requiredPaths: readonly string[];
  peerRequirements: readonly PeerRequirementOutcome[];
}>;

export class PeerDependencySemanticsError extends Error {
  readonly code = 'peer_semantics_invalid';
  readonly predicate: string;

  constructor(predicate: string) {
    super('peer semantics rejected');
    this.name = 'PeerDependencySemanticsError';
    this.predicate = predicate;
  }
}

type Version = readonly [number, number, number];
type Node = Readonly<{ path: string; name: string; version: Version; dependencies: Map<string, string>; peers: Map<string, Peer>; flags: Map<string, boolean | undefined> }>;
type Peer = Readonly<{ range: string; optional: boolean }>;
type Comparison = Readonly<{ operator: '<' | '<=' | '>' | '>=' | '='; version: Version }>;
type Range = ReadonlyArray<ReadonlyArray<Comparison>>;

const MAX_STRING_BYTES = 256;
const MAX_BRANCHES = 8;
const MAX_ATOMS = 16;
const MAX_COMPARISONS = 32;
const MAX_NODES = 256;
const MAX_DEPTH = 32;
const MAX_PATH_BYTES = 512;
const MAX_PEERS_PER_NODE = 64;
const MAX_PEERS = 2048;
const MAX_COMBINED = 4096;
const ROLE_FLAGS = ['dev', 'optional', 'peer', 'devOptional', 'link', 'inBundle'] as const;
const FIELD_REJECTIONS = ['hasInstallScript', 'optionalDependencies', 'bundleDependencies', 'bundledDependencies', 'os', 'cpu'] as const;
const NODE_KEYS = new Set<string>(['installPath', 'packageName', 'version', 'dependencies', 'peerDependencies', 'peerDependenciesMeta', ...ROLE_FLAGS, ...FIELD_REJECTIONS]);

export function analyzePeerDependencySemantics(input: PeerSemanticsInput): PeerSemanticsAnalysis {
  const inputRecord = ownRecord(input, 'shape');
  if (Object.keys(inputRecord).some((key) => key !== 'rootDependencies' && key !== 'nodes')) fail('shape');
  const root = ownRecord(inputRecord.rootDependencies, 'shape');
  const rawNodes = inputRecord.nodes;
  if (!Array.isArray(rawNodes)) fail('shape');
  if (rawNodes.length > MAX_NODES) fail('budget');
  const rootDependencies = stringMap(root, 'shape');
  for (const name of rootDependencies.keys()) packageName(name);
  const nodes = new Map<string, Node>();
  const shallow = rawNodes.map((raw) => {
    const record = ownRecord(raw, 'shape');
    return { record, path: boundedString(record.installPath, 'shape') };
  }).sort((a, b) => compareText(a.path, b.path));
  for (const { record } of shallow) {
    const node = parseNode(record);
    if (nodes.has(node.path)) fail('shape');
    nodes.set(node.path, node);
  }
  const orderedNodes = [...nodes.values()].sort(byPath);
  for (const node of orderedNodes) {
    const parent = parentPath(node.path);
    if (parent !== undefined && parent !== '' && !nodes.has(parent)) fail('shape');
  }
  let peerCount = 0;
  for (const node of orderedNodes) peerCount += node.peers.size;
  if (peerCount > MAX_PEERS || peerCount + nodes.size > MAX_COMBINED) fail('budget');

  const parsedRootRanges = new Map<string, Range>();
  const parsedNodeRanges = new Map<string, Map<string, Range>>();
  const parsedPeerRanges = new Map<string, Map<string, Range>>();
  for (const [name, range] of sorted(rootDependencies)) parsedRootRanges.set(name, parseRange(range));
  for (const node of orderedNodes) {
    const ordinary = new Map<string, Range>(); const peers = new Map<string, Range>();
    for (const [name, range] of sorted(node.dependencies)) ordinary.set(name, parseRange(range));
    for (const [name, peer] of sorted(node.peers)) peers.set(name, parseRange(peer.range));
    parsedNodeRanges.set(node.path, ordinary); parsedPeerRanges.set(node.path, peers);
  }
  const ordinaryTargets = new Map<string, Map<string, Node>>();
  for (const node of orderedNodes) {
    const resolved = new Map<string, Node>();
    for (const [name] of sorted(node.dependencies)) {
      const target = resolveNearest(nodes, node.path, name);
      if (!target) fail('ordinary_resolution');
      if (!satisfies(target.version, parsedNodeRanges.get(node.path)!.get(name)!)) fail('ordinary_range');
      resolved.set(name, target);
    }
    ordinaryTargets.set(node.path, resolved);
  }
  const rootTargets = new Map<string, Node>();
  for (const [name] of sorted(rootDependencies)) {
    const target = nodes.get(childPath('', name));
    if (!target) fail('ordinary_resolution');
    if (!satisfies(target.version, parsedRootRanges.get(name)!)) fail('ordinary_range');
    rootTargets.set(name, target);
  }

  const production = closure(rootTargets.values(), ordinaryTargets);
  assertOrdinaryDag(production, ordinaryTargets);
  const required = new Set(production);
  const outcomes: PeerRequirementOutcome[] = [];
  const queue = [...production].sort(byPath);
  for (let index = 0; index < queue.length; index += 1) {
    const node = queue[index]!;
    for (const [name, peer] of sorted(node.peers)) {
      if (name === node.name) fail('self_peer');
      const local = nodes.get(childPath(node.path, name));
      if (local) fail('peer_local');
      const target = resolveNearest(nodes, parentPath(node.path) ?? '', name);
      if (!target) {
        if (!peer.optional) fail('peer_missing');
        outcomes.push(Object.freeze({ from: node.path, name, optional: true }));
        continue;
      }
      if (target.path === node.path) fail('self_peer');
      if (!satisfies(target.version, parsedPeerRanges.get(node.path)!.get(name)!)) fail('peer_conflict');
      outcomes.push(Object.freeze({ from: node.path, name, optional: peer.optional, targetPath: target.path }));
      if (!peer.optional && !required.has(target)) {
        required.add(target);
        queue.push(target);
        queue.sort(byPath);
      }
    }
  }
  assertOrdinaryDag(required, ordinaryTargets);
  if (required.size !== nodes.size) fail('closure');
  for (const node of orderedNodes) {
    const expectedPeer = required.has(node) && !production.has(node);
    const peerFlag = node.flags.get('peer');
    if (peerFlag !== undefined && peerFlag !== expectedPeer) fail('role');
  }
  return Object.freeze({
    productionPaths: Object.freeze([...production].map((node) => node.path).sort(compareText)),
    requiredPaths: Object.freeze([...required].map((node) => node.path).sort(compareText)),
    peerRequirements: Object.freeze(outcomes.sort((a, b) => compareText(`${a.from}\0${a.name}`, `${b.from}\0${b.name}`))),
  });
}

function parseNode(record: Record<string, unknown>): Node {
  for (const key of Object.keys(record)) if (!NODE_KEYS.has(key)) fail('shape');
  const path = boundedString(record.installPath, 'shape');
  const name = packageName(record.packageName);
  if (!validPath(path) || Buffer.byteLength(path) > MAX_PATH_BYTES || depth(path) > MAX_DEPTH) fail('shape');
  if (pathName(path) !== name) fail('shape');
  const version = parseVersion(boundedString(record.version, 'version'));
  const flags = new Map<string, boolean | undefined>();
  for (const key of ROLE_FLAGS) {
    const valueAtKey = record[key];
    if (valueAtKey !== undefined && typeof valueAtKey !== 'boolean') fail('role_type');
    flags.set(key, valueAtKey as boolean | undefined);
    if (valueAtKey === true && key !== 'peer') fail('prohibited_role');
  }
  for (const key of FIELD_REJECTIONS) if (Object.hasOwn(record, key)) fail('prohibited_field');
  const dependencies = stringMap(record.dependencies === undefined ? Object.create(null) as Record<string, unknown> : ownRecord(record.dependencies, 'shape'), 'shape');
  const peers = peerMap(record.peerDependencies, record.peerDependenciesMeta, dependencies);
  return Object.freeze({ path, name, version, dependencies, peers, flags });
}

function peerMap(rawPeers: unknown, rawMeta: unknown, dependencies: Map<string, string>): Map<string, Peer> {
  if (rawPeers === undefined && rawMeta !== undefined) fail('peer_meta');
  const peers = rawPeers === undefined ? new Map<string, string>() : stringMap(ownRecord(rawPeers, 'peer_shape'), 'peer_shape');
  if (peers.size > MAX_PEERS_PER_NODE) fail('budget');
  const meta = rawMeta === undefined ? new Map<string, unknown>() : unknownMap(ownRecord(rawMeta, 'peer_meta'));
  const output = new Map<string, Peer>();
  for (const [name, range] of sorted(peers)) {
    packageName(name);
    if (dependencies.has(name)) fail('overlap');
    const metaValue = meta.get(name);
    let optional = false;
    if (metaValue !== undefined) {
      const descriptor = ownRecord(metaValue, 'peer_meta');
      const keys = Object.keys(descriptor);
      if (keys.some((key) => key !== 'optional') || (Object.hasOwn(descriptor, 'optional') && typeof descriptor.optional !== 'boolean')) fail('peer_meta');
      optional = descriptor.optional === true;
    }
    output.set(name, Object.freeze({ range, optional }));
  }
  for (const name of meta.keys()) if (!peers.has(name)) fail('peer_meta');
  return output;
}

function closure(initial: Iterable<Node>, edges: Map<string, Map<string, Node>>): Set<Node> {
  const result = new Set<Node>();
  const queue = [...initial].sort(byPath);
  while (queue.length > 0) {
    const node = queue.shift()!;
    if (result.has(node)) continue;
    result.add(node);
    for (const target of edges.get(node.path)?.values() ?? []) if (!result.has(target)) queue.push(target);
    queue.sort(byPath);
  }
  return result;
}

function assertOrdinaryDag(nodes: Set<Node>, edges: Map<string, Map<string, Node>>): void {
  const visiting = new Set<Node>();
  const done = new Set<Node>();
  const visit = (node: Node): void => {
    if (visiting.has(node)) fail('ordinary_cycle');
    if (done.has(node)) return;
    visiting.add(node);
    for (const target of edges.get(node.path)?.values() ?? []) if (nodes.has(target)) visit(target);
    visiting.delete(node); done.add(node);
  };
  for (const node of [...nodes].sort(byPath)) visit(node);
}

function resolveNearest(nodes: Map<string, Node>, start: string, name: string): Node | undefined {
  for (let context: string | undefined = start; context !== undefined; context = parentPath(context)) {
    const target = nodes.get(childPath(context, name));
    if (target) return target;
  }
  return undefined;
}

function childPath(context: string, name: string): string { return context === '' ? `node_modules/${name}` : `${context}/node_modules/${name}`; }
function parentPath(path: string): string | undefined {
  if (path === '') return undefined;
  if (/^node_modules\/(?:@[^/]+\/)?[^/]+$/.test(path)) return '';
  const match = /^(.*)\/node_modules\/(?:@[^/]+\/)?[^/]+$/.exec(path);
  return match ? match[1]! : undefined;
}
function validPath(path: string): boolean { return path === '' || /^(node_modules\/(?:@[^/]+\/)?[^/]+)(\/node_modules\/(?:@[^/]+\/)?[^/]+)*$/.test(path); }
function depth(path: string): number { return path === '' ? 0 : path.split('/node_modules/').length - 1; }
function byPath(a: Node, b: Node): number { return compareText(a.path, b.path); }
function sorted<T>(map: Map<string, T>): Array<[string, T]> { return [...map.entries()].sort(([a], [b]) => compareText(a, b)); }
function compareText(a: string, b: string): number { return a < b ? -1 : a > b ? 1 : 0; }
function pathName(path: string): string { const parts = path.split('/'); return parts.length >= 2 && parts[parts.length - 2]?.startsWith('@') ? `${parts[parts.length - 2]}/${parts[parts.length - 1]}` : parts[parts.length - 1] ?? ''; }

function ownRecord(value: unknown, predicate: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(predicate);
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) fail(predicate);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') fail(predicate);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !('value' in descriptor)) fail(predicate);
  }
  return value as Record<string, unknown>;
}
function unknownMap(record: Record<string, unknown>): Map<string, unknown> { return new Map(Object.keys(record).map((key) => [key, record[key]])); }
function stringMap(record: Record<string, unknown>, predicate: string): Map<string, string> {
  const output = new Map<string, string>();
  for (const key of Object.keys(record)) output.set(key, boundedString(record[key], predicate));
  return output;
}
function boundedString(value: unknown, predicate: string): string {
  if (typeof value !== 'string' || Buffer.byteLength(value) > MAX_STRING_BYTES) fail(predicate);
  return value;
}
function packageName(name: unknown): string {
  const value = boundedString(name, 'shape');
  if (!/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/.test(value)) fail('shape');
  return value;
}
function fail(predicate: string): never { throw new PeerDependencySemanticsError(predicate); }

function parseVersion(value: string): Version {
  const match = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(value);
  if (!match) fail('version');
  const tuple = match.slice(1).map(Number) as [number, number, number];
  if (tuple.some((part) => !Number.isSafeInteger(part))) fail('version');
  return tuple;
}
function parseRange(value: string): Range {
  if (Buffer.byteLength(value) > MAX_STRING_BYTES || value.length === 0 || value.trim() !== value || /[^\x20-\x7e]/.test(value)) fail('specifier');
  if (value === '*') return [[]];
  const branches = value.split(/ ?\|\| ?/);
  if (branches.length > MAX_BRANCHES || branches.some((branch) => branch.length === 0 || branch.includes('||'))) fail('specifier');
  let atoms = 0; let comparisons = 0;
  const parsed = branches.map((branch) => {
    if (branch.includes('  ')) fail('specifier');
    const branchComparisons: Comparison[] = [];
    for (const atom of branch.split(' ')) {
      atoms += 1;
      if (atoms > MAX_ATOMS) fail('budget');
      const match = /^(=|<=|>=|<|>|\^|~)?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(atom);
      if (!match) fail('specifier');
      const version = parseVersion(match.slice(2).join('.'));
      const operator = match[1] ?? '=';
      if (operator === '^' || operator === '~') {
        branchComparisons.push({ operator: '>=', version });
        const upper: Version = operator === '~'
          ? increment(version, 1)
          : version[0] > 0 ? increment(version, 0) : version[1] > 0 ? increment(version, 1) : increment(version, 2);
        branchComparisons.push({ operator: '<', version: upper });
      } else branchComparisons.push({ operator: operator as Comparison['operator'], version });
      comparisons += operator === '^' || operator === '~' ? 2 : 1;
      if (comparisons > MAX_COMPARISONS) fail('budget');
    }
    return branchComparisons;
  });
  return parsed;
}
function increment(version: Version, index: number): Version {
  const result: [number, number, number] = [...version] as [number, number, number];
  const current = result[index];
  if (current === undefined || current === Number.MAX_SAFE_INTEGER) fail('specifier');
  result[index] = current + 1; for (let i = index + 1; i < 3; i += 1) result[i] = 0;
  return result;
}
function satisfies(version: Version, range: Range): boolean { return range.some((and) => and.every((comparison) => compare(version, comparison.version, comparison.operator))); }
function compare(left: Version, right: Version, operator: Comparison['operator']): boolean {
  const ordering = left[0] === right[0] ? left[1] === right[1] ? left[2] - right[2] : left[1] - right[1] : left[0] - right[0];
  return operator === '=' ? ordering === 0 : operator === '<' ? ordering < 0 : operator === '<=' ? ordering <= 0 : operator === '>' ? ordering > 0 : ordering >= 0;
}
