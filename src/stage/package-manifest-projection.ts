import { createHash } from 'node:crypto';

import { canonicalJson } from '../audit/canonical-json.js';
import type { TarArchiveTranscript } from './tar-archive-parser.js';
import { PackageStageError } from './profile.js';
import type { ExactGraphCandidate, ExactGraphCandidateNode } from './exact-production-graph.js';

const MAX_MANIFEST_BYTES = 1024 * 1024;
const MAX_JSON_DEPTH = 64;
const MAX_JSON_KEYS = 10_000;
const INSTALL_LIFECYCLE_NAMES = new Set(['preinstall', 'install', 'postinstall']);

export type PackageManifestProjection = Readonly<{
  projectionVersion: 1;
  packageName: string;
  exactVersion: string;
  dependencies: readonly Readonly<{ packageName: string; declaredSpecifier: string }>[];
  lifecycleScriptNames: readonly string[];
  packageType: 'module' | 'commonjs' | null;
  entrypointFieldsDigest: string;
  packageJsonBodySha256: string;
  projectionDigest: string;
}>;

export function projectAndValidatePackageManifest(
  packageManifestBase64: string,
  transcript: TarArchiveTranscript,
  candidate: ExactGraphCandidate,
  nodes: readonly ExactGraphCandidateNode[],
): PackageManifestProjection {
  if (nodes.length === 0 || nodes.some((node) => !samePackageIdentity(node, nodes[0]!))) {
    throw new PackageStageError('manifest_mismatch');
  }
  const manifestEntry = transcript.entries.filter((entry) => entry.relativePath === 'package.json');
  if (
    manifestEntry.length !== 1
    || manifestEntry[0]!.type !== 'file'
    || manifestEntry[0]!.bodySha256 === null
  ) throw new PackageStageError('manifest_invalid');
  const bytes = decodeCanonicalBase64(packageManifestBase64);
  if (bytes.length === 0 || bytes.length > MAX_MANIFEST_BYTES) throw new PackageStageError('manifest_invalid');
  const bodySha256 = sha256(bytes);
  if (bodySha256 !== manifestEntry[0]!.bodySha256) throw new PackageStageError('manifest_mismatch');
  let text: string;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
  catch { throw new PackageStageError('manifest_invalid'); }
  scanJsonWithoutDuplicateKeys(text);
  let parsed: unknown;
  try { parsed = JSON.parse(text); } catch { throw new PackageStageError('manifest_invalid'); }
  assertRecord(parsed);

  const node = nodes[0]!;
  if (parsed.name !== node.packageName || parsed.version !== node.exactVersion) {
    throw new PackageStageError('manifest_mismatch');
  }
  for (const forbidden of [
    'optionalDependencies', 'peerDependencies', 'peerDependenciesMeta', 'bundleDependencies',
    'bundledDependencies', 'workspaces', 'os', 'cpu',
  ]) {
    if (Object.hasOwn(parsed, forbidden)) throw new PackageStageError('manifest_mismatch');
  }
  if (parsed.gypfile === true) throw new PackageStageError('manifest_mismatch');

  const dependencies = parseStringMap(parsed.dependencies, 'manifest_mismatch')
    .map(([packageName, declaredSpecifier]) => Object.freeze({ packageName, declaredSpecifier }))
    .sort((left, right) => compareText(left.packageName, right.packageName));
  const expectedDependencies = node.dependencyEdges.map((edge) => ({
    packageName: edge.packageName,
    declaredSpecifier: edge.declaredSpecifier,
  })).sort((left, right) => compareText(left.packageName, right.packageName));
  if (canonicalJson(dependencies) !== canonicalJson(expectedDependencies)) {
    throw new PackageStageError('manifest_mismatch');
  }

  const scripts = parseStringMap(parsed.scripts, 'manifest_invalid');
  const lifecycleScriptNames = scripts.map(([name]) => name)
    .filter((name) => INSTALL_LIFECYCLE_NAMES.has(name))
    .sort(compareText);
  if (canonicalJson(lifecycleScriptNames) !== canonicalJson(node.expectedLifecycleScriptNames)) {
    throw new PackageStageError('manifest_mismatch');
  }
  const packageType: PackageManifestProjection['packageType'] = parsed.type === undefined
    ? null
    : parsed.type === 'module' || parsed.type === 'commonjs'
      ? parsed.type
      : failManifest();
  const entrypointFields = deepFreeze({
    type: packageType,
    main: normalizeJsonField(parsed.main),
    exports: normalizeJsonField(parsed.exports),
    bin: normalizeJsonField(parsed.bin),
  });
  for (const candidateNode of nodes) {
    if (
      candidateNode.installPath === `node_modules/${candidate.topPackage.name}`
      && !transcript.entries.some((entry) =>
        entry.relativePath === candidate.topPackage.exactEntrypointRelativePath && entry.type === 'file')
    ) throw new PackageStageError('manifest_mismatch');
  }
  const unsigned = deepFreeze({
    projectionVersion: 1 as const,
    packageName: node.packageName,
    exactVersion: node.exactVersion,
    dependencies: Object.freeze(dependencies),
    lifecycleScriptNames: Object.freeze(lifecycleScriptNames),
    packageType,
    entrypointFieldsDigest: sha256(Buffer.from(canonicalJson(entrypointFields))),
    packageJsonBodySha256: bodySha256,
  });
  return deepFreeze({ ...unsigned, projectionDigest: sha256(Buffer.from(canonicalJson(unsigned))) });
}

function parseStringMap(input: unknown, code: 'manifest_invalid' | 'manifest_mismatch'): [string, string][] {
  if (input === undefined) return [];
  if (typeof input !== 'object' || input === null || Array.isArray(input)) throw new PackageStageError(code);
  const output: [string, string][] = [];
  for (const [key, value] of Object.entries(input)) {
    if (
      key.length === 0 || key.length > 214 || /[\u0000-\u001f\u007f]/u.test(key)
      || typeof value !== 'string' || value.length === 0 || value.length > 1024
      || /[\u0000-\u001f\u007f]/u.test(value)
    ) throw new PackageStageError(code);
    output.push([key, value]);
  }
  return output;
}

function normalizeJsonField(input: unknown): unknown {
  if (input === undefined) return null;
  if (
    input === null || typeof input === 'string' || typeof input === 'boolean'
    || (typeof input === 'number' && Number.isFinite(input))
  ) return input;
  if (Array.isArray(input)) return Object.freeze(input.map(normalizeJsonField));
  if (typeof input === 'object') {
    return deepFreeze(Object.fromEntries(Object.entries(input)
      .sort(([left], [right]) => compareText(left, right))
      .map(([key, value]) => [key, normalizeJsonField(value)])));
  }
  throw new PackageStageError('manifest_invalid');
}

function scanJsonWithoutDuplicateKeys(text: string): void {
  const scanner = new JsonScanner(text);
  scanner.parse();
}

class JsonScanner {
  #index = 0;
  #keys = 0;

  constructor(private readonly text: string) {}

  parse(): void {
    this.#skipWhitespace();
    this.#parseValue(0);
    this.#skipWhitespace();
    if (this.#index !== this.text.length) failManifest();
  }

  #parseValue(depth: number): void {
    if (depth > MAX_JSON_DEPTH) failManifest();
    const token = this.text[this.#index];
    if (token === '{') return this.#parseObject(depth + 1);
    if (token === '[') return this.#parseArray(depth + 1);
    if (token === '"') { this.#parseString(); return; }
    if (this.text.startsWith('true', this.#index)) { this.#index += 4; return; }
    if (this.text.startsWith('false', this.#index)) { this.#index += 5; return; }
    if (this.text.startsWith('null', this.#index)) { this.#index += 4; return; }
    const match = this.text.slice(this.#index).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u);
    if (match === null) failManifest();
    this.#index += match[0].length;
  }

  #parseObject(depth: number): void {
    this.#index += 1;
    this.#skipWhitespace();
    const keys = new Set<string>();
    if (this.text[this.#index] === '}') { this.#index += 1; return; }
    while (true) {
      if (this.text[this.#index] !== '"') failManifest();
      const key = this.#parseString();
      this.#keys += 1;
      if (this.#keys > MAX_JSON_KEYS || keys.has(key)) failManifest();
      keys.add(key);
      this.#skipWhitespace();
      if (this.text[this.#index] !== ':') failManifest();
      this.#index += 1;
      this.#skipWhitespace();
      this.#parseValue(depth);
      this.#skipWhitespace();
      const separator = this.text[this.#index];
      if (separator === '}') { this.#index += 1; return; }
      if (separator !== ',') failManifest();
      this.#index += 1;
      this.#skipWhitespace();
    }
  }

  #parseArray(depth: number): void {
    this.#index += 1;
    this.#skipWhitespace();
    if (this.text[this.#index] === ']') { this.#index += 1; return; }
    while (true) {
      this.#parseValue(depth);
      this.#skipWhitespace();
      const separator = this.text[this.#index];
      if (separator === ']') { this.#index += 1; return; }
      if (separator !== ',') failManifest();
      this.#index += 1;
      this.#skipWhitespace();
    }
  }

  #parseString(): string {
    const start = this.#index;
    this.#index += 1;
    let escaped = false;
    while (this.#index < this.text.length) {
      const code = this.text.charCodeAt(this.#index);
      if (!escaped && code === 0x22) {
        this.#index += 1;
        try { return JSON.parse(this.text.slice(start, this.#index)) as string; }
        catch { failManifest(); }
      }
      if (!escaped && code < 0x20) failManifest();
      if (!escaped && code === 0x5c) escaped = true;
      else escaped = false;
      this.#index += 1;
    }
    failManifest();
  }

  #skipWhitespace(): void {
    while (/\s/u.test(this.text[this.#index] ?? '')) this.#index += 1;
  }
}

function decodeCanonicalBase64(input: string): Buffer {
  if (!/^[A-Za-z0-9+/]*={0,2}$/u.test(input)) failManifest();
  const output = Buffer.from(input, 'base64');
  if (output.toString('base64') !== input) failManifest();
  return output;
}

function samePackageIdentity(left: ExactGraphCandidateNode, right: ExactGraphCandidateNode): boolean {
  return left.packageName === right.packageName && left.exactVersion === right.exactVersion
    && left.tarballUrl === right.tarballUrl && left.sha512Integrity === right.sha512Integrity;
}

function assertRecord(input: unknown): asserts input is Record<string, unknown> {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) failManifest();
}

function failManifest(): never {
  throw new PackageStageError('manifest_invalid');
}

function sha256(input: Uint8Array): string {
  return createHash('sha256').update(input).digest('hex');
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function deepFreeze<T>(input: T): T {
  if (typeof input !== 'object' || input === null || Object.isFrozen(input)) return input;
  for (const value of Object.values(input)) deepFreeze(value);
  return Object.freeze(input);
}
