import { createHash } from 'node:crypto';
import { constants, type BigIntStats } from 'node:fs';
import { lstat, open, readdir, realpath } from 'node:fs/promises';
import { join, relative, resolve, sep } from 'node:path';

import { canonicalJson } from '../audit/canonical-json.js';
import {
  PackageStageError,
  type VerifiedMcpGraphProfileAuthority,
  validatePortableRelativePath,
} from './profile.js';
import type {
  AuthenticatedVerifiedMcpGraphProfile,
  MaterializedTreeManifest,
  MaterializedTreeRecord,
  PackageStageLimits,
} from './types.js';

export type MaterializedPackageGraphValidation = Readonly<{
  treeManifest: MaterializedTreeManifest;
  entrypointRelativePath: string;
  entrypointSha256: string;
}>;

export async function createMaterializedTreeManifest(
  root: string,
  limits: PackageStageLimits,
): Promise<MaterializedTreeManifest> {
  const canonicalRoot = await canonicalDirectory(root);
  const records: MaterializedTreeRecord[] = [];
  let totalBytes = 0;

  const walk = async (directory: string): Promise<void> => {
    let names: string[];
    try {
      names = await readdir(directory);
    } catch {
      throw new PackageStageError('tree_invalid');
    }
    names.sort(compareText);
    for (const name of names) {
      const absolutePath = join(directory, name);
      const relativePath = toPortableRelative(canonicalRoot, absolutePath, limits);
      await assertCanonicalContained(canonicalRoot, absolutePath);
      let observed;
      try {
        observed = await lstat(absolutePath, { bigint: true });
      } catch {
        throw new PackageStageError('tree_invalid');
      }
      const mode = Number(observed.mode);
      if ((mode & 0o6000) !== 0) throw new PackageStageError('tree_invalid');

      if (observed.isSymbolicLink() || (!observed.isDirectory() && !observed.isFile())) {
        throw new PackageStageError('tree_invalid');
      }
      if (observed.isDirectory()) {
        if ((mode & 0o777) !== 0o755) throw new PackageStageError('tree_invalid');
        records.push(Object.freeze({
          relativePath,
          type: 'directory' as const,
          normalizedMode: 0o755,
          size: 0,
        }));
        if (records.length > limits.archiveEntries) throw new PackageStageError('tree_invalid');
        await walk(absolutePath);
        continue;
      }

      if (observed.nlink !== 1n || observed.size > BigInt(limits.regularFileBytes)) {
        throw new PackageStageError('tree_invalid');
      }
      const normalizedMode = (mode & 0o111) === 0 ? 0o644 : 0o755;
      if ((mode & 0o777) !== normalizedMode) throw new PackageStageError('tree_invalid');
      const size = Number(observed.size);
      totalBytes += size;
      if (totalBytes > limits.totalUncompressedBytes) throw new PackageStageError('tree_invalid');
      const sha256 = await hashRegularFile(absolutePath, observed, limits.regularFileBytes);
      records.push(Object.freeze({
        relativePath,
        type: 'file' as const,
        normalizedMode,
        size,
        sha256,
      }));
      if (records.length > limits.archiveEntries) throw new PackageStageError('tree_invalid');
    }
  };

  await walk(canonicalRoot);
  records.sort((left, right) => compareText(left.relativePath, right.relativePath));
  const frozenRecords = Object.freeze(records);
  const treeDigest = createHash('sha256').update(canonicalJson(frozenRecords)).digest('hex');
  return Object.freeze({ manifestVersion: 1 as const, records: frozenRecords, treeDigest });
}

export async function revalidateMaterializedTree(
  root: string,
  expected: MaterializedTreeManifest,
  limits: PackageStageLimits,
): Promise<MaterializedTreeManifest> {
  const current = await createMaterializedTreeManifest(root, limits);
  if (
    expected.manifestVersion !== 1
    || expected.treeDigest !== current.treeDigest
    || canonicalJson(expected.records) !== canonicalJson(current.records)
  ) {
    throw new PackageStageError('tree_changed');
  }
  return current;
}

export async function validateMaterializedPackageGraph(
  root: string,
  profile: AuthenticatedVerifiedMcpGraphProfile,
  profileAuthority: VerifiedMcpGraphProfileAuthority,
): Promise<MaterializedPackageGraphValidation> {
  profileAuthority.assertAuthenticates(profile);
  const treeManifest = await createMaterializedTreeManifest(root, profile.limits);
  const recordsByPath = new Map(treeManifest.records.map((record) => [record.relativePath, record]));
  const expectedPackageJsonPaths = new Set(profile.graphNodes.map((node) => `${node.installPath}/package.json`));
  const declaredInstallPaths = new Set(profile.graphNodes.map((node) => node.installPath));

  for (const record of treeManifest.records) {
    if (record.type === 'file' && record.relativePath.endsWith('/package.json') && !expectedPackageJsonPaths.has(record.relativePath)) {
      throw new PackageStageError('tree_invalid');
    }
    if (record.relativePath.endsWith('/binding.gyp')) throw new PackageStageError('tree_invalid');
    validateNodeModulesLayout(record, declaredInstallPaths);
  }

  const canonicalRoot = await canonicalDirectory(root);
  for (const node of profile.graphNodes) {
    const packageJsonPath = `${node.installPath}/package.json`;
    const packageJsonRecord = recordsByPath.get(packageJsonPath);
    if (packageJsonRecord?.type !== 'file' || packageJsonRecord.size > 1024 * 1024) {
      throw new PackageStageError('tree_invalid');
    }
    const manifest = await readJsonObject(join(canonicalRoot, ...packageJsonPath.split('/')));
    if (manifest.name !== node.packageName || manifest.version !== node.exactVersion) {
      throw new PackageStageError('tree_invalid');
    }
    const expectedDependencies = Object.fromEntries(
      node.dependencyEdges.map((edge) => [edge.packageName, edge.declaredSpecifier]),
    );
    if (canonicalJson(normalizeStringMap(manifest.dependencies)) !== canonicalJson(expectedDependencies)) {
      throw new PackageStageError('tree_invalid');
    }
    if (Object.keys(normalizeStringMap(manifest.optionalDependencies)).length > 0
      || Object.keys(normalizeStringMap(manifest.peerDependencies)).length > 0) {
      throw new PackageStageError('tree_invalid');
    }
    const scripts = normalizeStringMap(manifest.scripts);
    const observedScriptNames = Object.keys(scripts).sort(compareText);
    if (canonicalJson(observedScriptNames) !== canonicalJson(node.expectedLifecycleScriptNames)) {
      throw new PackageStageError('tree_invalid');
    }
  }

  const topNode = profile.graphNodes.find((node) => node.packageName === profile.topPackage.name
    && node.exactVersion === profile.topPackage.exactVersion
    && node.installPath === `node_modules/${profile.topPackage.name}`);
  if (topNode === undefined) throw new PackageStageError('tree_invalid');
  const entrypointRelativePath = `${topNode.installPath}/${profile.topPackage.exactEntrypointRelativePath}`;
  const entrypoint = recordsByPath.get(entrypointRelativePath);
  if (entrypoint?.type !== 'file' || entrypoint.sha256 === undefined) {
    throw new PackageStageError('tree_invalid');
  }
  const postValidationManifest = await createMaterializedTreeManifest(canonicalRoot, profile.limits);
  if (postValidationManifest.treeDigest !== treeManifest.treeDigest
    || canonicalJson(postValidationManifest.records) !== canonicalJson(treeManifest.records)) {
    throw new PackageStageError('tree_changed');
  }
  return Object.freeze({
    treeManifest: postValidationManifest,
    entrypointRelativePath,
    entrypointSha256: entrypoint.sha256,
  });
}

async function canonicalDirectory(path: string): Promise<string> {
  try {
    const before = await lstat(path, { bigint: true });
    if (!before.isDirectory() || before.isSymbolicLink()) throw new PackageStageError('tree_invalid');
    const canonical = await realpath(resolve(path));
    const after = await lstat(canonical, { bigint: true });
    if (!after.isDirectory() || before.dev !== after.dev || before.ino !== after.ino) {
      throw new PackageStageError('tree_invalid');
    }
    return canonical;
  } catch (error) {
    if (error instanceof PackageStageError) throw error;
    throw new PackageStageError('tree_invalid');
  }
}

async function assertCanonicalContained(root: string, path: string): Promise<void> {
  try {
    const canonical = await realpath(path);
    if (canonical !== path || (canonical !== root && !canonical.startsWith(`${root}${sep}`))) {
      throw new PackageStageError('tree_invalid');
    }
  } catch (error) {
    if (error instanceof PackageStageError) throw error;
    throw new PackageStageError('tree_invalid');
  }
}

function toPortableRelative(root: string, absolutePath: string, limits: PackageStageLimits): string {
  const value = relative(root, absolutePath).split(sep).join('/');
  try {
    validatePortableRelativePath(value, limits);
  } catch {
    throw new PackageStageError('tree_invalid');
  }
  return value;
}

async function hashRegularFile(
  path: string,
  expected: BigIntStats,
  maxBytes: number,
): Promise<string> {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size > BigInt(maxBytes)) {
      throw new PackageStageError('tree_invalid');
    }
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let position = 0;
    while (position < Number(before.size)) {
      const { bytesRead } = await handle.read(buffer, 0, Math.min(buffer.length, Number(before.size) - position), position);
      if (bytesRead === 0) throw new PackageStageError('tree_changed');
      hash.update(buffer.subarray(0, bytesRead));
      position += bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    if (!sameFileStat(expected, before) || !sameFileStat(before, after)) {
      throw new PackageStageError('tree_changed');
    }
    return hash.digest('hex');
  } catch (error) {
    if (error instanceof PackageStageError) throw error;
    throw new PackageStageError('tree_invalid');
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function sameFileStat(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mode === right.mode
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

async function readJsonObject(path: string): Promise<Record<string, unknown>> {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const observed = await handle.stat();
    if (!observed.isFile() || observed.size > 1024 * 1024) throw new PackageStageError('tree_invalid');
    const bytes = await handle.readFile();
    const parsed: unknown = JSON.parse(bytes.toString('utf8'));
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new PackageStageError('tree_invalid');
    }
    return parsed as Record<string, unknown>;
  } catch (error) {
    if (error instanceof PackageStageError) throw error;
    throw new PackageStageError('tree_invalid');
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function normalizeStringMap(value: unknown): Record<string, string> {
  if (value === undefined) return {};
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new PackageStageError('tree_invalid');
  }
  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.some(([key, nested]) => key.length === 0 || typeof nested !== 'string')) {
    throw new PackageStageError('tree_invalid');
  }
  return Object.fromEntries(entries.sort(([left], [right]) => compareText(left, right))) as Record<string, string>;
}

function validateNodeModulesLayout(
  record: MaterializedTreeRecord,
  declaredInstallPaths: ReadonlySet<string>,
): void {
  const segments = record.relativePath.split('/');
  const marker = segments.lastIndexOf('node_modules');
  if (marker < 0) return;
  if (marker === segments.length - 1) {
    if (record.type !== 'directory'
      || ![...declaredInstallPaths].some((path) => path.startsWith(`${record.relativePath}/`))) {
      throw new PackageStageError('tree_invalid');
    }
    return;
  }

  const firstPackageSegment = segments[marker + 1]!;
  const scoped = firstPackageSegment.startsWith('@');
  if (scoped && marker + 2 >= segments.length) {
    if (record.type !== 'directory'
      || ![...declaredInstallPaths].some((path) => path.startsWith(`${record.relativePath}/`))) {
      throw new PackageStageError('tree_invalid');
    }
    return;
  }
  const packageEnd = marker + (scoped ? 3 : 2);
  const packagePath = segments.slice(0, packageEnd).join('/');
  if (!declaredInstallPaths.has(packagePath)) throw new PackageStageError('tree_invalid');
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
