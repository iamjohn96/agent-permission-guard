import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, opendir } from 'node:fs/promises';
import { join } from 'node:path';

import { canonicalJson } from '../audit/canonical-json.js';
import type { GraphGenesisProtectedFile, GraphGenesisWorkspace } from './graph-genesis.js';
import { parseStrictJsonDocument } from './graph-genesis-broker.js';
import type { ExactCompilationContractV1 } from './graph-genesis-v2-binding.js';
import {
  type ExactGraphCandidateV2,
  type ExactGraphCandidateV2Authority,
  type ExactGraphCandidateV2Input,
} from './exact-production-graph-v2.js';

const MAX_LOCK_BYTES = 4 * 1024 * 1024;
const MAX_ENTRIES = 100_000;
const MAX_REGULAR_BYTES = 128 * 1024 * 1024;
const MAX_DEPTH = 64;
const MAX_CACHE_BYTES = 64 * 1024 * 1024;
const MAX_LOG_BYTES = 512 * 1024;
const SHA256 = /^[a-f0-9]{64}$/u;
const POST_STATE_NAMES = new Set([
  'package.json', 'package-lock.json', 'user.npmrc', 'global.npmrc', 'broker-profile.sb',
  'cache', 'logs', 'tmp',
]);
const ARCHIVE_NAME = /(?:\.tar|\.tgz|\.tar\.gz|\.zip|\.gz|\.bz2|\.xz)$/iu;
const NOOP = (): void => {};

export type SyntheticPostStateV2 = Readonly<{
  postStateVersion: 2;
  evidenceOrigin: 'synthetic_fixture';
  actionId: string;
  approvalId: string;
  planHash: string;
  executionEnvelopeHash: string;
  workspaceBinding: string;
  lockBytesDigest: string;
  lockDocumentDigest: string;
  inventoryDigest: string;
  protectedDigest: string;
  postStateDigest: string;
}>;

type OwnedPostState = Readonly<{
  publicState: SyntheticPostStateV2;
  lockDocument: ExactGraphCandidateV2Input['packageLock'];
  workspace: GraphGenesisWorkspace;
}>;

/** Fixture-only reader: paths and digests come from an owned session handoff. */
export class SyntheticPostStateV2Authority {
  readonly #owned = new WeakMap<object, OwnedPostState>();

  async capture(input: Readonly<{
    evidenceOrigin: 'synthetic_fixture'; actionId: string; approvalId: string; planHash: string;
    executionEnvelopeHash: string; workspaceBinding: string; workspace: GraphGenesisWorkspace;
    checkpoint?: () => void;
  }>): Promise<SyntheticPostStateV2> {
    try {
      if (input.evidenceOrigin !== 'synthetic_fixture' || !ids(input) || !digestValue(input.workspaceBinding)) fail();
      const checkpoint = input.checkpoint ?? NOOP;
      const root = await ownedRoot(input.workspace, checkpoint);
      const protectedDigest = await revalidateProtected(input.workspace, checkpoint);
      const inventory = await captureInventory(input.workspace, checkpoint);
      const lock = await readLock(input.workspace, checkpoint);
      if (!sameDirectory(root, await ownedRoot(input.workspace, checkpoint))) fail();
      if (protectedDigest !== await revalidateProtected(input.workspace, checkpoint)) fail();
      const inventoryAfter = await captureInventory(input.workspace, checkpoint);
      if (canonicalJson(inventory) !== canonicalJson(inventoryAfter)) fail();
      const unsigned = {
        postStateVersion: 2 as const, evidenceOrigin: 'synthetic_fixture' as const,
        actionId: input.actionId, approvalId: input.approvalId, planHash: input.planHash,
        executionEnvelopeHash: input.executionEnvelopeHash, workspaceBinding: input.workspaceBinding,
        lockBytesDigest: lock.bytesDigest, lockDocumentDigest: sha256(canonicalJson(lock.document)),
        inventoryDigest: sha256(canonicalJson(inventory)), protectedDigest,
      };
      const publicState = Object.freeze({ ...unsigned, postStateDigest: sha256(canonicalJson(unsigned)) });
      this.#owned.set(publicState, Object.freeze({ publicState, lockDocument: lock.document, workspace: input.workspace }));
      return publicState;
    } catch { fail(); }
  }

  authenticates(value: unknown): value is SyntheticPostStateV2 { return record(value) && this.#owned.has(value); }

  /** Rechecks the original owned workspace without exposing lock bytes or paths. */
  async revalidate(value: SyntheticPostStateV2, checkpoint: () => void = NOOP): Promise<void> {
    try {
      const owned = this.#owned.get(value); if (owned === undefined) fail();
      const root = await ownedRoot(owned.workspace, checkpoint);
      const protectedDigest = await revalidateProtected(owned.workspace, checkpoint);
      const inventory = await captureInventory(owned.workspace, checkpoint);
      const lock = await readLock(owned.workspace, checkpoint);
      if (!sameDirectory(root, await ownedRoot(owned.workspace, checkpoint))
        || protectedDigest !== value.protectedDigest
        || sha256(canonicalJson(inventory)) !== value.inventoryDigest
        || lock.bytesDigest !== value.lockBytesDigest
        || sha256(canonicalJson(lock.document)) !== value.lockDocumentDigest) fail();
      if (protectedDigest !== await revalidateProtected(owned.workspace, checkpoint)
        || canonicalJson(inventory) !== canonicalJson(await captureInventory(owned.workspace, checkpoint))) fail();
    } catch { fail(); }
  }

  matches(value: unknown, binding: Readonly<{ actionId: string; approvalId: string; planHash: string; executionEnvelopeHash: string }>): value is SyntheticPostStateV2 {
    const owned = record(value) ? this.#owned.get(value) : undefined;
    return owned?.publicState.actionId === binding.actionId && owned.publicState.approvalId === binding.approvalId
      && owned.publicState.planHash === binding.planHash && owned.publicState.executionEnvelopeHash === binding.executionEnvelopeHash;
  }

  compileCandidate(value: SyntheticPostStateV2, candidates: ExactGraphCandidateV2Authority, contract: ExactCompilationContractV1): ExactGraphCandidateV2 {
    const owned = this.#owned.get(value);
    if (owned === undefined || contract.compilationContractVersion !== 1) fail();
    return candidates.compile({
      profileId: contract.profileId, profileVersion: contract.profileVersion, topPackage: contract.topPackage,
      registryOrigin: contract.registryOrigin, runtimeConstraint: contract.runtimeConstraint,
      materializationRulesVersion: contract.materializationRulesVersion, archiveRulesVersion: contract.archiveRulesVersion,
      workerProtocolVersion: contract.workerProtocolVersion, limits: contract.limits, packageLock: owned.lockDocument,
      lowerCandidateByteLimit: contract.effectiveCandidateBytes,
    });
  }
}

async function readLock(workspace: GraphGenesisWorkspace, checkpoint: () => void): Promise<Readonly<{ document: ExactGraphCandidateV2Input['packageLock']; bytesDigest: string }>> {
  const path = join(workspace.rootRealpath, 'package-lock.json');
  checkpoint(); const linked = await lstat(path); checkpoint();
  if (!linked.isFile() || linked.isSymbolicLink() || linked.nlink !== 1 || linked.uid !== workspace.owner || linked.size < 1 || linked.size > MAX_LOCK_BYTES || (Number(linked.mode) & 0o7777) !== 0o600) fail();
  checkpoint(); const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    checkpoint();
    const before = await file.stat(); checkpoint();
    if (!sameFile(linked, before)) fail();
    const bytes = await boundedRead(file, before.size, MAX_LOCK_BYTES, checkpoint); checkpoint(); const after = await file.stat(); checkpoint(); const current = await lstat(path); checkpoint();
    if (bytes.byteLength !== before.size || !sameFile(before, after) || !sameFile(after, current)) fail();
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    return Object.freeze({ document: parseStrictJsonDocument(text) as ExactGraphCandidateV2Input['packageLock'], bytesDigest: sha256(bytes) });
  } finally {
    try { await file.close(); } finally { checkpoint(); }
  }
}

async function revalidateProtected(workspace: GraphGenesisWorkspace, checkpoint: () => void): Promise<string> {
  const seen: unknown[] = [];
  for (const expected of workspace.protectedFiles) {
    const path = join(workspace.rootRealpath, expected.name); checkpoint(); const linked = await lstat(path); checkpoint();
    if (!matches(linked, expected, workspace.owner)) fail();
    checkpoint(); const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      checkpoint();
      const before = await file.stat(); checkpoint(); const bytes = await boundedRead(file, before.size, 64 * 1024, checkpoint); checkpoint(); const after = await file.stat(); checkpoint(); const current = await lstat(path); checkpoint();
      if (!matches(before, expected, workspace.owner) || !sameFile(linked, before) || !sameFile(before, after) || !sameFile(after, current) || sha256(bytes) !== expected.sha256) fail();
      seen.push({ name: expected.name, dev: before.dev, ino: before.ino, sha256: expected.sha256 });
    } finally {
      try { await file.close(); } finally { checkpoint(); }
    }
  }
  return sha256(canonicalJson(seen));
}

async function captureInventory(workspace: GraphGenesisWorkspace, checkpoint: () => void): Promise<readonly unknown[]> {
  const root = workspace.rootRealpath;
  const inventory: unknown[] = []; let entries = 0; let regularBytes = 0; let cacheBytes = 0; let logBytes = 0;
  const visit = async (directory: string, relative: string, depth: number, top: string): Promise<void> => {
    if (depth > MAX_DEPTH) fail();
    checkpoint(); const directoryBefore = await lstat(directory); checkpoint();
    if (!directoryBefore.isDirectory() || directoryBefore.isSymbolicLink() || directoryBefore.uid !== workspace.owner || (Number(directoryBefore.mode) & 0o7777) !== 0o700) fail();
    checkpoint(); const handle = await opendir(directory);
    try {
      checkpoint();
      while (true) {
        checkpoint(); const child = await handle.read(); checkpoint();
        if (child === null) break;
        if (++entries > MAX_ENTRIES) fail();
        const next = join(directory, child.name); const name = relative === '' ? child.name : `${relative}/${child.name}`;
        if (relative === '' && !POST_STATE_NAMES.has(child.name)) fail();
        if (child.name === 'node_modules') fail();
        checkpoint(); const info = await lstat(next); checkpoint();
        if (info.isSymbolicLink() || info.uid !== workspace.owner || (!info.isFile() && !info.isDirectory()) || (info.isFile() && (info.nlink !== 1 || (Number(info.mode) & 0o111) !== 0))) fail();
        if ((info.isDirectory() && (Number(info.mode) & 0o7777) !== 0o700) || (info.isFile() && (Number(info.mode) & 0o7777) !== 0o600)) fail();
        if (info.isFile() && ARCHIVE_NAME.test(child.name)) fail();
        if (info.isFile()) {
          regularBytes += info.size; if (regularBytes > MAX_REGULAR_BYTES) fail();
          if (top === 'cache' && (cacheBytes += info.size) > MAX_CACHE_BYTES) fail();
          if (top === 'logs' && (logBytes += info.size) > MAX_LOG_BYTES) fail();
        }
        inventory.push({ name, dev: info.dev, ino: info.ino, uid: info.uid, mode: Number(info.mode) & 0o7777, size: info.size });
        if (info.isDirectory()) {
          checkpoint(); await visit(next, name, depth + 1, relative === '' ? child.name : top); checkpoint();
        }
      }
    } finally {
      try { await handle.close(); } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ERR_DIR_CLOSED') throw error;
      } finally { checkpoint(); }
    }
    checkpoint(); const directoryAfter = await lstat(directory); checkpoint();
    if (!sameDirectory(directoryBefore, directoryAfter)) fail();
  };
  await visit(root, '', 0, '');
  // This is a bounded metadata inventory, not a digest of unprotected file content.
  inventory.sort((left, right) => {
    const leftName = (left as { name: string }).name; const rightName = (right as { name: string }).name;
    return leftName < rightName ? -1 : leftName > rightName ? 1 : 0;
  });
  const topNames = new Set(inventory.map((entry) => (entry as { name: string }).name).filter((name) => !name.includes('/')));
  if ([...POST_STATE_NAMES].some((name) => !topNames.has(name))) fail();
  return Object.freeze(inventory);
}

async function boundedRead(file: Awaited<ReturnType<typeof open>>, expectedSize: number | bigint, maximum: number, checkpoint: () => void): Promise<Buffer> {
  const size = Number(expectedSize); if (!Number.isSafeInteger(size) || size < 0 || size > maximum) fail();
  const buffer = Buffer.alloc(size + 1); let offset = 0;
  while (offset < buffer.byteLength) {
    checkpoint(); const result = await file.read(buffer, offset, buffer.byteLength - offset, offset); checkpoint();
    if (result.bytesRead === 0) break;
    offset += result.bytesRead;
  }
  if (offset !== size) fail();
  return buffer.subarray(0, size);
}

async function ownedRoot(workspace: GraphGenesisWorkspace, checkpoint: () => void): Promise<Awaited<ReturnType<typeof lstat>>> {
  checkpoint(); const root = await lstat(workspace.rootRealpath); checkpoint();
  if (!root.isDirectory() || root.isSymbolicLink() || root.dev !== workspace.device || root.ino !== workspace.inode
    || root.uid !== workspace.owner || (Number(root.mode) & 0o7777) !== workspace.mode) fail();
  return root;
}

function ids(input: Readonly<{ actionId: string; approvalId: string; planHash: string; executionEnvelopeHash: string }>): boolean {
  return /^[0-9a-f-]{16,128}$/iu.test(input.actionId) && /^[0-9a-f-]{16,128}$/iu.test(input.approvalId) && digestValue(input.planHash) && digestValue(input.executionEnvelopeHash);
}
function matches(info: Awaited<ReturnType<typeof lstat>>, expected: GraphGenesisProtectedFile, owner: number): boolean { return info.isFile() && !info.isSymbolicLink() && info.nlink === 1 && info.uid === owner && info.dev === expected.device && info.ino === expected.inode && info.size === expected.size && (Number(info.mode) & 0o7777) === expected.mode; }
function sameFile(left: Awaited<ReturnType<typeof lstat>>, right: Awaited<ReturnType<typeof lstat>>): boolean { return left.isFile() && right.isFile() && left.nlink === 1 && right.nlink === 1 && left.dev === right.dev && left.ino === right.ino && left.uid === right.uid && (Number(left.mode) & 0o7777) === (Number(right.mode) & 0o7777) && left.size === right.size; }
function sameDirectory(left: Awaited<ReturnType<typeof lstat>>, right: Awaited<ReturnType<typeof lstat>>): boolean { return left.isDirectory() && right.isDirectory() && !left.isSymbolicLink() && !right.isSymbolicLink() && left.dev === right.dev && left.ino === right.ino && left.uid === right.uid && (Number(left.mode) & 0o7777) === (Number(right.mode) & 0o7777); }
function record(value: unknown): value is Record<string, unknown> { return typeof value === 'object' && value !== null && !Array.isArray(value); }
function digestValue(value: unknown): value is string { return typeof value === 'string' && SHA256.test(value); }
function sha256(value: Uint8Array | string): string { return createHash('sha256').update(value).digest('hex'); }
function fail(): never { throw new Error('graph_genesis_v2_post_state_invalid'); }
