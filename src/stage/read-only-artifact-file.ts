import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { constants, type BigIntStats } from 'node:fs';
import { lstat, open, realpath, unlink } from 'node:fs/promises';
import { join, resolve } from 'node:path';

import { canonicalJson } from '../audit/canonical-json.js';
import type { ArchiveWorkerArtifactSource } from './bounded-archive-worker.js';
import {
  PackageStageError,
  parseSha512Integrity,
} from './profile.js';
import type {
  ReadOnlyArtifactAcceptancePlan,
  ReadOnlyArtifactIdentity,
  SyntheticReadOnlyArtifactApproval,
  SyntheticReadOnlyArtifactApprovalAuthority,
  ReadOnlyArtifactAcceptancePlanAuthority,
} from './exact-production-graph.js';

const FILE_CHUNK_BYTES = 64 * 1024;

type ExactFileIdentity = Readonly<{
  device: string;
  inode: string;
  owner: string;
  mode: string;
  links: string;
  size: string;
  modifiedNs: string;
  changedNs: string;
}>;

export type PrivateArtifactRoot = Readonly<{
  path: string;
  device: string;
  inode: string;
  owner: string;
  mode: string;
  binding: string;
}>;

export type ArtifactFileResponse = Readonly<{
  status: number;
  redirected: boolean;
  finalUrl: string;
  contentType: string;
  contentEncoding: 'identity';
  contentLength: number | null;
  body: AsyncIterable<Uint8Array>;
}>;

export type ArtifactFileRequest = Readonly<{
  url: string;
  headers: Readonly<{
    accept: 'application/octet-stream';
    acceptEncoding: 'identity';
  }>;
}>;

export interface ReadOnlyArtifactTransport {
  fetch(request: ArtifactFileRequest, signal?: AbortSignal): Promise<ArtifactFileResponse>;
}

export type VerifiedArtifactFile = Readonly<{
  artifact: ReadOnlyArtifactIdentity;
  path: string;
  compressedBytes: number;
  identity: ExactFileIdentity;
}>;

export type VerifiedArtifactFileSet = Readonly<{
  planHash: string;
  rootBinding: string;
  files: readonly VerifiedArtifactFile[];
}>;

export class PrivateArtifactRootAuthority {
  readonly #authenticated = new WeakSet<object>();

  async capture(path: string): Promise<PrivateArtifactRoot> {
    try {
      const canonical = await realpath(resolve(path));
      const observed = await lstat(canonical, { bigint: true });
      assertPrivateRootStat(observed);
      const unsigned = Object.freeze({
        path: canonical,
        device: observed.dev.toString(),
        inode: observed.ino.toString(),
        owner: observed.uid.toString(),
        mode: observed.mode.toString(),
      });
      const root = Object.freeze({ ...unsigned, binding: sha256(canonicalJson(unsigned)) });
      this.#authenticated.add(root);
      return root;
    } catch (error) {
      if (error instanceof PackageStageError) throw error;
      throw new PackageStageError('artifact_file_invalid');
    }
  }

  authenticates(candidate: unknown): candidate is PrivateArtifactRoot {
    return typeof candidate === 'object' && candidate !== null && this.#authenticated.has(candidate);
  }

  async revalidate(root: PrivateArtifactRoot): Promise<void> {
    if (!this.authenticates(root)) throw new PackageStageError('artifact_file_invalid');
    try {
      const observed = await lstat(root.path, { bigint: true });
      assertPrivateRootStat(observed);
      if (
        observed.dev.toString() !== root.device || observed.ino.toString() !== root.inode
        || observed.uid.toString() !== root.owner || observed.mode.toString() !== root.mode
      ) throw new PackageStageError('artifact_file_invalid');
    } catch (error) {
      if (error instanceof PackageStageError) throw error;
      throw new PackageStageError('artifact_file_invalid');
    }
  }
}

export class VerifiedArtifactFileAuthority {
  readonly #authenticatedSets = new WeakSet<object>();
  readonly #authenticatedFiles = new WeakSet<object>();

  constructor(
    private readonly rootAuthority: PrivateArtifactRootAuthority,
    private readonly planAuthority: ReadOnlyArtifactAcceptancePlanAuthority,
    private readonly approvalAuthority: SyntheticReadOnlyArtifactApprovalAuthority,
  ) {}

  async downloadForTest(
    plan: ReadOnlyArtifactAcceptancePlan,
    approval: SyntheticReadOnlyArtifactApproval,
    root: PrivateArtifactRoot,
    transport: ReadOnlyArtifactTransport,
    now = new Date(),
    signal?: AbortSignal,
  ): Promise<VerifiedArtifactFileSet> {
    this.planAuthority.assertAuthenticates(plan);
    if (!this.rootAuthority.authenticates(root) || root.binding !== plan.quarantineRootBinding) {
      throw new PackageStageError('artifact_plan_invalid');
    }
    await this.rootAuthority.revalidate(root);
    this.approvalAuthority.consume(approval, plan, now);
    const files: VerifiedArtifactFile[] = [];
    let aggregateBytes = 0;
    const startedAt = Date.now();
    try {
      for (const artifact of plan.artifacts) {
        if (signal?.aborted === true) throw new PackageStageError('artifact_cancelled');
        const remainingMs = plan.totalArtifactTimeoutMs - (Date.now() - startedAt);
        if (remainingMs <= 0) throw new PackageStageError('artifact_file_invalid');
        const result = await this.#downloadOne(
          plan,
          artifact,
          root,
          transport,
          aggregateBytes,
          Math.min(plan.artifactRequestTimeoutMs, remainingMs),
          signal,
        );
        aggregateBytes += result.compressedBytes;
        files.push(result);
      }
      const set = Object.freeze({
        planHash: plan.planHash,
        rootBinding: root.binding,
        files: Object.freeze(files),
      });
      this.#authenticatedSets.add(set);
      return set;
    } catch (error) {
      const cleaned = await this.cleanupFiles(root, files).catch(() => false);
      if (!cleaned) throw new PackageStageError('artifact_cleanup_incomplete');
      if (error instanceof PackageStageError) throw error;
      throw new PackageStageError(signal?.aborted === true ? 'artifact_cancelled' : 'artifact_file_invalid');
    }
  }

  authenticates(set: unknown): set is VerifiedArtifactFileSet {
    return typeof set === 'object' && set !== null && this.#authenticatedSets.has(set);
  }

  sourceFor(file: VerifiedArtifactFile, signal?: AbortSignal): ArchiveWorkerArtifactSource {
    if (!this.#authenticatedFiles.has(file)) throw new PackageStageError('artifact_file_invalid');
    let handle: Awaited<ReturnType<typeof open>> | undefined;
    let before: BigIntStats | undefined;
    let completed = false;
    let used = false;
    return Object.freeze({
      artifactBytes: file.compressedBytes,
      artifactSha512: file.artifact.sha512Integrity,
      async *chunks() {
        try {
          if (used) throw new PackageStageError('artifact_file_invalid');
          used = true;
          handle = await open(file.path, constants.O_RDONLY | constants.O_NOFOLLOW);
          before = await handle.stat({ bigint: true });
          assertFileIdentity(before, file.identity);
          const buffer = Buffer.allocUnsafe(FILE_CHUNK_BYTES);
          let position = 0;
          while (position < file.compressedBytes) {
            if (signal?.aborted === true) throw new PackageStageError('artifact_cancelled');
            const { bytesRead } = await handle.read(
              buffer,
              0,
              Math.min(buffer.length, file.compressedBytes - position),
              position,
            );
            if (bytesRead <= 0) throw new PackageStageError('artifact_file_invalid');
            position += bytesRead;
            yield Buffer.from(buffer.subarray(0, bytesRead));
          }
          completed = true;
        } finally {
          if (!completed) {
            await handle?.close().catch(() => undefined);
            handle = undefined;
          }
        }
      },
      async validateAfterRead() {
        try {
          if (!completed) return;
          if (handle === undefined || before === undefined) {
            throw new PackageStageError('artifact_file_invalid');
          }
          const after = await handle.stat({ bigint: true });
          assertFileIdentity(after, file.identity);
          if (!sameExactStat(before, after)) throw new PackageStageError('artifact_file_invalid');
        } finally {
          await handle?.close().catch(() => undefined);
          handle = undefined;
          before = undefined;
        }
      },
    });
  }

  async cleanup(set: VerifiedArtifactFileSet, root: PrivateArtifactRoot): Promise<void> {
    if (!this.authenticates(set) || set.rootBinding !== root.binding) {
      throw new PackageStageError('artifact_cleanup_incomplete');
    }
    if (!(await this.cleanupFiles(root, set.files))) {
      throw new PackageStageError('artifact_cleanup_incomplete');
    }
  }

  private async cleanupFiles(root: PrivateArtifactRoot, files: readonly VerifiedArtifactFile[]): Promise<boolean> {
    try {
      await this.rootAuthority.revalidate(root);
      for (const file of files) {
        if (!this.#authenticatedFiles.has(file) || resolve(file.path).startsWith(`${root.path}/`) !== true) return false;
        const observed = await lstat(file.path, { bigint: true });
        assertFileIdentity(observed, file.identity);
        await unlink(file.path);
      }
      return true;
    } catch {
      return false;
    }
  }

  async #downloadOne(
    plan: ReadOnlyArtifactAcceptancePlan,
    artifact: ReadOnlyArtifactIdentity,
    root: PrivateArtifactRoot,
    transport: ReadOnlyArtifactTransport,
    aggregateBefore: number,
    timeoutMs: number,
    signal?: AbortSignal,
  ): Promise<VerifiedArtifactFile> {
    await this.rootAuthority.revalidate(root);
    const path = join(root.path, `artifact-${randomBytes(16).toString('hex')}.tgz`);
    let handle: Awaited<ReturnType<typeof open>> | undefined;
    let identityForCleanup: ExactFileIdentity | undefined;
    const controller = new AbortController();
    const forwardAbort = () => controller.abort();
    signal?.addEventListener('abort', forwardAbort, { once: true });
    const deadline = Date.now() + timeoutMs;
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      handle = await open(
        path,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        0o600,
      );
      identityForCleanup = captureFileIdentity(await handle.stat({ bigint: true }), 0);
      const response = await waitUntilDeadline(transport.fetch(Object.freeze({
        url: artifact.tarballUrl,
        headers: Object.freeze({
          accept: 'application/octet-stream' as const,
          acceptEncoding: 'identity' as const,
        }),
      }), controller.signal), controller, deadline, signal);
      if (
        response.status !== 200 || response.redirected || response.finalUrl !== artifact.tarballUrl
        || response.contentEncoding !== 'identity'
        || !['application/octet-stream', 'application/gzip'].includes(response.contentType.toLowerCase().split(';', 1)[0]!)
        || (response.contentLength !== null
          && (!Number.isSafeInteger(response.contentLength) || response.contentLength <= 0
            || response.contentLength > plan.limits.compressedArtifactBytes))
      ) throw new PackageStageError('artifact_file_invalid');

      const expected = parseSha512Integrity(artifact.sha512Integrity);
      const hash = createHash('sha512');
      let observedBytes = 0;
      const iterator = response.body[Symbol.asyncIterator]();
      while (true) {
        const next = await waitUntilDeadline(iterator.next(), controller, deadline, signal);
        if (next.done === true) break;
        const chunk = next.value;
        if (signal?.aborted === true) throw new PackageStageError('artifact_cancelled');
        if (!(chunk instanceof Uint8Array)) throw new PackageStageError('artifact_file_invalid');
        observedBytes += chunk.byteLength;
        if (
          observedBytes > plan.limits.compressedArtifactBytes
          || aggregateBefore + observedBytes > plan.limits.totalCompressedBytes
        ) throw new PackageStageError('artifact_too_large');
        hash.update(chunk);
        let offset = 0;
        while (offset < chunk.byteLength) {
          const { bytesWritten } = await handle.write(chunk, offset, chunk.byteLength - offset, observedBytes - chunk.byteLength + offset);
          if (bytesWritten <= 0) throw new PackageStageError('artifact_file_invalid');
          offset += bytesWritten;
        }
      }
      if (response.contentLength !== null && response.contentLength !== observedBytes) {
        throw new PackageStageError('artifact_file_invalid');
      }
      const observed = hash.digest();
      if (observed.length !== expected.length || !timingSafeEqual(observed, expected)) {
        throw new PackageStageError('integrity_mismatch');
      }
      await handle.sync();
      const fileStat = await handle.stat({ bigint: true });
      identityForCleanup = captureFileIdentity(fileStat, observedBytes);
      await handle.close();
      handle = undefined;
      const pathStat = await lstat(path, { bigint: true });
      assertFileIdentity(pathStat, identityForCleanup);
      const file = Object.freeze({ artifact, path, compressedBytes: observedBytes, identity: identityForCleanup });
      this.#authenticatedFiles.add(file);
      return file;
    } catch (error) {
      await handle?.close().catch(() => undefined);
      if (identityForCleanup !== undefined) {
        const observed = await lstat(path, { bigint: true }).catch(() => undefined);
        if (observed === undefined || !matchesStableFileIdentity(observed, identityForCleanup)) {
          throw new PackageStageError('artifact_cleanup_incomplete');
        }
      }
      await unlink(path).catch((unlinkError: NodeJS.ErrnoException) => {
        if (unlinkError.code !== 'ENOENT') throw new PackageStageError('artifact_cleanup_incomplete');
      });
      if (error instanceof PackageStageError) throw error;
      throw new PackageStageError(signal?.aborted === true ? 'artifact_cancelled' : 'artifact_file_invalid');
    } finally {
      clearTimeout(timeout);
      signal?.removeEventListener('abort', forwardAbort);
    }
  }
}

async function waitUntilDeadline<T>(
  promise: Promise<T>,
  controller: AbortController,
  deadline: number,
  outerSignal?: AbortSignal,
): Promise<T> {
  const remainingMs = deadline - Date.now();
  if (remainingMs <= 0) {
    controller.abort();
    throw new PackageStageError(outerSignal?.aborted === true ? 'artifact_cancelled' : 'artifact_file_invalid');
  }
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        controller.signal.addEventListener('abort', () => reject(new PackageStageError(
          outerSignal?.aborted === true ? 'artifact_cancelled' : 'artifact_file_invalid',
        )), { once: true });
      }),
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          reject(new PackageStageError(outerSignal?.aborted === true
            ? 'artifact_cancelled'
            : 'artifact_file_invalid'));
        }, remainingMs);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function captureFileIdentity(input: BigIntStats, expectedBytes: number): ExactFileIdentity {
  const identity = Object.freeze({
    device: input.dev.toString(),
    inode: input.ino.toString(),
    owner: input.uid.toString(),
    mode: input.mode.toString(),
    links: input.nlink.toString(),
    size: input.size.toString(),
    modifiedNs: input.mtimeNs.toString(),
    changedNs: input.ctimeNs.toString(),
  });
  assertFileIdentity(input, identity);
  if (input.size !== BigInt(expectedBytes)) throw new PackageStageError('artifact_file_invalid');
  return identity;
}

function assertPrivateRootStat(input: BigIntStats): void {
  const uidMatches = typeof process.getuid !== 'function' || input.uid === BigInt(process.getuid());
  if (!input.isDirectory() || input.isSymbolicLink() || !uidMatches || (input.mode & 0o777n) !== 0o700n) {
    throw new PackageStageError('artifact_file_invalid');
  }
}

function assertFileIdentity(input: BigIntStats, expected: ExactFileIdentity): void {
  if (!matchesFileIdentity(input, expected)) throw new PackageStageError('artifact_file_invalid');
}

function matchesFileIdentity(input: BigIntStats, expected: ExactFileIdentity): boolean {
  const uidMatches = typeof process.getuid !== 'function' || input.uid === BigInt(process.getuid());
  return input.isFile() && !input.isSymbolicLink() && uidMatches
    && (input.mode & 0o777n) === 0o600n && input.nlink === 1n
    && input.dev.toString() === expected.device && input.ino.toString() === expected.inode
    && input.uid.toString() === expected.owner && input.mode.toString() === expected.mode
    && input.nlink.toString() === expected.links && input.size.toString() === expected.size
    && input.mtimeNs.toString() === expected.modifiedNs && input.ctimeNs.toString() === expected.changedNs;
}

function matchesStableFileIdentity(input: BigIntStats, expected: ExactFileIdentity): boolean {
  const uidMatches = typeof process.getuid !== 'function' || input.uid === BigInt(process.getuid());
  return input.isFile() && !input.isSymbolicLink() && uidMatches
    && (input.mode & 0o777n) === 0o600n && input.nlink === 1n
    && input.dev.toString() === expected.device && input.ino.toString() === expected.inode
    && input.uid.toString() === expected.owner && input.mode.toString() === expected.mode
    && input.nlink.toString() === expected.links;
}

function sameExactStat(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.uid === right.uid
    && left.mode === right.mode && left.nlink === right.nlink && left.size === right.size
    && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

function sha256(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}
