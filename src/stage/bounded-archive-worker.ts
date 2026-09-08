import { createHash } from 'node:crypto';
import { constants, type BigIntStats } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { resolve } from 'node:path';
import type { Readable } from 'node:stream';

import { canonicalJson } from '../audit/canonical-json.js';
import {
  ARCHIVE_WORKER_ACK,
  ARCHIVE_WORKER_MAX_BODY_CHUNK_BYTES,
  ARCHIVE_WORKER_PROTOCOL_VERSION,
  encodeArchiveWorkerRequestHeader,
  type ArchiveWorkerCapabilities,
  type ArchiveWorkerPass,
  type ArchiveWorkerRequest,
} from './archive-worker-protocol.js';
import {
  PACKAGE_STAGE_HARD_CEILINGS,
  PackageStageError,
  type PackageStageErrorCode,
  validatePortableRelativePath,
} from './profile.js';
import {
  TAR_PARSER_ENTRYPOINT,
  TAR_PARSER_PACKAGE,
  TAR_PARSER_VERSION,
  type TarArchiveTranscript,
  type TarArchiveTranscriptEntry,
} from './tar-archive-parser.js';
import type { PackageStageLimits } from './types.js';

const MAX_RUNTIME_FILE_BYTES = 256 * 1024 * 1024;
const MAX_NODE_EXECUTABLE_BYTES = 512 * 1024 * 1024;
const MAX_RUNTIME_FILES = 64;
const SHA256 = /^[a-f0-9]{64}$/u;
const SHA512 = /^sha512-[A-Za-z0-9+/]+={0,2}$/u;

export const ARCHIVE_WORKER_RUNTIME_RELATIVE_FILES = Object.freeze([
  'package.json',
  'dist/src/audit/canonical-json.js',
  'dist/src/stage/archive-policy.js',
  'dist/src/stage/archive-worker-entry.js',
  'dist/src/stage/archive-worker-protocol.js',
  'dist/src/stage/profile.js',
  'dist/src/stage/tar-archive-parser.js',
  'node_modules/tar/package.json',
  'node_modules/tar/dist/esm/parse.js',
  'node_modules/tar/dist/esm/header.js',
  'node_modules/tar/dist/esm/large-numbers.js',
  'node_modules/tar/dist/esm/types.js',
  'node_modules/tar/dist/esm/pax.js',
  'node_modules/tar/dist/esm/read-entry.js',
  'node_modules/tar/dist/esm/warn-method.js',
  'node_modules/tar/dist/esm/normalize-windows-path.js',
  'node_modules/minizlib/package.json',
  'node_modules/minizlib/dist/esm/index.js',
  'node_modules/minizlib/dist/esm/constants.js',
  'node_modules/minipass/package.json',
  'node_modules/minipass/dist/esm/index.js',
] as const);

export type BoundedArchiveWorkerOptions = Readonly<{
  nodeExecutable: string;
  expectedNodeMajor: 24 | 25 | 26;
  workerEntrypoint: string;
  workingDirectory: string;
  readOnlyRuntimeFiles: readonly string[];
  timeoutMs: number;
  maxFrameBytes: number;
  maxStdoutBytes: number;
  maxStderrBytes: number;
  bodyChunkBytes: number;
  maxOldSpaceMb: number;
  maxSemiSpaceMb: number;
}>;

export type AuthenticatedArchiveWorkerTranscript = Readonly<{
  workerProtocolVersion: typeof ARCHIVE_WORKER_PROTOCOL_VERSION;
  runtimeDigest: string;
  transcript: TarArchiveTranscript;
}>;

export type ArchiveWorkerMaterializationSink = Readonly<{
  start(entry: TarArchiveTranscriptEntry, index: number): Promise<void>;
  write(entry: TarArchiveTranscriptEntry, index: number, offset: number, bytes: Buffer): Promise<void>;
  end(entry: TarArchiveTranscriptEntry, index: number): Promise<void>;
  abort(): Promise<void>;
}>;

type FileIdentity = Readonly<{
  path: string;
  device: string;
  inode: string;
  size: string;
  mode: string;
  modifiedNs: string;
  changedNs: string;
  sha256: string;
}>;

type RuntimeIdentity = Readonly<{
  node: FileIdentity;
  workerEntrypoint: string;
  files: readonly FileIdentity[];
  workingDirectory: Readonly<{ path: string; device: string; inode: string; mode: string }>;
  launchConfig: Readonly<{
    protocolVersion: 1;
    expectedNodeMajor: 24 | 25 | 26;
    timeoutMs: number;
    maxFrameBytes: number;
    maxStdoutBytes: number;
    maxStderrBytes: number;
    bodyChunkBytes: number;
    maxOldSpaceMb: number;
    maxSemiSpaceMb: number;
    permissionModel: 'enforce';
    networkGrant: 'none';
  }>;
  digest: string;
}>;

export class BoundedArchiveWorker {
  readonly #options: BoundedArchiveWorkerOptions;
  readonly #baseline: RuntimeIdentity;
  readonly #authenticated = new WeakSet<object>();

  private constructor(options: BoundedArchiveWorkerOptions, baseline: RuntimeIdentity) {
    this.#options = options;
    this.#baseline = baseline;
  }

  static async create(options: BoundedArchiveWorkerOptions): Promise<BoundedArchiveWorker> {
    assertWorkerOptions(options);
    const baseline = await captureRuntimeIdentity(options);
    return new BoundedArchiveWorker(freezeOptions(options), baseline);
  }

  async inspect(
    artifactBytes: Uint8Array,
    limits: PackageStageLimits,
    signal?: AbortSignal,
  ): Promise<AuthenticatedArchiveWorkerTranscript> {
    assertLimits(limits);
    const artifact = Buffer.from(artifactBytes);
    const artifactSha512 = sha512(artifact);
    const runtime = await this.#revalidateRuntime();
    const request = requestFor('pass_a', artifact, artifactSha512, limits, this.#options.bodyChunkBytes, null);
    const result = await this.#runPassA(request, artifact, runtime, signal);
    const authenticated = deepFreeze({
      workerProtocolVersion: ARCHIVE_WORKER_PROTOCOL_VERSION,
      runtimeDigest: runtime.digest,
      transcript: result,
    });
    this.#authenticated.add(authenticated);
    return authenticated;
  }

  authenticates(candidate: unknown): candidate is AuthenticatedArchiveWorkerTranscript {
    return typeof candidate === 'object' && candidate !== null && this.#authenticated.has(candidate);
  }

  async materialize(
    artifactBytes: Uint8Array,
    authenticated: AuthenticatedArchiveWorkerTranscript,
    limits: PackageStageLimits,
    sink: ArchiveWorkerMaterializationSink,
    signal?: AbortSignal,
  ): Promise<void> {
    if (!this.authenticates(authenticated)) throw new PackageStageError('archive_invalid');
    assertLimits(limits);
    const artifact = Buffer.from(artifactBytes);
    if (
      artifact.length !== authenticated.transcript.compressedBytes
      || sha512(artifact) !== authenticated.transcript.artifactSha512
    ) {
      throw new PackageStageError('archive_invalid');
    }
    const runtime = await this.#revalidateRuntime();
    if (runtime.digest !== authenticated.runtimeDigest) {
      throw new PackageStageError('archive_worker_failed');
    }
    const request = requestFor(
      'pass_b',
      artifact,
      authenticated.transcript.artifactSha512,
      limits,
      this.#options.bodyChunkBytes,
      authenticated.transcript.transcriptDigest,
    );
    await this.#runPassB(request, artifact, runtime, authenticated.transcript, sink, signal);
  }

  async #revalidateRuntime(): Promise<RuntimeIdentity> {
    const current = await captureRuntimeIdentity(this.#options);
    if (current.digest !== this.#baseline.digest || canonicalJson(current) !== canonicalJson(this.#baseline)) {
      throw new PackageStageError('archive_worker_failed');
    }
    return current;
  }

  async #runPassA(
    request: ArchiveWorkerRequest,
    artifact: Buffer,
    runtime: RuntimeIdentity,
    signal?: AbortSignal,
  ): Promise<TarArchiveTranscript> {
    const session = this.#spawn(request, artifact, signal);
    try {
      const first = await session.nextFrame();
      if (isErrorFrame(first)) {
        await session.acknowledge();
        await session.finishExpectedFailure();
        throw new PackageStageError(first.code);
      }
      const transcript = validateTranscriptFrame(first, request, runtime.digest);
      await session.acknowledge();
      const complete = validateCompleteFrame(await session.nextFrame(), 'pass_a', transcript);
      assertCapabilities(complete.capabilities, this.#options.expectedNodeMajor);
      await session.acknowledge();
      await session.finishSuccess();
      return transcript;
    } catch (error) {
      await session.abort();
      if (error instanceof PackageStageError) throw error;
      throw new PackageStageError('archive_protocol_invalid');
    }
  }

  async #runPassB(
    request: ArchiveWorkerRequest,
    artifact: Buffer,
    runtime: RuntimeIdentity,
    transcript: TarArchiveTranscript,
    sink: ArchiveWorkerMaterializationSink,
    signal?: AbortSignal,
  ): Promise<void> {
    const session = this.#spawn(request, artifact, signal);
    try {
      for (let index = 0; index < transcript.entries.length; index += 1) {
        const expected = transcript.entries[index]!;
        const start = await session.nextFrame();
        if (isErrorFrame(start)) {
          await session.acknowledge();
          await session.finishExpectedFailure();
          throw new PackageStageError(start.code);
        }
        validateEntryStart(start, expected, index);
        await sink.start(expected, index);
        await session.acknowledge();

        let offset = 0;
        while (offset < expected.declaredSize) {
          const frame = await session.nextFrame();
          validateBodyChunk(frame, index, offset, this.#options.bodyChunkBytes);
          const bytes = decodeCanonicalBase64(frame.bytes);
          if (bytes.length === 0 || offset + bytes.length > expected.declaredSize) {
            throw new PackageStageError('archive_protocol_invalid');
          }
          await sink.write(expected, index, offset, bytes);
          offset += bytes.length;
          await session.acknowledge();
        }

        validateEntryEnd(await session.nextFrame(), expected, index);
        await sink.end(expected, index);
        await session.acknowledge();
      }
      const complete = validateCompleteFrame(await session.nextFrame(), 'pass_b', transcript);
      assertCapabilities(complete.capabilities, this.#options.expectedNodeMajor);
      if (runtime.digest !== this.#baseline.digest) throw new PackageStageError('archive_worker_failed');
      await session.acknowledge();
      await session.finishSuccess();
    } catch (error) {
      await sink.abort().catch(() => undefined);
      await session.abort();
      if (error instanceof PackageStageError) throw error;
      throw new PackageStageError('archive_protocol_invalid');
    }
  }

  #spawn(request: ArchiveWorkerRequest, artifact: Buffer, signal?: AbortSignal): WorkerSession {
    const args = [
      `--max-old-space-size=${this.#options.maxOldSpaceMb}`,
      `--max-semi-space-size=${this.#options.maxSemiSpaceMb}`,
      '--permission',
      '--no-addons',
      ...this.#baseline.files.map((file) => `--allow-fs-read=${file.path}`),
      this.#baseline.workerEntrypoint,
    ];
    const child = spawn(this.#baseline.node.path, args, {
      cwd: this.#baseline.workingDirectory.path,
      env: {},
      shell: false,
      detached: process.platform !== 'win32',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    return new WorkerSession(child, request, artifact, this.#options, signal);
  }
}

class WorkerSession {
  readonly #child: ChildProcessWithoutNullStreams;
  readonly #reader: BoundedReader;
  readonly #exit: Promise<Readonly<{ code: number | null; signal: NodeJS.Signals | null }>>;
  readonly #options: BoundedArchiveWorkerOptions;
  readonly #timeout: NodeJS.Timeout;
  readonly #guard: Promise<never>;
  readonly #abortListener?: () => void;
  readonly #abortSignal?: AbortSignal;
  #guardReject!: (error: PackageStageError) => void;
  #stderrBytes = 0;
  #finished = false;

  constructor(
    child: ChildProcessWithoutNullStreams,
    request: ArchiveWorkerRequest,
    artifact: Buffer,
    options: BoundedArchiveWorkerOptions,
    signal?: AbortSignal,
  ) {
    this.#child = child;
    this.#options = options;
    this.#reader = new BoundedReader(child.stdout, options.maxStdoutBytes);
    this.#guard = new Promise<never>((_resolve, reject) => {
      this.#guardReject = reject;
    });
    this.#guard.catch(() => undefined);
    this.#exit = new Promise((resolveExit) => {
      child.once('exit', (code, exitSignal) => resolveExit({ code, signal: exitSignal }));
    });
    child.once('error', () => this.#fail(new PackageStageError('archive_worker_failed')));
    child.stdin.on('error', () => this.#fail(new PackageStageError('archive_worker_failed')));
    child.stderr.on('data', (chunk: Buffer) => {
      this.#stderrBytes += chunk.length;
      if (this.#stderrBytes > options.maxStderrBytes) {
        this.#fail(new PackageStageError('archive_protocol_invalid'));
      }
    });
    this.#timeout = setTimeout(() => {
      this.#fail(new PackageStageError('archive_worker_timeout'));
    }, options.timeoutMs);
    if (signal !== undefined) {
      const listener = () => this.#fail(new PackageStageError('artifact_cancelled'));
      this.#abortListener = listener;
      this.#abortSignal = signal;
      signal.addEventListener('abort', listener, { once: true });
      if (signal.aborted) listener();
    }
    void this.#writeInitial(request, artifact).catch(() => {
      this.#fail(new PackageStageError('archive_worker_failed'));
    });
  }

  async nextFrame(): Promise<Record<string, unknown>> {
    return Promise.race([this.#readFrame(), this.#guard]);
  }

  async acknowledge(): Promise<void> {
    await Promise.race([writeAll(this.#child.stdin, Buffer.from([ARCHIVE_WORKER_ACK])), this.#guard]);
  }

  async finishSuccess(): Promise<void> {
    this.#child.stdin.end();
    const trailing = await Promise.race([this.#reader.readToEnd(), this.#guard]);
    const exit = await Promise.race([this.#exit, this.#guard]);
    if (trailing.length !== 0 || exit.code !== 0 || exit.signal !== null || this.#stderrBytes !== 0) {
      throw new PackageStageError('archive_protocol_invalid');
    }
    this.#finish();
  }

  async finishExpectedFailure(): Promise<void> {
    this.#child.stdin.end();
    const trailing = await Promise.race([this.#reader.readToEnd(), this.#guard]);
    const exit = await Promise.race([this.#exit, this.#guard]);
    if (trailing.length !== 0 || exit.code === 0 || exit.signal !== null || this.#stderrBytes !== 0) {
      throw new PackageStageError('archive_protocol_invalid');
    }
    this.#finish();
  }

  async abort(): Promise<void> {
    if (this.#finished) return;
    this.#terminate('SIGTERM');
    const forced = setTimeout(() => this.#terminate('SIGKILL'), 250);
    await Promise.race([this.#exit, new Promise((resolveDelay) => setTimeout(resolveDelay, 500))]);
    clearTimeout(forced);
    this.#finish();
  }

  async #writeInitial(request: ArchiveWorkerRequest, artifact: Buffer): Promise<void> {
    await writeAll(this.#child.stdin, encodeArchiveWorkerRequestHeader(request));
    await writeAll(this.#child.stdin, artifact);
  }

  async #readFrame(): Promise<Record<string, unknown>> {
    const header = await this.#reader.readExact(4);
    if (header === null) throw new PackageStageError('archive_protocol_invalid');
    const length = header.readUInt32BE(0);
    if (length === 0 || length > this.#options.maxFrameBytes) {
      throw new PackageStageError('archive_protocol_invalid');
    }
    const body = await this.#reader.readExact(length);
    if (body === null) throw new PackageStageError('archive_protocol_invalid');
    let parsed: unknown;
    try {
      parsed = JSON.parse(body.toString('utf8'));
    } catch {
      throw new PackageStageError('archive_protocol_invalid');
    }
    assertRecord(parsed);
    return parsed;
  }

  #fail(error: PackageStageError): void {
    if (this.#finished) return;
    this.#terminate('SIGTERM');
    this.#guardReject(error);
  }

  #terminate(signal: NodeJS.Signals): void {
    try {
      if (process.platform !== 'win32' && this.#child.pid !== undefined) {
        process.kill(-this.#child.pid, signal);
      } else {
        this.#child.kill(signal);
      }
    } catch {
      this.#child.kill(signal);
    }
  }

  #finish(): void {
    if (this.#finished) return;
    this.#finished = true;
    clearTimeout(this.#timeout);
    if (this.#abortListener !== undefined) {
      this.#abortSignal?.removeEventListener('abort', this.#abortListener);
    }
  }
}

class BoundedReader {
  readonly #iterator: AsyncIterator<unknown>;
  readonly #maxBytes: number;
  #buffer = Buffer.alloc(0);
  #observedBytes = 0;
  #ended = false;

  constructor(stream: Readable, maxBytes: number) {
    this.#iterator = stream[Symbol.asyncIterator]();
    this.#maxBytes = maxBytes;
  }

  async readExact(length: number): Promise<Buffer | null> {
    while (this.#buffer.length < length && !this.#ended) await this.#readMore();
    if (this.#buffer.length === 0 && this.#ended) return null;
    if (this.#buffer.length < length) throw new PackageStageError('archive_protocol_invalid');
    const output = this.#buffer.subarray(0, length);
    this.#buffer = this.#buffer.subarray(length);
    return output;
  }

  async readToEnd(): Promise<Buffer> {
    while (!this.#ended) await this.#readMore();
    const output = this.#buffer;
    this.#buffer = Buffer.alloc(0);
    return output;
  }

  async #readMore(): Promise<void> {
    const next = await this.#iterator.next();
    if (next.done === true) {
      this.#ended = true;
      return;
    }
    const bytes = Buffer.from(next.value as Uint8Array);
    this.#observedBytes += bytes.length;
    if (this.#observedBytes > this.#maxBytes) throw new PackageStageError('archive_protocol_invalid');
    this.#buffer = Buffer.concat([this.#buffer, bytes]);
  }
}

export function repositoryArchiveWorkerOptions(
  repositoryRoot: string,
  workingDirectory: string,
  override: Partial<Omit<BoundedArchiveWorkerOptions,
    'nodeExecutable' | 'workerEntrypoint' | 'workingDirectory' | 'readOnlyRuntimeFiles'>> = {},
): BoundedArchiveWorkerOptions {
  const root = resolve(repositoryRoot);
  return Object.freeze({
    nodeExecutable: process.execPath,
    expectedNodeMajor: Number.parseInt(process.versions.node.split('.')[0]!, 10) as 24 | 25 | 26,
    workerEntrypoint: resolve(root, 'dist/src/stage/archive-worker-entry.js'),
    workingDirectory: resolve(workingDirectory),
    readOnlyRuntimeFiles: Object.freeze(
      ARCHIVE_WORKER_RUNTIME_RELATIVE_FILES.map((path) => resolve(root, path)),
    ),
    timeoutMs: 5_000,
    maxFrameBytes: 128 * 1024,
    maxStdoutBytes: 16 * 1024 * 1024,
    maxStderrBytes: 4 * 1024,
    bodyChunkBytes: 32 * 1024,
    maxOldSpaceMb: 64,
    maxSemiSpaceMb: 8,
    ...override,
  });
}

export function supportsArchiveWorkerNetworkDenial(nodeMajor: number): boolean {
  return Number.isSafeInteger(nodeMajor) && nodeMajor >= 25 && nodeMajor <= 26;
}

async function captureRuntimeIdentity(options: BoundedArchiveWorkerOptions): Promise<RuntimeIdentity> {
  const node = await captureFileIdentity(options.nodeExecutable, MAX_NODE_EXECUTABLE_BYTES);
  const files = await Promise.all(options.readOnlyRuntimeFiles.map((path) =>
    captureFileIdentity(path, MAX_RUNTIME_FILE_BYTES)));
  files.sort((left, right) => compareText(left.path, right.path));
  if (new Set(files.map((file) => file.path)).size !== files.length) {
    throw new PackageStageError('archive_worker_failed');
  }
  const workerEntrypoint = await realpath(resolve(options.workerEntrypoint));
  if (!files.some((file) => file.path === workerEntrypoint)) {
    throw new PackageStageError('archive_worker_failed');
  }
  const workingDirectory = await captureWorkingDirectory(options.workingDirectory);
  const unsigned = deepFreeze({
    node,
    workerEntrypoint,
    files: Object.freeze(files),
    workingDirectory,
    launchConfig: {
      protocolVersion: ARCHIVE_WORKER_PROTOCOL_VERSION,
      expectedNodeMajor: options.expectedNodeMajor,
      timeoutMs: options.timeoutMs,
      maxFrameBytes: options.maxFrameBytes,
      maxStdoutBytes: options.maxStdoutBytes,
      maxStderrBytes: options.maxStderrBytes,
      bodyChunkBytes: options.bodyChunkBytes,
      maxOldSpaceMb: options.maxOldSpaceMb,
      maxSemiSpaceMb: options.maxSemiSpaceMb,
      permissionModel: 'enforce' as const,
      networkGrant: 'none' as const,
    },
  });
  return deepFreeze({ ...unsigned, digest: sha256(canonicalJson(unsigned)) });
}

async function captureWorkingDirectory(path: string): Promise<RuntimeIdentity['workingDirectory']> {
  try {
    const canonical = await realpath(resolve(path));
    const observed = await lstat(canonical, { bigint: true });
    const uidMatches = typeof process.getuid !== 'function' || observed.uid === BigInt(process.getuid());
    if (!observed.isDirectory() || observed.isSymbolicLink() || !uidMatches || (observed.mode & 0o777n) !== 0o700n) {
      throw new PackageStageError('archive_worker_failed');
    }
    return Object.freeze({
      path: canonical,
      device: observed.dev.toString(),
      inode: observed.ino.toString(),
      mode: observed.mode.toString(),
    });
  } catch (error) {
    if (error instanceof PackageStageError) throw error;
    throw new PackageStageError('archive_worker_failed');
  }
}

async function captureFileIdentity(path: string, maxBytes: number): Promise<FileIdentity> {
  let handle;
  try {
    const canonical = await realpath(resolve(path));
    const pathStat = await lstat(canonical, { bigint: true });
    handle = await open(canonical, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.size <= 0n || before.size > BigInt(maxBytes) || !sameFile(pathStat, before)) {
      throw new PackageStageError('archive_worker_failed');
    }
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let position = 0;
    while (position < Number(before.size)) {
      const { bytesRead } = await handle.read(buffer, 0, Math.min(buffer.length, Number(before.size) - position), position);
      if (bytesRead === 0) throw new PackageStageError('archive_worker_failed');
      hash.update(buffer.subarray(0, bytesRead));
      position += bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    if (!sameFile(before, after)) throw new PackageStageError('archive_worker_failed');
    return Object.freeze({
      path: canonical,
      device: before.dev.toString(),
      inode: before.ino.toString(),
      size: before.size.toString(),
      mode: before.mode.toString(),
      modifiedNs: before.mtimeNs.toString(),
      changedNs: before.ctimeNs.toString(),
      sha256: hash.digest('hex'),
    });
  } catch (error) {
    if (error instanceof PackageStageError) throw error;
    throw new PackageStageError('archive_worker_failed');
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function validateTranscriptFrame(
  frame: Record<string, unknown>,
  request: ArchiveWorkerRequest,
  _runtimeDigest: string,
): TarArchiveTranscript {
  assertExactKeys(frame, ['type', 'transcript']);
  if (frame.type !== 'transcript') throw new PackageStageError('archive_protocol_invalid');
  assertRecord(frame.transcript);
  const input = frame.transcript;
  assertExactKeys(input, [
    'adapterContractVersion',
    'candidatePackage',
    'candidateVersion',
    'candidateEntrypoint',
    'archiveRulesVersion',
    'format',
    'artifactSha512',
    'compressedBytes',
    'expandedBytes',
    'entries',
    'entryCount',
    'transcriptDigest',
  ]);
  if (
    input.adapterContractVersion !== 1
    || input.candidatePackage !== TAR_PARSER_PACKAGE
    || input.candidateVersion !== TAR_PARSER_VERSION
    || input.candidateEntrypoint !== TAR_PARSER_ENTRYPOINT
    || input.archiveRulesVersion !== 1
    || input.format !== 'gzip_ustar_v0'
    || input.artifactSha512 !== request.artifactSha512
    || input.compressedBytes !== request.artifactBytes
    || !isNonNegativeInteger(input.expandedBytes)
    || !Array.isArray(input.entries)
    || input.entryCount !== input.entries.length
    || input.entries.length === 0
    || input.entries.length > request.limits.archiveEntries
    || !isSha256(input.transcriptDigest)
  ) {
    throw new PackageStageError('archive_protocol_invalid');
  }
  let expandedBytes = 0;
  const paths = new Set<string>();
  const entries = input.entries.map((entry) => {
    const normalized = validateTranscriptEntry(entry, request.limits);
    const portable = normalized.relativePath.toLocaleLowerCase('en-US');
    if (paths.has(portable)) throw new PackageStageError('archive_protocol_invalid');
    paths.add(portable);
    if (normalized.type === 'file') expandedBytes += normalized.declaredSize;
    return normalized;
  });
  if (expandedBytes !== input.expandedBytes || expandedBytes > request.limits.uncompressedArtifactBytes) {
    throw new PackageStageError('archive_protocol_invalid');
  }
  const unsigned = deepFreeze({
    adapterContractVersion: 1 as const,
    candidatePackage: TAR_PARSER_PACKAGE,
    candidateVersion: TAR_PARSER_VERSION,
    candidateEntrypoint: TAR_PARSER_ENTRYPOINT,
    archiveRulesVersion: 1 as const,
    format: 'gzip_ustar_v0' as const,
    artifactSha512: input.artifactSha512 as string,
    compressedBytes: input.compressedBytes as number,
    expandedBytes: input.expandedBytes as number,
    entries: Object.freeze(entries),
    entryCount: entries.length,
  });
  if (sha256(canonicalJson(unsigned)) !== input.transcriptDigest) {
    throw new PackageStageError('archive_protocol_invalid');
  }
  return deepFreeze({ ...unsigned, transcriptDigest: input.transcriptDigest as string });
}

function validateTranscriptEntry(input: unknown, limits: PackageStageLimits): TarArchiveTranscriptEntry {
  assertRecord(input);
  assertExactKeys(input, [
    'archivePath',
    'relativePath',
    'type',
    'declaredSize',
    'observedSize',
    'normalizedMode',
    'bodySha256',
  ]);
  if (
    typeof input.relativePath !== 'string'
    || input.archivePath !== `package/${input.relativePath}`
    || !['file', 'directory'].includes(String(input.type))
    || !isNonNegativeInteger(input.declaredSize)
    || input.observedSize !== input.declaredSize
    || ![0o644, 0o755].includes(Number(input.normalizedMode))
    || (input.type === 'directory' && (input.declaredSize !== 0 || input.bodySha256 !== null))
    || (input.type === 'file' && !isSha256(input.bodySha256))
    || Number(input.declaredSize) > limits.regularFileBytes
  ) {
    throw new PackageStageError('archive_protocol_invalid');
  }
  try {
    validatePortableRelativePath(input.relativePath, limits);
  } catch {
    throw new PackageStageError('archive_protocol_invalid');
  }
  return Object.freeze({
    archivePath: input.archivePath as string,
    relativePath: input.relativePath,
    type: input.type as 'file' | 'directory',
    declaredSize: input.declaredSize as number,
    observedSize: input.observedSize as number,
    normalizedMode: input.normalizedMode as number,
    bodySha256: input.bodySha256 as string | null,
  });
}

function validateEntryStart(frame: Record<string, unknown>, expected: TarArchiveTranscriptEntry, index: number): void {
  assertExactKeys(frame, [
    'type',
    'index',
    'archivePath',
    'relativePath',
    'entryType',
    'declaredSize',
    'normalizedMode',
  ]);
  if (
    frame.type !== 'entry_start'
    || frame.index !== index
    || frame.archivePath !== expected.archivePath
    || frame.relativePath !== expected.relativePath
    || frame.entryType !== expected.type
    || frame.declaredSize !== expected.declaredSize
    || frame.normalizedMode !== expected.normalizedMode
  ) {
    throw new PackageStageError('archive_protocol_invalid');
  }
}

function validateBodyChunk(
  frame: Record<string, unknown>,
  index: number,
  offset: number,
  maxBytes: number,
): asserts frame is Record<string, unknown> & { bytes: string } {
  assertExactKeys(frame, ['type', 'index', 'offset', 'bytes']);
  if (
    frame.type !== 'body_chunk'
    || frame.index !== index
    || frame.offset !== offset
    || typeof frame.bytes !== 'string'
    || frame.bytes.length > Math.ceil(maxBytes / 3) * 4
  ) {
    throw new PackageStageError('archive_protocol_invalid');
  }
}

function validateEntryEnd(frame: Record<string, unknown>, expected: TarArchiveTranscriptEntry, index: number): void {
  assertExactKeys(frame, ['type', 'index', 'observedSize', 'bodySha256']);
  if (
    frame.type !== 'entry_end'
    || frame.index !== index
    || frame.observedSize !== expected.observedSize
    || frame.bodySha256 !== expected.bodySha256
  ) {
    throw new PackageStageError('archive_protocol_invalid');
  }
}

function validateCompleteFrame(
  frame: Record<string, unknown>,
  pass: ArchiveWorkerPass,
  transcript: TarArchiveTranscript,
): Readonly<{ capabilities: ArchiveWorkerCapabilities }> {
  assertExactKeys(frame, ['type', 'pass', 'entryCount', 'transcriptDigest', 'capabilities']);
  if (
    frame.type !== 'complete'
    || frame.pass !== pass
    || frame.entryCount !== transcript.entryCount
    || frame.transcriptDigest !== transcript.transcriptDigest
  ) {
    throw new PackageStageError('archive_protocol_invalid');
  }
  assertRecord(frame.capabilities);
  assertExactKeys(frame.capabilities, [
    'nodeMajor',
    'permissionModel',
    'fileSystemWriteDenied',
    'childProcessDenied',
    'workerThreadDenied',
    'nativeAddonDenied',
    'networkDenied',
  ]);
  return Object.freeze({ capabilities: frame.capabilities as ArchiveWorkerCapabilities });
}

function assertCapabilities(input: ArchiveWorkerCapabilities, expectedNodeMajor: 24 | 25 | 26): void {
  if (
    input.nodeMajor !== expectedNodeMajor
    || input.permissionModel !== true
    || input.fileSystemWriteDenied !== true
    || input.childProcessDenied !== true
    || input.workerThreadDenied !== true
    || input.nativeAddonDenied !== true
    || (supportsArchiveWorkerNetworkDenial(input.nodeMajor)
      ? input.networkDenied !== true
      : input.networkDenied !== null)
  ) {
    throw new PackageStageError('archive_worker_failed');
  }
}

function isErrorFrame(input: Record<string, unknown>): input is Record<string, unknown> & { code: PackageStageErrorCode } {
  if (input.type !== 'error' || typeof input.code !== 'string') return false;
  assertExactKeys(input, ['type', 'code']);
  return ['artifact_cancelled', 'archive_invalid', 'archive_limit_exceeded'].includes(input.code);
}

function requestFor(
  pass: ArchiveWorkerPass,
  artifact: Buffer,
  artifactSha512: string,
  limits: PackageStageLimits,
  bodyChunkBytes: number,
  expectedTranscriptDigest: string | null,
): ArchiveWorkerRequest {
  if (artifact.length === 0 || artifact.length > limits.compressedArtifactBytes) {
    throw new PackageStageError('archive_limit_exceeded');
  }
  return deepFreeze({
    protocolVersion: ARCHIVE_WORKER_PROTOCOL_VERSION,
    pass,
    artifactBytes: artifact.length,
    artifactSha512,
    bodyChunkBytes,
    expectedTranscriptDigest,
    limits: { ...limits },
  });
}

function assertWorkerOptions(input: BoundedArchiveWorkerOptions): void {
  if (
    process.platform === 'win32'
    || ![24, 25, 26].includes(input.expectedNodeMajor)
    || !isBoundedInteger(input.timeoutMs, 100, 30_000)
    || !isBoundedInteger(input.maxFrameBytes, 1024, 256 * 1024)
    || !isBoundedInteger(input.maxStdoutBytes, input.maxFrameBytes, 512 * 1024 * 1024)
    || !isBoundedInteger(input.maxStderrBytes, 0, 64 * 1024)
    || !isBoundedInteger(input.bodyChunkBytes, 1, ARCHIVE_WORKER_MAX_BODY_CHUNK_BYTES)
    || !isBoundedInteger(input.maxOldSpaceMb, 16, 256)
    || !isBoundedInteger(input.maxSemiSpaceMb, 1, 32)
    || !Array.isArray(input.readOnlyRuntimeFiles)
    || input.readOnlyRuntimeFiles.length === 0
    || input.readOnlyRuntimeFiles.length > MAX_RUNTIME_FILES
  ) {
    throw new PackageStageError('archive_worker_failed');
  }
}

function assertLimits(input: PackageStageLimits): void {
  for (const key of Object.keys(PACKAGE_STAGE_HARD_CEILINGS) as (keyof PackageStageLimits)[]) {
    if (!isBoundedInteger(input[key], 1, PACKAGE_STAGE_HARD_CEILINGS[key])) {
      throw new PackageStageError('archive_limit_exceeded');
    }
  }
}

function freezeOptions(input: BoundedArchiveWorkerOptions): BoundedArchiveWorkerOptions {
  return Object.freeze({ ...input, readOnlyRuntimeFiles: Object.freeze([...input.readOnlyRuntimeFiles]) });
}

async function writeAll(stream: NodeJS.WritableStream, bytes: Buffer): Promise<void> {
  await new Promise<void>((resolveWrite, rejectWrite) => {
    stream.write(bytes, (error?: Error | null) => error === undefined || error === null
      ? resolveWrite()
      : rejectWrite(error));
  });
}

function decodeCanonicalBase64(input: string): Buffer {
  if (!/^[A-Za-z0-9+/]*={0,2}$/u.test(input)) throw new PackageStageError('archive_protocol_invalid');
  const output = Buffer.from(input, 'base64');
  if (output.toString('base64') !== input) throw new PackageStageError('archive_protocol_invalid');
  return output;
}

function sameFile(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mode === right.mode
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function assertRecord(input: unknown): asserts input is Record<string, unknown> {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw new PackageStageError('archive_protocol_invalid');
  }
}

function assertExactKeys(input: Record<string, unknown>, expected: readonly string[]): void {
  const actual = Object.keys(input).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new PackageStageError('archive_protocol_invalid');
  }
}

function isNonNegativeInteger(input: unknown): input is number {
  return typeof input === 'number' && Number.isSafeInteger(input) && input >= 0;
}

function isBoundedInteger(input: unknown, min: number, max: number): input is number {
  return typeof input === 'number' && Number.isSafeInteger(input) && input >= min && input <= max;
}

function isSha256(input: unknown): input is string {
  return typeof input === 'string' && SHA256.test(input);
}

function sha256(input: string | Uint8Array): string {
  return createHash('sha256').update(input).digest('hex');
}

function sha512(input: Uint8Array): string {
  return `sha512-${createHash('sha512').update(input).digest('base64')}`;
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function deepFreeze<T>(input: T): T {
  if (typeof input !== 'object' || input === null || Object.isFrozen(input)) return input;
  for (const value of Object.values(input)) deepFreeze(value);
  return Object.freeze(input);
}
