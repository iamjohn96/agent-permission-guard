import { createHash, randomUUID } from 'node:crypto';
import { constants, type BigIntStats } from 'node:fs';
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  open,
  realpath,
  unlink,
  type FileHandle,
} from 'node:fs/promises';
import { basename, dirname, join, relative, resolve, sep } from 'node:path';

import { canonicalJson } from '../audit/canonical-json.js';
import {
  BoundedArchiveWorker,
  type ArchiveWorkerMaterializationSink,
  type AuthenticatedArchiveWorkerTranscript,
} from './bounded-archive-worker.js';
import { PackageStageError, validatePortableRelativePath } from './profile.js';
import { PackageStageStateMachine } from './state-machine.js';
import type { TarArchiveTranscript, TarArchiveTranscriptEntry } from './tar-archive-parser.js';
import { createMaterializedTreeManifest } from './tree-manifest.js';
import type { MaterializedTreeManifest, MaterializedTreeRecord, PackageStageLimits } from './types.js';

export type SyntheticMaterializationAuditEvent =
  | 'materialization_started'
  | 'ready_to_commit'
  | 'ready';

export type SyntheticMaterializationAuditEvidence = Readonly<{
  artifactSha512: string;
  transcriptDigest: string;
  runtimeDigest: string;
  treeDigest: string | null;
  sealDigest: string | null;
}>;

export interface SyntheticMaterializationAudit {
  record(
    event: SyntheticMaterializationAuditEvent,
    evidence: SyntheticMaterializationAuditEvidence,
  ): Promise<void>;
}

export class SyntheticMaterializationAuditAuthority implements SyntheticMaterializationAudit {
  readonly #records: Array<Readonly<{
    event: SyntheticMaterializationAuditEvent;
    evidence: SyntheticMaterializationAuditEvidence;
  }>> = [];

  constructor(private readonly failAt: SyntheticMaterializationAuditEvent | null = null) {}

  async record(
    event: SyntheticMaterializationAuditEvent,
    evidence: SyntheticMaterializationAuditEvidence,
  ): Promise<void> {
    const expected = ['materialization_started', 'ready_to_commit', 'ready'][this.#records.length];
    const validEvidence = /^sha512-[A-Za-z0-9+/]+={0,2}$/u.test(evidence.artifactSha512)
      && /^[a-f0-9]{64}$/u.test(evidence.transcriptDigest)
      && /^[a-f0-9]{64}$/u.test(evidence.runtimeDigest)
      && (evidence.treeDigest === null || /^[a-f0-9]{64}$/u.test(evidence.treeDigest))
      && (evidence.sealDigest === null || /^[a-f0-9]{64}$/u.test(evidence.sealDigest));
    const validStage = event === 'materialization_started'
      ? evidence.treeDigest === null && evidence.sealDigest === null
      : event === 'ready_to_commit'
        ? evidence.treeDigest !== null && evidence.sealDigest === null
        : evidence.treeDigest !== null && evidence.sealDigest !== null;
    if (event !== expected || !validEvidence || !validStage) {
      throw new PackageStageError('stage_audit_incomplete');
    }
    if (event === this.failAt) throw new PackageStageError('stage_audit_incomplete');
    this.#records.push(Object.freeze({ event, evidence: Object.freeze({ ...evidence }) }));
  }

  get events(): readonly SyntheticMaterializationAuditEvent[] {
    return Object.freeze(this.#records.map((record) => record.event));
  }

  get records(): readonly Readonly<{
    event: SyntheticMaterializationAuditEvent;
    evidence: SyntheticMaterializationAuditEvidence;
  }>[] {
    return Object.freeze([...this.#records]);
  }
}

export type SyntheticMaterializationFaultPoint =
  | 'after_pending_root'
  | 'before_entry'
  | 'after_entry'
  | 'before_tree_verification'
  | 'before_seal'
  | 'after_seal';

export type SyntheticReadyStage = Readonly<{
  resultVersion: 1;
  state: 'READY';
  pendingRoot: string;
  sealPath: string;
  artifactSha512: string;
  runtimeDigest: string;
  transcriptDigest: string;
  treeDigest: string;
  sealDigest: string;
}>;

type SealRecord = Readonly<{
  sealVersion: 1;
  state: 'sealed_pending_audit';
  rootName: string;
  rootDevice: string;
  rootInode: string;
  artifactSha512: string;
  runtimeDigest: string;
  transcriptDigest: string;
  treeDigest: string;
  sealDigest: string;
}>;

export class SyntheticTwoPassMaterializer {
  readonly #authenticated = new WeakSet<object>();

  constructor(
    private readonly worker: BoundedArchiveWorker,
    private readonly injectFault?: (point: SyntheticMaterializationFaultPoint) => void,
  ) {}

  async materialize(
    artifactBytes: Uint8Array,
    limits: PackageStageLimits,
    stageParent: string,
    audit: SyntheticMaterializationAudit,
    signal?: AbortSignal,
  ): Promise<SyntheticReadyStage> {
    if (process.platform === 'win32') throw new PackageStageError('materialization_failed');
    const state = new PackageStageStateMachine('ARTIFACTS_VERIFIED');
    let transcript: AuthenticatedArchiveWorkerTranscript | undefined;
    let writer: PosixTranscriptWriter | undefined;
    let pendingRoot: string | undefined;
    try {
      state.transition('PASS_A_RUNNING');
      transcript = await this.worker.inspect(artifactBytes, limits, signal);
      state.transition('ARCHIVES_PREFLIGHTED');
      await audit.record('materialization_started', auditEvidence(transcript, null, null));

      const parent = await assertPrivateStageParent(stageParent);
      pendingRoot = await mkdtemp(join(parent.path, 'pending-'));
      await chmod(pendingRoot, 0o700);
      const rootIdentity = await captureRootIdentity(pendingRoot, parent);
      await syncDirectory(pendingRoot);
      await syncDirectory(parent.path);
      this.injectFault?.('after_pending_root');

      writer = new PosixTranscriptWriter(rootIdentity, transcript.transcript, limits, this.injectFault);
      state.transition('PASS_B_RUNNING');
      state.transition('MATERIALIZING');
      await this.worker.materialize(artifactBytes, transcript, limits, writer, signal);
      await writer.finish();

      this.injectFault?.('before_tree_verification');
      const tree = await createMaterializedTreeManifest(pendingRoot, limits);
      assertTreeMatchesTranscript(tree, transcript.transcript);
      await assertRootIdentity(rootIdentity);
      state.transition('TREE_VERIFIED');
      state.transition('READY_TO_COMMIT');
      await audit.record('ready_to_commit', auditEvidence(transcript, tree.treeDigest, null));

      this.injectFault?.('before_seal');
      const seal = await publishSeal(parent, rootIdentity, transcript, tree);
      state.transition('SEALED_PENDING_AUDIT');
      this.injectFault?.('after_seal');
      await audit.record('ready', auditEvidence(transcript, tree.treeDigest, seal.record.sealDigest));
      state.transition('READY');

      const ready = Object.freeze({
        resultVersion: 1 as const,
        state: 'READY' as const,
        pendingRoot,
        sealPath: seal.path,
        artifactSha512: transcript.transcript.artifactSha512,
        runtimeDigest: transcript.runtimeDigest,
        transcriptDigest: transcript.transcript.transcriptDigest,
        treeDigest: tree.treeDigest,
        sealDigest: seal.record.sealDigest,
      });
      this.#authenticated.add(ready);
      return ready;
    } catch (error) {
      await writer?.abort().catch(() => undefined);
      if (state.state !== 'FAILED_QUARANTINE') {
        try {
          state.transition('FAILED_QUARANTINE');
        } catch {
          // Terminal state is intentionally preserved; no recovery occurs here.
        }
      }
      if (error instanceof PackageStageError) throw error;
      throw new PackageStageError('materialization_failed');
    }
  }

  authenticates(candidate: unknown): candidate is SyntheticReadyStage {
    return typeof candidate === 'object' && candidate !== null && this.#authenticated.has(candidate);
  }
}

type StageParentIdentity = Readonly<{
  path: string;
  device: bigint;
  inode: bigint;
  owner: bigint;
}>;

type StageRootIdentity = Readonly<{
  path: string;
  name: string;
  device: bigint;
  inode: bigint;
  owner: bigint;
  parent: StageParentIdentity;
}>;

class PosixTranscriptWriter implements ArchiveWorkerMaterializationSink {
  readonly #createdDirectories = new Map<string, BigIntStats>();
  readonly #seen = new Set<string>();
  #current: {
    index: number;
    entry: TarArchiveTranscriptEntry;
    path: string;
    handle: FileHandle;
    hash: ReturnType<typeof createHash>;
    bytes: number;
  } | null = null;
  #aborted = false;

  constructor(
    private readonly root: StageRootIdentity,
    private readonly transcript: TarArchiveTranscript,
    private readonly limits: PackageStageLimits,
    private readonly injectFault?: (point: SyntheticMaterializationFaultPoint) => void,
  ) {}

  async start(entry: TarArchiveTranscriptEntry, index: number): Promise<void> {
    this.#assertActive();
    if (this.#current !== null || this.transcript.entries[index] !== entry || this.#seen.has(entry.relativePath)) {
      throw new PackageStageError('materialization_failed');
    }
    this.injectFault?.('before_entry');
    await assertRootIdentity(this.root);
    const absolute = stagePath(this.root.path, entry.relativePath, this.limits);
    await assertParentChain(this.root, dirname(absolute), this.#createdDirectories);
    if (entry.type === 'directory') {
      let identity: BigIntStats;
      try {
        await mkdir(absolute, { mode: 0o700, recursive: false });
        const observed = await lstat(absolute, { bigint: true });
        if (!observed.isDirectory() || observed.isSymbolicLink() || (observed.mode & 0o777n) !== 0o700n) {
          throw new PackageStageError('materialization_failed');
        }
        identity = observed;
        await syncDirectory(dirname(absolute));
      } catch (error) {
        if (error instanceof PackageStageError) throw error;
        throw new PackageStageError('materialization_failed');
      }
      this.#createdDirectories.set(absolute, identity);
      this.#seen.add(entry.relativePath);
      return;
    }

    let handle: FileHandle | undefined;
    try {
      handle = await open(
        absolute,
        constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW | constants.O_WRONLY,
        0o600,
      );
      const observed = await handle.stat({ bigint: true });
      if (!observed.isFile() || observed.nlink !== 1n || (observed.mode & 0o777n) !== 0o600n) {
        throw new PackageStageError('materialization_failed');
      }
      this.#current = {
        index,
        entry,
        path: absolute,
        handle,
        hash: createHash('sha256'),
        bytes: 0,
      };
      handle = undefined;
    } catch (error) {
      await handle?.close().catch(() => undefined);
      if (error instanceof PackageStageError) throw error;
      throw new PackageStageError('materialization_failed');
    }
  }

  async write(
    entry: TarArchiveTranscriptEntry,
    index: number,
    offset: number,
    bytes: Buffer,
  ): Promise<void> {
    this.#assertActive();
    const current = this.#current;
    if (
      current === null
      || current.entry !== entry
      || current.index !== index
      || current.bytes !== offset
      || bytes.length === 0
      || current.bytes + bytes.length > entry.declaredSize
    ) {
      throw new PackageStageError('materialization_failed');
    }
    let written = 0;
    while (written < bytes.length) {
      const result = await current.handle.write(bytes, written, bytes.length - written, offset + written);
      if (result.bytesWritten === 0) throw new PackageStageError('materialization_failed');
      written += result.bytesWritten;
    }
    current.hash.update(bytes);
    current.bytes += bytes.length;
  }

  async end(entry: TarArchiveTranscriptEntry, index: number): Promise<void> {
    this.#assertActive();
    if (entry.type === 'directory') {
      if (this.#current !== null || this.transcript.entries[index] !== entry) {
        throw new PackageStageError('materialization_failed');
      }
      this.injectFault?.('after_entry');
      return;
    }
    const current = this.#current;
    if (current === null || current.entry !== entry || current.index !== index) {
      throw new PackageStageError('materialization_failed');
    }
    this.#current = null;
    try {
      if (
        current.bytes !== entry.observedSize
        || current.hash.digest('hex') !== entry.bodySha256
      ) {
        throw new PackageStageError('materialization_failed');
      }
      await current.handle.sync();
      const beforeMode = await current.handle.stat({ bigint: true });
      if (!beforeMode.isFile() || beforeMode.nlink !== 1n || beforeMode.size !== BigInt(entry.declaredSize)) {
        throw new PackageStageError('materialization_failed');
      }
      await current.handle.chmod(entry.normalizedMode);
      await current.handle.sync();
      const final = await current.handle.stat({ bigint: true });
      if (
        !sameNode(beforeMode, final)
        || final.size !== BigInt(entry.declaredSize)
        || (final.mode & 0o777n) !== BigInt(entry.normalizedMode)
      ) {
        throw new PackageStageError('materialization_failed');
      }
    } finally {
      await current.handle.close().catch(() => undefined);
    }
    await syncDirectory(dirname(current.path));
    this.#seen.add(entry.relativePath);
    this.injectFault?.('after_entry');
  }

  async finish(): Promise<void> {
    this.#assertActive();
    if (this.#current !== null || this.#seen.size !== this.transcript.entries.length) {
      throw new PackageStageError('materialization_failed');
    }
    for (const [path, identity] of [...this.#createdDirectories].reverse()) {
      await assertRootIdentity(this.root);
      const before = await lstat(path, { bigint: true });
      if (!before.isDirectory() || before.isSymbolicLink() || !sameDirectory(identity, before)) {
        throw new PackageStageError('materialization_failed');
      }
      await chmod(path, 0o755);
      const after = await lstat(path, { bigint: true });
      if (!sameDirectory(identity, after) || (after.mode & 0o777n) !== 0o755n) {
        throw new PackageStageError('materialization_failed');
      }
      await syncDirectory(path);
      await syncDirectory(dirname(path));
    }
    await syncDirectory(this.root.path);
    await assertRootIdentity(this.root);
  }

  async abort(): Promise<void> {
    if (this.#aborted) return;
    this.#aborted = true;
    const current = this.#current;
    this.#current = null;
    await current?.handle.close().catch(() => undefined);
  }

  #assertActive(): void {
    if (this.#aborted) throw new PackageStageError('materialization_failed');
  }
}

async function assertPrivateStageParent(path: string): Promise<StageParentIdentity> {
  try {
    const canonical = await realpath(resolve(path));
    const observed = await lstat(canonical, { bigint: true });
    const uidMatches = typeof process.getuid !== 'function' || observed.uid === BigInt(process.getuid());
    if (!observed.isDirectory() || observed.isSymbolicLink() || !uidMatches || (observed.mode & 0o777n) !== 0o700n) {
      throw new PackageStageError('materialization_failed');
    }
    return Object.freeze({
      path: canonical,
      device: observed.dev,
      inode: observed.ino,
      owner: observed.uid,
    });
  } catch (error) {
    if (error instanceof PackageStageError) throw error;
    throw new PackageStageError('materialization_failed');
  }
}

async function captureRootIdentity(path: string, parent: StageParentIdentity): Promise<StageRootIdentity> {
  const canonical = await realpath(path);
  const observed = await lstat(canonical, { bigint: true });
  if (
    dirname(canonical) !== parent.path
    || !observed.isDirectory()
    || observed.isSymbolicLink()
    || observed.dev !== parent.device
    || observed.uid !== parent.owner
    || (observed.mode & 0o777n) !== 0o700n
  ) {
    throw new PackageStageError('materialization_failed');
  }
  return Object.freeze({
    path: canonical,
    name: basename(canonical),
    device: observed.dev,
    inode: observed.ino,
    owner: observed.uid,
    parent,
  });
}

async function assertRootIdentity(root: StageRootIdentity): Promise<void> {
  try {
    const parent = await lstat(root.parent.path, { bigint: true });
    const current = await lstat(root.path, { bigint: true });
    if (
      !parent.isDirectory()
      || parent.isSymbolicLink()
      || parent.dev !== root.parent.device
      || parent.ino !== root.parent.inode
      || parent.uid !== root.parent.owner
      || (parent.mode & 0o777n) !== 0o700n
      || !current.isDirectory()
      || current.isSymbolicLink()
      || current.dev !== root.device
      || current.ino !== root.inode
      || current.uid !== root.owner
      || (current.mode & 0o777n) !== 0o700n
      || dirname(root.path) !== root.parent.path
    ) {
      throw new PackageStageError('materialization_failed');
    }
  } catch (error) {
    if (error instanceof PackageStageError) throw error;
    throw new PackageStageError('materialization_failed');
  }
}

async function assertParentChain(
  root: StageRootIdentity,
  parentPath: string,
  createdDirectories: ReadonlyMap<string, BigIntStats>,
): Promise<void> {
  if (parentPath === root.path) return;
  const portable = relative(root.path, parentPath).split(sep).join('/');
  if (portable.startsWith('../') || portable === '..') throw new PackageStageError('materialization_failed');
  let current = root.path;
  for (const segment of portable.split('/')) {
    current = join(current, segment);
    const observed = await lstat(current, { bigint: true });
    const expected = createdDirectories.get(current);
    if (
      expected === undefined
      || !observed.isDirectory()
      || observed.isSymbolicLink()
      || observed.dev !== root.device
      || observed.uid !== root.owner
      || !sameDirectory(expected, observed)
    ) {
      throw new PackageStageError('materialization_failed');
    }
  }
}

function stagePath(root: string, relativePath: string, limits: PackageStageLimits): string {
  try {
    const segments = validatePortableRelativePath(relativePath, limits);
    const output = join(root, ...segments);
    if (!output.startsWith(`${root}${sep}`)) throw new PackageStageError('materialization_failed');
    return output;
  } catch {
    throw new PackageStageError('materialization_failed');
  }
}

function assertTreeMatchesTranscript(tree: MaterializedTreeManifest, transcript: TarArchiveTranscript): void {
  const expected = transcript.entries.map((entry): MaterializedTreeRecord => Object.freeze({
    relativePath: entry.relativePath,
    type: entry.type,
    normalizedMode: entry.normalizedMode,
    size: entry.declaredSize,
    ...(entry.bodySha256 === null ? {} : { sha256: entry.bodySha256 }),
  })).sort((left, right) => compareText(left.relativePath, right.relativePath));
  if (canonicalJson(tree.records) !== canonicalJson(expected)) {
    throw new PackageStageError('tree_changed');
  }
}

async function publishSeal(
  parent: StageParentIdentity,
  root: StageRootIdentity,
  transcript: AuthenticatedArchiveWorkerTranscript,
  tree: MaterializedTreeManifest,
): Promise<Readonly<{ path: string; record: SealRecord }>> {
  await assertRootIdentity(root);
  const sealPath = join(parent.path, `${root.name}.seal.json`);
  const tempPath = join(parent.path, `${root.name}.seal-${randomUUID()}.tmp`);
  const unsigned = Object.freeze({
    sealVersion: 1 as const,
    state: 'sealed_pending_audit' as const,
    rootName: root.name,
    rootDevice: root.device.toString(),
    rootInode: root.inode.toString(),
    artifactSha512: transcript.transcript.artifactSha512,
    runtimeDigest: transcript.runtimeDigest,
    transcriptDigest: transcript.transcript.transcriptDigest,
    treeDigest: tree.treeDigest,
  });
  const record = Object.freeze({ ...unsigned, sealDigest: sha256(canonicalJson(unsigned)) });
  let handle: FileHandle | undefined;
  let linked = false;
  try {
    handle = await open(
      tempPath,
      constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW | constants.O_WRONLY,
      0o600,
    );
    const bytes = Buffer.from(`${canonicalJson(record)}\n`, 'utf8');
    await writeFileHandle(handle, bytes);
    await handle.sync();
    await handle.chmod(0o400);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await link(tempPath, sealPath);
    linked = true;
    await unlink(tempPath);
    await syncDirectory(parent.path);
    const observed = await lstat(sealPath, { bigint: true });
    if (
      !observed.isFile()
      || observed.isSymbolicLink()
      || observed.nlink !== 1n
      || observed.dev !== parent.device
      || (observed.mode & 0o777n) !== 0o400n
      || observed.size !== BigInt(bytes.length)
    ) {
      throw new PackageStageError('stage_seal_invalid');
    }
    await assertRootIdentity(root);
    return Object.freeze({ path: sealPath, record });
  } catch (error) {
    await handle?.close().catch(() => undefined);
    if (!linked) await unlink(tempPath).catch(() => undefined);
    if (error instanceof PackageStageError) throw error;
    throw new PackageStageError('stage_seal_invalid');
  }
}

async function writeFileHandle(handle: FileHandle, bytes: Buffer): Promise<void> {
  let written = 0;
  while (written < bytes.length) {
    const result = await handle.write(bytes, written, bytes.length - written, written);
    if (result.bytesWritten === 0) throw new PackageStageError('stage_seal_invalid');
    written += result.bytesWritten;
  }
}

async function syncDirectory(path: string): Promise<void> {
  let handle: FileHandle | undefined;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_DIRECTORY);
    await handle.sync();
  } catch {
    throw new PackageStageError('materialization_failed');
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function auditEvidence(
  transcript: AuthenticatedArchiveWorkerTranscript,
  treeDigest: string | null,
  sealDigest: string | null,
) {
  return Object.freeze({
    artifactSha512: transcript.transcript.artifactSha512,
    transcriptDigest: transcript.transcript.transcriptDigest,
    runtimeDigest: transcript.runtimeDigest,
    treeDigest,
    sealDigest,
  });
}

function sameNode(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.nlink === right.nlink;
}

function sameDirectory(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.uid === right.uid;
}

function sha256(input: string | Uint8Array): string {
  return createHash('sha256').update(input).digest('hex');
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
