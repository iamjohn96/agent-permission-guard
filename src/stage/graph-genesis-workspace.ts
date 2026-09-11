import { createHash } from 'node:crypto';
import { lstat, open, opendir } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';

import { canonicalJson } from '../audit/canonical-json.js';
import { ARCHIVE_WORKER_PROTOCOL_VERSION } from './archive-worker-protocol.js';
import {
  ExactGraphCandidateAuthority,
  type AuthenticatedExactGraphCandidateFailure,
  type ExactGraphCandidate,
} from './exact-production-graph.js';
import { parseStrictJsonDocument } from './graph-genesis-broker.js';
import type {
  FinalizedGraphGenesisWorkspaceAuthority,
  HardenedGraphGenesisPlan,
  HardenedGraphGenesisPlanAuthority,
} from './graph-genesis-hardening.js';
import {
  CANONICAL_EXACT_GRAPH_GENESIS_MANIFEST,
  type GraphGenesisWorkspace,
} from './graph-genesis.js';
import { PACKAGE_STAGE_HARD_CEILINGS, PackageStageError } from './profile.js';

const TARGET = '@modelcontextprotocol/server-filesystem';
const VERSION = '2026.7.10';
const ALLOWED_TOP = new Set([
  'package.json', 'package-lock.json', 'user.npmrc', 'global.npmrc', 'broker-profile.sb',
  'cache', 'logs', 'tmp',
]);
const POST_STATE_DIAGNOSTIC_PREFIX = '[apg] graph-genesis-post-state-diagnostic ';
const MAX_POST_STATE_DIAGNOSTIC_BYTES = 1024;
const CANDIDATE_DIAGNOSTIC_PREFIX = '[apg] graph-genesis-candidate-diagnostic ';

export type AuthenticatedHardenedGraphGenesisPostState = Readonly<{
  evidenceVersion: 1;
  planHash: string;
  workspaceBinding: string;
  packageJsonSha256: string;
  packageLockSha256: string;
  packageLockDocumentDigest: string;
  entryCount: number;
  regularFileBytes: number;
  cacheBytes: number;
  logBytes: number;
  evidenceDigest: string;
}>;

export type GraphGenesisPostStateFailurePredicate =
  | 'authority_binding_rejected'
  | 'workspace_identity_rejected'
  | 'protected_file_identity_rejected'
  | 'inventory_rejected'
  | 'manifest_rejected'
  | 'lock_document_rejected'
  | 'config_empty_rejected';

/** Fixed, non-sensitive diagnostic evidence. Authenticity is authority-local. */
export type AuthenticatedHardenedGraphGenesisPostStateFailure = Readonly<{
  diagnosticVersion: 1;
  predicate: GraphGenesisPostStateFailurePredicate;
}>;

type DiagnosticWriter = (line: string) => unknown;

type PrivatePostStateCapsule = Readonly<{
  capsuleVersion: 1;
  planHash: string;
  packageLock: unknown;
  packageLockDocumentDigest: string;
}>;

export class HardenedGraphGenesisPostStateAuthority {
  readonly #authenticated = new WeakSet<object>();
  readonly #capsules = new WeakSet<object>();
  readonly #pairs = new WeakMap<object, object>();
  readonly #failures = new WeakSet<object>();
  readonly #errors = new WeakMap<object, AuthenticatedHardenedGraphGenesisPostStateFailure>();
  readonly #claimedErrors = new WeakSet<object>();
  readonly #diagnosticsAttempted = new WeakSet<object>();

  constructor(
    private readonly plans: HardenedGraphGenesisPlanAuthority,
    private readonly workspaces: FinalizedGraphGenesisWorkspaceAuthority,
  ) {}

  async inspect(input: Readonly<{
    plan: HardenedGraphGenesisPlan;
    executionCapsule: object;
    workspace: GraphGenesisWorkspace;
  }>): Promise<Readonly<{
    evidence: AuthenticatedHardenedGraphGenesisPostState;
    privateCapsule: object;
  }>> {
    if (!this.plans.authenticatesPair(input.plan, input.executionCapsule)
      || !this.workspaces.authenticates(input.workspace)
      || input.plan.workspaceBinding !== workspaceBinding(input.workspace)) this.#fail('authority_binding_rejected');
    const root = await this.#stage('workspace_identity_rejected', () => lstat(input.workspace.rootRealpath));
    if (!root.isDirectory() || root.isSymbolicLink() || root.dev !== input.workspace.device
      || root.ino !== input.workspace.inode || root.uid !== input.workspace.owner
      || (root.mode & 0o777) !== input.workspace.mode) this.#fail('workspace_identity_rejected');
    await this.#stage('protected_file_identity_rejected',
      () => this.workspaces.revalidateProtectedFiles(input.workspace));
    const inventory = await this.#stage('inventory_rejected', () => inspectTree(input.workspace.rootRealpath, input.plan));
    const manifest = await this.#stage('manifest_rejected',
      () => readDocument(join(input.workspace.rootRealpath, 'package.json'), input.plan.limits.packageJsonBytes));
    if (canonicalJson(manifest.document) !== canonicalJson(CANONICAL_EXACT_GRAPH_GENESIS_MANIFEST)) {
      this.#fail('manifest_rejected');
    }
    const lock = await this.#stage('lock_document_rejected',
      () => readDocument(join(input.workspace.rootRealpath, 'package-lock.json'), input.plan.limits.packageLockBytes));
    for (const config of ['user.npmrc', 'global.npmrc']) {
      const info = await this.#stage('config_empty_rejected', () => lstat(join(input.workspace.rootRealpath, config)));
      if (info.size !== 0) this.#fail('config_empty_rejected');
    }
    await this.#stage('protected_file_identity_rejected',
      () => this.workspaces.revalidateProtectedFiles(input.workspace));
    const lockDocument = deepFreeze(lock.document);
    const lockDocumentDigest = sha256(canonicalJson(lockDocument));
    const unsigned = Object.freeze({
      evidenceVersion: 1 as const,
      planHash: input.plan.planHash,
      workspaceBinding: input.plan.workspaceBinding,
      packageJsonSha256: manifest.sha256,
      packageLockSha256: lock.sha256,
      packageLockDocumentDigest: lockDocumentDigest,
      ...inventory,
    });
    const evidence = Object.freeze({ ...unsigned, evidenceDigest: sha256(canonicalJson(unsigned)) });
    const capsule = Object.freeze({
      capsuleVersion: 1 as const,
      planHash: input.plan.planHash,
      packageLock: lockDocument,
      packageLockDocumentDigest: lockDocumentDigest,
    });
    this.#authenticated.add(evidence);
    this.#capsules.add(capsule);
    this.#pairs.set(capsule, evidence);
    return Object.freeze({ evidence, privateCapsule: capsule });
  }

  authenticatesPair(evidence: unknown, capsule: unknown): evidence is AuthenticatedHardenedGraphGenesisPostState {
    return typeof evidence === 'object' && evidence !== null && this.#authenticated.has(evidence)
      && typeof capsule === 'object' && capsule !== null && this.#capsules.has(capsule)
      && this.#pairs.get(capsule) === evidence;
  }

  authenticates(evidence: unknown): evidence is AuthenticatedHardenedGraphGenesisPostState {
    return typeof evidence === 'object' && evidence !== null && this.#authenticated.has(evidence);
  }

  /** Returns a failure once only when this exact authority issued the thrown error. */
  claimFailure(error: unknown): AuthenticatedHardenedGraphGenesisPostStateFailure | undefined {
    if (typeof error !== 'object' || error === null || this.#claimedErrors.has(error)) return undefined;
    const failure = this.#errors.get(error);
    if (failure === undefined) return undefined;
    this.#claimedErrors.add(error);
    return failure;
  }

  authenticatesFailure(value: unknown): value is AuthenticatedHardenedGraphGenesisPostStateFailure {
    return typeof value === 'object' && value !== null && this.#failures.has(value);
  }

  /** One local best-effort projection per authenticated failure; write errors are inert. */
  emitFailureDiagnostic(failure: AuthenticatedHardenedGraphGenesisPostStateFailure, write: DiagnosticWriter): boolean {
    if (!this.authenticatesFailure(failure) || this.#diagnosticsAttempted.has(failure)) return false;
    this.#diagnosticsAttempted.add(failure);
    const line = `${POST_STATE_DIAGNOSTIC_PREFIX}${canonicalJson({
      diagnosticVersion: failure.diagnosticVersion,
      predicate: failure.predicate,
    })}\n`;
    if (Buffer.byteLength(line, 'utf8') > MAX_POST_STATE_DIAGNOSTIC_BYTES) return false;
    try {
      write(line);
      return true;
    } catch {
      return false;
    }
  }

  packageLock(evidence: AuthenticatedHardenedGraphGenesisPostState, capsule: object): unknown {
    if (!this.authenticatesPair(evidence, capsule)) failPostState();
    return (capsule as PrivatePostStateCapsule).packageLock;
  }

  async #stage<T>(
    predicate: GraphGenesisPostStateFailurePredicate,
    operation: () => Promise<T>,
  ): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      if (typeof error === 'object' && error !== null && this.#errors.has(error)) throw error;
      return this.#fail(predicate);
    }
  }

  #fail(predicate: GraphGenesisPostStateFailurePredicate): never {
    const failure = Object.freeze({ diagnosticVersion: 1 as const, predicate });
    const error = new PackageStageError('acceptance_incomplete');
    this.#failures.add(failure);
    this.#errors.set(error, failure);
    throw error;
  }
}

export class HardenedGraphGenesisCandidateCompiler {
  readonly #pairs = new WeakMap<object, object>();
  readonly #failures = new WeakSet<object>();
  readonly #errors = new WeakMap<object, AuthenticatedExactGraphCandidateFailure>();
  readonly #claimedErrors = new WeakSet<object>();
  readonly #diagnosticsAttempted = new WeakSet<object>();

  constructor(
    private readonly postStates: HardenedGraphGenesisPostStateAuthority,
    private readonly candidates: ExactGraphCandidateAuthority,
  ) {}

  compile(input: Readonly<{
    plan: HardenedGraphGenesisPlan;
    postState: AuthenticatedHardenedGraphGenesisPostState;
    privatePostStateCapsule: object;
  }>): ExactGraphCandidate {
    const packageLock = this.postStates.packageLock(input.postState, input.privatePostStateCapsule);
    if (input.postState.planHash !== input.plan.planHash) failPostState();
    let candidate: ExactGraphCandidate;
    try {
      candidate = this.candidates.compile({
        profileId: 'filesystem-2026-7-10-candidate',
        profileVersion: 1,
        topPackage: { name: TARGET, exactVersion: VERSION, exactEntrypointRelativePath: 'dist/index.js' },
        registryOrigin: input.plan.registryOrigin,
        runtimeConstraint: {
          os: 'darwin', architecture: 'arm64', nodeMajor: 26,
          nodeVersion: input.plan.nodeVersion,
          npmGraphGeneratorVersion: input.plan.npmVersion,
          lockfileVersion: 3,
        },
        materializationRulesVersion: 1,
        archiveRulesVersion: 1,
        workerProtocolVersion: ARCHIVE_WORKER_PROTOCOL_VERSION,
        limits: PACKAGE_STAGE_HARD_CEILINGS,
        packageLock,
      });
    } catch (error) {
      const failure = this.candidates.claimFailure(error);
      if (failure !== undefined && this.candidates.authenticatesFailure(failure)
        && typeof error === 'object' && error !== null) {
        this.#failures.add(failure);
        this.#errors.set(error, failure);
      }
      throw error;
    }
    this.#pairs.set(candidate, input.postState);
    return candidate;
  }

  authenticatesPair(candidate: unknown, postState: unknown): candidate is ExactGraphCandidate {
    return this.candidates.authenticates(candidate) && typeof postState === 'object' && postState !== null
      && this.#pairs.get(candidate) === postState;
  }

  /** Claims only the failure paired by this compiler's own compile call, once. */
  claimFailure(error: unknown): AuthenticatedExactGraphCandidateFailure | undefined {
    if (typeof error !== 'object' || error === null || this.#claimedErrors.has(error)) return undefined;
    const failure = this.#errors.get(error);
    if (failure === undefined || !this.#failures.has(failure)) return undefined;
    this.#claimedErrors.add(error);
    return failure;
  }

  authenticatesFailure(value: unknown): value is AuthenticatedExactGraphCandidateFailure {
    return typeof value === 'object' && value !== null && this.#failures.has(value);
  }

  /** One bounded local projection per compiler-paired failure; writer failures are inert. */
  emitFailureDiagnostic(failure: AuthenticatedExactGraphCandidateFailure, write: DiagnosticWriter): boolean {
    if (!this.authenticatesFailure(failure) || this.#diagnosticsAttempted.has(failure)) return false;
    this.#diagnosticsAttempted.add(failure);
    const line = `${CANDIDATE_DIAGNOSTIC_PREFIX}${canonicalJson({
      diagnosticVersion: failure.diagnosticVersion,
      predicate: failure.predicate,
    })}\n`;
    if (Buffer.byteLength(line, 'utf8') > MAX_POST_STATE_DIAGNOSTIC_BYTES) return false;
    try {
      write(line);
      return true;
    } catch {
      return false;
    }
  }
}

async function inspectTree(root: string, plan: HardenedGraphGenesisPlan): Promise<Readonly<{
  entryCount: number;
  regularFileBytes: number;
  cacheBytes: number;
  logBytes: number;
}>> {
  let entryCount = 0;
  let regularFileBytes = 0;
  let cacheBytes = 0;
  let logBytes = 0;
  const visit = async (directory: string): Promise<void> => {
    const handle = await opendir(directory);
    for await (const item of handle) {
      const path = join(directory, item.name);
      const rel = relative(root, path).split(sep).join('/');
      const top = rel.split('/', 1)[0]!;
      if (++entryCount > 100_000 || !ALLOWED_TOP.has(top) || item.name === 'node_modules'
        || item.name === '.npmrc' || item.name.endsWith('.tgz') || /[\u0000-\u001f\u007f]/u.test(rel)) failPostState();
      const info = await lstat(path);
      if (info.isSymbolicLink() || (!info.isFile() && !info.isDirectory()) || (info.mode & 0o002) !== 0) failPostState();
      if (info.isDirectory()) { await visit(path); continue; }
      if (info.nlink !== 1 || (info.mode & 0o111) !== 0) failPostState();
      regularFileBytes += info.size;
      if (top === 'cache') cacheBytes += info.size;
      if (top === 'logs') logBytes += info.size;
      if (regularFileBytes > 128 * 1024 * 1024
        || cacheBytes > plan.limits.broker.aggregateResponseBytes
        || logBytes > plan.limits.stdoutBytes + plan.limits.stderrBytes) failPostState();
      const file = await open(path, 'r');
      try {
        const magic = Buffer.alloc(Math.min(265, info.size));
        await file.read(magic, 0, magic.length, 0);
        if (magic.subarray(0, 2).equals(Buffer.from([0x1f, 0x8b]))
          || magic.subarray(0, 4).equals(Buffer.from([0x50, 0x4b, 0x03, 0x04]))
          || magic.subarray(257, 262).toString('ascii') === 'ustar') failPostState();
      } finally { await file.close(); }
    }
  };
  await visit(root);
  return Object.freeze({ entryCount, regularFileBytes, cacheBytes, logBytes });
}

async function readDocument(path: string, maximumBytes: number): Promise<Readonly<{ document: unknown; sha256: string }>> {
  const file = await open(path, 'r');
  try {
    const before = await file.stat();
    if (!before.isFile() || before.nlink !== 1 || before.size <= 0 || before.size > maximumBytes) failPostState();
    const bytes = await file.readFile();
    const after = await file.stat();
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size
      || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) failPostState();
    let text: string;
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { failPostState(); }
    return Object.freeze({ document: parseStrictJsonDocument(text), sha256: sha256(bytes) });
  } finally { await file.close(); }
}

function workspaceBinding(workspace: GraphGenesisWorkspace): string {
  return sha256(canonicalJson({
    root: workspace.rootRealpath,
    device: workspace.device,
    inode: workspace.inode,
    owner: workspace.owner,
    mode: workspace.mode,
    protectedFiles: workspace.protectedFiles,
    initialManifestDigest: workspace.initialManifestDigest,
  }));
}

function sha256(value: string | Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
}

function deepFreeze<T>(input: T): T {
  if (typeof input !== 'object' || input === null || Object.isFrozen(input)) return input;
  for (const value of Object.values(input)) deepFreeze(value);
  return Object.freeze(input);
}

function failPostState(): never { throw new PackageStageError('acceptance_incomplete'); }
