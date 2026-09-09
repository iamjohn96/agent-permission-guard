import { createHash, randomBytes } from 'node:crypto';
import { lstat, mkdir, open, opendir, readlink, realpath, rm, stat } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';

import { canonicalJson } from '../audit/canonical-json.js';
import type { ExactGraphCandidate, ExactGraphCandidateInput } from './exact-production-graph.js';
import { ExactGraphCandidateAuthority } from './exact-production-graph.js';
import type {
  AuthenticatedBrokerLedger,
  MetadataBrokerLimits,
} from './graph-genesis-broker.js';
import {
  MetadataBrokerAuthority,
  parseStrictJsonDocument,
  validateMetadataBrokerLimits,
} from './graph-genesis-broker.js';
import type {
  AuthenticatedContainmentSelfTest,
  SeatbeltLoopbackProfile,
} from './graph-genesis-containment.js';
import { SeatbeltLoopbackContainmentAuthority } from './graph-genesis-containment.js';
import { PackageStageError } from './profile.js';

const SHA256 = /^[a-f0-9]{64}$/u;
const EXACT_TARGET_NAME = '@modelcontextprotocol/server-filesystem';
const EXACT_TARGET_VERSION = '2026.7.10';
export const REQUIRED_COMPLETE_EVENTS = Object.freeze([
  'runtime_snapshot_complete',
  'containment_self_test_complete',
  'graph_genesis_plan_ready',
  'graph_genesis_authorized',
  'broker_armed',
  'npm_spawn_started',
  'metadata_request_started',
  'metadata_response_validated',
  'npm_terminal_observed',
  'lock_validation_started',
  'candidate_compiled',
  'cleanup_complete',
  'genesis_complete',
]);

export type RuntimeTreeEntry = Readonly<{
  relativePath: string;
  type: 'file' | 'directory' | 'symlink';
  mode: number;
  device: number;
  inode: number;
  size: number;
  mtimeMs: number;
  ctimeMs: number;
  sha256?: string;
  linkTarget?: string;
}>;

export type AuthenticatedRuntimeTreeSnapshot = Readonly<{
  snapshotVersion: 1;
  rootRealpath: string;
  entryCount: number;
  regularFileBytes: number;
  entries: readonly RuntimeTreeEntry[];
  treeDigest: string;
}>;

export type GraphGenesisWorkspace = Readonly<{
  workspaceVersion: 1;
  rootRealpath: string;
  device: number;
  inode: number;
  owner: number;
  mode: 0o700;
  protectedFiles: readonly Readonly<{ name: string; device: number; inode: number; mode: 0o600 }>[];
  initialManifestDigest: string;
}>;

export type GraphGenesisLimits = Readonly<{
  broker: MetadataBrokerLimits;
  completeTimeoutMs: number;
  stdoutBytes: number;
  stderrBytes: number;
  packageJsonBytes: number;
  packageLockBytes: number;
}>;

export type GraphGenesisLaunch = Readonly<{
  executable: string;
  args: readonly string[];
  cwd: string;
  env: Readonly<Record<string, string>>;
  stdin: 'ignore';
  shell: false;
  launchDigest: string;
}>;

export type GraphGenesisPlan = Readonly<{
  planVersion: 1;
  sessionId: string;
  targetName: typeof EXACT_TARGET_NAME;
  exactTargetVersion: typeof EXACT_TARGET_VERSION;
  registryOrigin: 'https://registry.npmjs.org/';
  platform: 'darwin';
  architecture: 'arm64';
  osBuild: string;
  nodeVersion: string;
  npmVersion: '11.16.0';
  nodeExecutable: string;
  npmCliEntrypoint: string;
  nodeRuntimeDigest: string;
  npmRuntimeTreeDigest: string;
  brokerRuntimeDigest: string;
  sandboxExecSha256: string;
  containmentProfileDigest: string;
  containmentSelfTestDigest: string;
  workspaceBinding: string;
  brokerAddress: '127.0.0.1';
  brokerPort: number;
  routeTokenDigest: string;
  launch: GraphGenesisLaunch;
  limits: GraphGenesisLimits;
  consequence: 'bounded_public_metadata_graph_genesis';
  planHash: string;
}>;

export type SyntheticGraphGenesisApproval = Readonly<{
  approvalVersion: 1;
  approvalId: string;
  planHash: string;
  consequence: GraphGenesisPlan['consequence'];
  expiresAt: string;
}>;

export type AuthorizedGraphGenesis = Readonly<{
  authorizationVersion: 1;
  plan: GraphGenesisPlan;
  approvalId: string;
  authorizedAt: string;
  authorizationDigest: string;
}>;

export type GraphGenesisSafeReport = Readonly<{
  reportVersion: 1;
  planHash: string;
  runtimeDigest: string;
  candidateDigest: string;
  brokerLedgerDigest: string;
  targetName: typeof EXACT_TARGET_NAME;
  exactTargetVersion: typeof EXACT_TARGET_VERSION;
  packageNames: readonly string[];
  nodeCount: number;
  edgeCount: number;
  providerId: SeatbeltLoopbackProfile['providerId'];
  cleanupComplete: true;
  terminalAuditComplete: true;
  reportDigest: string;
}>;

export type ControlledGraphGenesisEvidence = Readonly<{
  evidenceVersion: 1;
  candidate: ExactGraphCandidate;
  report: GraphGenesisSafeReport;
  evidenceDigest: string;
}>;

export type AuthenticatedGraphGenesisTerminalAudit = Readonly<{
  auditVersion: 1;
  planHash: string;
  orderedEvents: readonly string[];
  terminalState: 'genesis_complete';
  auditDigest: string;
}>;

export class RuntimeTreeSnapshotAuthority {
  readonly #authenticated = new WeakSet<object>();

  async capture(root: string, limits = { entries: 4096, regularFileBytes: 64 * 1024 * 1024 }): Promise<AuthenticatedRuntimeTreeSnapshot> {
    if (!Number.isSafeInteger(limits.entries) || limits.entries < 1 || limits.entries > 4096
      || !Number.isSafeInteger(limits.regularFileBytes) || limits.regularFileBytes < 1
      || limits.regularFileBytes > 64 * 1024 * 1024) failPlan();
    const rootRealpath = await realpath(root);
    const rootInfo = await lstat(rootRealpath);
    if (!rootInfo.isDirectory() || (rootInfo.mode & 0o002) !== 0) failPlan();
    const entries: RuntimeTreeEntry[] = [];
    const portable = new Set<string>();
    let bytes = 0;
    const visit = async (absolute: string): Promise<void> => {
      const directory = await opendir(absolute);
      const names: string[] = [];
      for await (const item of directory) names.push(item.name);
      names.sort(compareText);
      for (const name of names) {
        const path = join(absolute, name);
        const rel = relative(rootRealpath, path).split(sep).join('/');
        if (rel.startsWith('../') || rel === '..' || rel.includes('\0')
          || /[\u0000-\u001f\u007f]/u.test(rel)) failPlan();
        const folded = rel.normalize('NFC').toLocaleLowerCase('en-US');
        if (portable.has(folded) || rel.normalize('NFC') !== rel) failPlan();
        portable.add(folded);
        const info = await lstat(path, { bigint: false });
        if ((info.isFile() || info.isDirectory()) && (info.mode & 0o002) !== 0) failPlan();
        if (++entries.length > limits.entries || info.nlink > 1 && info.isFile()) failPlan();
        const base = {
          relativePath: rel,
          mode: info.mode & 0o7777,
          device: info.dev,
          inode: info.ino,
          size: info.size,
          mtimeMs: info.mtimeMs,
          ctimeMs: info.ctimeMs,
        };
        if (info.isDirectory()) {
          entries[entries.length - 1] = Object.freeze({ ...base, type: 'directory' as const });
          await visit(path);
        } else if (info.isFile()) {
          bytes += info.size;
          if (bytes > limits.regularFileBytes) failPlan();
          const file = await open(path, 'r');
          try {
            const before = await file.stat();
            const digest = createHash('sha256');
            for await (const chunk of file.createReadStream({ autoClose: false })) digest.update(chunk);
            const after = await file.stat();
            if (!sameIdentity(before, after)) failPlan();
            entries[entries.length - 1] = Object.freeze({ ...base, type: 'file' as const, sha256: digest.digest('hex') });
          } finally { await file.close(); }
        } else if (info.isSymbolicLink()) {
          const target = await realpath(path);
          if (target !== rootRealpath && !target.startsWith(`${rootRealpath}${sep}`)) failPlan();
          entries[entries.length - 1] = Object.freeze({
            ...base, type: 'symlink' as const, linkTarget: await readlink(path),
          });
        } else failPlan();
      }
    };
    await visit(rootRealpath);
    const unsigned = deepFreeze({
      snapshotVersion: 1 as const,
      rootRealpath,
      entryCount: entries.length,
      regularFileBytes: bytes,
      entries: Object.freeze(entries),
    });
    const snapshot = deepFreeze({ ...unsigned, treeDigest: sha256(canonicalJson(unsigned)) });
    this.#authenticated.add(snapshot);
    return snapshot;
  }

  authenticates(value: unknown): value is AuthenticatedRuntimeTreeSnapshot {
    return typeof value === 'object' && value !== null && this.#authenticated.has(value);
  }

  async revalidate(snapshot: AuthenticatedRuntimeTreeSnapshot): Promise<void> {
    if (!this.authenticates(snapshot)) failPlan();
    const current = await this.capture(snapshot.rootRealpath, {
      entries: 4096,
      regularFileBytes: 64 * 1024 * 1024,
    });
    if (current.treeDigest !== snapshot.treeDigest) failPlan();
  }
}

export class GraphGenesisWorkspaceAuthority {
  readonly #authenticated = new WeakSet<object>();
  readonly #cleaned = new WeakSet<object>();

  async initialize(root: string): Promise<GraphGenesisWorkspace> {
    await mkdir(root, { recursive: false, mode: 0o700 });
    const rootRealpath = await realpath(root);
    const rootInfo = await stat(rootRealpath);
    if (!rootInfo.isDirectory() || (rootInfo.mode & 0o777) !== 0o700) failPlan();
    for (const directory of ['cache', 'logs', 'tmp', 'prefix']) await mkdir(join(rootRealpath, directory), { mode: 0o700 });
    await exclusiveFile(join(rootRealpath, 'package.json'), `${canonicalJson({ name: 'apg-graph-genesis', version: '0.0.0', private: true })}\n`);
    await exclusiveFile(join(rootRealpath, 'user.npmrc'), '');
    await exclusiveFile(join(rootRealpath, 'global.npmrc'), '');
    await exclusiveFile(join(rootRealpath, 'broker-profile.sb'), '');
    const protectedFiles = Object.freeze(await Promise.all(
      ['package.json', 'user.npmrc', 'global.npmrc', 'broker-profile.sb'].map(async (name) => {
        const info = await lstat(join(rootRealpath, name));
        if (!info.isFile() || info.nlink !== 1 || (info.mode & 0o777) !== 0o600) failPlan();
        return Object.freeze({ name, device: info.dev, inode: info.ino, mode: 0o600 as const });
      }),
    ));
    const initialManifestDigest = await simpleTreeDigest(rootRealpath);
    const workspace = deepFreeze({
      workspaceVersion: 1 as const,
      rootRealpath,
      device: rootInfo.dev,
      inode: rootInfo.ino,
      owner: rootInfo.uid,
      mode: 0o700 as const,
      protectedFiles,
      initialManifestDigest,
    });
    this.#authenticated.add(workspace);
    return workspace;
  }

  assertAuthenticates(workspace: unknown): asserts workspace is GraphGenesisWorkspace {
    if (typeof workspace !== 'object' || workspace === null || !this.#authenticated.has(workspace)) failPlan();
  }

  async validateSyntheticPostState(workspace: GraphGenesisWorkspace, expectedLock: unknown): Promise<void> {
    this.assertAuthenticates(workspace);
    const current = await lstat(workspace.rootRealpath);
    if (current.dev !== workspace.device || current.ino !== workspace.inode || (current.mode & 0o777) !== 0o700) failPlan();
    const allowedTop = new Set(['package.json', 'package-lock.json', 'user.npmrc', 'global.npmrc', 'broker-profile.sb', 'cache', 'logs', 'tmp', 'prefix']);
    const dir = await opendir(workspace.rootRealpath);
    for await (const item of dir) {
      if (!allowedTop.has(item.name) || item.name === 'node_modules' || item.isSymbolicLink()) failPlan();
    }
    for (const expected of workspace.protectedFiles) {
      const info = await lstat(join(workspace.rootRealpath, expected.name));
      if (!info.isFile() || info.nlink !== 1 || info.dev !== expected.device || info.ino !== expected.inode
        || (info.mode & 0o777) !== expected.mode) failPlan();
    }
    await validateWorkspaceContent(workspace.rootRealpath);
    const manifest = await readBoundedJson(join(workspace.rootRealpath, 'package.json'), 4 * 1024 * 1024);
    const wanted = { name: 'apg-graph-genesis', version: '0.0.0', private: true, dependencies: { [EXACT_TARGET_NAME]: EXACT_TARGET_VERSION } };
    if (canonicalJson(manifest) !== canonicalJson(wanted)) failPlan();
    const lock = await readBoundedJson(join(workspace.rootRealpath, 'package-lock.json'), 4 * 1024 * 1024);
    if (canonicalJson(lock) !== canonicalJson(expectedLock)) failPlan();
    for (const config of ['user.npmrc', 'global.npmrc']) {
      const handle = await open(join(workspace.rootRealpath, config), 'r');
      try { if ((await handle.stat()).size !== 0) failPlan(); } finally { await handle.close(); }
    }
  }

  async cleanup(workspace: GraphGenesisWorkspace): Promise<void> {
    this.assertAuthenticates(workspace);
    const current = await lstat(workspace.rootRealpath);
    if (!current.isDirectory() || current.isSymbolicLink() || current.dev !== workspace.device || current.ino !== workspace.inode) failPlan();
    await rm(workspace.rootRealpath, { recursive: true, force: false });
    this.#cleaned.add(workspace);
  }

  cleanupComplete(workspace: GraphGenesisWorkspace): boolean {
    return this.#cleaned.has(workspace);
  }
}

export function buildGraphGenesisLaunch(input: Readonly<{
  sandboxExecPath: string;
  profilePath: string;
  nodePath: string;
  npmCliPath: string;
  npmRuntimeRoot: string;
  workspaceRoot: string;
  brokerPort: number;
  routeToken: string;
}>): GraphGenesisLaunch {
  for (const path of [input.sandboxExecPath, input.profilePath, input.nodePath, input.npmCliPath, input.npmRuntimeRoot, input.workspaceRoot]) {
    if (!path.startsWith('/') || /[\u0000-\u001f\u007f]/u.test(path)) failPlan();
  }
  if (!Number.isSafeInteger(input.brokerPort) || input.brokerPort < 1024 || input.brokerPort > 65535
    || !/^[a-f0-9]{32}$/u.test(input.routeToken)) failPlan();
  const workspace = input.workspaceRoot;
  const args = Object.freeze([
    '-f', input.profilePath, input.nodePath, '--permission', '--allow-net',
    `--allow-fs-read=${input.npmRuntimeRoot}`, `--allow-fs-read=${workspace}`,
    `--allow-fs-write=${workspace}`, input.npmCliPath,
    'install', `${EXACT_TARGET_NAME}@${EXACT_TARGET_VERSION}`, '--package-lock-only', '--save-exact',
    '--maxsockets=4', '--ignore-scripts', '--audit=false', '--fund=false', '--update-notifier=false', '--workspaces=false',
    '--bin-links=false', '--allow-directory=none', '--allow-file=none', '--allow-git=none',
    '--allow-remote=none', '--replace-registry-host=never',
    `--registry=http://127.0.0.1:${input.brokerPort}/${input.routeToken}/`,
    `--cache=${join(workspace, 'cache')}`, `--userconfig=${join(workspace, 'user.npmrc')}`,
    `--globalconfig=${join(workspace, 'global.npmrc')}`, `--prefix=${join(workspace, 'prefix')}`,
    `--logs-dir=${join(workspace, 'logs')}`, '--loglevel=warn',
  ]);
  const env = deepFreeze({
    HOME: workspace,
    TMPDIR: join(workspace, 'tmp'),
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
  });
  const unsigned = deepFreeze({ executable: input.sandboxExecPath, args, cwd: workspace, env, stdin: 'ignore' as const, shell: false as const });
  return deepFreeze({ ...unsigned, launchDigest: sha256(canonicalJson(unsigned)) });
}

export class GraphGenesisPlanAuthority {
  readonly #authenticated = new WeakSet<object>();

  constructor(
    private readonly runtimeAuthority: RuntimeTreeSnapshotAuthority,
    private readonly workspaceAuthority: GraphGenesisWorkspaceAuthority,
    private readonly containmentAuthority: SeatbeltLoopbackContainmentAuthority,
  ) {}

  create(input: Readonly<{
    sessionId?: string;
    osBuild: string;
    nodeVersion: string;
    nodeExecutable: string;
    npmCliEntrypoint: string;
    nodeSnapshot: AuthenticatedRuntimeTreeSnapshot;
    npmSnapshot: AuthenticatedRuntimeTreeSnapshot;
    brokerRuntimeDigest: string;
    sandboxExecSha256: string;
    containmentProfile: SeatbeltLoopbackProfile;
    containmentSelfTest: AuthenticatedContainmentSelfTest;
    workspace: GraphGenesisWorkspace;
    brokerPort: number;
    routeTokenDigest: string;
    launch: GraphGenesisLaunch;
    limits: GraphGenesisLimits;
  }>): GraphGenesisPlan {
    if (!this.runtimeAuthority.authenticates(input.nodeSnapshot) || !this.runtimeAuthority.authenticates(input.npmSnapshot)) failPlan();
    this.workspaceAuthority.assertAuthenticates(input.workspace);
    this.containmentAuthority.assertProfile(input.containmentProfile);
    this.containmentAuthority.assertSelfTest(input.containmentSelfTest);
    assertPlanRelations(input);
    const sessionId = input.sessionId ?? randomBytes(16).toString('hex');
    if (!/^[a-f0-9]{32}$/u.test(sessionId)) failPlan();
    const unsigned = deepFreeze({
      planVersion: 1 as const,
      sessionId,
      targetName: EXACT_TARGET_NAME as typeof EXACT_TARGET_NAME,
      exactTargetVersion: EXACT_TARGET_VERSION as typeof EXACT_TARGET_VERSION,
      registryOrigin: 'https://registry.npmjs.org/' as const,
      platform: 'darwin' as const,
      architecture: 'arm64' as const,
      osBuild: input.osBuild,
      nodeVersion: input.nodeVersion,
      npmVersion: '11.16.0' as const,
      nodeExecutable: input.nodeExecutable,
      npmCliEntrypoint: input.npmCliEntrypoint,
      nodeRuntimeDigest: input.nodeSnapshot.treeDigest,
      npmRuntimeTreeDigest: input.npmSnapshot.treeDigest,
      brokerRuntimeDigest: input.brokerRuntimeDigest,
      sandboxExecSha256: input.sandboxExecSha256,
      containmentProfileDigest: input.containmentProfile.profileDigest,
      containmentSelfTestDigest: input.containmentSelfTest.evidenceDigest,
      workspaceBinding: workspaceBinding(input.workspace),
      brokerAddress: '127.0.0.1' as const,
      brokerPort: input.brokerPort,
      routeTokenDigest: input.routeTokenDigest,
      launch: input.launch,
      limits: input.limits,
      consequence: 'bounded_public_metadata_graph_genesis' as const,
    });
    const plan = deepFreeze({ ...unsigned, planHash: sha256(canonicalJson(unsigned)) });
    this.#authenticated.add(plan);
    return plan;
  }

  assertAuthenticates(value: unknown): asserts value is GraphGenesisPlan {
    if (typeof value !== 'object' || value === null || !this.#authenticated.has(value)) failPlan();
  }
}

/** Network-free test boundary. A product approval provider must replace this for a real run. */
export class SyntheticGraphGenesisApprovalAuthority {
  readonly #issued = new WeakSet<object>();
  readonly #consumed = new WeakSet<object>();
  readonly #authorized = new WeakSet<object>();

  constructor(private readonly planAuthority: GraphGenesisPlanAuthority) {}

  issueForTest(plan: GraphGenesisPlan, expiresAt: string, approvalId = randomBytes(16).toString('hex')): SyntheticGraphGenesisApproval {
    this.planAuthority.assertAuthenticates(plan);
    if (!/^[a-f0-9]{32}$/u.test(approvalId) || !Number.isFinite(Date.parse(expiresAt))) failApproval();
    const approval = Object.freeze({ approvalVersion: 1 as const, approvalId, planHash: plan.planHash, consequence: plan.consequence, expiresAt });
    this.#issued.add(approval);
    return approval;
  }

  consume(plan: GraphGenesisPlan, approval: SyntheticGraphGenesisApproval, now = new Date()): AuthorizedGraphGenesis {
    this.planAuthority.assertAuthenticates(plan);
    if (!this.#issued.has(approval) || this.#consumed.has(approval) || approval.planHash !== plan.planHash
      || approval.consequence !== plan.consequence || Date.parse(approval.expiresAt) <= now.getTime()) failApproval();
    this.#consumed.add(approval);
    const unsigned = deepFreeze({ authorizationVersion: 1 as const, plan, approvalId: approval.approvalId, authorizedAt: now.toISOString() });
    const authorization = deepFreeze({ ...unsigned, authorizationDigest: sha256(canonicalJson(unsigned)) });
    this.#authorized.add(authorization);
    return authorization;
  }

  authenticatesAuthorization(value: unknown): value is AuthorizedGraphGenesis {
    return typeof value === 'object' && value !== null && this.#authorized.has(value);
  }
}

/** Network-free test audit authority; it does not write the product audit database. */
export class SyntheticGraphGenesisAuditAuthority {
  readonly #authenticated = new WeakSet<object>();

  constructor(private readonly approvalAuthority: SyntheticGraphGenesisApprovalAuthority) {}

  completeForTest(authorization: AuthorizedGraphGenesis, orderedEvents: readonly string[]): AuthenticatedGraphGenesisTerminalAudit {
    if (!this.approvalAuthority.authenticatesAuthorization(authorization)
      || canonicalJson(orderedEvents) !== canonicalJson(REQUIRED_COMPLETE_EVENTS)) failPlan();
    const unsigned = deepFreeze({
      auditVersion: 1 as const,
      planHash: authorization.plan.planHash,
      orderedEvents: Object.freeze([...orderedEvents]),
      terminalState: 'genesis_complete' as const,
    });
    const audit = deepFreeze({ ...unsigned, auditDigest: sha256(canonicalJson(unsigned)) });
    this.#authenticated.add(audit);
    return audit;
  }

  authenticates(value: unknown): value is AuthenticatedGraphGenesisTerminalAudit {
    return typeof value === 'object' && value !== null && this.#authenticated.has(value);
  }
}

export class ControlledGraphGenesisAuthority {
  readonly #authenticated = new WeakSet<object>();

  constructor(
    private readonly candidateAuthority: ExactGraphCandidateAuthority,
    private readonly brokerAuthority: MetadataBrokerAuthority,
    private readonly workspaceAuthority: GraphGenesisWorkspaceAuthority,
    private readonly approvalAuthority: SyntheticGraphGenesisApprovalAuthority,
    private readonly auditAuthority: SyntheticGraphGenesisAuditAuthority,
  ) {}

  complete(input: Readonly<{
    authorization: AuthorizedGraphGenesis;
    candidate: ExactGraphCandidate;
    ledger: AuthenticatedBrokerLedger;
    workspace: GraphGenesisWorkspace;
    terminalAudit: AuthenticatedGraphGenesisTerminalAudit;
  }>): ControlledGraphGenesisEvidence {
    this.candidateAuthority.assertAuthenticates(input.candidate);
    if (!this.approvalAuthority.authenticatesAuthorization(input.authorization)
      || !this.brokerAuthority.authenticatesLedger(input.ledger) || !this.workspaceAuthority.cleanupComplete(input.workspace)
      || !this.auditAuthority.authenticates(input.terminalAudit)
      || input.ledger.planHash !== input.authorization.plan.planHash
      || input.terminalAudit.planHash !== input.authorization.plan.planHash
      || workspaceBinding(input.workspace) !== input.authorization.plan.workspaceBinding
      || input.candidate.topPackage.name !== EXACT_TARGET_NAME
      || input.candidate.topPackage.exactVersion !== EXACT_TARGET_VERSION
      || input.candidate.registryOrigin !== input.authorization.plan.registryOrigin
      || input.candidate.runtimeConstraint.nodeVersion !== input.authorization.plan.nodeVersion
      || input.candidate.runtimeConstraint.npmGraphGeneratorVersion !== input.authorization.plan.npmVersion) failPlan();
    const packageNames = Object.freeze([...new Set(input.candidate.graphNodes.map((node) => node.packageName))].sort(compareText));
    const ledgerNames = [...new Set(input.ledger.entries.map((entry) => entry.packageName))].sort(compareText);
    if (canonicalJson(packageNames) !== canonicalJson(ledgerNames)) failPlan();
    const edgeCount = input.candidate.graphNodes.reduce((sum, node) => sum + node.dependencyEdges.length, 0);
    const reportUnsigned = deepFreeze({
      reportVersion: 1 as const,
      planHash: input.authorization.plan.planHash,
      runtimeDigest: input.authorization.plan.npmRuntimeTreeDigest,
      candidateDigest: input.candidate.candidateDigest,
      brokerLedgerDigest: input.ledger.ledgerDigest,
      targetName: EXACT_TARGET_NAME as typeof EXACT_TARGET_NAME,
      exactTargetVersion: EXACT_TARGET_VERSION as typeof EXACT_TARGET_VERSION,
      packageNames,
      nodeCount: input.candidate.graphNodes.length,
      edgeCount,
      providerId: 'macos-seatbelt-loopback-development-v0' as const,
      cleanupComplete: true as const,
      terminalAuditComplete: true as const,
    });
    const report = deepFreeze({ ...reportUnsigned, reportDigest: sha256(canonicalJson(reportUnsigned)) });
    const evidenceUnsigned = deepFreeze({ evidenceVersion: 1 as const, candidate: input.candidate, report });
    const evidence = deepFreeze({ ...evidenceUnsigned, evidenceDigest: sha256(canonicalJson(evidenceUnsigned)) });
    this.#authenticated.add(evidence);
    return evidence;
  }

  authenticates(value: unknown): value is ControlledGraphGenesisEvidence {
    return typeof value === 'object' && value !== null && this.#authenticated.has(value);
  }
}

export function compileSyntheticGenesisLock(
  authority: ExactGraphCandidateAuthority,
  plan: GraphGenesisPlan,
  packageLock: unknown,
  input: Omit<ExactGraphCandidateInput, 'topPackage' | 'registryOrigin' | 'runtimeConstraint' | 'packageLock'>,
): ExactGraphCandidate {
  return authority.compile({
    ...input,
    topPackage: { name: plan.targetName, exactVersion: plan.exactTargetVersion, exactEntrypointRelativePath: 'dist/index.js' },
    registryOrigin: plan.registryOrigin,
    runtimeConstraint: {
      os: 'darwin', architecture: 'arm64', nodeMajor: 26, nodeVersion: plan.nodeVersion,
      npmGraphGeneratorVersion: plan.npmVersion, lockfileVersion: 3,
    },
    packageLock,
  });
}

function assertPlanRelations(input: Parameters<GraphGenesisPlanAuthority['create']>[0]): void {
  validateMetadataBrokerLimits(input.limits.broker);
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u.test(input.nodeVersion)
    || !SHA256.test(input.brokerRuntimeDigest) || !SHA256.test(input.sandboxExecSha256)
    || !SHA256.test(input.routeTokenDigest) || input.brokerPort !== input.containmentProfile.allowedPort
    || input.brokerPort !== input.containmentSelfTest.testedPort
    || input.osBuild !== input.containmentProfile.osBuild
    || input.containmentProfile.profileDigest !== input.containmentSelfTest.profileDigest
    || input.sandboxExecSha256 !== input.containmentProfile.sandboxExecSha256
    || input.launch.cwd !== input.workspace.rootRealpath) failPlan();
  const registryArgument = input.launch.args.find((argument) => argument.startsWith('--registry='));
  const routeMatch = /^--registry=http:\/\/127\.0\.0\.1:(\d+)\/([a-f0-9]{32})\/$/u.exec(registryArgument ?? '');
  if (routeMatch === null || Number(routeMatch[1]) !== input.brokerPort
    || sha256(routeMatch[2]!) !== input.routeTokenDigest) failPlan();
  if (!snapshotContains(input.nodeSnapshot, input.nodeExecutable)
    || !snapshotContains(input.npmSnapshot, input.npmCliEntrypoint)) failPlan();
  const expectedLaunch = buildGraphGenesisLaunch({
    sandboxExecPath: '/usr/bin/sandbox-exec',
    profilePath: join(input.workspace.rootRealpath, 'broker-profile.sb'),
    nodePath: input.nodeExecutable,
    npmCliPath: input.npmCliEntrypoint,
    npmRuntimeRoot: input.npmSnapshot.rootRealpath,
    workspaceRoot: input.workspace.rootRealpath,
    brokerPort: input.brokerPort,
    routeToken: routeMatch[2]!,
  });
  if (canonicalJson(expectedLaunch) !== canonicalJson(input.launch)) failPlan();
  const limits = input.limits;
  if (limits.completeTimeoutMs < 1 || limits.completeTimeoutMs > 120_000
    || limits.stdoutBytes < 1 || limits.stdoutBytes > 256 * 1024
    || limits.stderrBytes < 1 || limits.stderrBytes > 256 * 1024
    || limits.packageJsonBytes < 1 || limits.packageJsonBytes > 4 * 1024 * 1024
    || limits.packageLockBytes < 1 || limits.packageLockBytes > 4 * 1024 * 1024) failPlan();
}

function workspaceBinding(workspace: GraphGenesisWorkspace): string {
  return sha256(canonicalJson({
    root: workspace.rootRealpath,
    device: workspace.device,
    inode: workspace.inode,
    initialManifestDigest: workspace.initialManifestDigest,
    protectedFiles: workspace.protectedFiles,
  }));
}

function snapshotContains(snapshot: AuthenticatedRuntimeTreeSnapshot, absolutePath: string): boolean {
  const rel = relative(snapshot.rootRealpath, absolutePath).split(sep).join('/');
  return rel !== '' && !rel.startsWith('../')
    && snapshot.entries.some((entry) => entry.type === 'file' && entry.relativePath === rel);
}

async function exclusiveFile(path: string, content: string): Promise<void> {
  const file = await open(path, 'wx', 0o600);
  try { await file.writeFile(content, 'utf8'); await file.sync(); } finally { await file.close(); }
}

async function readBoundedJson(path: string, maxBytes: number): Promise<unknown> {
  const file = await open(path, 'r');
  try {
    const before = await file.stat();
    if (!before.isFile() || before.nlink !== 1 || before.size <= 0 || before.size > maxBytes) failPlan();
    const bytes = await file.readFile();
    const after = await file.stat();
    if (!sameIdentity(before, after)) failPlan();
    let body: string;
    try { body = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { failPlan(); }
    try { return parseStrictJsonDocument(body); } catch { failPlan(); }
  } finally { await file.close(); }
}

async function simpleTreeDigest(root: string): Promise<string> {
  const names: string[] = [];
  const dir = await opendir(root);
  for await (const item of dir) names.push(`${item.name}:${item.isDirectory() ? 'd' : 'f'}`);
  return sha256(canonicalJson(names.sort(compareText)));
}

async function validateWorkspaceContent(root: string): Promise<void> {
  let entries = 0;
  let bytes = 0;
  const visit = async (directoryPath: string): Promise<void> => {
    const directory = await opendir(directoryPath);
    for await (const item of directory) {
      const path = join(directoryPath, item.name);
      const info = await lstat(path);
      if (++entries > 100_000 || item.name === 'node_modules'
        || (item.name === '.npmrc') || item.name.endsWith('.tgz')
        || info.isSymbolicLink() || (!info.isDirectory() && !info.isFile())) failPlan();
      if (info.isDirectory()) { await visit(path); continue; }
      if (info.nlink !== 1 || (info.mode & 0o111) !== 0) failPlan();
      bytes += info.size;
      if (bytes > 128 * 1024 * 1024) failPlan();
      const file = await open(path, 'r');
      try {
        const magic = Buffer.alloc(Math.min(265, info.size));
        await file.read(magic, 0, magic.length, 0);
        if (magic.subarray(0, 2).equals(Buffer.from([0x1f, 0x8b]))
          || magic.subarray(0, 4).equals(Buffer.from([0x50, 0x4b, 0x03, 0x04]))
          || magic.subarray(257, 262).toString('ascii') === 'ustar') failPlan();
      } finally { await file.close(); }
    }
  };
  await visit(root);
}

function sameIdentity(left: { dev: number; ino: number; size: number; mtimeMs: number; ctimeMs: number }, right: typeof left): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size
    && left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
}

function compareText(left: string, right: string): number {
  return Buffer.from(left).compare(Buffer.from(right));
}

function failPlan(): never { throw new PackageStageError('artifact_plan_invalid'); }
function failApproval(): never { throw new PackageStageError('approval_invalid'); }

function sha256(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

function deepFreeze<T>(input: T): T {
  if (typeof input !== 'object' || input === null || Object.isFrozen(input)) return input;
  for (const value of Object.values(input)) deepFreeze(value);
  return Object.freeze(input);
}
