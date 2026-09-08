import { execFile } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { lstat, mkdir, open, opendir, realpath, rmdir, stat, unlink } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';
import { promisify } from 'node:util';

import { canonicalJson } from '../audit/canonical-json.js';
import type {
  AuthenticatedRuntimeTreeSnapshot,
  GraphGenesisLaunch,
  GraphGenesisLimits,
  GraphGenesisWorkspace,
} from './graph-genesis.js';
import { RuntimeTreeSnapshotAuthority, buildGraphGenesisLaunch } from './graph-genesis.js';
import { validateMetadataBrokerLimits } from './graph-genesis-broker.js';
import type { SeatbeltLoopbackProfile, SeatbeltSelfTestObservations } from './graph-genesis-containment.js';
import { PackageStageError } from './profile.js';

const SHA256 = /^[a-f0-9]{64}$/u;
const EXACT_TARGET_NAME = '@modelcontextprotocol/server-filesystem';
const EXACT_TARGET_VERSION = '2026.7.10';
const execFileAsync = promisify(execFile);
const NODE_RUNTIME_VERSION_EXECUTORS = new WeakSet<object>();
const NODE_HOST_PLATFORM_EXECUTORS = new WeakSet<object>();

export type AuthenticatedRuntimeFileSnapshot = Readonly<{
  snapshotVersion: 1;
  role: 'node' | 'npm_cli' | 'sandbox_exec' | 'broker_runtime' | 'probe_runtime';
  absolutePath: string;
  device: number;
  inode: number;
  owner: number;
  mode: number;
  size: number;
  mtimeMs: number;
  ctimeMs: number;
  sha256: string;
  snapshotDigest: string;
}>;

export class RuntimeFileSnapshotAuthority {
  readonly #authenticated = new WeakSet<object>();

  async capture(role: AuthenticatedRuntimeFileSnapshot['role'], path: string): Promise<AuthenticatedRuntimeFileSnapshot> {
    if (!['node', 'npm_cli', 'sandbox_exec', 'broker_runtime', 'probe_runtime'].includes(role)) failPlan();
    const absolutePath = await realpath(path);
    const file = await open(absolutePath, 'r');
    try {
      const before = await file.stat();
      if (!before.isFile() || before.nlink !== 1 || before.size <= 0 || before.size > 64 * 1024 * 1024
        || (before.mode & 0o002) !== 0) failPlan();
      const digest = createHash('sha256');
      for await (const chunk of file.createReadStream({ autoClose: false })) digest.update(chunk);
      const after = await file.stat();
      if (!sameIdentity(before, after)) failPlan();
      const unsigned = Object.freeze({
        snapshotVersion: 1 as const,
        role,
        absolutePath,
        device: before.dev,
        inode: before.ino,
        owner: before.uid,
        mode: before.mode & 0o7777,
        size: before.size,
        mtimeMs: before.mtimeMs,
        ctimeMs: before.ctimeMs,
        sha256: digest.digest('hex'),
      });
      const snapshot = Object.freeze({ ...unsigned, snapshotDigest: sha256(canonicalJson(unsigned)) });
      this.#authenticated.add(snapshot);
      return snapshot;
    } finally { await file.close(); }
  }

  authenticates(value: unknown, role?: AuthenticatedRuntimeFileSnapshot['role']): value is AuthenticatedRuntimeFileSnapshot {
    return typeof value === 'object' && value !== null && this.#authenticated.has(value)
      && (role === undefined || (value as AuthenticatedRuntimeFileSnapshot).role === role);
  }

  async revalidate(snapshot: AuthenticatedRuntimeFileSnapshot): Promise<void> {
    if (!this.authenticates(snapshot)) failPlan();
    const current = await this.capture(snapshot.role, snapshot.absolutePath);
    if (current.snapshotDigest !== snapshot.snapshotDigest) failPlan();
  }
}

export type RuntimeVersionObservation = Readonly<{
  nodeVersion: string;
  npmVersion: string;
}>;

export interface RuntimeVersionProbeExecutor {
  readonly implementationKind: 'local_observed' | 'synthetic';
  observe(input: Readonly<{
    node: AuthenticatedRuntimeFileSnapshot;
    npmCli: AuthenticatedRuntimeFileSnapshot;
    npmTree: AuthenticatedRuntimeTreeSnapshot;
  }>): Promise<RuntimeVersionObservation>;
}

/** Network-free production adapter. It executes only the already-snapshotted Node binary. */
export class NodeRuntimeVersionProbeExecutor implements RuntimeVersionProbeExecutor {
  readonly implementationKind = 'local_observed' as const;

  constructor() { NODE_RUNTIME_VERSION_EXECUTORS.add(this); }

  async observe(input: Readonly<{
    node: AuthenticatedRuntimeFileSnapshot;
    npmCli: AuthenticatedRuntimeFileSnapshot;
    npmTree: AuthenticatedRuntimeTreeSnapshot;
  }>): Promise<RuntimeVersionObservation> {
    if (!treeContains(input.npmTree, input.npmCli.absolutePath)
      || !treeContains(input.npmTree, join(input.npmTree.rootRealpath, 'package.json'))) failPlan();
    try {
      const options = {
        cwd: input.npmTree.rootRealpath,
        env: { LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8' },
        timeout: 5_000,
        maxBuffer: 1_024,
        windowsHide: true,
      } as const;
      const node = await execFileAsync(input.node.absolutePath, ['--version'], options);
      const npm = await execFileAsync(input.node.absolutePath, [
        '-e',
        "const f=require('node:fs');const p=process.argv[1];process.stdout.write(JSON.parse(f.readFileSync(p,'utf8')).version);",
        join(input.npmTree.rootRealpath, 'package.json'),
      ], options);
      return Object.freeze({
        nodeVersion: String(node.stdout).trim().replace(/^v/u, ''),
        npmVersion: String(npm.stdout).trim(),
      });
    } catch { failPlan(); }
  }
}

export type AuthenticatedRuntimeVersionEvidence = Readonly<{
  evidenceVersion: 1;
  implementationKind: RuntimeVersionProbeExecutor['implementationKind'];
  nodeSnapshotDigest: string;
  npmCliSnapshotDigest: string;
  npmTreeDigest: string;
  nodeVersion: '26.3.1';
  npmVersion: '11.16.0';
  evidenceDigest: string;
}>;

export class OwnedRuntimeVersionAuthority {
  readonly #authenticated = new WeakSet<object>();

  constructor(
    private readonly files: RuntimeFileSnapshotAuthority,
    private readonly trees: RuntimeTreeSnapshotAuthority,
    private readonly executor: RuntimeVersionProbeExecutor,
  ) {
    if (executor.implementationKind === 'local_observed' && !NODE_RUNTIME_VERSION_EXECUTORS.has(executor)) failPlan();
  }

  async observe(input: Readonly<{
    node: AuthenticatedRuntimeFileSnapshot;
    npmCli: AuthenticatedRuntimeFileSnapshot;
    npmTree: AuthenticatedRuntimeTreeSnapshot;
  }>): Promise<AuthenticatedRuntimeVersionEvidence> {
    if (!this.files.authenticates(input.node, 'node') || !this.files.authenticates(input.npmCli, 'npm_cli')
      || !this.trees.authenticates(input.npmTree) || !treeContains(input.npmTree, input.npmCli.absolutePath)) failPlan();
    await this.files.revalidate(input.node);
    await this.files.revalidate(input.npmCli);
    await this.trees.revalidate(input.npmTree);
    const observation = await this.executor.observe(input);
    if (observation.nodeVersion !== '26.3.1' || observation.npmVersion !== '11.16.0') failPlan();
    const unsigned = Object.freeze({
      evidenceVersion: 1 as const,
      implementationKind: this.executor.implementationKind,
      nodeSnapshotDigest: input.node.snapshotDigest,
      npmCliSnapshotDigest: input.npmCli.snapshotDigest,
      npmTreeDigest: input.npmTree.treeDigest,
      nodeVersion: '26.3.1' as const,
      npmVersion: '11.16.0' as const,
    });
    const evidence = Object.freeze({ ...unsigned, evidenceDigest: sha256(canonicalJson(unsigned)) });
    this.#authenticated.add(evidence);
    return evidence;
  }

  authenticates(value: unknown, implementationKind?: RuntimeVersionProbeExecutor['implementationKind']): value is AuthenticatedRuntimeVersionEvidence {
    return typeof value === 'object' && value !== null && this.#authenticated.has(value)
      && (implementationKind === undefined || (value as AuthenticatedRuntimeVersionEvidence).implementationKind === implementationKind);
  }
}

export interface HostPlatformProbeExecutor {
  readonly implementationKind: 'local_observed' | 'synthetic';
  observe(): Promise<Readonly<{ platform: string; architecture: string; osBuild: string; bootSessionId: string }>>;
}

export class NodeHostPlatformProbeExecutor implements HostPlatformProbeExecutor {
  readonly implementationKind = 'local_observed' as const;

  constructor() { NODE_HOST_PLATFORM_EXECUTORS.add(this); }

  async observe(): Promise<Readonly<{ platform: string; architecture: string; osBuild: string; bootSessionId: string }>> {
    try {
      const options = {
        env: { LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8' }, timeout: 5_000, maxBuffer: 1_024, windowsHide: true,
      } as const;
      const build = await execFileAsync('/usr/bin/sw_vers', ['-buildVersion'], options);
      const boot = await execFileAsync('/usr/sbin/sysctl', ['-n', 'kern.bootsessionuuid'], options);
      return Object.freeze({
        platform: process.platform,
        architecture: process.arch,
        osBuild: String(build.stdout).trim(),
        bootSessionId: String(boot.stdout).trim().toLowerCase(),
      });
    } catch { failPlan(); }
  }
}

export type AuthenticatedHostPlatformEvidence = Readonly<{
  evidenceVersion: 1;
  implementationKind: HostPlatformProbeExecutor['implementationKind'];
  platform: 'darwin';
  architecture: 'arm64';
  osBuild: string;
  bootSessionDigest: string;
  evidenceDigest: string;
}>;

export class OwnedHostPlatformAuthority {
  readonly #authenticated = new WeakSet<object>();

  constructor(private readonly executor: HostPlatformProbeExecutor) {
    if (executor.implementationKind === 'local_observed' && !NODE_HOST_PLATFORM_EXECUTORS.has(executor)) failPlan();
  }

  async observe(): Promise<AuthenticatedHostPlatformEvidence> {
    const observed = await this.executor.observe();
    if (observed.platform !== 'darwin' || observed.architecture !== 'arm64' || !isSafeText(observed.osBuild, 128)
      || !/^[a-f0-9-]{36}$/u.test(observed.bootSessionId)) failPlan();
    const unsigned = Object.freeze({
      evidenceVersion: 1 as const,
      implementationKind: this.executor.implementationKind,
      platform: 'darwin' as const,
      architecture: 'arm64' as const,
      osBuild: observed.osBuild,
      bootSessionDigest: sha256(observed.bootSessionId),
    });
    const evidence = Object.freeze({ ...unsigned, evidenceDigest: sha256(canonicalJson(unsigned)) });
    this.#authenticated.add(evidence);
    return evidence;
  }

  authenticates(value: unknown, implementationKind?: HostPlatformProbeExecutor['implementationKind']): value is AuthenticatedHostPlatformEvidence {
    return typeof value === 'object' && value !== null && this.#authenticated.has(value)
      && (implementationKind === undefined || (value as AuthenticatedHostPlatformEvidence).implementationKind === implementationKind);
  }
}

/** Owns the complete initial workspace, including the final containment profile bytes. */
export class FinalizedGraphGenesisWorkspaceAuthority {
  readonly #authenticated = new WeakSet<object>();

  constructor(private readonly trees: RuntimeTreeSnapshotAuthority) {}

  async initialize(root: string, profileText: string): Promise<GraphGenesisWorkspace> {
    if (!root.startsWith('/') || profileText.length === 0 || profileText.length > 64 * 1024
      || /\u0000/u.test(profileText)) failPlan();
    await mkdir(root, { recursive: false, mode: 0o700 });
    const rootRealpath = await realpath(root);
    const rootInfo = await stat(rootRealpath);
    if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink() || (rootInfo.mode & 0o777) !== 0o700) failPlan();
    for (const directory of ['cache', 'logs', 'tmp', 'prefix']) await mkdir(join(rootRealpath, directory), { mode: 0o700 });
    await exclusiveFile(join(rootRealpath, 'package.json'), `${canonicalJson({
      name: 'apg-graph-genesis', version: '0.0.0', private: true,
    })}\n`);
    await exclusiveFile(join(rootRealpath, 'user.npmrc'), '');
    await exclusiveFile(join(rootRealpath, 'global.npmrc'), '');
    await exclusiveFile(join(rootRealpath, 'broker-profile.sb'), profileText);
    const protectedFiles = Object.freeze(await Promise.all(
      ['package.json', 'user.npmrc', 'global.npmrc', 'broker-profile.sb'].map(async (name) => {
        const info = await lstat(join(rootRealpath, name));
        if (!info.isFile() || info.nlink !== 1 || (info.mode & 0o777) !== 0o600) failPlan();
        return Object.freeze({ name, device: info.dev, inode: info.ino, mode: 0o600 as const });
      }),
    ));
    const initial = await this.trees.capture(rootRealpath);
    const workspace = deepFreeze({
      workspaceVersion: 1 as const,
      rootRealpath,
      device: rootInfo.dev,
      inode: rootInfo.ino,
      owner: rootInfo.uid,
      mode: 0o700 as const,
      protectedFiles,
      initialManifestDigest: initial.treeDigest,
    });
    this.#authenticated.add(workspace);
    return workspace;
  }

  authenticates(value: unknown): value is GraphGenesisWorkspace {
    return typeof value === 'object' && value !== null && this.#authenticated.has(value);
  }

  async revalidateInitial(workspace: GraphGenesisWorkspace): Promise<void> {
    if (!this.authenticates(workspace)) failPlan();
    const root = await lstat(workspace.rootRealpath);
    if (!root.isDirectory() || root.isSymbolicLink() || root.dev !== workspace.device || root.ino !== workspace.inode
      || root.uid !== workspace.owner || (root.mode & 0o777) !== workspace.mode) failPlan();
    for (const expected of workspace.protectedFiles) {
      const info = await lstat(join(workspace.rootRealpath, expected.name));
      if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.dev !== expected.device
        || info.ino !== expected.inode || (info.mode & 0o777) !== expected.mode) failPlan();
    }
    const current = await this.trees.capture(workspace.rootRealpath);
    if (current.treeDigest !== workspace.initialManifestDigest) failPlan();
  }
}

export type ContainmentProbeBinding = Readonly<{
  osBuild: string;
  hostEvidenceDigest: string;
  nodeSnapshotDigest: string;
  probeSnapshotDigest: string;
  sandboxExecSnapshotDigest: string;
  workspaceBinding: string;
  profileDigest: string;
  allowedPort: number;
}>;

export interface ContainmentProbeExecutor {
  readonly implementationKind: 'local_observed' | 'synthetic';
  run(
    binding: ContainmentProbeBinding,
    profile: SeatbeltLoopbackProfile,
    runtime: Readonly<{
      node: AuthenticatedRuntimeFileSnapshot;
      probe: AuthenticatedRuntimeFileSnapshot;
      sandboxExec: AuthenticatedRuntimeFileSnapshot;
      workspace: GraphGenesisWorkspace;
    }>,
  ): Promise<SeatbeltSelfTestObservations>;
}

export type AuthenticatedOwnedContainmentEvidence = Readonly<{
  evidenceVersion: 1;
  implementationKind: ContainmentProbeExecutor['implementationKind'];
  binding: ContainmentProbeBinding;
  observations: SeatbeltSelfTestObservations;
  evidenceDigest: string;
}>;

export class OwnedContainmentProbeAuthority {
  readonly #authenticated = new WeakSet<object>();

  constructor(
    private readonly files: RuntimeFileSnapshotAuthority,
    private readonly workspaces: FinalizedGraphGenesisWorkspaceAuthority,
    private readonly executor: ContainmentProbeExecutor,
  ) {}

  async observe(
    binding: ContainmentProbeBinding,
    profile: SeatbeltLoopbackProfile,
    runtime: Readonly<{
      node: AuthenticatedRuntimeFileSnapshot;
      probe: AuthenticatedRuntimeFileSnapshot;
      sandboxExec: AuthenticatedRuntimeFileSnapshot;
      workspace: GraphGenesisWorkspace;
    }>,
  ): Promise<AuthenticatedOwnedContainmentEvidence> {
    assertProbeBinding(binding, profile);
    if (!this.files.authenticates(runtime.node, 'node') || !this.files.authenticates(runtime.probe, 'probe_runtime')
      || !this.files.authenticates(runtime.sandboxExec, 'sandbox_exec') || !this.workspaces.authenticates(runtime.workspace)
      || runtime.node.snapshotDigest !== binding.nodeSnapshotDigest
      || runtime.probe.snapshotDigest !== binding.probeSnapshotDigest
      || runtime.sandboxExec.snapshotDigest !== binding.sandboxExecSnapshotDigest
      || computeWorkspaceBinding(runtime.workspace) !== binding.workspaceBinding) failPlan();
    await this.files.revalidate(runtime.node);
    await this.files.revalidate(runtime.probe);
    await this.files.revalidate(runtime.sandboxExec);
    await this.workspaces.revalidateInitial(runtime.workspace);
    const observations = await this.executor.run(binding, profile, runtime);
    assertContainmentObservations(observations);
    const unsigned = deepFreeze({
      evidenceVersion: 1 as const,
      implementationKind: this.executor.implementationKind,
      binding: { ...binding },
      observations: { ...observations },
    });
    const evidence = deepFreeze({ ...unsigned, evidenceDigest: sha256(canonicalJson(unsigned)) });
    this.#authenticated.add(evidence);
    return evidence;
  }

  authenticates(value: unknown, implementationKind?: ContainmentProbeExecutor['implementationKind']): value is AuthenticatedOwnedContainmentEvidence {
    return typeof value === 'object' && value !== null && this.#authenticated.has(value)
      && (implementationKind === undefined
        || (value as AuthenticatedOwnedContainmentEvidence).implementationKind === implementationKind);
  }
}

export type HardenedGraphGenesisPlan = Readonly<{
  planVersion: 2;
  planId: string;
  targetName: typeof EXACT_TARGET_NAME;
  exactTargetVersion: typeof EXACT_TARGET_VERSION;
  registryOrigin: 'https://registry.npmjs.org/';
  platform: 'darwin';
  architecture: 'arm64';
  osBuild: string;
  nodeVersion: '26.3.1';
  npmVersion: '11.16.0';
  hostEvidenceDigest: string;
  runtimeVersionEvidenceDigest: string;
  runtimeSnapshots: Readonly<{
    node: string;
    npmCli: string;
    sandboxExec: string;
    brokerRuntime: string;
    probeRuntime: string;
    npmTree: string;
    brokerTree: string;
  }>;
  containmentEvidenceDigest: string;
  containmentProfileDigest: string;
  containmentProviderId: 'macos-seatbelt-loopback-development-v0';
  workspaceBinding: string;
  brokerAddress: '127.0.0.1';
  brokerPort: number;
  routeTokenDigest: string;
  privatePathSetDigest: string;
  launchDigest: string;
  environmentDigest: string;
  executionCapsuleDigest: string;
  limits: GraphGenesisLimits;
  consequence: 'bounded_public_metadata_graph_genesis';
  planHash: string;
}>;

export type GraphGenesisPlanProjection = Readonly<{
  planVersion: 2;
  planId: string;
  planHash: string;
  target: `${typeof EXACT_TARGET_NAME}@${typeof EXACT_TARGET_VERSION}`;
  registryOrigin: HardenedGraphGenesisPlan['registryOrigin'];
  host: Readonly<{ platform: 'darwin'; architecture: 'arm64'; osBuild: string }>;
  runtime: Readonly<{ nodeVersion: '26.3.1'; npmVersion: '11.16.0'; containmentProviderId: HardenedGraphGenesisPlan['containmentProviderId'] }>;
  limits: GraphGenesisLimits;
  consequence: HardenedGraphGenesisPlan['consequence'];
  statements: readonly [
    'metadata_only_no_artifact_install_or_package_execution',
    'private_disposable_workspace_writes',
    'development_only_containment',
    'direct_npm_npx_outside_apg_protection',
  ];
}>;

export type AuthenticatedGraphGenesisExecutionCapsule = Readonly<{
  capsuleVersion: 1;
  planId: string;
  routeToken: string;
  launch: GraphGenesisLaunch;
  runtimePaths: Readonly<{
    node: string;
    npmCli: string;
    sandboxExec: string;
    brokerRuntime: string;
    brokerRuntimeRoot: string;
    probeRuntime: string;
    npmTreeRoot: string;
    workspaceRoot: string;
  }>;
  capsuleDigest: string;
}>;

export type PreparedHardenedGraphGenesis = Readonly<{
  plan: HardenedGraphGenesisPlan;
  projection: GraphGenesisPlanProjection;
  capsule: AuthenticatedGraphGenesisExecutionCapsule;
}>;

export class HardenedGraphGenesisPlanAuthority {
  readonly #plans = new WeakSet<object>();
  readonly #capsules = new WeakSet<object>();
  readonly #pairs = new WeakMap<object, object>();
  readonly #bindings = new WeakMap<object, Readonly<{
    files: readonly AuthenticatedRuntimeFileSnapshot[];
    trees: readonly AuthenticatedRuntimeTreeSnapshot[];
    workspace: GraphGenesisWorkspace;
  }>>();

  constructor(
    private readonly files: RuntimeFileSnapshotAuthority,
    private readonly trees: RuntimeTreeSnapshotAuthority,
    private readonly probes: OwnedContainmentProbeAuthority,
    private readonly versions: OwnedRuntimeVersionAuthority,
    private readonly workspaces: FinalizedGraphGenesisWorkspaceAuthority,
    private readonly hosts: OwnedHostPlatformAuthority,
  ) {}

  prepare(input: Readonly<{
    planId?: string;
    host: AuthenticatedHostPlatformEvidence;
    node: AuthenticatedRuntimeFileSnapshot;
    npmCli: AuthenticatedRuntimeFileSnapshot;
    sandboxExec: AuthenticatedRuntimeFileSnapshot;
    brokerRuntime: AuthenticatedRuntimeFileSnapshot;
    probeRuntime: AuthenticatedRuntimeFileSnapshot;
    npmTree: AuthenticatedRuntimeTreeSnapshot;
    brokerTree: AuthenticatedRuntimeTreeSnapshot;
    runtimeVersions: AuthenticatedRuntimeVersionEvidence;
    containmentEvidence: AuthenticatedOwnedContainmentEvidence;
    workspace: GraphGenesisWorkspace;
    brokerPort: number;
    routeToken: string;
    launch: GraphGenesisLaunch;
    limits: GraphGenesisLimits;
    allowSynthetic?: boolean;
  }>): PreparedHardenedGraphGenesis {
    if (!this.files.authenticates(input.node, 'node') || !this.files.authenticates(input.npmCli, 'npm_cli')
      || !this.files.authenticates(input.sandboxExec, 'sandbox_exec')
      || !this.files.authenticates(input.brokerRuntime, 'broker_runtime')
      || !this.files.authenticates(input.probeRuntime, 'probe_runtime')
      || !this.trees.authenticates(input.npmTree)
      || !this.trees.authenticates(input.brokerTree)
      || !treeContains(input.brokerTree, input.brokerRuntime.absolutePath)
      || !this.probes.authenticates(input.containmentEvidence)
      || !this.versions.authenticates(input.runtimeVersions)
      || !this.workspaces.authenticates(input.workspace)
      || !this.hosts.authenticates(input.host)
      || input.runtimeVersions.nodeSnapshotDigest !== input.node.snapshotDigest
      || input.runtimeVersions.npmCliSnapshotDigest !== input.npmCli.snapshotDigest
      || input.runtimeVersions.npmTreeDigest !== input.npmTree.treeDigest
      || (!input.allowSynthetic && input.containmentEvidence.implementationKind !== 'local_observed')) failPlan();
    if (!input.allowSynthetic && input.runtimeVersions.implementationKind !== 'local_observed') failPlan();
    if (!input.allowSynthetic && input.host.implementationKind !== 'local_observed') failPlan();
    const workspaceBinding = computeWorkspaceBinding(input.workspace);
    if (!/^[a-f0-9]{32}$/u.test(input.routeToken)
      || input.brokerPort !== input.containmentEvidence.binding.allowedPort
      || input.host.osBuild !== input.containmentEvidence.binding.osBuild
      || input.host.evidenceDigest !== input.containmentEvidence.binding.hostEvidenceDigest
      || input.node.snapshotDigest !== input.containmentEvidence.binding.nodeSnapshotDigest
      || input.probeRuntime.snapshotDigest !== input.containmentEvidence.binding.probeSnapshotDigest
      || input.sandboxExec.snapshotDigest !== input.containmentEvidence.binding.sandboxExecSnapshotDigest
      || workspaceBinding !== input.containmentEvidence.binding.workspaceBinding
      || input.launch.cwd !== input.workspace.rootRealpath
      || input.launch.executable !== input.sandboxExec.absolutePath) failPlan();
    const expectedLaunch = buildGraphGenesisLaunch({
      sandboxExecPath: input.sandboxExec.absolutePath,
      profilePath: join(input.workspace.rootRealpath, 'broker-profile.sb'),
      nodePath: input.node.absolutePath,
      npmCliPath: input.npmCli.absolutePath,
      npmRuntimeRoot: input.npmTree.rootRealpath,
      workspaceRoot: input.workspace.rootRealpath,
      brokerPort: input.brokerPort,
      routeToken: input.routeToken,
    });
    if (canonicalJson(expectedLaunch) !== canonicalJson(input.launch)) failPlan();
    validateMetadataBrokerLimits(input.limits.broker);
    assertGraphGenesisLimits(input.limits);
    const planId = input.planId ?? randomBytes(16).toString('hex');
    if (!/^[a-f0-9]{32}$/u.test(planId)) failPlan();
    const runtimePaths = deepFreeze({
      node: input.node.absolutePath,
      npmCli: input.npmCli.absolutePath,
      sandboxExec: input.sandboxExec.absolutePath,
      brokerRuntime: input.brokerRuntime.absolutePath,
      brokerRuntimeRoot: input.brokerTree.rootRealpath,
      probeRuntime: input.probeRuntime.absolutePath,
      npmTreeRoot: input.npmTree.rootRealpath,
      workspaceRoot: input.workspace.rootRealpath,
    });
    const privatePathSetDigest = sha256(canonicalJson(runtimePaths));
    const environmentDigest = sha256(canonicalJson(input.launch.env));
    const capsuleUnsigned = deepFreeze({
      capsuleVersion: 1 as const,
      planId,
      routeToken: input.routeToken,
      launch: input.launch,
      runtimePaths,
    });
    const capsule = deepFreeze({ ...capsuleUnsigned, capsuleDigest: sha256(canonicalJson(capsuleUnsigned)) });
    const unsigned = deepFreeze({
      planVersion: 2 as const,
      planId,
      targetName: EXACT_TARGET_NAME as typeof EXACT_TARGET_NAME,
      exactTargetVersion: EXACT_TARGET_VERSION as typeof EXACT_TARGET_VERSION,
      registryOrigin: 'https://registry.npmjs.org/' as const,
      platform: 'darwin' as const,
      architecture: 'arm64' as const,
      osBuild: input.host.osBuild,
      nodeVersion: '26.3.1' as const,
      npmVersion: '11.16.0' as const,
      hostEvidenceDigest: input.host.evidenceDigest,
      runtimeVersionEvidenceDigest: input.runtimeVersions.evidenceDigest,
      runtimeSnapshots: {
        node: input.node.snapshotDigest,
        npmCli: input.npmCli.snapshotDigest,
        sandboxExec: input.sandboxExec.snapshotDigest,
        brokerRuntime: input.brokerRuntime.snapshotDigest,
        probeRuntime: input.probeRuntime.snapshotDigest,
        npmTree: input.npmTree.treeDigest,
        brokerTree: input.brokerTree.treeDigest,
      },
      containmentEvidenceDigest: input.containmentEvidence.evidenceDigest,
      containmentProfileDigest: input.containmentEvidence.binding.profileDigest,
      containmentProviderId: 'macos-seatbelt-loopback-development-v0' as const,
      workspaceBinding,
      brokerAddress: '127.0.0.1' as const,
      brokerPort: input.brokerPort,
      routeTokenDigest: sha256(input.routeToken),
      privatePathSetDigest,
      launchDigest: input.launch.launchDigest,
      environmentDigest,
      executionCapsuleDigest: capsule.capsuleDigest,
      limits: {
        broker: { ...input.limits.broker },
        completeTimeoutMs: input.limits.completeTimeoutMs,
        stdoutBytes: input.limits.stdoutBytes,
        stderrBytes: input.limits.stderrBytes,
        packageJsonBytes: input.limits.packageJsonBytes,
        packageLockBytes: input.limits.packageLockBytes,
      },
      consequence: 'bounded_public_metadata_graph_genesis' as const,
    });
    const plan = deepFreeze({ ...unsigned, planHash: sha256(canonicalJson(unsigned)) });
    const projection = projectPlan(plan);
    this.#plans.add(plan);
    this.#capsules.add(capsule);
    this.#pairs.set(capsule, plan);
    this.#bindings.set(capsule, Object.freeze({
      files: Object.freeze([input.node, input.npmCli, input.sandboxExec, input.brokerRuntime, input.probeRuntime]),
      trees: Object.freeze([input.npmTree, input.brokerTree]),
      workspace: input.workspace,
    }));
    return Object.freeze({ plan, projection, capsule });
  }

  authenticatesPlan(value: unknown): value is HardenedGraphGenesisPlan {
    return typeof value === 'object' && value !== null && this.#plans.has(value);
  }

  authenticatesPair(plan: unknown, capsule: unknown): plan is HardenedGraphGenesisPlan {
    return this.authenticatesPlan(plan) && typeof capsule === 'object' && capsule !== null
      && this.#capsules.has(capsule) && this.#pairs.get(capsule) === plan;
  }

  async revalidatePair(plan: HardenedGraphGenesisPlan, capsule: AuthenticatedGraphGenesisExecutionCapsule): Promise<void> {
    if (!this.authenticatesPair(plan, capsule)) failPlan();
    const binding = this.#bindings.get(capsule);
    if (binding === undefined) failPlan();
    for (const file of binding.files) await this.files.revalidate(file);
    for (const tree of binding.trees) await this.trees.revalidate(tree);
    await this.workspaces.revalidateInitial(binding.workspace);
  }
}

export interface HardenedGraphGenesisAuthorizationVerifier {
  authenticatesAuthorization(value: unknown): value is HardenedGraphGenesisAuthorization;
}

export type HardenedGraphGenesisAuthorization = Readonly<{
  authorizationVersion: 1;
  implementationKind: 'production' | 'synthetic';
  planHash: string;
  approvalId: string;
  expiresAt: string;
  authorizationDigest: string;
}>;

export class SyntheticHardenedGraphGenesisApprovalAuthority implements HardenedGraphGenesisAuthorizationVerifier {
  readonly #authorized = new WeakSet<object>();
  readonly #consumedPlans = new Set<string>();

  constructor(private readonly plans: HardenedGraphGenesisPlanAuthority) {}

  authorizeForTest(plan: HardenedGraphGenesisPlan, expiresAt: string, now = new Date()): HardenedGraphGenesisAuthorization {
    if (!this.plans.authenticatesPlan(plan) || this.#consumedPlans.has(plan.planHash)
      || !Number.isFinite(Date.parse(expiresAt)) || Date.parse(expiresAt) <= now.getTime()) failApproval();
    this.#consumedPlans.add(plan.planHash);
    const unsigned = Object.freeze({
      authorizationVersion: 1 as const,
      implementationKind: 'synthetic' as const,
      planHash: plan.planHash,
      approvalId: randomBytes(16).toString('hex'),
      expiresAt,
    });
    const authorization = Object.freeze({ ...unsigned, authorizationDigest: sha256(canonicalJson(unsigned)) });
    this.#authorized.add(authorization);
    return authorization;
  }

  authenticatesAuthorization(value: unknown): value is HardenedGraphGenesisAuthorization {
    return typeof value === 'object' && value !== null && this.#authorized.has(value);
  }
}

export type GraphGenesisAuditEventName =
  | 'authorization_finalized'
  | 'broker_armed'
  | 'npm_spawn_intent_recorded'
  | 'npm_spawn_started'
  | 'metadata_request_started'
  | 'metadata_response_validated'
  | 'npm_terminal_observed'
  | 'lock_validation_started'
  | 'candidate_compiled'
  | 'cleanup_complete'
  | 'cleanup_incomplete'
  | 'genesis_complete'
  | 'genesis_incomplete';

export interface GraphGenesisDurableAuditSink {
  readonly implementationKind: 'production' | 'synthetic';
  append(event: GraphGenesisAuditEventName, safePayload: Readonly<Record<string, string | number | boolean>>): Promise<void>;
}

export class GraphGenesisAuditGate {
  readonly #events: GraphGenesisAuditEventName[] = [];
  readonly #records: Array<Readonly<{ event: GraphGenesisAuditEventName; payload: Readonly<Record<string, string | number | boolean>> }>> = [];
  readonly #completions = new WeakSet<object>();
  #terminal = false;

  constructor(
    readonly planHash: string,
    private readonly sink: GraphGenesisDurableAuditSink,
  ) {
    if (!SHA256.test(planHash)) failPlan();
  }

  async record(event: GraphGenesisAuditEventName, payload: Readonly<Record<string, string | number | boolean>> = {}): Promise<void> {
    if (this.#terminal) failAudit();
    assertAuditPayload(event, payload);
    try {
      await this.sink.append(event, Object.freeze({ ...payload, planHash: this.planHash }));
    } catch { failAudit(); }
    this.#events.push(event);
    this.#records.push(deepFreeze({ event, payload: { ...payload } }));
    if (event === 'genesis_complete' || event === 'genesis_incomplete') this.#terminal = true;
  }

  async finalizeSuccess(): Promise<AuthenticatedHardenedGraphGenesisTerminalAudit> {
    assertCompleteAudit(this.#records);
    await this.record('genesis_complete');
    const unsigned = Object.freeze({
      auditVersion: 2 as const,
      planHash: this.planHash,
      eventCount: this.#records.length,
      eventsDigest: sha256(canonicalJson(this.#records)),
      terminalState: 'genesis_complete' as const,
    });
    const completion = Object.freeze({ ...unsigned, auditDigest: sha256(canonicalJson(unsigned)) });
    this.#completions.add(completion);
    return completion;
  }

  authenticatesCompletion(value: unknown): value is AuthenticatedHardenedGraphGenesisTerminalAudit {
    return typeof value === 'object' && value !== null && this.#completions.has(value);
  }

  get events(): readonly GraphGenesisAuditEventName[] { return Object.freeze([...this.#events]); }
  get implementationKind(): GraphGenesisDurableAuditSink['implementationKind'] { return this.sink.implementationKind; }
}

export type AuthenticatedHardenedGraphGenesisTerminalAudit = Readonly<{
  auditVersion: 2;
  planHash: string;
  eventCount: number;
  eventsDigest: string;
  terminalState: 'genesis_complete';
  auditDigest: string;
}>;

export type AuthenticatedExactCleanup = Readonly<{
  cleanupVersion: 1;
  workspaceBinding: string;
  removedEntryCount: number;
  cleanupDigest: string;
}>;

export class NoFollowWorkspaceCleanupAuthority {
  readonly #authenticated = new WeakSet<object>();

  constructor(private readonly workspaces: FinalizedGraphGenesisWorkspaceAuthority) {}

  async cleanup(workspace: GraphGenesisWorkspace, workspaceBinding: string): Promise<AuthenticatedExactCleanup> {
    if (!this.workspaces.authenticates(workspace) || !SHA256.test(workspaceBinding)
      || workspaceBinding !== computeWorkspaceBinding(workspace)) failCleanup();
    const root = await lstat(workspace.rootRealpath);
    if (!root.isDirectory() || root.isSymbolicLink() || root.dev !== workspace.device || root.ino !== workspace.inode) failCleanup();
    const files: string[] = [];
    const directories: string[] = [];
    const visit = async (directory: string): Promise<void> => {
      const handle = await opendir(directory);
      for await (const item of handle) {
        const path = join(directory, item.name);
        const rel = relative(workspace.rootRealpath, path);
        if (rel.startsWith(`..${sep}`) || rel === '..') failCleanup();
        const info = await lstat(path);
        if (info.isSymbolicLink() || (!info.isFile() && !info.isDirectory()) || (info.isFile() && info.nlink !== 1)) failCleanup();
        if (info.isDirectory()) { await visit(path); directories.push(path); } else files.push(path);
        if (files.length + directories.length > 100_000) failCleanup();
      }
    };
    await visit(workspace.rootRealpath);
    for (const file of files) await unlink(file);
    for (const directory of directories) await rmdir(directory);
    await rmdir(workspace.rootRealpath);
    const unsigned = Object.freeze({ cleanupVersion: 1 as const, workspaceBinding, removedEntryCount: files.length + directories.length + 1 });
    const evidence = Object.freeze({ ...unsigned, cleanupDigest: sha256(canonicalJson(unsigned)) });
    this.#authenticated.add(evidence);
    return evidence;
  }

  authenticates(value: unknown): value is AuthenticatedExactCleanup {
    return typeof value === 'object' && value !== null && this.#authenticated.has(value);
  }
}

function projectPlan(plan: HardenedGraphGenesisPlan): GraphGenesisPlanProjection {
  return deepFreeze({
    planVersion: plan.planVersion,
    planId: plan.planId,
    planHash: plan.planHash,
    target: `${plan.targetName}@${plan.exactTargetVersion}` as const,
    registryOrigin: plan.registryOrigin,
    host: { platform: plan.platform, architecture: plan.architecture, osBuild: plan.osBuild },
    runtime: { nodeVersion: plan.nodeVersion, npmVersion: plan.npmVersion, containmentProviderId: plan.containmentProviderId },
    limits: plan.limits,
    consequence: plan.consequence,
    statements: [
      'metadata_only_no_artifact_install_or_package_execution',
      'private_disposable_workspace_writes',
      'development_only_containment',
      'direct_npm_npx_outside_apg_protection',
    ] as const,
  });
}

async function exclusiveFile(path: string, content: string): Promise<void> {
  const file = await open(path, 'wx', 0o600);
  try { await file.writeFile(content, 'utf8'); await file.sync(); } finally { await file.close(); }
}

export function computeWorkspaceBinding(workspace: GraphGenesisWorkspace): string {
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

function assertProbeBinding(binding: ContainmentProbeBinding, profile: SeatbeltLoopbackProfile): void {
  if (!isSafeText(binding.osBuild, 128) || !Number.isSafeInteger(binding.allowedPort)
    || binding.allowedPort < 1024 || binding.allowedPort > 65535
    || !SHA256.test(binding.nodeSnapshotDigest) || !SHA256.test(binding.probeSnapshotDigest)
    || !SHA256.test(binding.hostEvidenceDigest)
    || !SHA256.test(binding.sandboxExecSnapshotDigest) || !SHA256.test(binding.workspaceBinding)
    || binding.profileDigest !== profile.profileDigest || binding.allowedPort !== profile.allowedPort
    || binding.osBuild !== profile.osBuild) failPlan();
}

function assertContainmentObservations(value: SeatbeltSelfTestObservations): void {
  if (!value.approvedLoopbackPortConnected || !value.alternateLoopbackPortDenied
    || !value.nonLoopbackLocalAddressDenied || !value.ipv6LoopbackDenied
    || !value.outsideWorkspaceWriteDenied || !value.childProcessDenied
    || !value.workerThreadDenied || !value.addonGrantAbsent || value.publicNetworkAttempted !== false) failPlan();
}

function assertGraphGenesisLimits(limits: GraphGenesisLimits): void {
  if (!Number.isSafeInteger(limits.completeTimeoutMs) || limits.completeTimeoutMs < 1 || limits.completeTimeoutMs > 120_000
    || !Number.isSafeInteger(limits.stdoutBytes) || limits.stdoutBytes < 1 || limits.stdoutBytes > 256 * 1024
    || !Number.isSafeInteger(limits.stderrBytes) || limits.stderrBytes < 1 || limits.stderrBytes > 256 * 1024
    || !Number.isSafeInteger(limits.packageJsonBytes) || limits.packageJsonBytes < 1 || limits.packageJsonBytes > 4 * 1024 * 1024
    || !Number.isSafeInteger(limits.packageLockBytes) || limits.packageLockBytes < 1 || limits.packageLockBytes > 4 * 1024 * 1024) failPlan();
}

function assertCompleteAudit(records: readonly Readonly<{
  event: GraphGenesisAuditEventName;
  payload: Readonly<Record<string, string | number | boolean>>;
}>[]): void {
  const required = [
    'authorization_finalized', 'broker_armed', 'npm_spawn_intent_recorded', 'npm_spawn_started',
    'npm_terminal_observed', 'lock_validation_started', 'candidate_compiled', 'cleanup_complete',
  ] as const;
  let previous = -1;
  for (const event of required) {
    const index = records.findIndex((record) => record.event === event);
    if (index <= previous || records.filter((record) => record.event === event).length !== 1) failAudit();
    previous = index;
  }
  if (records.some((record) => record.event === 'genesis_incomplete' || record.event === 'cleanup_incomplete'
    || record.event === 'genesis_complete')) failAudit();
  const terminal = records.find((record) => record.event === 'npm_terminal_observed');
  if (terminal?.payload.status !== 'completed' || terminal.payload.exitCode !== 0) failAudit();
  const spawnStartedIndex = records.findIndex((record) => record.event === 'npm_spawn_started');
  const terminalIndex = records.findIndex((record) => record.event === 'npm_terminal_observed');
  const started = new Map<number, string>();
  const completed = new Set<number>();
  for (const [index, record] of records.entries()) {
    if (record.event === 'metadata_request_started') {
      const sequence = record.payload.sequence;
      const packageName = record.payload.packageName;
      if (!Number.isSafeInteger(sequence) || typeof packageName !== 'string' || started.has(sequence as number)
        || index <= spawnStartedIndex || index >= terminalIndex) failAudit();
      started.set(sequence as number, packageName);
    } else if (record.event === 'metadata_response_validated') {
      const sequence = record.payload.sequence;
      const packageName = record.payload.packageName;
      const requestIndex = records.findIndex((candidate) => candidate.event === 'metadata_request_started'
        && candidate.payload.sequence === sequence && candidate.payload.packageName === packageName);
      if (!Number.isSafeInteger(sequence) || requestIndex < 0 || requestIndex >= index || index >= terminalIndex
        || completed.has(sequence as number)) failAudit();
      completed.add(sequence as number);
    }
  }
  if (started.size === 0 || completed.size !== started.size) failAudit();
}

function assertAuditPayload(
  event: GraphGenesisAuditEventName,
  payload: Readonly<Record<string, string | number | boolean>>,
): void {
  const keys = Object.keys(payload).sort();
  const exactKeys: Partial<Record<GraphGenesisAuditEventName, readonly string[]>> = {
    metadata_request_started: ['packageName', 'sequence'],
    metadata_response_validated: ['packageName', 'responseBytes', 'sequence'],
    npm_terminal_observed: ['exitCode', 'status', 'stderrBytes', 'stdoutBytes'],
    genesis_incomplete: ['externalReadMayHaveOccurred'],
  };
  const expected = [...(exactKeys[event] ?? [])].sort();
  if (canonicalJson(keys) !== canonicalJson(expected)) failAudit();
  if (event === 'metadata_request_started' || event === 'metadata_response_validated') {
    if (!Number.isSafeInteger(payload.sequence) || (payload.sequence as number) < 1
      || typeof payload.packageName !== 'string' || payload.packageName.length > 256
      || /[\u0000-\u001f\u007f]/u.test(payload.packageName)) failAudit();
  }
  if (event === 'metadata_response_validated'
    && (!Number.isSafeInteger(payload.responseBytes) || (payload.responseBytes as number) < 1
      || (payload.responseBytes as number) > 8 * 1024 * 1024)) failAudit();
  if (event === 'npm_terminal_observed') {
    if (!['completed', 'failed', 'timed_out', 'cancelled', 'output_overflow'].includes(String(payload.status))
      || !Number.isSafeInteger(payload.exitCode) || (payload.exitCode as number) < -1 || (payload.exitCode as number) > 255
      || !Number.isSafeInteger(payload.stdoutBytes) || (payload.stdoutBytes as number) < 0 || (payload.stdoutBytes as number) > 256 * 1024
      || !Number.isSafeInteger(payload.stderrBytes) || (payload.stderrBytes as number) < 0 || (payload.stderrBytes as number) > 256 * 1024) failAudit();
  }
  if (event === 'genesis_incomplete' && typeof payload.externalReadMayHaveOccurred !== 'boolean') failAudit();
}

function sameIdentity(left: { dev: number; ino: number; size: number; mtimeMs: number; ctimeMs: number }, right: typeof left): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size
    && left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
}

function treeContains(snapshot: AuthenticatedRuntimeTreeSnapshot, absolutePath: string): boolean {
  const rel = relative(snapshot.rootRealpath, absolutePath).split(sep).join('/');
  return rel !== '' && !rel.startsWith('../')
    && snapshot.entries.some((entry) => entry.type === 'file' && entry.relativePath === rel);
}

function isSafeText(value: unknown, max: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max && !/[\u0000-\u001f\u007f]/u.test(value);
}

function failPlan(): never { throw new PackageStageError('artifact_plan_invalid'); }
function failApproval(): never { throw new PackageStageError('approval_invalid'); }
function failAudit(): never { throw new PackageStageError('stage_audit_incomplete'); }
function failCleanup(): never { throw new PackageStageError('artifact_cleanup_incomplete'); }

function sha256(value: string | Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
}

function deepFreeze<T>(input: T): T {
  if (typeof input !== 'object' || input === null || Object.isFrozen(input)) return input;
  for (const value of Object.values(input)) deepFreeze(value);
  return Object.freeze(input);
}
