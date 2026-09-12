import { randomUUID } from 'node:crypto';
import { access, chmod, mkdir, mkdtemp, readFile, realpath, rename, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { performance } from 'node:perf_hooks';
import { dirname, join } from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../src/dashboard/server.js', () => ({ startDashboard: vi.fn() }));

import { SqliteAuditRecorder } from '../../src/audit/recorder.js';
import { openAuditDatabase, openExistingGraphGenesisAuditDatabase } from '../../src/db/database.js';
import { startDashboard, type DashboardHandle } from '../../src/dashboard/server.js';
import { RuntimeTreeSnapshotAuthority } from '../../src/stage/graph-genesis.js';
import { LocalSeatbeltContainmentProbeExecutor } from '../../src/stage/graph-genesis-containment-runner.js';
import {
  SeatbeltLoopbackContainmentAuthority,
  type SeatbeltSelfTestObservations,
} from '../../src/stage/graph-genesis-containment.js';
import {
  FinalizedGraphGenesisWorkspaceAuthority,
  NodeHostPlatformProbeExecutor,
  NodeRuntimeVersionProbeExecutor,
  OwnedContainmentProbeAuthority,
  OwnedHostPlatformAuthority,
  OwnedRuntimeVersionAuthority,
  RuntimeFileSnapshotAuthority,
  computeWorkspaceBinding,
} from '../../src/stage/graph-genesis-hardening.js';
import {
  ProductionGraphGenesisV2SnapshotAuthority,
  ProductionGraphGenesisV2SessionAuthority,
  type AuthenticatedGraphGenesisV2ProductionSnapshot,
  type GraphGenesisV2ConcreteProductionBundle,
} from '../../src/stage/graph-genesis-v2-production.js';
import * as productionModule from '../../src/stage/graph-genesis-v2-production.js';
import { GRAPH_GENESIS_POLICY, ProductionGraphGenesisSessionAuthority } from '../../src/stage/graph-genesis-composition.js';
import { GRAPH_GENESIS_V2_POLICY, GRAPH_GENESIS_V2_POLICY_DIGEST } from '../../src/stage/graph-genesis-v2-binding.js';

const INVALID = 'graph_genesis_v2_production_invalid';
const describeMac = process.platform === 'darwin' ? describe : describe.skip;
const testRoots: string[] = [];
const cleanupActions: Array<() => Promise<void>> = [];
const openedAuditSources: ReturnType<typeof openExistingGraphGenesisAuditDatabase>[] = [];
const successfulContainment = Object.freeze({
  approvedLoopbackPortConnected: true,
  alternateLoopbackPortDenied: true,
  nonLoopbackLocalAddressDenied: true,
  ipv6LoopbackDenied: true,
  outsideWorkspaceWriteDenied: true,
  childProcessDenied: true,
  workerThreadDenied: true,
  addonGrantAbsent: true,
  publicNetworkAttempted: false,
} satisfies SeatbeltSelfTestObservations);

afterEach(async () => {
  vi.useRealTimers();
  await Promise.all(cleanupActions.splice(0).map((cleanup) => cleanup()));
  for (const source of openedAuditSources.splice(0)) {
    try {
      source.database.close();
    } catch {
      // A test may deliberately close it first.
    }
  }
  await Promise.all(testRoots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
  vi.restoreAllMocks();
});

async function writeFixture(path: string, contents: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, contents, { mode: 0o600 });
  await chmod(path, 0o600);
}

async function createFixture() {
  const createdRoot = await mkdtemp(join(tmpdir(), 'apg-v2-production-'));
  const root = await realpath(createdRoot);
  testRoots.push(root);
  await chmod(root, 0o700);

  const toolRoot = join(root, 'tools');
  const npmRoot = join(root, 'npm');
  const repositoryRoot = join(root, 'repository');
  const sqliteRoot = join(root, 'better-sqlite3');
  const paths = {
    node: join(toolRoot, 'node'),
    npmCli: join(npmRoot, 'bin', 'npm-cli.js'),
    sandboxExec: join(toolRoot, 'sandbox-exec'),
    brokerRuntime: join(repositoryRoot, 'dist', 'src', 'stage', 'graph-genesis-live.js'),
    probeRuntime: join(repositoryRoot, 'dist', 'src', 'stage', 'graph-genesis-containment-probe.js'),
    sqlitePackage: join(sqliteRoot, 'package.json'),
    sqliteNative: join(sqliteRoot, 'prebuilds', 'darwin-arm64.node'),
    repositoryPackageJson: join(repositoryRoot, 'package.json'),
    repositoryPackageLock: join(repositoryRoot, 'package-lock.json'),
    npmPackage: join(npmRoot, 'package.json'),
    sqliteLibrary: join(sqliteRoot, 'lib', 'database.js'),
    migration: join(repositoryRoot, 'migrations', '001.sql'),
    webAsset: join(repositoryRoot, 'web', 'app.js'),
  };
  for (const [name, path] of Object.entries(paths)) {
    await writeFixture(path, `${name}\n`);
  }

  const files = new RuntimeFileSnapshotAuthority();
  const trees = new RuntimeTreeSnapshotAuthority();
  const fileSnapshots = {
    node: await files.capture('node', paths.node),
    npmCli: await files.capture('npm_cli', paths.npmCli),
    sandboxExec: await files.capture('sandbox_exec', paths.sandboxExec),
    brokerRuntime: await files.capture('broker_runtime', paths.brokerRuntime),
    probeRuntime: await files.capture('probe_runtime', paths.probeRuntime),
    sqlitePackage: await files.capture('broker_runtime', paths.sqlitePackage),
    sqliteNative: await files.capture('broker_runtime', paths.sqliteNative),
    repositoryPackageJson: await files.capture('broker_runtime', paths.repositoryPackageJson),
    repositoryPackageLock: await files.capture('broker_runtime', paths.repositoryPackageLock),
    swVers: await files.capture('broker_runtime', '/usr/bin/sw_vers'),
    sysctl: await files.capture('broker_runtime', '/usr/sbin/sysctl'),
  };
  const treeSnapshots = {
    npmTree: await trees.capture(npmRoot),
    distRuntimeTree: await trees.capture(join(repositoryRoot, 'dist', 'src')),
    sqliteLib: await trees.capture(join(sqliteRoot, 'lib')),
    migrations: await trees.capture(join(repositoryRoot, 'migrations')),
    webAssets: await trees.capture(join(repositoryRoot, 'web')),
  };

  // Synthetic observation coverage is isolated at concrete executor methods. All file/tree/workspace
  // captures and every authority ownership check remain the real production implementation.
  const hostExecutor = new NodeHostPlatformProbeExecutor();
  const hostObservation = Object.freeze({
    platform: 'darwin',
    architecture: 'arm64',
    osBuild: '25A1',
    bootSessionId: '12345678-1234-4123-8123-123456789abc',
  });
  const hostExecutorSpy = vi.spyOn(hostExecutor, 'observe').mockResolvedValue(hostObservation);
  const hosts = new OwnedHostPlatformAuthority(hostExecutor);
  const host = await hosts.observe();

  const versionExecutor = new NodeRuntimeVersionProbeExecutor();
  const versionExecutorSpy = vi.spyOn(versionExecutor, 'observe').mockResolvedValue(Object.freeze({
    nodeVersion: '26.3.1',
    npmVersion: '11.16.0',
  }));
  const versions = new OwnedRuntimeVersionAuthority(files, trees, versionExecutor);
  const runtimeVersions = await versions.observe({
    node: fileSnapshots.node,
    npmCli: fileSnapshots.npmCli,
    npmTree: treeSnapshots.npmTree,
  });

  const profiles = new SeatbeltLoopbackContainmentAuthority();
  const containmentProfile = profiles.prepare({
    osBuild: host.osBuild,
    sandboxExecSha256: fileSnapshots.sandboxExec.sha256,
    allowedPort: 43121,
  });
  const workspaces = new FinalizedGraphGenesisWorkspaceAuthority(trees);
  const workspace = await workspaces.initialize(join(root, 'workspace'), containmentProfile.profileText);
  const containmentExecutor = new LocalSeatbeltContainmentProbeExecutor();
  const containmentExecutorSpy = vi.spyOn(containmentExecutor, 'run').mockResolvedValue(successfulContainment);
  const containments = new OwnedContainmentProbeAuthority(files, workspaces, containmentExecutor);
  const containment = await containments.observe({
    osBuild: host.osBuild,
    hostEvidenceDigest: host.evidenceDigest,
    nodeSnapshotDigest: fileSnapshots.node.snapshotDigest,
    probeSnapshotDigest: fileSnapshots.probeRuntime.snapshotDigest,
    sandboxExecSnapshotDigest: fileSnapshots.sandboxExec.snapshotDigest,
    workspaceBinding: computeWorkspaceBinding(workspace),
    profileDigest: containmentProfile.profileDigest,
    allowedPort: containmentProfile.allowedPort,
  }, containmentProfile, {
    node: fileSnapshots.node,
    probe: fileSnapshots.probeRuntime,
    sandboxExec: fileSnapshots.sandboxExec,
    workspace,
  });

  const production = new ProductionGraphGenesisV2SnapshotAuthority(
    files,
    trees,
    versions,
    hosts,
    workspaces,
    containments,
    profiles,
  );
  const bundle: GraphGenesisV2ConcreteProductionBundle = {
    files: { ...fileSnapshots },
    trees: { ...treeSnapshots },
    runtimeVersions,
    host,
    workspace,
    containmentProfile,
    containment,
  };
  const snapshot = production.prepare(bundle);

  return {
    root,
    paths,
    files,
    trees,
    versions,
    hosts,
    workspaces,
    containments,
    profiles,
    hostExecutorSpy,
    versionExecutorSpy,
    containmentExecutorSpy,
    bundle,
    snapshot,
    production,
  };
}

type Fixture = Awaited<ReturnType<typeof createFixture>>;

function revalidationOptions(signal?: AbortSignal) {
  let now = 0;
  return {
    ...(signal === undefined ? {} : { signal }),
    monotonicNow: () => ++now,
    deadline: 10_000,
  };
}

function copiedBundle(fixture: Fixture): GraphGenesisV2ConcreteProductionBundle {
  return {
    files: { ...fixture.bundle.files },
    trees: { ...fixture.bundle.trees },
    runtimeVersions: fixture.bundle.runtimeVersions,
    host: fixture.bundle.host,
    workspace: fixture.bundle.workspace,
    containmentProfile: fixture.bundle.containmentProfile,
    containment: fixture.bundle.containment,
  };
}

type DashboardStart = Readonly<{
  options: Parameters<typeof startDashboard>[0];
  handle: DashboardHandle;
  close: ReturnType<typeof vi.fn>;
}>;

function installDashboardMock(ports: readonly number[] = [48_101]): DashboardStart[] {
  const starts: DashboardStart[] = [];
  vi.mocked(startDashboard).mockImplementation(async (options) => {
    const port = ports[starts.length] ?? 48_101 + starts.length;
    const close = vi.fn(async () => {});
    const handle = Object.freeze({
      url: `http://127.0.0.1:${port}/#token=${encodeURIComponent(options.token)}`,
      instanceId: randomUUID(),
      close,
      bindGraphAction: vi.fn(),
    });
    starts.push(Object.freeze({ options, handle, close }));
    return handle;
  });
  return starts;
}

async function createAuditSource(root: string) {
  const parent = join(root, 'audit-source');
  await mkdir(parent, { mode: 0o700 });
  const path = join(parent, 'audit.sqlite');
  const created = openAuditDatabase(path);
  created.close();
  await chmod(path, 0o600);
  const source = openExistingGraphGenesisAuditDatabase(path);
  openedAuditSources.push(source);
  return source;
}

async function createPreparationFixture() {
  const snapshotFixture = await createFixture();
  const dashboardStarts = installDashboardMock();
  const source = await createAuditSource(snapshotFixture.root);
  const sessions = new ProductionGraphGenesisV2SessionAuthority(snapshotFixture.production);
  const context = await sessions.createContext(source);
  const outputParent = join(snapshotFixture.root, 'output');
  await mkdir(outputParent, { mode: 0o700 });
  const outputPath = join(outputParent, 'candidate.json');
  const output = await sessions.captureOutputIntent(context, outputPath);
  cleanupActions.push(async () => {
    try {
      await sessions.closeContext(context);
    } catch {
      // A test may deliberately revoke the context first.
    }
  });
  return {
    ...snapshotFixture,
    dashboardStarts,
    source,
    sessions,
    context,
    output,
    outputParent,
    outputPath,
  };
}

type PreparationFixture = Awaited<ReturnType<typeof createPreparationFixture>>;

function databaseCounts(fixture: PreparationFixture) {
  return Object.freeze({
    toolCalls: Number(fixture.source.database.prepare('SELECT COUNT(*) AS count FROM tool_calls').pluck().get()),
    approvals: Number(fixture.source.database.prepare('SELECT COUNT(*) AS count FROM approvals').pluck().get()),
    auditEvents: Number(fixture.source.database.prepare('SELECT COUNT(*) AS count FROM audit_events').pluck().get()),
  });
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

function dashboardApprovals(fixture: PreparationFixture) {
  return fixture.dashboardStarts[0]!.options.approvals;
}

async function waitForGraphApproval(fixture: PreparationFixture) {
  const approvals = dashboardApprovals(fixture);
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const pending = approvals.listPending();
    if (pending.length === 1) return pending[0]!;
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
  throw new Error('Graph approval was not published');
}

describe('Graph Genesis v2 closed platform-independent boundary', () => {
  it('exposes no raw session factory and rejects an unowned snapshot before authority use', async () => {
    const unavailable = undefined as never;
    const snapshots = new ProductionGraphGenesisV2SnapshotAuthority(
      unavailable,
      unavailable,
      unavailable,
      unavailable,
      unavailable,
      unavailable,
      unavailable,
    );
    const sessions = new ProductionGraphGenesisV2SessionAuthority(snapshots);
    const unowned = Object.freeze({}) as AuthenticatedGraphGenesisV2ProductionSnapshot;

    expect(Object.keys(productionModule)).not.toContain('GraphGenesisV2ProductionInputAuthority');
    expect(Object.getOwnPropertyNames(ProductionGraphGenesisV2SnapshotAuthority.prototype).sort()).toEqual([
      'authenticates', 'constructor', 'prepare', 'revalidate',
    ]);
    expect(Object.getOwnPropertyNames(ProductionGraphGenesisV2SessionAuthority.prototype).sort()).toEqual([
      'authenticatesPrepared', 'authenticatesSealed', 'authenticatesSnapshot', 'authorize',
      'captureOutputIntent', 'closeContext', 'closeOutputIntent', 'constructor', 'createContext',
      'prepare', 'revalidateSnapshot',
    ]);
    expect(snapshots.authenticates(unowned)).toBe(false);
    await expect(snapshots.revalidate(unowned, {
      monotonicNow: () => 0.5,
      deadline: 1,
    })).rejects.toThrow(INVALID);
  });
});

describeMac('Graph Genesis v2 production snapshot provenance (macOS concrete captures)', () => {
  it('derives one private-owned, role-labelled 11-file/5-tree manifest and revalidates every role', async () => {
    const fixture = await createFixture();
    const fileRevalidate = vi.spyOn(fixture.files, 'revalidate');
    const treeRevalidate = vi.spyOn(fixture.trees, 'revalidate');
    const workspaceRevalidate = vi.spyOn(fixture.workspaces, 'revalidateInitial');
    const hostObserve = vi.spyOn(fixture.hosts, 'observe');
    const versionObserve = vi.spyOn(fixture.versions, 'observe');
    const containmentObserve = vi.spyOn(fixture.containments, 'observe');

    expect(fixture.snapshot.snapshotVersion).toBe(1);
    expect(fixture.snapshot.snapshots.map(({ role }) => role)).toEqual([
      'node', 'npmCli', 'sandboxExec', 'brokerRuntime', 'probeRuntime',
      'npmTree', 'distRuntimeTree', 'sqliteLib', 'migrations', 'webAssets',
      'sqlitePackage', 'sqliteNative', 'repositoryPackageJson', 'repositoryPackageLock', 'swVers', 'sysctl',
    ]);
    expect(fixture.snapshot.snapshots.filter(({ kind }) => kind === 'file')).toHaveLength(11);
    expect(fixture.snapshot.snapshots.filter(({ kind }) => kind === 'tree')).toHaveLength(5);

    await fixture.production.revalidate(fixture.snapshot, revalidationOptions());

    for (const file of Object.values(fixture.bundle.files)) {
      expect(fileRevalidate).toHaveBeenCalledWith(file);
    }
    for (const tree of Object.values(fixture.bundle.trees)) {
      expect(treeRevalidate).toHaveBeenCalledWith(tree);
    }
    expect(workspaceRevalidate).toHaveBeenCalledWith(fixture.bundle.workspace);
    expect(hostObserve).toHaveBeenCalledOnce();
    expect(versionObserve).toHaveBeenCalledOnce();
    expect(containmentObserve).toHaveBeenCalledOnce();
  });

  it('keeps paths and profile text out of the public projection', async () => {
    const fixture = await createFixture();
    const publicBytes = JSON.stringify(fixture.snapshot);

    expect(publicBytes).not.toContain(fixture.root);
    expect(publicBytes).not.toContain(fixture.bundle.containmentProfile.profileText);
    expect(publicBytes).not.toContain('absolutePath');
    expect(publicBytes).not.toContain('rootRealpath');
    expect(Object.keys(fixture.snapshot).sort()).toEqual([
      'containmentEvidenceDigest', 'containmentProfileDigest', 'hostEvidenceDigest',
      'runtimeManifestDigest', 'runtimeManifestVersion', 'runtimeVersionEvidenceDigest',
      'snapshotVersion', 'snapshots', 'workspaceBinding',
    ].sort());
  });

  it('rejects copied snapshots, foreign snapshot authorities, and foreign file ownership', async () => {
    const fixture = await createFixture();
    const copy = { ...fixture.snapshot } as AuthenticatedGraphGenesisV2ProductionSnapshot;
    const foreignProduction = new ProductionGraphGenesisV2SnapshotAuthority(
      fixture.files,
      fixture.trees,
      fixture.versions,
      fixture.hosts,
      fixture.workspaces,
      fixture.containments,
      fixture.profiles,
    );
    const foreignFiles = new RuntimeFileSnapshotAuthority();
    const foreignNode = await foreignFiles.capture('node', fixture.paths.node);

    expect(fixture.production.authenticates(copy)).toBe(false);
    expect(foreignProduction.authenticates(fixture.snapshot)).toBe(false);
    await expect(fixture.production.revalidate(copy, revalidationOptions())).rejects.toThrow(INVALID);
    expect(() => fixture.production.prepare({
      ...copiedBundle(fixture),
      files: { ...fixture.bundle.files, node: foreignNode },
    })).toThrow(INVALID);
  });

  it('rejects missing, extra, accessor, aliased, and authority-role-mismatched fields', async () => {
    const fixture = await createFixture();
    const missing = copiedBundle(fixture) as unknown as Record<string, unknown>;
    delete missing.containment;
    const extra = { ...copiedBundle(fixture), unexpected: true };
    const aliased = copiedBundle(fixture);
    (aliased.files as { repositoryPackageLock: unknown }).repositoryPackageLock = aliased.files.repositoryPackageJson;
    const mismatched = copiedBundle(fixture);
    (mismatched.files as { npmCli: unknown }).npmCli = mismatched.files.brokerRuntime;
    const recapturedProbeAlias = await fixture.files.capture('probe_runtime', fixture.paths.brokerRuntime);
    const recapturedAlias = {
      ...copiedBundle(fixture),
      files: { ...fixture.bundle.files, probeRuntime: recapturedProbeAlias },
    };
    const getter = vi.fn(() => fixture.bundle.files.node);
    const accessorFiles = { ...fixture.bundle.files } as Record<string, unknown>;
    Object.defineProperty(accessorFiles, 'node', { enumerable: true, get: getter });

    for (const candidate of [missing, extra, aliased, mismatched, recapturedAlias]) {
      expect(() => fixture.production.prepare(candidate as unknown as GraphGenesisV2ConcreteProductionBundle)).toThrow(INVALID);
    }
    expect(() => fixture.production.prepare({
      ...copiedBundle(fixture),
      files: accessorFiles,
    } as unknown as GraphGenesisV2ConcreteProductionBundle)).toThrow(INVALID);
    expect(getter).not.toHaveBeenCalled();
  });

  it('rejects exact-path relationship substitutions even when the same authority owns both files', async () => {
    const fixture = await createFixture();
    expect(() => fixture.production.prepare({
      ...copiedBundle(fixture),
      files: {
        ...fixture.bundle.files,
        repositoryPackageJson: fixture.bundle.files.repositoryPackageLock,
        repositoryPackageLock: fixture.bundle.files.repositoryPackageJson,
      },
    })).toThrow(INVALID);
  });

  it('rejects cross-version, cross-workspace, and cross-host evidence from the same authorities', async () => {
    const fixture = await createFixture();
    const alternateNodePath = join(fixture.root, 'alternate', 'node');
    const alternateNpmRoot = join(fixture.root, 'alternate-npm');
    const alternateNpmCliPath = join(alternateNpmRoot, 'bin', 'npm-cli.js');
    await writeFixture(alternateNodePath, 'alternate-node\n');
    await writeFixture(alternateNpmCliPath, 'alternate-npm-cli\n');
    await writeFixture(join(alternateNpmRoot, 'package.json'), 'alternate-package\n');
    const alternateNode = await fixture.files.capture('node', alternateNodePath);
    const alternateNpmCli = await fixture.files.capture('npm_cli', alternateNpmCliPath);
    const alternateNpmTree = await fixture.trees.capture(alternateNpmRoot);
    const alternateVersions = await fixture.versions.observe({
      node: alternateNode,
      npmCli: alternateNpmCli,
      npmTree: alternateNpmTree,
    });
    const alternateWorkspace = await fixture.workspaces.initialize(
      join(fixture.root, 'alternate-workspace'),
      fixture.bundle.containmentProfile.profileText,
    );
    fixture.hostExecutorSpy.mockResolvedValueOnce(Object.freeze({
      platform: 'darwin',
      architecture: 'arm64',
      osBuild: '25A1',
      bootSessionId: 'abcdefab-cdef-4abc-8def-abcdefabcdef',
    }));
    const alternateHost = await fixture.hosts.observe();

    for (const candidate of [
      { ...copiedBundle(fixture), runtimeVersions: alternateVersions },
      { ...copiedBundle(fixture), workspace: alternateWorkspace },
      { ...copiedBundle(fixture), host: alternateHost },
    ]) {
      expect(() => fixture.production.prepare(candidate)).toThrow(INVALID);
    }
  });

  it('uses unmocked authority ownership to reject synthetic and foreign host evidence', async () => {
    const fixture = await createFixture();
    const syntheticHosts = new OwnedHostPlatformAuthority({
      implementationKind: 'synthetic',
      observe: async () => Object.freeze({
        platform: 'darwin',
        architecture: 'arm64',
        osBuild: '25A1',
        bootSessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      }),
    });
    const syntheticHost = await syntheticHosts.observe();
    const syntheticProduction = new ProductionGraphGenesisV2SnapshotAuthority(
      fixture.files,
      fixture.trees,
      fixture.versions,
      syntheticHosts,
      fixture.workspaces,
      fixture.containments,
      fixture.profiles,
    );

    expect(() => syntheticProduction.prepare({
      ...copiedBundle(fixture),
      host: syntheticHost,
    })).toThrow(INVALID);
    expect(() => fixture.production.prepare({
      ...copiedBundle(fixture),
      host: syntheticHost,
    })).toThrow(INVALID);
  });

  it('retains original authenticated references when the caller mutates its bundle wrappers', async () => {
    const fixture = await createFixture();
    const originalNode = fixture.bundle.files.node;
    const alternateNodePath = join(fixture.root, 'replacement-node');
    await writeFixture(alternateNodePath, 'replacement-node\n');
    const alternateNode = await fixture.files.capture('node', alternateNodePath);
    (fixture.bundle.files as { node: unknown }).node = alternateNode;
    const revalidate = vi.spyOn(fixture.files, 'revalidate');

    await fixture.production.revalidate(fixture.snapshot, revalidationOptions());

    expect(revalidate).toHaveBeenCalledWith(originalNode);
    expect(revalidate).not.toHaveBeenCalledWith(alternateNode);
  });
});

describeMac('Graph Genesis v2 owned session preparation (macOS synthetic Dashboard only)', () => {
  it('derives one exact source-to-Plan3-to-Projection3-to-Envelope2 tuple without approval or audit writes', async () => {
    const fixture = await createPreparationFixture();
    const before = databaseCounts(fixture);

    const prepared = await fixture.sessions.prepare(fixture.snapshot, fixture.context, fixture.output);

    expect(fixture.sessions.authenticatesPrepared(prepared)).toBe(true);
    expect(prepared.plan).toMatchObject({
      planVersion: 3,
      candidateSchemaVersion: 2,
      peerSemanticsVersion: 1,
      compilationContractVersion: 1,
      runtimeManifestDigest: fixture.snapshot.runtimeManifestDigest,
      workspaceBinding: fixture.snapshot.workspaceBinding,
      maxCandidateOutputs: 1,
    });
    expect(prepared.projection).toMatchObject({
      projectionVersion: 3,
      planHash: prepared.plan.planHash,
      runtimeManifestDigest: fixture.snapshot.runtimeManifestDigest,
      target: '@modelcontextprotocol/server-filesystem@2026.7.10',
    });
    expect(prepared.envelope).toMatchObject({
      envelopeVersion: 2,
      planHash: prepared.plan.planHash,
      projectionDigest: prepared.envelope.projectionDigest,
      auditSchemaDigest: fixture.source.schemaDigest,
      auditFileIdentityDigest: fixture.source.fileIdentityDigest,
      auditDatabaseInstanceId: fixture.source.databaseInstanceId,
      initialAuditChainTail: fixture.source.initialChainTail,
      auditDurabilityProfileDigest: fixture.source.durabilityProfileDigest,
      dashboardInstanceId: fixture.dashboardStarts[0]!.handle.instanceId,
      dashboardPort: 48_101,
      outputRule: 'exclusive_new_private_file',
      policyDigest: GRAPH_GENESIS_V2_POLICY_DIGEST,
    });
    expect(prepared.plan.runtimeSnapshots).toEqual({
      node: fixture.bundle.files.node.snapshotDigest,
      npmCli: fixture.bundle.files.npmCli.snapshotDigest,
      sandboxExec: fixture.bundle.files.sandboxExec.snapshotDigest,
      brokerRuntime: fixture.bundle.files.brokerRuntime.snapshotDigest,
      probeRuntime: fixture.bundle.files.probeRuntime.snapshotDigest,
      npmTree: fixture.bundle.trees.npmTree.treeDigest,
      brokerTree: fixture.bundle.trees.distRuntimeTree.treeDigest,
    });
    expect(GRAPH_GENESIS_V2_POLICY).toEqual(GRAPH_GENESIS_POLICY);
    expect(prepared.envelope.policy).toEqual(GRAPH_GENESIS_POLICY);
    expect(prepared.approval).toMatchObject({
      approvalIdentityVersion: 2,
      executionEnvelopeHash: prepared.envelope.executionEnvelopeHash,
      planHash: prepared.plan.planHash,
      projectionDigest: prepared.envelope.projectionDigest,
      auditPath: fixture.source.canonicalPath,
      outputPath: fixture.outputPath,
      maxCandidateOutputs: 1,
      host: { platform: 'darwin', architecture: 'arm64', osBuild: '25A1' },
      runtime: { nodeVersion: '26.3.1', npmVersion: '11.16.0' },
    });
    expect(prepared.receipt).toMatchObject({
      adapter: 'graph_genesis',
      adapterVersion: '2',
      boundary: 'graph_genesis_plan',
      executionPlanHash: prepared.envelope.executionEnvelopeHash,
      policy: {
        schemaVersion: GRAPH_GENESIS_POLICY.schemaVersion,
        evaluatorName: GRAPH_GENESIS_POLICY.evaluatorName,
        evaluatorVersion: GRAPH_GENESIS_POLICY.evaluatorVersion,
      },
    });
    expect(prepared.receipt.policy.contentDigest).toMatch(/^sha256:[a-f0-9]{64}$/u);
    expect(prepared.receipt.identityMaterial).toMatchObject({
      executionEnvelopeHash: prepared.envelope.executionEnvelopeHash,
      planHash: prepared.plan.planHash,
      projectionDigest: prepared.envelope.projectionDigest,
      auditFileIdentityDigest: fixture.source.fileIdentityDigest,
      outputCanonicalPathDigest: prepared.envelope.outputCanonicalPathDigest,
      policyDigest: GRAPH_GENESIS_V2_POLICY_DIGEST,
    });
    expect(fixture.dashboardStarts[0]!.options).toMatchObject({ port: 0, mode: 'graph_run' });
    expect(fixture.dashboardStarts[0]!.options.approvals.listPending()).toEqual([]);
    expect(databaseCounts(fixture)).toEqual(before);
    expect(await pathExists(fixture.outputPath)).toBe(false);

    const publicBytes = JSON.stringify(prepared);
    expect(publicBytes).not.toContain(fixture.dashboardStarts[0]!.options.token);
    expect(publicBytes).not.toContain(fixture.bundle.containmentProfile.profileText);
    expect(publicBytes).not.toContain(fixture.paths.node);
    expect(Object.keys(prepared.privateCapsule)).toEqual(['capsuleVersion']);
    expect(JSON.stringify(fixture.context)).toBe('{"contextVersion":1}');
    expect(JSON.stringify(fixture.output)).toBe('{"outputIntentVersion":1}');
  });

  it('rejects copied prepared/context/output objects and Plan2/V1-shaped substitutions', async () => {
    const fixture = await createPreparationFixture();
    const prepared = await fixture.sessions.prepare(fixture.snapshot, fixture.context, fixture.output);
    const copiedPrepared = { ...prepared };
    const copiedContext = { ...fixture.context };
    const copiedOutput = { ...fixture.output };

    expect(fixture.sessions.authenticatesPrepared(copiedPrepared)).toBe(false);
    await expect(fixture.sessions.prepare(
      fixture.snapshot,
      copiedContext,
      fixture.output,
    )).rejects.toThrow(INVALID);
    await expect(fixture.sessions.prepare(
      fixture.snapshot,
      fixture.context,
      copiedOutput,
    )).rejects.toThrow(INVALID);
    await expect(fixture.sessions.prepare(
      { planVersion: 2 } as unknown as AuthenticatedGraphGenesisV2ProductionSnapshot,
      fixture.context,
      fixture.output,
    )).rejects.toThrow(INVALID);
    expect(Object.getOwnPropertyNames(ProductionGraphGenesisV2SessionAuthority.prototype)).toContain('authorize');
    expect(Object.getOwnPropertyNames(ProductionGraphGenesisV2SessionAuthority.prototype)).not.toContain('seal');
  });

  it('rejects foreign and same-source cross-context output bindings', async () => {
    const fixture = await createPreparationFixture();
    const secondContext = await fixture.sessions.createContext(fixture.source);
    const secondOutputParent = join(fixture.root, 'second-output');
    await mkdir(secondOutputParent, { mode: 0o700 });
    const secondOutput = await fixture.sessions.captureOutputIntent(
      secondContext,
      join(secondOutputParent, 'candidate.json'),
    );
    const foreignSessions = new ProductionGraphGenesisV2SessionAuthority(fixture.production);
    const foreignContext = await foreignSessions.createContext(fixture.source);
    const foreignOutputParent = join(fixture.root, 'foreign-output');
    await mkdir(foreignOutputParent, { mode: 0o700 });
    const foreignOutput = await foreignSessions.captureOutputIntent(
      foreignContext,
      join(foreignOutputParent, 'candidate.json'),
    );
    cleanupActions.push(async () => {
      try { await fixture.sessions.closeContext(secondContext); } catch {}
      try { await foreignSessions.closeContext(foreignContext); } catch {}
    });

    await expect(fixture.sessions.prepare(
      fixture.snapshot,
      secondContext,
      fixture.output,
    )).rejects.toThrow(INVALID);
    await expect(fixture.sessions.prepare(
      fixture.snapshot,
      foreignContext,
      foreignOutput,
    )).rejects.toThrow(INVALID);
    expect(fixture.dashboardStarts[0]!.handle.instanceId)
      .not.toBe(fixture.dashboardStarts[1]!.handle.instanceId);
  });

  it('revokes closed output and context handles while preserving the caller-owned database and parent', async () => {
    const outputClosed = await createPreparationFixture();
    await outputClosed.sessions.closeOutputIntent(outputClosed.output);
    await expect(outputClosed.sessions.prepare(
      outputClosed.snapshot,
      outputClosed.context,
      outputClosed.output,
    )).rejects.toThrow(INVALID);

    const contextClosed = await createPreparationFixture();
    await contextClosed.sessions.closeContext(contextClosed.context);
    await expect(contextClosed.sessions.prepare(
      contextClosed.snapshot,
      contextClosed.context,
      contextClosed.output,
    )).rejects.toThrow(INVALID);
    expect(contextClosed.source.database.prepare('SELECT 1').pluck().get()).toBe(1);
    expect(await pathExists(contextClosed.outputParent)).toBe(true);
    expect(await pathExists(contextClosed.outputPath)).toBe(false);
  });

  it('rejects audit source chain drift before creating Plan3', async () => {
    const fixture = await createPreparationFixture();
    new SqliteAuditRecorder(fixture.source.database).begin({
      serverId: 'drift-fixture',
      toolName: 'write',
      arguments: {},
    }, { action: 'forward' });

    await expect(fixture.sessions.prepare(
      fixture.snapshot,
      fixture.context,
      fixture.output,
    )).rejects.toThrow(INVALID);
  });

  it('rejects a target created after intent capture and preserves its bytes', async () => {
    const fixture = await createPreparationFixture();
    await writeFile(fixture.outputPath, 'caller-owned-output\n', { mode: 0o600 });

    await expect(fixture.sessions.prepare(
      fixture.snapshot,
      fixture.context,
      fixture.output,
    )).rejects.toThrow(INVALID);
    expect(await readFile(fixture.outputPath, 'utf8')).toBe('caller-owned-output\n');
  });

  it('rejects output parent replacement and symlink substitution', async () => {
    const replaced = await createPreparationFixture();
    const originalParent = `${replaced.outputParent}-original`;
    await rename(replaced.outputParent, originalParent);
    await mkdir(replaced.outputParent, { mode: 0o700 });
    await expect(replaced.sessions.prepare(
      replaced.snapshot,
      replaced.context,
      replaced.output,
    )).rejects.toThrow(INVALID);

    const linked = await createPreparationFixture();
    const linkedOriginal = `${linked.outputParent}-original`;
    await rename(linked.outputParent, linkedOriginal);
    await symlink(linkedOriginal, linked.outputParent);
    await expect(linked.sessions.prepare(
      linked.snapshot,
      linked.context,
      linked.output,
    )).rejects.toThrow(INVALID);
  });

  it('rejects a reused Dashboard handle without closing the already-owned context resource', async () => {
    const fixture = await createPreparationFixture();
    vi.mocked(startDashboard).mockResolvedValue(fixture.dashboardStarts[0]!.handle);

    await expect(fixture.sessions.createContext(fixture.source)).rejects.toThrow(INVALID);
    expect(fixture.dashboardStarts[0]!.close).not.toHaveBeenCalled();
    await expect(fixture.sessions.prepare(
      fixture.snapshot,
      fixture.context,
      fixture.output,
    )).resolves.toMatchObject({ plan: { planVersion: 3 } });
  });

  it('rejects different Dashboard handles that copy an active instance ID or port', async () => {
    const fixture = await createPreparationFixture();
    const copiedIdClose = vi.fn(async () => {});
    vi.mocked(startDashboard).mockImplementationOnce(async (options) => Object.freeze({
      url: `http://127.0.0.1:48152/#token=${encodeURIComponent(options.token)}`,
      instanceId: fixture.dashboardStarts[0]!.handle.instanceId,
      close: copiedIdClose,
      bindGraphAction: vi.fn(),
    }));
    await expect(fixture.sessions.createContext(fixture.source)).rejects.toThrow(INVALID);
    expect(copiedIdClose).toHaveBeenCalledOnce();

    const copiedPortClose = vi.fn(async () => {});
    vi.mocked(startDashboard).mockImplementationOnce(async (options) => Object.freeze({
      url: `http://127.0.0.1:48101/#token=${encodeURIComponent(options.token)}`,
      instanceId: randomUUID(),
      close: copiedPortClose,
      bindGraphAction: vi.fn(),
    }));
    await expect(fixture.sessions.createContext(fixture.source)).rejects.toThrow(INVALID);
    expect(copiedPortClose).toHaveBeenCalledOnce();
    expect(fixture.dashboardStarts[0]!.close).not.toHaveBeenCalled();
  });

  it('rejects a copied audit source before Dashboard creation', async () => {
    const snapshotFixture = await createFixture();
    installDashboardMock();
    const source = await createAuditSource(snapshotFixture.root);
    const sessions = new ProductionGraphGenesisV2SessionAuthority(snapshotFixture.production);
    const copiedSource = { ...source };
    const dashboardCallsBefore = vi.mocked(startDashboard).mock.calls.length;

    await expect(sessions.createContext(copiedSource)).rejects.toThrow(INVALID);
    expect(vi.mocked(startDashboard).mock.calls).toHaveLength(dashboardCallsBefore);
    expect(source.database.prepare('SELECT 1').pluck().get()).toBe(1);
  });

  it('closes a newly-created invalid Dashboard handle and leaves its source database open', async () => {
    const snapshotFixture = await createFixture();
    const source = await createAuditSource(snapshotFixture.root);
    const close = vi.fn(async () => {});
    vi.mocked(startDashboard).mockImplementation(async (options) => Object.freeze({
      url: `http://127.0.0.1:48151/#token=${encodeURIComponent(options.token)}`,
      instanceId: 'copied-invalid-id',
      close,
      bindGraphAction: vi.fn(),
    }));
    const sessions = new ProductionGraphGenesisV2SessionAuthority(snapshotFixture.production);

    await expect(sessions.createContext(source)).rejects.toThrow(INVALID);
    expect(close).toHaveBeenCalledOnce();
    expect(source.database.prepare('SELECT 1').pluck().get()).toBe(1);
  });

  it('closes its internal approval service when Dashboard startup fails', async () => {
    const snapshotFixture = await createFixture();
    const source = await createAuditSource(snapshotFixture.root);
    let captured: Parameters<typeof startDashboard>[0] | undefined;
    vi.mocked(startDashboard).mockImplementation(async (options) => {
      captured = options;
      throw new Error('synthetic-dashboard-failure');
    });
    const sessions = new ProductionGraphGenesisV2SessionAuthority(snapshotFixture.production);

    await expect(sessions.createContext(source)).rejects.toThrow(INVALID);
    expect(source.database.prepare('SELECT 1').pluck().get()).toBe(1);
    expect(() => captured!.approvals.request({
      serverId: 'closed-context',
      toolName: 'none',
      arguments: {},
      risk: { score: 0, band: 'low', signals: [] },
      reasonCodes: [],
    }, 1_000)).toThrow('Approval service is closed');
  });

  it('rejects an existing output target during intent capture without deleting it', async () => {
    const snapshotFixture = await createFixture();
    installDashboardMock();
    const source = await createAuditSource(snapshotFixture.root);
    const sessions = new ProductionGraphGenesisV2SessionAuthority(snapshotFixture.production);
    const context = await sessions.createContext(source);
    cleanupActions.push(async () => {
      try { await sessions.closeContext(context); } catch {}
    });
    const outputParent = join(snapshotFixture.root, 'occupied-output');
    const outputPath = join(outputParent, 'candidate.json');
    await mkdir(outputParent, { mode: 0o700 });
    await writeFile(outputPath, 'existing\n', { mode: 0o600 });

    await expect(sessions.captureOutputIntent(context, outputPath)).rejects.toThrow(INVALID);
    expect(await readFile(outputPath, 'utf8')).toBe('existing\n');
  });
});

describeMac('Graph Genesis v2 durable approval lifecycle (macOS disposable SQLite only)', () => {
  it('records before publication, finalizes one approved authorization, and mints only an opaque seal', async () => {
    const fixture = await createPreparationFixture();
    const prepared = await fixture.sessions.prepare(fixture.snapshot, fixture.context, fixture.output);
    const handle = fixture.dashboardStarts[0]!.handle;
    let pendingAtBinding = -1;
    let eventTypesAtBinding: string[] = [];
    vi.mocked(handle.bindGraphAction).mockImplementation(() => {
      pendingAtBinding = dashboardApprovals(fixture).listPending().length;
      eventTypesAtBinding = fixture.source.database.prepare(`
        SELECT event_type FROM audit_events ORDER BY sequence
      `).pluck().all() as string[];
    });

    const authorization = fixture.sessions.authorize(prepared);
    const request = await waitForGraphApproval(fixture);
    expect(pendingAtBinding).toBe(0);
    expect(eventTypesAtBinding).toEqual([
      'decision_recorded',
      'graph_genesis_v2_session_created',
      'approval_requested',
    ]);
    expect(dashboardApprovals(fixture).decide(request.id, 'approved')).toBe('approved');
    const result = await authorization;
    expect(result.status).toBe('authorized');
    if (result.status !== 'authorized') throw new Error('Expected sealed authorization');

    expect(result.actionId).toMatch(/^[0-9a-f-]{36}$/u);
    expect(Object.keys(result.sealedAuthorization)).toEqual(['sealedAuthorizationVersion']);
    expect(fixture.sessions.authenticatesSealed(result.sealedAuthorization, prepared)).toBe(true);
    expect(fixture.sessions.authenticatesSealed({ ...result.sealedAuthorization }, prepared)).toBe(false);
    expect(new ProductionGraphGenesisV2SessionAuthority(fixture.production)
      .authenticatesSealed(result.sealedAuthorization, prepared)).toBe(false);
    const v1Sessions = new ProductionGraphGenesisSessionAuthority(undefined as never, undefined as never, undefined as never);
    expect(v1Sessions.authenticatesStartLease(result.sealedAuthorization as never, prepared.plan.planHash)).toBe(false);
    expect(fixture.source.database.prepare(`
      SELECT event_type FROM audit_events WHERE tool_call_id = ? ORDER BY sequence
    `).pluck().all(result.actionId)).toEqual([
      'decision_recorded',
      'graph_genesis_v2_session_created',
      'approval_requested',
      'approval_approved',
      'graph_genesis_v2_approved_revalidation_complete',
      'authorization_receipt_finalized',
      'graph_genesis_authorization_ready',
      'graph_genesis_v2_authorization_finalized',
    ]);
    expect(await pathExists(fixture.outputPath)).toBe(false);
    await expect(fixture.sessions.authorize(prepared)).rejects.toThrow(INVALID);

    await fixture.sessions.closeContext(fixture.context);
    expect(fixture.sessions.authenticatesSealed(result.sealedAuthorization, prepared)).toBe(false);
    expect(fixture.source.database.prepare('SELECT 1').pluck().get()).toBe(1);
  });

  it.each(['denied', 'cancelled'] as const)(
    'durably blocks %s exactly once without sealed authority',
    async (outcome) => {
      const fixture = await createPreparationFixture();
      const prepared = await fixture.sessions.prepare(fixture.snapshot, fixture.context, fixture.output);
      const controller = new AbortController();
      const authorization = fixture.sessions.authorize(prepared, { signal: controller.signal });
      const request = await waitForGraphApproval(fixture);
      if (outcome === 'denied') {
        expect(dashboardApprovals(fixture).decide(request.id, 'denied')).toBe('denied');
      } else {
        controller.abort();
      }
      const result = await authorization;
      expect(result).toEqual({ status: outcome, actionId: expect.any(String) });
      expect(fixture.source.database.prepare('SELECT status FROM approvals WHERE id = ?').pluck().get(request.id))
        .toBe(outcome);
      expect(await pathExists(fixture.outputPath)).toBe(false);
      await expect(fixture.sessions.authorize(prepared)).rejects.toThrow(INVALID);
    },
  );

  it('treats an expiry as a durable terminal outcome without a seal', async () => {
    const fixture = await createPreparationFixture();
    const prepared = await fixture.sessions.prepare(fixture.snapshot, fixture.context, fixture.output);
    const authorization = fixture.sessions.authorize(prepared);
    const request = await waitForGraphApproval(fixture);
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date(request.expiresAt));
    expect(dashboardApprovals(fixture).decide(request.id, 'approved')).toBe('expired');
    await expect(authorization).resolves.toEqual({ status: 'expired', actionId: expect.any(String) });
    expect(fixture.source.database.prepare('SELECT status FROM approvals WHERE id = ?').pluck().get(request.id))
      .toBe('expired');
  });

  it('bounds a delayed hidden request to remaining plan time and cannot approve at deadline equality', async () => {
    const fixture = await createPreparationFixture();
    const prepared = await fixture.sessions.prepare(fixture.snapshot, fixture.context, fixture.output);
    const remainingMonotonicMs = 5_000;
    let monotonicNow = prepared.envelope.planDeadlineMonotonicMs - remainingMonotonicMs;
    const monotonic = vi.spyOn(performance, 'now').mockImplementation(() => monotonicNow);
    const requestWallMs = Math.max(Date.now(), Date.parse(prepared.envelope.requestedAt));
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date(requestWallMs));

    const authorization = fixture.sessions.authorize(prepared);
    const request = await waitForGraphApproval(fixture);
    expect(Date.parse(request.expiresAt)).toBeLessThanOrEqual(requestWallMs + remainingMonotonicMs);
    monotonicNow = prepared.envelope.planDeadlineMonotonicMs;
    vi.setSystemTime(new Date(request.expiresAt));
    expect(dashboardApprovals(fixture).decide(request.id, 'approved')).toBe('expired');
    await expect(authorization).resolves.toEqual({ status: 'expired', actionId: expect.any(String) });
    monotonic.mockRestore();
  });

  it.each(['bind', 'publish'] as const)(
    'fails closed with no reusable visible request when Dashboard %s fails',
    async (stage) => {
      const fixture = await createPreparationFixture();
      const prepared = await fixture.sessions.prepare(fixture.snapshot, fixture.context, fixture.output);
      if (stage === 'bind') {
        vi.mocked(fixture.dashboardStarts[0]!.handle.bindGraphAction)
          .mockImplementation(() => { throw new Error('synthetic bind failure'); });
      } else {
        vi.spyOn(dashboardApprovals(fixture) as unknown as { publish(id: string): void }, 'publish')
          .mockImplementation(() => { throw new Error('synthetic publish failure'); });
      }

      await expect(fixture.sessions.authorize(prepared)).rejects.toThrow(INVALID);
      expect(dashboardApprovals(fixture).listPending()).toEqual([]);
      expect(fixture.source.database.prepare('SELECT status FROM approvals').pluck().all()).toEqual(['cancelled']);
      expect(fixture.source.database.prepare('SELECT status FROM tool_calls').pluck().all()).toEqual(['failed']);
      expect(await pathExists(fixture.outputPath)).toBe(false);
      await expect(fixture.sessions.authorize(prepared)).rejects.toThrow(INVALID);
    },
  );

  it('resolves cancellation conservatively when its context closes while awaiting outcome', async () => {
    const fixture = await createPreparationFixture();
    const prepared = await fixture.sessions.prepare(fixture.snapshot, fixture.context, fixture.output);
    const authorization = fixture.sessions.authorize(prepared);
    await waitForGraphApproval(fixture);

    await expect(fixture.sessions.closeContext(fixture.context)).resolves.toBeUndefined();
    await expect(authorization).resolves.toEqual({ status: 'cancelled', actionId: expect.any(String) });
    expect(dashboardApprovals(fixture).listPending()).toEqual([]);
    expect(fixture.source.database.prepare('SELECT status FROM approvals').pluck().all()).toEqual(['cancelled']);
    expect(fixture.source.database.prepare('SELECT status FROM tool_calls').pluck().all()).toEqual(['approval_cancelled']);
    expect(await pathExists(fixture.outputPath)).toBe(false);
    await expect(fixture.sessions.authorize(prepared)).rejects.toThrow(INVALID);
  });

  it('fails closed after approval when the durable authorization evidence write fails', async () => {
    const fixture = await createPreparationFixture();
    const prepared = await fixture.sessions.prepare(fixture.snapshot, fixture.context, fixture.output);
    const authorization = fixture.sessions.authorize(prepared);
    const request = await waitForGraphApproval(fixture);
    fixture.source.database.exec(`
      CREATE TRIGGER reject_v2_authorization_evidence
      BEFORE INSERT ON audit_events
      WHEN NEW.event_type = 'graph_genesis_v2_approved_revalidation_complete'
      BEGIN SELECT RAISE(ABORT, 'synthetic authorization evidence failure'); END
    `);
    expect(dashboardApprovals(fixture).decide(request.id, 'approved')).toBe('approved');
    await expect(authorization).rejects.toThrow(INVALID);
    expect(fixture.source.database.prepare('SELECT status FROM approvals WHERE id = ?').pluck().get(request.id))
      .toBe('approved');
    expect(await pathExists(fixture.outputPath)).toBe(false);
    await expect(fixture.sessions.authorize(prepared)).rejects.toThrow(INVALID);
  });

  it.each(['snapshot', 'output', 'audit'] as const)(
    'rejects %s drift after approval before sealing',
    async (kind) => {
      const fixture = await createPreparationFixture();
      const prepared = await fixture.sessions.prepare(fixture.snapshot, fixture.context, fixture.output);
      const authorization = fixture.sessions.authorize(prepared);
      const request = await waitForGraphApproval(fixture);
      if (kind === 'snapshot') {
        await writeFile(fixture.paths.repositoryPackageLock, 'changed-after-approval\n', { mode: 0o600 });
      } else if (kind === 'output') {
        await writeFile(fixture.outputPath, 'caller-output\n', { mode: 0o600 });
      } else {
        new SqliteAuditRecorder(fixture.source.database).begin({
          serverId: 'external-drift', toolName: 'write', arguments: {},
        }, { action: 'forward' });
      }
      expect(dashboardApprovals(fixture).decide(request.id, 'approved')).toBe('approved');
      await expect(authorization).rejects.toThrow(INVALID);
      if (kind === 'output') expect(await readFile(fixture.outputPath, 'utf8')).toBe('caller-output\n');
      await expect(fixture.sessions.authorize(prepared)).rejects.toThrow(INVALID);
    },
  );

  it('fails before the first audit write for an already-cancelled or deadline-expired authorization', async () => {
    const cancelled = await createPreparationFixture();
    const cancelledPrepared = await cancelled.sessions.prepare(cancelled.snapshot, cancelled.context, cancelled.output);
    const controller = new AbortController();
    controller.abort();
    await expect(cancelled.sessions.authorize(cancelledPrepared, { signal: controller.signal })).rejects.toThrow(INVALID);
    expect(databaseCounts(cancelled)).toEqual({ toolCalls: 0, approvals: 0, auditEvents: 0 });

    const expired = await createPreparationFixture();
    const expiredPrepared = await expired.sessions.prepare(expired.snapshot, expired.context, expired.output);
    const now = vi.spyOn(performance, 'now').mockReturnValue(expiredPrepared.envelope.planDeadlineMonotonicMs);
    await expect(expired.sessions.authorize(expiredPrepared)).rejects.toThrow(INVALID);
    now.mockRestore();
    expect(databaseCounts(expired)).toEqual({ toolCalls: 0, approvals: 0, auditEvents: 0 });
  });

  it('fails closed when the deadline reaches equality after approved snapshot revalidation', async () => {
    const fixture = await createPreparationFixture();
    const prepared = await fixture.sessions.prepare(fixture.snapshot, fixture.context, fixture.output);
    let now = prepared.envelope.planDeadlineMonotonicMs - 10_000;
    const clock = vi.spyOn(performance, 'now').mockImplementation(() => now);
    const originalRevalidate = fixture.production.revalidate.bind(fixture.production);
    vi.spyOn(fixture.production, 'revalidate').mockImplementation(async (snapshot, options) => {
      await originalRevalidate(snapshot, options);
      now = prepared.envelope.planDeadlineMonotonicMs;
    });
    const authorization = fixture.sessions.authorize(prepared);
    const request = await waitForGraphApproval(fixture);
    expect(dashboardApprovals(fixture).decide(request.id, 'approved')).toBe('approved');
    await expect(authorization).rejects.toThrow(INVALID);
    clock.mockRestore();
    expect(await pathExists(fixture.outputPath)).toBe(false);
  });
});

describeMac('Graph Genesis v2 production snapshot drift rejection (macOS concrete captures)', () => {
  it('stops before tree probes after file drift', async () => {
    const fixture = await createFixture();
    await writeFile(fixture.paths.repositoryPackageLock, 'changed-lock\n');
    const later = vi.spyOn(fixture.trees, 'revalidate');

    await expect(fixture.production.revalidate(fixture.snapshot, revalidationOptions())).rejects.toThrow(INVALID);
    expect(later).not.toHaveBeenCalled();
  });

  it('stops before workspace probes after tree drift', async () => {
    const fixture = await createFixture();
    await writeFixture(join(dirname(fixture.paths.webAsset), 'changed.js'), 'changed-web\n');
    const later = vi.spyOn(fixture.workspaces, 'revalidateInitial');

    await expect(fixture.production.revalidate(fixture.snapshot, revalidationOptions())).rejects.toThrow(INVALID);
    expect(later).not.toHaveBeenCalled();
  });

  it('stops before host probes after workspace drift', async () => {
    const fixture = await createFixture();
    await writeFile(join(fixture.bundle.workspace.rootRealpath, 'broker-profile.sb'), 'changed-profile\n');
    const later = vi.spyOn(fixture.hosts, 'observe');

    await expect(fixture.production.revalidate(fixture.snapshot, revalidationOptions())).rejects.toThrow(INVALID);
    expect(later).not.toHaveBeenCalled();
  });

  it('stops before version probes after host drift', async () => {
    const fixture = await createFixture();
    fixture.hostExecutorSpy.mockResolvedValue(Object.freeze({
      platform: 'darwin',
      architecture: 'arm64',
      osBuild: '25A1',
      bootSessionId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    }));
    const later = vi.spyOn(fixture.versions, 'observe');

    await expect(fixture.production.revalidate(fixture.snapshot, revalidationOptions())).rejects.toThrow(INVALID);
    expect(later).not.toHaveBeenCalled();
  });

  it('stops before containment probes after version drift', async () => {
    const fixture = await createFixture();
    fixture.versionExecutorSpy.mockResolvedValue(Object.freeze({
      nodeVersion: '26.3.1',
      npmVersion: '11.16.1',
    }));
    const later = vi.spyOn(fixture.containments, 'observe');

    await expect(fixture.production.revalidate(fixture.snapshot, revalidationOptions())).rejects.toThrow(INVALID);
    expect(later).not.toHaveBeenCalled();
  });

  it('rejects containment re-observation drift', async () => {
    const fixture = await createFixture();
    fixture.containmentExecutorSpy.mockResolvedValue(Object.freeze({
      ...successfulContainment,
      alternateLoopbackPortDenied: false,
    }));

    await expect(fixture.production.revalidate(fixture.snapshot, revalidationOptions())).rejects.toThrow(INVALID);
  });
});

type RevalidationGroup = 'files' | 'trees' | 'workspace' | 'host' | 'version' | 'containment';

function abortAfterGroup(fixture: Fixture, group: RevalidationGroup, controller: AbortController) {
  if (group === 'files') {
    const original = fixture.files.revalidate.bind(fixture.files);
    vi.spyOn(fixture.files, 'revalidate').mockImplementation(async (snapshot) => {
      await original(snapshot);
      if (snapshot === fixture.bundle.files.sysctl) controller.abort();
    });
    return vi.spyOn(fixture.trees, 'revalidate');
  }
  if (group === 'trees') {
    const original = fixture.trees.revalidate.bind(fixture.trees);
    vi.spyOn(fixture.trees, 'revalidate').mockImplementation(async (snapshot) => {
      await original(snapshot);
      if (snapshot === fixture.bundle.trees.webAssets) controller.abort();
    });
    return vi.spyOn(fixture.workspaces, 'revalidateInitial');
  }
  if (group === 'workspace') {
    const original = fixture.workspaces.revalidateInitial.bind(fixture.workspaces);
    vi.spyOn(fixture.workspaces, 'revalidateInitial').mockImplementation(async (workspace) => {
      await original(workspace);
      controller.abort();
    });
    return vi.spyOn(fixture.hosts, 'observe');
  }
  if (group === 'host') {
    const original = fixture.hosts.observe.bind(fixture.hosts);
    vi.spyOn(fixture.hosts, 'observe').mockImplementation(async () => {
      const evidence = await original();
      controller.abort();
      return evidence;
    });
    return vi.spyOn(fixture.versions, 'observe');
  }
  if (group === 'version') {
    const original = fixture.versions.observe.bind(fixture.versions);
    vi.spyOn(fixture.versions, 'observe').mockImplementation(async (input) => {
      const evidence = await original(input);
      controller.abort();
      return evidence;
    });
    return vi.spyOn(fixture.containments, 'observe');
  }
  const original = fixture.containments.observe.bind(fixture.containments);
  vi.spyOn(fixture.containments, 'observe').mockImplementation(async (...input) => {
    const evidence = await original(...input);
    controller.abort();
    return evidence;
  });
  return undefined;
}

function laterProbe(fixture: Fixture, group: RevalidationGroup) {
  if (group === 'files') return vi.spyOn(fixture.trees, 'revalidate');
  if (group === 'trees') return vi.spyOn(fixture.workspaces, 'revalidateInitial');
  if (group === 'workspace') return vi.spyOn(fixture.hosts, 'observe');
  if (group === 'host') return vi.spyOn(fixture.versions, 'observe');
  if (group === 'version') return vi.spyOn(fixture.containments, 'observe');
  return undefined;
}

const groupDeadlines: Readonly<Record<RevalidationGroup, number>> = Object.freeze({
  files: 22,
  trees: 32,
  workspace: 34,
  host: 36,
  version: 38,
  containment: 40,
});

describeMac('Graph Genesis v2 production snapshot interruption fences (macOS concrete captures)', () => {
  it('rejects cancellation and deadline equality before the first operation', async () => {
    const fixture = await createFixture();
    const controller = new AbortController();
    controller.abort();
    const revalidate = vi.spyOn(fixture.files, 'revalidate');

    await expect(fixture.production.revalidate(
      fixture.snapshot,
      revalidationOptions(controller.signal),
    )).rejects.toThrow(INVALID);
    await expect(fixture.production.revalidate(fixture.snapshot, {
      monotonicNow: () => 0,
      deadline: 0,
    })).rejects.toThrow(INVALID);
    expect(revalidate).not.toHaveBeenCalled();
  });

  for (const group of ['files', 'trees', 'workspace', 'host', 'version', 'containment'] as const) {
    it(`stops after ${group} when cancellation arrives at the post-await fence`, async () => {
      const fixture = await createFixture();
      const controller = new AbortController();
      const later = abortAfterGroup(fixture, group, controller);

      await expect(fixture.production.revalidate(
        fixture.snapshot,
        revalidationOptions(controller.signal),
      )).rejects.toThrow(INVALID);
      if (later !== undefined) expect(later).not.toHaveBeenCalled();
    });

    it(`stops after ${group} when deadline equality arrives at the post-await fence`, async () => {
      const fixture = await createFixture();
      const later = laterProbe(fixture, group);
      let now = 0;

      await expect(fixture.production.revalidate(fixture.snapshot, {
        monotonicNow: () => ++now,
        deadline: groupDeadlines[group],
      })).rejects.toThrow(INVALID);
      if (later !== undefined) expect(later).not.toHaveBeenCalled();
    });
  }

  it('rejects a non-finite or decreasing monotonic clock before later operations', async () => {
    const fixture = await createFixture();
    const later = vi.spyOn(fixture.trees, 'revalidate');
    const values = [1, 0];

    await expect(fixture.production.revalidate(fixture.snapshot, {
      monotonicNow: () => values.shift() ?? Number.NaN,
      deadline: 100,
    })).rejects.toThrow(INVALID);
    expect(later).not.toHaveBeenCalled();
  });

  it('rejects negative time and nonpositive or unsafe deadlines', async () => {
    const fixture = await createFixture();
    const revalidate = vi.spyOn(fixture.files, 'revalidate');
    const invalidOptions = [
      { monotonicNow: () => -1, deadline: 100 },
      { monotonicNow: () => 0, deadline: 0 },
      { monotonicNow: () => 0, deadline: -1 },
      { monotonicNow: () => 0, deadline: Number.POSITIVE_INFINITY },
      { monotonicNow: () => 0, deadline: Number.MAX_SAFE_INTEGER + 1 },
    ];

    for (const options of invalidOptions) {
      await expect(fixture.production.revalidate(fixture.snapshot, options)).rejects.toThrow(INVALID);
    }
    expect(revalidate).not.toHaveBeenCalled();
  });

  it('allows finite fractional monotonic observations below a positive safe deadline', async () => {
    const fixture = await createFixture();
    let now = 0;

    await expect(fixture.production.revalidate(fixture.snapshot, {
      monotonicNow: () => now += 0.25,
      deadline: 100.5,
    })).resolves.toBeUndefined();
  });
});
