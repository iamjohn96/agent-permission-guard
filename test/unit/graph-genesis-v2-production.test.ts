import { createHash, randomUUID } from 'node:crypto';
import * as auditDatabaseModule from '../../src/db/database.js';
import { Buffer } from 'node:buffer';
import { access, chmod, mkdir, mkdtemp, readFile, realpath, rename, rm, symlink, writeFile } from 'node:fs/promises';
import * as fixtureFs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { performance } from 'node:perf_hooks';
import { dirname, join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';

const concreteBoundary = vi.hoisted(() => ({
  childMode: 'close' as 'close' | 'hold' | 'throw' | 'error' | 'error-before-spawn' | 'overflow',
  closeMode: 'close' as 'close' | 'hold', connectionsMode: 'zero' as 'zero' | 'hold',
  listenMode: 'listen' as 'listen' | 'error' | 'hold',
  termIgnored: false, allSignalsIgnored: false,
  onSpawn: undefined as undefined | (() => void),
  onKill: undefined as undefined | ((signal: string) => void),
}));
vi.mock('node:http', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:http')>();
  const { EventEmitter } = await import('node:events');
  return { ...actual, createServer: vi.fn((handler) => {
    const server = Object.assign(new EventEmitter(), {
      listening: false,
      listen: vi.fn((_port: number, _host: string, callback: () => void) => {
        if (concreteBoundary.listenMode === 'error') queueMicrotask(() => server.emit('error', new Error('private listen error')));
        else if (concreteBoundary.listenMode === 'listen') { server.listening = true; callback(); }
        return server;
      }),
      address: vi.fn(() => ({ address: '127.0.0.1', family: 'IPv4', port: 43121 })),
      getConnections: vi.fn((callback: (error: Error | null, count: number) => void) => {
        if (concreteBoundary.connectionsMode === 'zero') callback(null, 0);
      }),
      close: vi.fn((callback?: (error?: Error) => void) => {
        if (concreteBoundary.closeMode === 'close') { server.listening = false; callback?.(); server.emit('close'); }
        return server;
      }),
      closeAllConnections: vi.fn(),
    });
    server.on('request', handler); return server;
  }) };
});
vi.mock('node:child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:child_process')>();
  const { EventEmitter } = await import('node:events');
  const { PassThrough } = await import('node:stream');
  return { ...actual, spawn: vi.fn(() => {
    if (concreteBoundary.childMode === 'throw') throw new Error('private spawn detail');
    const child = Object.assign(new EventEmitter(), {
      pid: 7654321, exitCode: null as number | null, signalCode: null as string | null,
      stdout: new PassThrough(), stderr: new PassThrough(),
      kill: vi.fn((signal: string) => {
        concreteBoundary.onKill?.(signal);
        if (!concreteBoundary.allSignalsIgnored && (signal === 'SIGKILL' || !concreteBoundary.termIgnored)) {
          queueMicrotask(() => { child.signalCode = signal; child.emit('close', null, signal); });
        }
        return true;
      }),
    });
    concreteBoundary.onSpawn?.();
    queueMicrotask(() => {
      if (concreteBoundary.childMode === 'error-before-spawn') {
        child.emit('error', new Error('private asynchronous detail')); child.emit('close', null, null); return;
      }
      child.emit('spawn');
      if (concreteBoundary.childMode === 'close') { child.exitCode = 0; child.emit('close', 0, null); }
      if (concreteBoundary.childMode === 'error') child.emit('error', new Error('private asynchronous detail'));
      if (concreteBoundary.childMode === 'overflow') child.stdout.emit('data', Buffer.alloc(256 * 1024 + 1));
    });
    return child;
  }) };
});
vi.mock('../../src/dashboard/server.js', () => ({ startDashboard: vi.fn() }));
vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs/promises')>();
  return { ...actual, lstat: vi.fn(actual.lstat), open: vi.fn(actual.open) };
});

import { SqliteAuditRecorder } from '../../src/audit/recorder.js';
import { receiptDigest } from '../../src/audit/receipt.js';
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
import { canonicalJson } from '../../src/audit/canonical-json.js';

const INVALID = 'graph_genesis_v2_production_invalid';
const originalAuditBegin = SqliteAuditRecorder.prototype.begin;
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

beforeEach(() => {
  Object.assign(concreteBoundary, { childMode: 'close', closeMode: 'close', connectionsMode: 'zero',
    listenMode: 'listen', termIgnored: false, allSignalsIgnored: false, onSpawn: undefined, onKill: undefined });
  vi.mocked(spawn).mockClear(); vi.mocked(createServer).mockClear();
});

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

async function createFixture(beforeProfile?: (authority: ProductionGraphGenesisV2SnapshotAuthority, root: string) => Promise<number>) {
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
  const workspaces = new FinalizedGraphGenesisWorkspaceAuthority(trees);
  const containmentExecutor = new LocalSeatbeltContainmentProbeExecutor();
  const containmentExecutorSpy = vi.spyOn(containmentExecutor, 'run').mockResolvedValue(successfulContainment);
  const containments = new OwnedContainmentProbeAuthority(files, workspaces, containmentExecutor);
  const production = new ProductionGraphGenesisV2SnapshotAuthority(
    files,
    trees,
    versions,
    hosts,
    workspaces,
    containments,
    profiles,
  );
  const port = beforeProfile === undefined ? 43121 : await beforeProfile(production, root);
  const containmentProfile = profiles.prepare({
    osBuild: host.osBuild,
    sandboxExecSha256: fileSnapshots.sandboxExec.sha256,
    allowedPort: port,
  });
  const workspace = await workspaces.initialize(join(root, 'workspace'), containmentProfile.profileText);
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

async function completionFixture(signal?: AbortSignal) {
  const fixture = await createPreparationFixture();
  const prepared = await fixture.sessions.prepare(fixture.snapshot, fixture.context, fixture.output);
  const pending = fixture.sessions.authorize(prepared, signal === undefined ? {} : { signal });
  const request = await waitForGraphApproval(fixture);
  dashboardApprovals(fixture).decide(request.id, 'approved');
  const authorized = await pending;
  if (authorized.status !== 'authorized') throw new Error('Expected authorization');
  await writeSyntheticLock(fixture.bundle.workspace.rootRealpath);
  const completion = fixture.sessions.createSyntheticCompletion(prepared, authorized.sealedAuthorization);
  const run = completion.issueSyntheticQuiescedRun(() => 1);
  return { ...fixture, prepared, authorized, completion, run };
}

async function writtenCompletionFixture() {
  const fixture = await completionFixture();
  const state = await fixture.completion.captureSyntheticPostState(fixture.run, () => 2);
  const artifact = fixture.completion.compileSyntheticArtifact(fixture.run, state, () => 3);
  const reservation = await fixture.completion.reserveOutput(fixture.run, () => 4);
  const output = await fixture.completion.writeReservedArtifact(fixture.run, reservation, artifact, () => 5);
  return { ...fixture, state, artifact, outputIntent: fixture.output, output };
}

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
    await new Promise<void>((resolve) => setTimeout(resolve, 10));
  }
  throw new Error('Graph approval was not published');
}

async function writeSyntheticLock(workspaceRoot: string): Promise<void> {
  const integrity = `sha512-${Buffer.alloc(64, 9).toString('base64')}`;
  await writeFile(join(workspaceRoot, 'package-lock.json'), canonicalJson({
    name: 'fixture', version: '1.0.0', lockfileVersion: 3, requires: true,
    packages: {
      '': { name: 'fixture', version: '1.0.0', dependencies: { '@modelcontextprotocol/server-filesystem': '2026.7.10' } },
      'node_modules/@modelcontextprotocol/server-filesystem': {
        version: '2026.7.10',
        resolved: 'https://registry.npmjs.org/@modelcontextprotocol/server-filesystem/-/server-filesystem-2026.7.10.tgz', integrity,
      },
    },
  }), { mode: 0o600 });
  await chmod(join(workspaceRoot, 'package-lock.json'), 0o600);
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
      'authenticates', 'captureConcreteRuntimeSeed', 'claimConcreteRuntimeSeed', 'constructConcreteSnapshot',
      'constructor', 'prepare', 'revalidate', 'revalidateConcreteImmutable',
    ]);
    expect(Object.getOwnPropertyNames(ProductionGraphGenesisV2SessionAuthority.prototype).sort()).toEqual([
      'authenticatesPrepared', 'authenticatesSealed', 'authenticatesSnapshot', 'authorize',
      'captureOutputIntent', 'closeContext', 'closeOutputIntent', 'constructor', 'createContext', 'createDormantConcreteExecution', 'createDormantMockedExecution', 'createSyntheticCompletion',
      'prepare', 'prepareConcrete', 'prepareConcreteRoot', 'revalidateSnapshot',
    ]);
    expect(Object.getOwnPropertyNames(ProductionGraphGenesisV2SessionAuthority.prototype))
      .not.toContain('createCompletionFoundation');
    expect(snapshots.authenticates(unowned)).toBe(false);
    await expect(snapshots.revalidate(unowned, {
      monotonicNow: () => 0.5,
      deadline: 1,
    })).rejects.toThrow(INVALID);
  });
});

/** The first concrete unit uses only module-mocked listener/process boundaries and disposable SQLite. */
async function concreteFixture(options: { signal?: AbortSignal; outcome?: 'approved' | 'denied'; beforeDecision?: (request: { expiresAt: string }) => void } = {}) {
  let owned!: {
    sessions: ProductionGraphGenesisV2SessionAuthority; context: Awaited<ReturnType<ProductionGraphGenesisV2SessionAuthority['createContext']>>;
    concreteRoot: Awaited<ReturnType<ProductionGraphGenesisV2SessionAuthority['prepareConcreteRoot']>>;
    source: ReturnType<typeof openExistingGraphGenesisAuditDatabase>; dashboardStarts: DashboardStart[];
  };
  const f = await createFixture(async (authority, rootPath) => {
    const dashboardStarts = installDashboardMock();
    const source = await createAuditSource(rootPath);
    const sessions = new ProductionGraphGenesisV2SessionAuthority(authority);
    const context = await sessions.createContext(source);
    const root = await sessions.prepareConcreteRoot(context);
    owned = { sessions, context, concreteRoot: root, source, dashboardStarts };
    cleanupActions.push(async () => { try { await sessions.closeContext(context); } catch { /* already revoked */ } });
    return root.brokerPort;
  });
  const outputParent = join(f.root, 'concrete-output');
  await mkdir(outputParent, { mode: 0o700 });
  const outputPath = join(outputParent, 'candidate.json');
  const output = await owned.sessions.captureOutputIntent(owned.context, outputPath);
  const seed = f.production.captureConcreteRuntimeSeed(runtimeSeedInput(f));
  const capture = vi.spyOn(f.production, 'prepare');
  const prepared = await owned.sessions.prepareConcrete(owned.concreteRoot, seed, owned.context, output);
  const bundle = capture.mock.calls.at(-1)![0];
  const snapshot = capture.mock.results.at(-1)!.value as typeof f.snapshot;
  let audit!: ReturnType<SqliteAuditRecorder['begin']>;
  vi.spyOn(SqliteAuditRecorder.prototype, 'begin').mockImplementation(function (this: SqliteAuditRecorder, ...args) {
    audit = originalAuditBegin.apply(this, args); return audit;
  });
  const pending = owned.sessions.authorize(prepared, options.signal ? { signal: options.signal } : {});
  void pending.catch(() => {}); // Observe rejection before any bounded wait for publication.
  const fixture = { ...f, bundle, snapshot, ...owned, output, outputParent, outputPath };
  const request = await waitForGraphApproval(fixture);
  options.beforeDecision?.(request);
  dashboardApprovals(fixture).decide(request.id, options.outcome ?? 'approved');
  const authorized = await pending;
  return { ...fixture, prepared, authorized, audit };
}
async function concreteExecutionFixture(signal?: AbortSignal) {
  const f = await concreteFixture(signal ? { signal } : {});
  if (f.authorized.status !== 'authorized') throw new Error('fixture authorization missing');
  const seal = f.authorized.sealedAuthorization;
  const execution = f.sessions.createDormantConcreteExecution(f.prepared, seal);
  return { ...f, seal, execution };
}
function concreteRows(f: Awaited<ReturnType<typeof concreteFixture>>) {
  return f.source.database.prepare('SELECT event_type,event_json FROM audit_events WHERE tool_call_id=? ORDER BY sequence')
    .all(f.authorized.actionId) as Array<{ event_type: string; event_json: string }>;
}
function concreteServer() {
  return vi.mocked(createServer).mock.results.at(-1)!.value as EventEmitter & {
    close: ReturnType<typeof vi.fn>; getConnections: ReturnType<typeof vi.fn>;
  };
}
function concreteChild() {
  return vi.mocked(spawn).mock.results.at(-1)!.value as EventEmitter & {
    stdout: PassThrough; stderr: PassThrough; kill: ReturnType<typeof vi.fn>;
  };
}
async function awaitConcreteSpawn() {
  await awaitConcreteCondition(() => vi.mocked(spawn).mock.calls.length > 0);
}
async function awaitConcreteCondition(condition: () => boolean, timeoutMs = 5_000) {
  const deadline = performance.now() + timeoutMs;
  while (performance.now() < deadline) {
    if (condition()) return;
    await new Promise<void>(resolve => setImmediate(resolve));
  }
  throw new Error('mocked lifecycle condition was not reached');
}
describeMac('concrete failure owner first unit', () => {
  it('accepts its own append-only authorization journal while the initial source predicate rejects it', async () => {
    const f = await concreteExecutionFixture();
    expect(auditDatabaseModule.revalidatesExistingGraphGenesisAuditDatabase(f.source)).toBe(false);
    const result = await f.execution.execute();
    expect(result).toMatchObject({ terminalStatus: 'execution_error', childAttempted: true, childCreated: true,
      childCloseObserved: true, exitCode: 0, reconciliation: 'proven' });
    expect(result).not.toHaveProperty('evidenceOrigin');
    expect(result).not.toHaveProperty('artifactDigest');
    expect(await pathExists(f.outputPath)).toBe(false);
    const rows = concreteRows(f);
    expect(rows.map(r => r.event_type).filter(t => t === 'execution_start_recorded')).toHaveLength(1);
    expect(rows.map(r => r.event_type).filter(t => t === 'outcome_receipt_finalized')).toHaveLength(1);
    const summary = JSON.parse(rows.find(r => r.event_type === 'execution_completed')!.event_json).details;
    expect(summary.metadata.externalReadStatus).toBe('not_started');
    expect(summary.process).toMatchObject({ status: 'completed', exitCode: 0 });
    expect(concreteServer().close).toHaveBeenCalledTimes(1);
    expect(vi.mocked(spawn).mock.calls[0]![1]).toContain('--prefix=' + f.bundle.workspace.rootRealpath);
  });

  it('rejects parallel/reentrant execute and seal replay without a second effect', async () => {
    const f = await concreteExecutionFixture();
    const first = f.execution.execute();
    await expect(f.execution.execute()).rejects.toThrow(INVALID);
    await first;
    await expect(f.execution.execute()).rejects.toThrow(INVALID);
    expect(() => f.sessions.createSyntheticCompletion(f.prepared, f.seal)).toThrow(INVALID);
    expect(() => f.sessions.createDormantConcreteExecution(f.prepared, { ...f.seal })).toThrow(INVALID);
    expect(spawn).toHaveBeenCalledTimes(1);
    const Constructor = Object.getPrototypeOf(f.execution).constructor;
    expect(() => new Constructor(Symbol(), {}, {}, {}, {}, {}, () => true)).toThrow();
  });

  it.each(['tamper', 'same-action-extra', 'cross-action'] as const)('rejects %s before effects and does not repair the DB', async (mode) => {
    const f = await concreteExecutionFixture();
    if (mode === 'tamper') f.source.database.prepare("UPDATE audit_events SET event_json='{}' WHERE tool_call_id=?").run(f.authorized.actionId);
    else if (mode === 'same-action-extra') f.audit.appendEvidence('graph_genesis_unexpected_owner_append', {});
    else {
      const recorder = new SqliteAuditRecorder(f.source.database, () => new Date(), 'immediate');
      const foreign = recorder.begin({ serverId: 'foreign', toolName: 'foreign', arguments: {} }, {
        action: 'forward', evaluation: { baseDecision: 'allow', effectiveDecision: 'allow',
          reasonCodes: [], risk: { score: 0, band: 'low', signals: [] } },
      });
      foreign.appendEvidence('graph_genesis_foreign_append', {});
    }
    const finalize = vi.spyOn(f.audit, 'finalizeGraphGenesisOutcome');
    const result = await f.execution.execute();
    expect(result.terminalStatus).toBe('outcome_unknown_after_interruption');
    expect(spawn).not.toHaveBeenCalled();
    expect(finalize).not.toHaveBeenCalled();
    expect(result.reconciliation).toBe('unknown');
  });

  it('revalidates protected files before durable start and before spawn', async () => {
    const f = await concreteExecutionFixture();
    await writeFile(join(f.bundle.workspace.rootRealpath, 'package.json'), '{}');
    const result = await f.execution.execute();
    expect(result.childAttempted).toBe(false);
    expect(spawn).not.toHaveBeenCalled();
    expect(concreteRows(f).some(r => r.event_type === 'execution_start_recorded')).toBe(false);
  });

  it('revokes before start with no terminal write and releases the original listener', async () => {
    const signal = new AbortController(); const f = await concreteExecutionFixture(signal.signal);
    const finalize = vi.spyOn(f.audit, 'finalizeGraphGenesisOutcome');
    signal.abort();
    const result = await f.execution.execute();
    expect(result.childAttempted).toBe(false);
    expect(finalize).not.toHaveBeenCalled();
    expect(spawn).not.toHaveBeenCalled();
    expect(concreteServer().close).toHaveBeenCalledTimes(1);
  });

  it.each(['context', 'output'] as const)('revokes %s immediately and retains custody until child close and terminal', async kind => {
    concreteBoundary.childMode = 'hold';
    const f = await concreteExecutionFixture();
    const opening = vi.mocked(fixtureFs.open).mock.calls.findLastIndex(args => args[0] === f.outputParent);
    const descriptor = await vi.mocked(fixtureFs.open).mock.results[opening]!.value;
    const closeDescriptor = vi.spyOn(descriptor, 'close');
    concreteBoundary.onKill = () => { expect(closeDescriptor).not.toHaveBeenCalled(); };
    const first = f.execution.execute(); await awaitConcreteSpawn();
    let completed = false;
    const close = (kind === 'context' ? f.sessions.closeContext(f.context) : f.sessions.closeOutputIntent(f.output))
      .then(() => { completed = true; });
    expect(f.sessions.authenticatesSealed(f.seal, f.prepared)).toBe(false);
    await close; const result = await first;
    expect(completed).toBe(true);
    expect(result).toMatchObject({ childCloseObserved: true, exitCode: null, reconciliation: 'proven' });
    expect(concreteChild().kill).toHaveBeenCalledWith('SIGTERM');
    expect(concreteRows(f).filter(r => r.event_type === 'outcome_receipt_finalized')).toHaveLength(1);
    expect(closeDescriptor).toHaveBeenCalledTimes(1);
  });

  it.each(['throw', 'error', 'error-before-spawn', 'overflow'] as const)('handles child %s using one factual terminal', async mode => {
    concreteBoundary.childMode = mode;
    const f = await concreteExecutionFixture(); const finalize = vi.spyOn(f.audit, 'finalizeGraphGenesisOutcome');
    const result = await f.execution.execute();
    expect(result.terminalStatus).toBe('execution_error');
    expect(result.childAttempted).toBe(true);
    expect(result.childCreated).toBe(mode !== 'throw' && mode !== 'error-before-spawn');
    expect(result.exitCode).toBe(null);
    expect(finalize).toHaveBeenCalledTimes(1);
    expect(result.reconciliation).toBe('proven');
    expect(JSON.stringify(concreteRows(f))).not.toContain('private spawn detail');
    expect(JSON.stringify(concreteRows(f))).not.toContain('private asynchronous detail');
    if (mode === 'overflow') expect(result.stdoutBytes).toBe(256 * 1024);
  });

  it.each([false, true])('bounds no-close deadline and TERM ignored (all signals ignored=%s)', async ignored => {
    concreteBoundary.childMode = 'hold'; concreteBoundary.termIgnored = true; concreteBoundary.allSignalsIgnored = ignored;
    const f = await concreteExecutionFixture(); const signal = new AbortController();
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const first = f.execution.execute(); await awaitConcreteSpawn();
    await vi.advanceTimersByTimeAsync(140_000);
    const result = await first;
    expect(concreteChild().kill.mock.calls.map(c => c[0])).toEqual(['SIGTERM', 'SIGKILL']);
    expect(result.childCloseObserved).toBe(!ignored);
    expect(result.exitCode).toBe(null);
    expect(result.terminalStatus).toBe(ignored ? 'outcome_unknown_after_interruption' : 'execution_error');
    expect(vi.getTimerCount()).toBe(0);
    void signal;
  });

  it('start commit-then-throw performs zero effects, no finalize, and one readonly reconciliation', async () => {
    const f = await concreteExecutionFixture();
    const start = f.audit.markExecutionStarted;
    vi.spyOn(f.audit, 'markExecutionStarted').mockImplementation(() => { start(); throw new Error('private uncertain start'); });
    const finalize = vi.spyOn(f.audit, 'finalizeGraphGenesisOutcome'), failed = vi.spyOn(f.audit, 'markFailed');
    const readonly = vi.spyOn(auditDatabaseModule, 'openAuditDatabaseReadOnly');
    const result = await f.execution.execute();
    expect(result.terminalStatus).toBe('outcome_unknown_after_interruption');
    expect(spawn).not.toHaveBeenCalled(); expect(finalize).not.toHaveBeenCalled(); expect(failed).not.toHaveBeenCalled();
    expect(readonly).toHaveBeenCalledTimes(1);
    expect(concreteRows(f).filter(r => r.event_type === 'execution_start_recorded')).toHaveLength(1);
  });

  it('terminal commit-then-throw reconciles the exact receipt once without second finalize', async () => {
    const f = await concreteExecutionFixture();
    const terminal = f.audit.finalizeGraphGenesisOutcome;
    const finalize = vi.spyOn(f.audit, 'finalizeGraphGenesisOutcome').mockImplementation((...args) => {
      terminal(...args); throw new Error('private uncertain terminal');
    });
    const readonly = vi.spyOn(auditDatabaseModule, 'openAuditDatabaseReadOnly');
    const result = await f.execution.execute();
    expect(finalize).toHaveBeenCalledTimes(1); expect(readonly).toHaveBeenCalledTimes(1);
    expect(result).toMatchObject({ terminalStatus: 'execution_error', reconciliation: 'proven' });
  });

  it('readonly proof failure returns unknown without fallback writes', async () => {
    const f = await concreteExecutionFixture();
    const finalize = vi.spyOn(f.audit, 'finalizeGraphGenesisOutcome');
    vi.spyOn(auditDatabaseModule, 'openAuditDatabaseReadOnly').mockImplementation(() => { throw new Error('private readonly error'); });
    const result = await f.execution.execute();
    expect(result).toMatchObject({ terminalStatus: 'outcome_unknown_after_interruption', reconciliation: 'unknown' });
    expect(finalize).toHaveBeenCalledTimes(1);
  });

  it('does not prove a prefix-only journal after transient verify-before-finalize failure', async () => {
    const f = await concreteExecutionFixture();
    const prepare = f.source.database.prepare.bind(f.source.database);
    let afterSpawn = false, chainReads = 0;
    concreteBoundary.onSpawn = () => { afterSpawn = true; };
    vi.spyOn(f.source.database, 'prepare').mockImplementation((sql: string) => {
      if (afterSpawn && sql.includes('SELECT count(*) FROM (SELECT 1 FROM audit_events LIMIT 16385)')
        && ++chainReads === 2) throw new Error('transient pre-finalize read failure');
      return prepare(sql);
    });
    const finalize = vi.spyOn(f.audit, 'finalizeGraphGenesisOutcome');
    const result = await f.execution.execute();
    expect(finalize).not.toHaveBeenCalled();
    expect(concreteRows(f).filter(r => r.event_type === 'outcome_receipt_finalized')).toHaveLength(0);
    expect(result).toMatchObject({ terminalStatus: 'outcome_unknown_after_interruption', reconciliation: 'unknown' });
  });

  it('bounds an unresolved output-parent read and retains its descriptor custody until settlement', async () => {
    const caller = new AbortController(); const f = await concreteExecutionFixture(caller.signal);
    const original = (await vi.importActual<typeof import('node:fs/promises')>('node:fs/promises')).lstat;
    let release!: () => void, reached = false;
    const held = new Promise<void>(resolve => { release = resolve; });
    vi.spyOn(fixtureFs, 'lstat').mockImplementation(((path: Parameters<typeof original>[0], ...args: unknown[]) => {
      if (path === f.outputParent && !reached) {
        reached = true; return held.then(() => Reflect.apply(original, fixtureFs, [path, ...args]));
      }
      return Reflect.apply(original, fixtureFs, [path, ...args]);
    }) as typeof original);
    const first = f.execution.execute();
    await awaitConcreteCondition(() => reached);
    caller.abort();
    const raced = await Promise.race([first, new Promise<'held'>(resolve => setTimeout(() => resolve('held'), 250))]);
    release();
    expect(raced).not.toBe('held');
    expect(raced).toMatchObject({ terminalStatus: 'outcome_unknown_after_interruption', reconciliation: 'unknown' });
    await first;
  });

  it.each(['hold', 'zero'] as const)('bounds original listener drain callbacks (connections=%s)', async mode => {
    const f = await concreteExecutionFixture();
    concreteBoundary.connectionsMode = mode; concreteBoundary.closeMode = 'hold';
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const first = f.execution.execute(); await awaitConcreteSpawn();
    await awaitConcreteCondition(() => concreteServer().getConnections.mock.calls.length > 0);
    await vi.advanceTimersByTimeAsync(6_000);
    const result = await first;
    expect(result.terminalStatus).toBe('outcome_unknown_after_interruption');
    expect(concreteServer().close).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('denial releases the original disarmed listener without a child', async () => {
    const f = await concreteFixture({ outcome: 'denied' });
    expect(f.authorized.status).toBe('denied');
    expect(concreteServer().close).toHaveBeenCalledTimes(1); expect(spawn).not.toHaveBeenCalled();
  });

  it('handles synchronous spawn reentry and caller abort without a second dispatch', async () => {
    concreteBoundary.childMode = 'hold';
    const caller = new AbortController(); const f = await concreteExecutionFixture(caller.signal);
    let rejected!: Promise<unknown>;
    concreteBoundary.onSpawn = () => {
      rejected = f.execution.execute().catch(error => error);
      caller.abort();
    };
    const result = await f.execution.execute();
    expect(await rejected).toBeInstanceOf(Error);
    expect(result).toMatchObject({ childAttempted: true, childCreated: true, childCloseObserved: true, reconciliation: 'proven' });
    expect(spawn).toHaveBeenCalledTimes(1);
    expect(concreteChild().kill).toHaveBeenCalledTimes(1);
  });

  it.each([Number.NaN, Number.POSITIVE_INFINITY, -1, -0, 0])('fails closed for invalid/backward monotonic time %s', async now => {
    const f = await concreteExecutionFixture();
    vi.spyOn(performance, 'now').mockReturnValue(now);
    const result = await f.execution.execute();
    expect(result.terminalStatus).toBe('outcome_unknown_after_interruption');
    expect(spawn).not.toHaveBeenCalled();
    expect(concreteRows(f).some(row => row.event_type === 'execution_start_recorded')).toBe(false);
  });

  it.each(['start', 'arm', 'spawn'] as const)('rejects exact start-window equality at %s with no later effect', async phase => {
    let clock = performance.now() + 100;
    let decidedAt = clock;
    const f = await concreteFixture({ beforeDecision: () => {
      clock = performance.now() + 100; decidedAt = clock; vi.spyOn(performance, 'now').mockImplementation(() => clock);
    } });
    if (f.authorized.status !== 'authorized') throw new Error('fixture authorization missing');
    const execution = f.sessions.createDormantConcreteExecution(f.prepared, f.authorized.sealedAuthorization);
    if (phase === 'start') clock = decidedAt + 15_000;
    else if (phase === 'arm') {
      const original = f.audit.markExecutionStarted;
      vi.spyOn(f.audit, 'markExecutionStarted').mockImplementation(() => { original(); clock = decidedAt + 15_000; });
    } else {
      const original = f.audit.appendEvidence;
      vi.spyOn(f.audit, 'appendEvidence').mockImplementation((type, details) => {
        original(type, details); if (type === 'graph_genesis_v2_spawn_intent') clock = decidedAt + 15_000;
      });
    }
    const result = await execution.execute();
    expect(spawn).not.toHaveBeenCalled();
    const events = concreteRows(f).map(row => row.event_type);
    expect(events.includes('execution_start_recorded')).toBe(phase !== 'start');
    if (phase === 'arm') expect(events).not.toContain('graph_genesis_v2_broker_arm_intent');
    expect(result.terminalStatus).toBe(phase === 'start' ? 'outcome_unknown_after_interruption' : 'execution_error');
  });

  it('uses the execution window after spawn without reapplying the 15-second start window', async () => {
    let clock = performance.now() + 100, decidedAt = clock;
    const f = await concreteFixture({ beforeDecision: () => {
      clock = performance.now() + 100; decidedAt = clock; vi.spyOn(performance, 'now').mockImplementation(() => clock);
    } });
    if (f.authorized.status !== 'authorized') throw new Error('fixture authorization missing');
    concreteBoundary.onSpawn = () => { clock = decidedAt + 20_000; };
    const result = await f.sessions.createDormantConcreteExecution(f.prepared, f.authorized.sealedAuthorization).execute();
    expect(result).toMatchObject({ childCreated: true, childCloseObserved: true, exitCode: 0, reconciliation: 'proven' });
    const summary = JSON.parse(concreteRows(f).find(row => row.event_type === 'execution_completed')!.event_json).details;
    expect(summary.process.status).toBe('completed');
  });

  it('expires the absolute 120-second execution budget at equality without granting a new window', async () => {
    let clock = performance.now() + 100, decidedAt = clock;
    const f = await concreteFixture({ beforeDecision: () => {
      clock = performance.now() + 100; decidedAt = clock; vi.spyOn(performance, 'now').mockImplementation(() => clock);
    } });
    if (f.authorized.status !== 'authorized') throw new Error('fixture authorization missing');
    concreteBoundary.childMode = 'hold';
    concreteBoundary.onSpawn = () => { clock = decidedAt + 120_000; };
    const result = await f.sessions.createDormantConcreteExecution(f.prepared, f.authorized.sealedAuthorization).execute();
    expect(result).toMatchObject({ childCreated: true, childCloseObserved: true, reconciliation: 'proven' });
    expect(concreteChild().kill).toHaveBeenCalledWith('SIGTERM');
    const summary = JSON.parse(concreteRows(f).find(row => row.event_type === 'execution_completed')!.event_json).details;
    expect(summary.process.status).toBe('timed_out');
  });

  it('does not rerun initial empty-workspace/probe predicates after child close', async () => {
    concreteBoundary.childMode = 'hold'; const f = await concreteExecutionFixture();
    let spawned = false; concreteBoundary.onSpawn = () => { spawned = true; };
    const initial = f.workspaces.revalidateInitial.bind(f.workspaces);
    const check = vi.spyOn(f.workspaces, 'revalidateInitial').mockImplementation(async workspace => {
      if (spawned) throw new Error('post-child initial predicate forbidden'); await initial(workspace);
    });
    const first = f.execution.execute(); await awaitConcreteSpawn();
    await writeFile(join(f.bundle.workspace.rootRealpath, 'package-lock.json'), '{}', { mode: 0o600 });
    concreteChild().emit('close', 0, null);
    const result = await first;
    expect(check).toHaveBeenCalled();
    expect(result).toMatchObject({ childCloseObserved: true, reconciliation: 'proven' });
    expect(await pathExists(f.outputPath)).toBe(false);
  });

  it('reconciles readonly close failure to unknown and still disposes run timers', async () => {
    const f = await concreteExecutionFixture();
    const open = auditDatabaseModule.openAuditDatabaseReadOnly;
    vi.spyOn(auditDatabaseModule, 'openAuditDatabaseReadOnly').mockImplementation(path => {
      const db = open(path); const close = db.close.bind(db);
      vi.spyOn(db, 'close').mockImplementation(() => { close(); throw new Error('private readonly close failure'); });
      return db;
    });
    const result = await f.execution.execute();
    expect(result).toMatchObject({ terminalStatus: 'outcome_unknown_after_interruption', reconciliation: 'unknown' });
    expect(concreteServer().close).toHaveBeenCalledTimes(1);
    expect(concreteRows(f).filter(row => row.event_type === 'outcome_receipt_finalized')).toHaveLength(1);
  });

  it('real approval expiry releases the disarmed listener without minting a seal', async () => {
    const f = await concreteFixture({ beforeDecision: request => {
      vi.useFakeTimers({ toFake: ['Date'] }); vi.setSystemTime(new Date(request.expiresAt));
    } });
    expect(f.authorized.status).toBe('expired');
    expect(concreteServer().close).toHaveBeenCalledTimes(1);
    expect(spawn).not.toHaveBeenCalled();
  });

  it.each(['error', 'hold'] as const)('bounds failed original listener preparation (%s)', async mode => {
    const f = await createPreparationFixture();
    concreteBoundary.listenMode = mode;
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const pending = f.sessions.prepareConcreteRoot(f.context);
    const observed = pending.catch(error => error);
    await vi.advanceTimersByTimeAsync(126_000);
    expect(await observed).toBeInstanceOf(Error);
    expect(concreteServer().close).toHaveBeenCalledTimes(1);
    expect(spawn).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each(['expiry', 'context'] as const)('releases an unattached original root on %s exactly once', async reason => {
    const f = await createPreparationFixture();
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const root = await f.sessions.prepareConcreteRoot(f.context);
    if (reason === 'expiry') await vi.advanceTimersByTimeAsync(126_000);
    else await f.sessions.closeContext(f.context);
    expect(concreteServer().close).toHaveBeenCalledTimes(1);
    expect(spawn).not.toHaveBeenCalled();
    await expect(f.sessions.prepareConcrete(root, f.snapshot as never, f.context, f.output)).rejects.toThrow(INVALID);
    expect(concreteServer().close).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('rejects the removed snapshot input at a later same-port root and releases it on attach failure', async () => {
    const f = await createPreparationFixture();
    const root = await f.sessions.prepareConcreteRoot(f.context);
    expect(root.brokerPort).toBe(f.bundle.containmentProfile.allowedPort);
    await expect(f.sessions.prepareConcrete(root, f.snapshot as never, f.context, f.output)).rejects.toThrow(INVALID);
    expect(concreteServer().close).toHaveBeenCalledTimes(1);
    await expect(f.sessions.prepareConcrete(root, f.snapshot as never, f.context, f.output)).rejects.toThrow(INVALID);
    expect(concreteServer().close).toHaveBeenCalledTimes(1);
    expect(spawn).not.toHaveBeenCalled();
  });

  it('refuses cross-session and copied prepared/seal pairs before creating an execution owner', async () => {
    const first = await concreteFixture(), second = await concreteFixture();
    if (first.authorized.status !== 'authorized' || second.authorized.status !== 'authorized') throw new Error('fixture authorization missing');
    expect(() => first.sessions.createDormantConcreteExecution(first.prepared, second.authorized.status === 'authorized'
      ? second.authorized.sealedAuthorization : {} as never)).toThrow(INVALID);
    expect(() => first.sessions.createDormantConcreteExecution({ ...first.prepared }, first.authorized.status === 'authorized'
      ? first.authorized.sealedAuthorization : {} as never)).toThrow(INVALID);
    expect(spawn).not.toHaveBeenCalled();
  });

  it('does not retry a start failure that did not commit', async () => {
    const f = await concreteExecutionFixture();
    const start = vi.spyOn(f.audit, 'markExecutionStarted').mockImplementation(() => { throw new Error('private start failure'); });
    const finalize = vi.spyOn(f.audit, 'finalizeGraphGenesisOutcome');
    const result = await f.execution.execute();
    expect(result.terminalStatus).toBe('outcome_unknown_after_interruption');
    expect(start).toHaveBeenCalledTimes(1); expect(finalize).not.toHaveBeenCalled();
    expect(spawn).not.toHaveBeenCalled();
    expect(concreteRows(f).some(row => row.event_type === 'execution_start_recorded')).toBe(false);
  });

  it.each(['graph_genesis_v2_broker_arm_intent', 'graph_genesis_v2_spawn_intent'])('does not progress after uncertain %s append', async type => {
    const f = await concreteExecutionFixture(); const append = f.audit.appendEvidence;
    vi.spyOn(f.audit, 'appendEvidence').mockImplementation((eventType, details) => {
      append(eventType, details); if (eventType === type) throw new Error('private uncertain append');
    });
    const result = await f.execution.execute();
    expect(result.terminalStatus).toBe('outcome_unknown_after_interruption');
    expect(spawn).not.toHaveBeenCalled();
    expect(concreteRows(f).filter(row => row.event_type === type)).toHaveLength(1);
    expect(concreteRows(f).some(row => row.event_type === 'outcome_receipt_finalized')).toBe(false);
  });

  it('rejects post-child protected bytes drift without creating an Artifact2', async () => {
    concreteBoundary.childMode = 'hold'; const f = await concreteExecutionFixture();
    const first = f.execution.execute(); await awaitConcreteSpawn();
    await writeFile(join(f.bundle.workspace.rootRealpath, 'package.json'), '{}');
    concreteChild().emit('close', 0, null);
    const result = await first;
    expect(result).toMatchObject({ terminalStatus: 'execution_error', childCloseObserved: true, reconciliation: 'proven' });
    const summary = JSON.parse(concreteRows(f).find(row => row.event_type === 'execution_completed')!.event_json).details;
    expect(summary.errorCode).toBe('graph_genesis_v2_revalidation_failed');
    expect(await pathExists(f.outputPath)).toBe(false);
  });

  it('rejects clock decrease after sealing even when still later than root creation', async () => {
    let clock = 0;
    const f = await concreteFixture({ beforeDecision: () => { clock = performance.now() + 1_000; vi.spyOn(performance, 'now').mockImplementation(() => clock); } });
    if (f.authorized.status !== 'authorized') throw new Error('fixture authorization missing');
    clock -= 100;
    const result = await f.sessions.createDormantConcreteExecution(f.prepared, f.authorized.sealedAuthorization).execute();
    expect(result.terminalStatus).toBe('outcome_unknown_after_interruption');
    expect(spawn).not.toHaveBeenCalled();
  });

  it('shares one descriptor disposal when context and output close reenter concurrently', async () => {
    concreteBoundary.childMode = 'hold'; const f = await concreteExecutionFixture();
    const index = vi.mocked(fixtureFs.open).mock.calls.findLastIndex(args => args[0] === f.outputParent);
    const descriptor = await vi.mocked(fixtureFs.open).mock.results[index]!.value;
    const dispose = vi.spyOn(descriptor, 'close');
    const first = f.execution.execute(); await awaitConcreteSpawn();
    const outputClosed = f.sessions.closeOutputIntent(f.output);
    const contextClosed = f.sessions.closeContext(f.context);
    await Promise.all([first, outputClosed, contextClosed]);
    expect(dispose).toHaveBeenCalledTimes(1);
    expect(concreteChild().kill).toHaveBeenCalledTimes(1);
    expect(concreteServer().close).toHaveBeenCalledTimes(1);
  });

  it('bounds context close while an underlying read remains pending and releases its descriptor only later', async () => {
    const caller = new AbortController(); const f = await concreteExecutionFixture(caller.signal);
    const index = vi.mocked(fixtureFs.open).mock.calls.findLastIndex(args => args[0] === f.outputParent);
    const descriptor = await vi.mocked(fixtureFs.open).mock.results[index]!.value;
    const dispose = vi.spyOn(descriptor, 'close');
    const original = (await vi.importActual<typeof import('node:fs/promises')>('node:fs/promises')).lstat;
    let release!: () => void, reached = false;
    const held = new Promise<void>(resolve => { release = resolve; });
    vi.spyOn(fixtureFs, 'lstat').mockImplementation(((path: Parameters<typeof original>[0], ...args: unknown[]) => {
      if (path === f.outputParent && !reached) {
        reached = true; return held.then(() => Reflect.apply(original, fixtureFs, [path, ...args]));
      }
      return Reflect.apply(original, fixtureFs, [path, ...args]);
    }) as typeof original);
    const first = f.execution.execute(); await awaitConcreteCondition(() => reached);
    caller.abort();
    expect(await first).toMatchObject({ terminalStatus: 'outcome_unknown_after_interruption', reconciliation: 'unknown' });
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const closed = f.sessions.closeContext(f.context).catch(error => error);
    await vi.advanceTimersByTimeAsync(6_000);
    expect(await closed).toBeInstanceOf(Error);
    expect(dispose).not.toHaveBeenCalled();
    release();
    await awaitConcreteCondition(() => dispose.mock.calls.length === 1);
    expect(dispose).toHaveBeenCalledTimes(1);
  });

  it('rejects a rehashed Outcome receipt whose startedAt is later than its actual execution_start event', async () => {
    const f = await concreteExecutionFixture();
    const open = auditDatabaseModule.openAuditDatabaseReadOnly;
    vi.spyOn(auditDatabaseModule, 'openAuditDatabaseReadOnly').mockImplementation(path => {
      const rows = f.source.database.prepare('SELECT sequence,event_json FROM audit_events ORDER BY sequence').all() as
        Array<{ sequence: number; event_json: string }>;
      const parsed = rows.map(row => JSON.parse(row.event_json));
      const start = parsed.find(event => event.eventType === 'execution_start_recorded');
      const outcome = parsed.find(event => event.eventType === 'outcome_receipt_finalized');
      outcome.details.receipt.execution.startedAt = new Date(Date.parse(start.createdAt) + 1).toISOString();
      outcome.details.receiptDigest = receiptDigest(outcome.details.receipt);
      parsed.find(event => event.eventType === 'graph_genesis_incomplete').details.outcomeReceiptDigest = outcome.details.receiptDigest;
      let tail = '0'.repeat(64);
      for (let i = 0; i < rows.length; i++) {
        const json = canonicalJson(parsed[i]); const hash = createHash('sha256').update(tail + '\n' + json).digest('hex');
        f.source.database.prepare('UPDATE audit_events SET event_json=?,previous_hash=?,event_hash=? WHERE sequence=?')
          .run(json, tail, hash, rows[i]!.sequence); tail = hash;
      }
      return open(path);
    });
    const result = await f.execution.execute();
    expect(result).toMatchObject({ terminalStatus: 'outcome_unknown_after_interruption', reconciliation: 'unknown' });
  });
});

function runtimeSeedInput(f: Fixture) {
  return { files: f.bundle.files, trees: f.bundle.trees, host: f.bundle.host, runtimeVersions: f.bundle.runtimeVersions };
}
async function rootPreparationFixture() {
  const f = await createPreparationFixture();
  const seed = f.production.captureConcreteRuntimeSeed(runtimeSeedInput(f));
  const root = await f.sessions.prepareConcreteRoot(f.context);
  const destination = join(f.outputParent, '.apg-graph-genesis-v2-workspace');
  return { ...f, seed, concreteRoot: root, destination };
}
describeMac('root-owned preparation lineage', () => {
  it('rejects an authentic old tuple rewrapped after a same-port root instead of trusting snapshot order', async () => {
    const f = await createPreparationFixture();
    const root = await f.sessions.prepareConcreteRoot(f.context);
    const rewrapped = f.production.prepare(f.bundle);
    expect(rewrapped.runtimeManifestDigest).toBe(f.snapshot.runtimeManifestDigest);
    expect(root.brokerPort).toBe(f.bundle.containmentProfile.allowedPort);
    await expect(f.sessions.prepareConcrete(root, rewrapped as never, f.context, f.output)).rejects.toThrow(INVALID);
    expect(spawn).not.toHaveBeenCalled();
  });

  it('exposes opaque runtime seed capture rather than a raw concrete snapshot input', async () => {
    const f = await createPreparationFixture();
    expect(typeof (f.production as unknown as Record<string, unknown>).captureConcreteRuntimeSeed).toBe('function');
  });

  it('rejects an invalid audit source before any workspace or containment construction', async () => {
    const f = await rootPreparationFixture();
    const initialize = vi.spyOn(f.workspaces, 'initialize');
    const observe = vi.spyOn(f.containments, 'observe');
    f.source.database.close();
    await expect(f.sessions.prepareConcrete(f.concreteRoot, f.seed, f.context, f.output)).rejects.toThrow(INVALID);
    expect(initialize).not.toHaveBeenCalled(); expect(observe).not.toHaveBeenCalled();
    expect(await pathExists(f.destination)).toBe(false);
  });

  it.each(['host', 'runtimeVersions'] as const)('rejects unauthenticated %s without reading its getters or proxy traps', async key => {
    const f = await createPreparationFixture();
    const get = vi.fn(() => { throw new Error('private unauthenticated getter'); });
    const input = runtimeSeedInput(f);
    const raw = Object.defineProperty({}, 'platform', { get });
    for (const value of [raw, new Proxy({}, { get })]) {
      expect(() => f.production.captureConcreteRuntimeSeed({ ...input, [key]: value } as never)).toThrow(INVALID);
    }
    expect(get).not.toHaveBeenCalled();
  });

  it('retains descriptor custody and stops nested revalidation after an output-revoked late file read', async () => {
    const f = await rootPreparationFixture();
    const index = vi.mocked(fixtureFs.open).mock.calls.findLastIndex(args => args[0] === f.outputParent);
    const descriptor = await vi.mocked(fixtureFs.open).mock.results[index]!.value;
    const dispose = vi.spyOn(descriptor, 'close');
    let nested = false, reached = false, release!: () => void;
    const held = new Promise<void>(resolve => { release = resolve; });
    const revalidate = f.production.revalidate.bind(f.production), file = f.files.revalidate.bind(f.files);
    vi.spyOn(f.production, 'revalidate').mockImplementation((...args) => { nested = true; return revalidate(...args); });
    const files = vi.spyOn(f.files, 'revalidate').mockImplementation(value => {
      if (nested && !reached) { reached = true; return held.then(() => file(value)); }
      return file(value);
    });
    const host = vi.spyOn(f.hosts, 'observe'), version = vi.spyOn(f.versions, 'observe');
    const containment = vi.spyOn(f.containments, 'observe');
    const preparation = f.sessions.prepareConcrete(f.concreteRoot, f.seed, f.context, f.output).catch(error => error);
    await awaitConcreteCondition(() => reached, 15_000);
    const counts = [files.mock.calls.length, host.mock.calls.length, version.mock.calls.length, containment.mock.calls.length];
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const closed = f.sessions.closeOutputIntent(f.output).catch(error => error);
    try {
      expect(await preparation).toBeInstanceOf(Error);
      await vi.advanceTimersByTimeAsync(6_000);
      expect(await closed).toBeInstanceOf(Error); expect(dispose).not.toHaveBeenCalled();
    } finally { release(); }
    await awaitConcreteCondition(() => dispose.mock.calls.length === 1);
    expect([files.mock.calls.length, host.mock.calls.length, version.mock.calls.length, containment.mock.calls.length]).toEqual(counts);
    expect(dispose).toHaveBeenCalledTimes(1);
    expect(await pathExists(f.outputPath)).toBe(false); expect(spawn).not.toHaveBeenCalled();
  });

  it('constructs and binds the exact profile/workspace/containment/snapshot from a write-free seed', async () => {
    const f = await rootPreparationFixture();
    expect(Object.keys(f.seed)).toEqual(['runtimeSeedVersion']);
    expect(Object.isFrozen(f.seed)).toBe(true);
    expect(await pathExists(f.destination)).toBe(false);
    const profile = vi.spyOn(f.profiles, 'prepare'), workspace = vi.spyOn(f.workspaces, 'initialize');
    const containment = vi.spyOn(f.containments, 'observe'), snapshot = vi.spyOn(f.production, 'prepare');
    const prepared = await f.sessions.prepareConcrete(f.concreteRoot, f.seed, f.context, f.output);
    expect(profile).toHaveBeenCalledTimes(1); expect(workspace).toHaveBeenCalledTimes(1);
    expect(snapshot).toHaveBeenCalledTimes(1);
    const created = snapshot.mock.calls[0]![0];
    expect(created.containmentProfile).toBe(profile.mock.results[0]!.value);
    expect(created.workspace).toBe(await workspace.mock.results[0]!.value);
    expect(created.containment).toBe(await containment.mock.results[0]!.value);
    expect(created.host).toBe(f.bundle.host); expect(created.runtimeVersions).toBe(f.bundle.runtimeVersions);
    for (const key of Object.keys(f.bundle.files) as Array<keyof typeof f.bundle.files>) expect(created.files[key]).toBe(f.bundle.files[key]);
    for (const key of Object.keys(f.bundle.trees) as Array<keyof typeof f.bundle.trees>) expect(created.trees[key]).toBe(f.bundle.trees[key]);
    expect(workspace.mock.calls[0]).toEqual([f.destination, created.containmentProfile.profileText]);
    expect(prepared.plan.workspaceBinding).toBe(computeWorkspaceBinding(created.workspace));
    expect(prepared.plan.brokerPort).toBe(f.concreteRoot.brokerPort);
    expect(f.sessions.authenticatesPrepared(prepared)).toBe(true);
    expect(await readFile(join(f.destination, 'package.json'), 'utf8')).toBe(await readFile(join(f.bundle.workspace.rootRealpath, 'package.json'), 'utf8'));
    for (const file of created.workspace.protectedFiles) expect(file.mode).toBe(0o600);
    expect(await pathExists(f.outputPath)).toBe(false); expect(spawn).not.toHaveBeenCalled();
  });

  it.each(['path', 'digest', 'clock', 'callback', 'proof', 'profile', 'workspace', 'snapshot'] as const)(
    'rejects a runtime seed with injected %s before construction', async key => {
      const f = await createPreparationFixture();
      expect(() => f.production.captureConcreteRuntimeSeed({ ...runtimeSeedInput(f), [key]: {} } as never)).toThrow(INVALID);
      expect(spawn).not.toHaveBeenCalled(); expect(createServer).not.toHaveBeenCalled();
    },
  );

  it.each(['missing-file', 'duplicate-file', 'copied-host', 'copied-version', 'missing-tree'] as const)(
    'rejects non-exact seed references (%s)', async kind => {
      const f = await createPreparationFixture(); const input = runtimeSeedInput(f);
      if (kind === 'missing-file') input.files = { ...input.files, node: undefined } as never;
      if (kind === 'duplicate-file') input.files = { ...input.files, probeRuntime: input.files.brokerRuntime };
      if (kind === 'copied-host') input.host = { ...input.host };
      if (kind === 'copied-version') input.runtimeVersions = { ...input.runtimeVersions };
      if (kind === 'missing-tree') input.trees = { ...input.trees, npmTree: undefined } as never;
      expect(() => f.production.captureConcreteRuntimeSeed(input)).toThrow(INVALID);
    },
  );

  it.each(['seed-copy', 'foreign-seed', 'root-copy', 'context-copy', 'output-copy'] as const)(
    'rejects foreign or copied construction capabilities (%s)', async kind => {
      const f = await rootPreparationFixture();
      let seed = f.seed, root = f.concreteRoot, context = f.context, output = f.output;
      if (kind === 'seed-copy') seed = { ...seed };
      if (kind === 'root-copy') root = { ...root };
      if (kind === 'context-copy') context = { ...context };
      if (kind === 'output-copy') output = { ...output };
      if (kind === 'foreign-seed') {
        const foreign = await createPreparationFixture();
        seed = foreign.production.captureConcreteRuntimeSeed(runtimeSeedInput(foreign));
      }
      const initialize = vi.spyOn(f.workspaces, 'initialize');
      await expect(f.sessions.prepareConcrete(root, seed, context, output)).rejects.toThrow(INVALID);
      expect(initialize).not.toHaveBeenCalled(); expect(await pathExists(f.destination)).toBe(false);
    },
  );

  it('rejects token forgery and claims construction before synchronous reentry or parallel calls', async () => {
    const f = await rootPreparationFixture();
    expect(() => f.production.claimConcreteRuntimeSeed(Symbol(), f.seed)).toThrow(INVALID);
    await expect(f.production.constructConcreteSnapshot(Symbol(), {} as never)).rejects.toThrow(INVALID);
    const original = f.profiles.prepare.bind(f.profiles); let reentry!: Promise<unknown>;
    vi.spyOn(f.profiles, 'prepare').mockImplementation(input => {
      reentry = f.sessions.prepareConcrete(f.concreteRoot, f.seed, f.context, f.output).catch(error => error);
      return original(input);
    });
    const first = f.sessions.prepareConcrete(f.concreteRoot, f.seed, f.context, f.output);
    await expect(f.sessions.prepareConcrete(f.concreteRoot, f.seed, f.context, f.output)).rejects.toThrow(INVALID);
    const prepared = await first;
    expect(await reentry).toBeInstanceOf(Error); expect(f.sessions.authenticatesPrepared(prepared)).toBe(true);
    await expect(f.sessions.prepareConcrete(f.concreteRoot, f.seed, f.context, f.output)).rejects.toThrow(INVALID);
    expect(f.profiles.prepare).toHaveBeenCalledTimes(1);
  });

  it.each(['file', 'directory', 'symlink', 'parent-mode', 'parent-replacement', 'runtime-overlap'] as const)(
    'rejects destination/parent invalidity before initialization (%s)', async kind => {
      const f = await rootPreparationFixture();
      let output = f.output;
      if (kind === 'file') await writeFile(f.destination, 'preserve', { mode: 0o600 });
      if (kind === 'directory') await mkdir(f.destination, { mode: 0o700 });
      if (kind === 'symlink') await symlink(f.root, f.destination);
      if (kind === 'parent-mode') await chmod(f.outputParent, 0o755);
      if (kind === 'parent-replacement') { await rename(f.outputParent, f.outputParent + '-retained'); await mkdir(f.outputParent, { mode: 0o700 }); }
      if (kind === 'runtime-overlap') output = await f.sessions.captureOutputIntent(f.context, join(f.bundle.trees.npmTree.rootRealpath, 'candidate.json'));
      const initialize = vi.spyOn(f.workspaces, 'initialize');
      await expect(f.sessions.prepareConcrete(f.concreteRoot, f.seed, f.context, output)).rejects.toThrow(INVALID);
      expect(initialize).not.toHaveBeenCalled();
      if (kind === 'file') expect(await readFile(f.destination, 'utf8')).toBe('preserve');
    },
  );

  it.each(['file', 'tree', 'host', 'version'] as const)('rejects drifted runtime seed before workspace creation (%s)', async kind => {
    const f = await rootPreparationFixture();
    if (kind === 'file') await writeFile(f.paths.node, 'drift');
    if (kind === 'tree') await writeFile(join(f.bundle.trees.webAssets.rootRealpath, 'extra'), 'drift');
    if (kind === 'host') f.hostExecutorSpy.mockResolvedValue({ platform: 'darwin', architecture: 'arm64', osBuild: 'changed', bootSessionId: '12345678-1234-4123-8123-123456789abc' });
    if (kind === 'version') f.versionExecutorSpy.mockResolvedValue({ nodeVersion: '26.3.2', npmVersion: '11.16.0' });
    const initialize = vi.spyOn(f.workspaces, 'initialize');
    await expect(f.sessions.prepareConcrete(f.concreteRoot, f.seed, f.context, f.output)).rejects.toThrow(INVALID);
    expect(initialize).not.toHaveBeenCalled();
  });

  it('preserves partial initializer output and never retries or adopts the failed destination', async () => {
    const f = await rootPreparationFixture();
    const initialize = vi.spyOn(f.workspaces, 'initialize').mockImplementation(async root => {
      await mkdir(root, { mode: 0o700 }); await writeFile(join(root, 'partial'), 'preserve', { mode: 0o600 });
      throw new Error('private partial initializer');
    });
    await expect(f.sessions.prepareConcrete(f.concreteRoot, f.seed, f.context, f.output)).rejects.toThrow(INVALID);
    expect(await readFile(join(f.destination, 'partial'), 'utf8')).toBe('preserve');
    await expect(f.sessions.prepareConcrete(f.concreteRoot, f.seed, f.context, f.output)).rejects.toThrow(INVALID);
    expect(initialize).toHaveBeenCalledTimes(1);
    expect(concreteServer().close).toHaveBeenCalledTimes(1);
    expect(spawn).not.toHaveBeenCalled();
  });

  it.each(['root-context', 'foreign-output', 'consumed-seed', 'consumed-context', 'partial-destination'] as const)(
    'rejects genuine same-port roots and owned capabilities at their exact boundary (%s)', async kind => {
      const f = await rootPreparationFixture();
      const context2 = await f.sessions.createContext(f.source);
      cleanupActions.push(async () => { try { await f.sessions.closeContext(context2); } catch {} });
      const parent2 = join(f.root, 'output-2'); await mkdir(parent2, { mode: 0o700 });
      const output2 = await f.sessions.captureOutputIntent(context2, join(parent2, 'candidate.json'));
      const root2 = await f.sessions.prepareConcreteRoot(context2);
      expect(root2).not.toBe(f.concreteRoot); expect(root2.brokerPort).toBe(f.concreteRoot.brokerPort);
      const initialize = vi.spyOn(f.workspaces, 'initialize');
      if (kind === 'root-context') {
        await expect(f.sessions.prepareConcrete(f.concreteRoot, f.seed, context2, output2)).rejects.toThrow(INVALID);
        expect(initialize).not.toHaveBeenCalled();
      } else if (kind === 'foreign-output') {
        await expect(f.sessions.prepareConcrete(root2, f.seed, context2, f.output)).rejects.toThrow(INVALID);
        expect(initialize).not.toHaveBeenCalled();
      } else if (kind === 'partial-destination') {
        initialize.mockImplementationOnce(async root => { await mkdir(root, { mode: 0o700 }); throw new Error('partial'); });
        await expect(f.sessions.prepareConcrete(f.concreteRoot, f.seed, f.context, f.output)).rejects.toThrow(INVALID);
        await f.sessions.closeOutputIntent(f.output);
        const sameDestination = await f.sessions.captureOutputIntent(context2, f.outputPath);
        const freshSeed = f.production.captureConcreteRuntimeSeed(runtimeSeedInput(f));
        await expect(f.sessions.prepareConcrete(root2, freshSeed, context2, sameDestination)).rejects.toThrow(INVALID);
        expect(initialize).toHaveBeenCalledTimes(1); expect(await pathExists(f.destination)).toBe(true);
      } else {
        const prepared = await f.sessions.prepareConcrete(f.concreteRoot, f.seed, f.context, f.output);
        const freshSeed = f.production.captureConcreteRuntimeSeed(runtimeSeedInput(f));
        if (kind === 'consumed-seed') await expect(f.sessions.prepareConcrete(root2, f.seed, context2, output2)).rejects.toThrow(INVALID);
        else {
          const sameContextRoot = await f.sessions.prepareConcreteRoot(f.context);
          await expect(f.sessions.prepareConcrete(sameContextRoot, freshSeed, f.context, f.output)).rejects.toThrow(INVALID);
        }
        expect(initialize).toHaveBeenCalledTimes(1); expect(f.sessions.authenticatesPrepared(prepared)).toBe(true);
      }
      expect(spawn).not.toHaveBeenCalled(); expect(await pathExists(join(parent2, '.apg-graph-genesis-v2-workspace'))).toBe(false);
    },
  );

  it.each(['replace', 'chain'] as const)('rejects audit %s drift before construction', async kind => {
    const f = await rootPreparationFixture();
    if (kind === 'replace') {
      await rename(f.source.canonicalPath, f.source.canonicalPath + '.retained');
      await writeFile(f.source.canonicalPath, 'replacement', { mode: 0o600 });
    } else {
      const call = new SqliteAuditRecorder(f.source.database, () => new Date(), 'immediate').begin({
        serverId: 'test', toolName: 'outside-construction', arguments: {},
      }, { action: 'deny' });
      call.markBlocked('denied');
    }
    const initialize = vi.spyOn(f.workspaces, 'initialize'), containment = vi.spyOn(f.containments, 'observe');
    await expect(f.sessions.prepareConcrete(f.concreteRoot, f.seed, f.context, f.output)).rejects.toThrow(INVALID);
    expect(initialize).not.toHaveBeenCalled(); expect(containment).not.toHaveBeenCalled();
  });

  it.each(['mode', 'replacement', 'audit-close'] as const)('stops after initialization when parent or audit identity drifts (%s)', async kind => {
    const f = await rootPreparationFixture(), initialize = f.workspaces.initialize.bind(f.workspaces);
    vi.spyOn(f.workspaces, 'initialize').mockImplementation(async (...args) => {
      const workspace = await initialize(...args);
      if (kind === 'mode') await chmod(f.outputParent, 0o755);
      if (kind === 'replacement') { await rename(f.outputParent, f.outputParent + '-retained'); await mkdir(f.outputParent, { mode: 0o700 }); }
      if (kind === 'audit-close') f.source.database.close();
      return workspace;
    });
    const observe = vi.spyOn(f.containments, 'observe');
    await expect(f.sessions.prepareConcrete(f.concreteRoot, f.seed, f.context, f.output)).rejects.toThrow(INVALID);
    expect(observe).not.toHaveBeenCalled(); expect(spawn).not.toHaveBeenCalled();
  });

  it.each((['profile', 'workspace', 'containment', 'snapshot'] as const).flatMap(stage =>
    (['failure', 'cancel', 'expiry'] as const).map(mode => ({ stage, mode }))))(
    'blocks publication and later phases after $stage $mode', async ({ stage, mode }) => {
      const f = await rootPreparationFixture();
      const before = databaseCounts(f); let closing: Promise<unknown> | undefined;
      const interrupt = () => {
        if (mode === 'failure') throw new Error('private construction detail');
        if (mode === 'cancel') closing = f.sessions.closeOutputIntent(f.output).catch(error => error);
        if (mode === 'expiry') { const expired = performance.now() + 130_000; vi.spyOn(performance, 'now').mockReturnValue(expired); }
      };
      const profileOriginal = f.profiles.prepare.bind(f.profiles), workspaceOriginal = f.workspaces.initialize.bind(f.workspaces);
      const containmentOriginal = f.containments.observe.bind(f.containments), snapshotOriginal = f.production.prepare.bind(f.production);
      const profile = vi.spyOn(f.profiles, 'prepare').mockImplementation(input => { const value = profileOriginal(input); if (stage === 'profile') interrupt(); return value; });
      const workspace = vi.spyOn(f.workspaces, 'initialize').mockImplementation(async (...args) => { const value = await workspaceOriginal(...args); if (stage === 'workspace') interrupt(); return value; });
      const containment = vi.spyOn(f.containments, 'observe').mockImplementation(async (...args) => { const value = await containmentOriginal(...args); if (stage === 'containment') interrupt(); return value; });
      const snapshot = vi.spyOn(f.production, 'prepare').mockImplementation(input => { const value = snapshotOriginal(input); if (stage === 'snapshot') interrupt(); return value; });
      await expect(f.sessions.prepareConcrete(f.concreteRoot, f.seed, f.context, f.output)).rejects.toThrow(INVALID);
      await closing;
      const stop = ['profile', 'workspace', 'containment', 'snapshot'].indexOf(stage);
      [profile, workspace, containment, snapshot].forEach((spy, index) => expect(spy).toHaveBeenCalledTimes(index <= stop ? 1 : 0));
      expect(databaseCounts(f)).toEqual(before); expect(spawn).not.toHaveBeenCalled();
      expect(concreteServer().close).toHaveBeenCalledTimes(1); expect(await pathExists(f.outputPath)).toBe(false);
    },
  );

  it.each((['workspace', 'containment'] as const).flatMap(stage =>
    (['output', 'context', 'expiry'] as const).map(mode => ({ stage, mode }))))(
    'bounds $mode while native $stage stays pending and preserves late results without promotion', async ({ stage, mode }) => {
      const f = await rootPreparationFixture();
      const index = vi.mocked(fixtureFs.open).mock.calls.findLastIndex(args => args[0] === f.outputParent);
      const descriptor = await vi.mocked(fixtureFs.open).mock.results[index]!.value;
      const dispose = vi.spyOn(descriptor, 'close');
      let reached = false, settled = false, release!: () => void;
      const held = new Promise<void>(resolve => { release = resolve; });
      const initialize = f.workspaces.initialize.bind(f.workspaces), observe = f.containments.observe.bind(f.containments);
      vi.spyOn(f.workspaces, 'initialize').mockImplementation(async (...args) => {
        if (stage === 'workspace') { reached = true; await held; }
        try { return await initialize(...args); } finally { if (stage === 'workspace') settled = true; }
      });
      const containment = vi.spyOn(f.containments, 'observe').mockImplementation(async (...args) => {
        if (stage === 'containment') { reached = true; await held; }
        try { return await observe(...args); } finally { if (stage === 'containment') settled = true; }
      });
      const snapshot = vi.spyOn(f.production, 'prepare');
      let clock = performance.now();
      if (mode === 'expiry') vi.spyOn(performance, 'now').mockImplementation(() => clock);
      vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
      const preparation = f.sessions.prepareConcrete(f.concreteRoot, f.seed, f.context, f.output).catch(error => error);
      let closed: Promise<unknown> | undefined;
      try {
        await awaitConcreteCondition(() => reached, 15_000);
        if (mode === 'expiry') { clock += 130_000; await vi.advanceTimersByTimeAsync(130_000); }
        closed = (mode === 'context' ? f.sessions.closeContext(f.context) : f.sessions.closeOutputIntent(f.output)).catch(error => error);
        expect(await preparation).toBeInstanceOf(Error);
        await vi.advanceTimersByTimeAsync(6_000);
        expect(await closed).toBeInstanceOf(Error); expect(dispose).not.toHaveBeenCalled(); expect(settled).toBe(false);
      } finally { release(); }
      await awaitConcreteCondition(() => settled && dispose.mock.calls.length === 1);
      expect(await pathExists(f.destination)).toBe(true);
      expect(snapshot).not.toHaveBeenCalled(); expect(containment).toHaveBeenCalledTimes(stage === 'workspace' ? 0 : 1);
      expect(spawn).not.toHaveBeenCalled(); expect(await pathExists(f.outputPath)).toBe(false);
      expect(dispose).toHaveBeenCalledTimes(1);
    },
  );

  it('closes proxy metadata errors at seed capture without granting construction authority', async () => {
    const f = await createPreparationFixture();
    expect(() => f.production.captureConcreteRuntimeSeed(new Proxy(runtimeSeedInput(f), {
      ownKeys: () => { throw new Error('private wrapper detail'); },
    }))).toThrow(INVALID);
    expect(createServer).not.toHaveBeenCalled(); expect(spawn).not.toHaveBeenCalled();
  });

  it.each(['expired', 'decreasing'] as const)('keeps the original root clock fence before the first construction effect (%s)', async kind => {
    const f = await rootPreparationFixture();
    vi.spyOn(performance, 'now').mockReturnValue(kind === 'expired' ? performance.now() + 130_000 : 0);
    const initialize = vi.spyOn(f.workspaces, 'initialize'), observe = vi.spyOn(f.containments, 'observe');
    await expect(f.sessions.prepareConcrete(f.concreteRoot, f.seed, f.context, f.output)).rejects.toThrow(INVALID);
    expect(initialize).not.toHaveBeenCalled(); expect(observe).not.toHaveBeenCalled();
  });

  it.each(['failure', 'expiry'] as const)('rejects the final snapshot revalidation %s without publishing a prepared tuple', async kind => {
    const f = await rootPreparationFixture(), revalidate = f.production.revalidate.bind(f.production);
    vi.spyOn(f.production, 'revalidate').mockImplementation(async (...args) => {
      await revalidate(...args);
      if (kind === 'failure') throw new Error('private final revalidation');
      const expired = performance.now() + 130_000; vi.spyOn(performance, 'now').mockReturnValue(expired);
    });
    const before = databaseCounts(f);
    await expect(f.sessions.prepareConcrete(f.concreteRoot, f.seed, f.context, f.output)).rejects.toThrow(INVALID);
    expect(databaseCounts(f)).toEqual(before); expect(spawn).not.toHaveBeenCalled();
  });

  it.each(['output', 'context'] as const)('rechecks exact construction association before authorization after %s revocation', async kind => {
    const f = await rootPreparationFixture();
    const prepared = await f.sessions.prepareConcrete(f.concreteRoot, f.seed, f.context, f.output);
    const before = databaseCounts(f);
    if (kind === 'output') await f.sessions.closeOutputIntent(f.output);
    else await f.sessions.closeContext(f.context);
    expect(f.sessions.authenticatesPrepared(prepared)).toBe(false);
    await expect(f.sessions.authorize(prepared)).rejects.toThrow(INVALID);
    expect(databaseCounts(f)).toEqual(before); expect(spawn).not.toHaveBeenCalled();
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
  it('latches a concurrent continuation error without allowing the pending operation to progress', async () => {
    const f = await completionFixture();
    const first = f.completion.captureSyntheticPostState(f.run, () => 2).then(() => 'resolved', () => 'rejected');
    await expect(f.completion.captureSyntheticPostState(f.run, () => 2)).rejects.toThrow(INVALID);
    expect(f.source.database.prepare('SELECT status FROM tool_calls WHERE id=?').pluck().get(f.run.actionId)).toBe('failed');
    expect(await first).toBe('rejected');
  });

  it('does not start when the clock callback revokes its output during the initial fence', async () => {
    const f = await createPreparationFixture();
    const prepared = await f.sessions.prepare(f.snapshot, f.context, f.output);
    const pending = f.sessions.authorize(prepared);
    const request = await waitForGraphApproval(f);
    dashboardApprovals(f).decide(request.id, 'approved');
    const authorized = await pending;
    if (authorized.status !== 'authorized') throw new Error('Expected authorization');
    const completion = f.sessions.createSyntheticCompletion(prepared, authorized.sealedAuthorization);
    let closing: Promise<void> | undefined;
    expect(() => completion.issueSyntheticQuiescedRun(() => {
      closing = f.sessions.closeOutputIntent(f.output); return 1;
    })).toThrow(INVALID);
    await closing;
    expect(f.source.database.prepare("SELECT count(*) FROM audit_events WHERE event_type='execution_start_recorded'").pluck().get()).toBe(0);
  });

  it('reconciles one committed-then-thrown terminal without a second writer', async () => {
    const begin = SqliteAuditRecorder.prototype.begin;
    let terminals = 0;
    vi.spyOn(SqliteAuditRecorder.prototype, 'begin').mockImplementation(function (this: SqliteAuditRecorder, ...args) {
      const call = begin.apply(this, args);
      return Object.freeze({ ...call, finalizeGraphGenesisOutcome: (...terminalArgs: Parameters<typeof call.finalizeGraphGenesisOutcome>) => {
        terminals += 1;
        call.finalizeGraphGenesisOutcome(...terminalArgs);
        throw new Error('fixture post-commit uncertainty');
      } });
    });
    const f = await writtenCompletionFixture();
    const reopen = vi.spyOn(auditDatabaseModule, 'openAuditDatabaseReadOnly');
    expect(f.completion.finalizeSyntheticIncomplete(f.run, f.output, () => 6)).toMatchObject({ evidenceOrigin: 'synthetic_fixture', terminalStatus: 'incomplete_external_read' });
    expect(terminals).toBe(1);
    expect(reopen).toHaveBeenCalledOnce();
    expect(() => f.completion.finalizeSyntheticIncomplete(f.run, f.output, () => 7)).toThrow(INVALID);
    expect(terminals).toBe(1);
  });

  it('owns cancellation while idle and never retries terminal recording', async () => {
    const controller = new AbortController();
    const f = await completionFixture(controller.signal);
    controller.abort();
    expect(f.source.database.prepare('SELECT status FROM tool_calls WHERE id=?').pluck().get(f.run.actionId)).toBe('failed');
    await expect(f.completion.captureSyntheticPostState(f.run, () => 2)).rejects.toThrow(INVALID);
    expect(f.source.database.prepare("SELECT count(*) FROM audit_events WHERE event_type='outcome_receipt_finalized'").pluck().get()).toBe(1);
  });

  it('preserves output and never retries when the single terminal transaction is rejected', async () => {
    const f = await writtenCompletionFixture();
    const reopen = vi.spyOn(auditDatabaseModule, 'openAuditDatabaseReadOnly');
    f.source.database.exec("CREATE TEMP TRIGGER reject_terminal BEFORE INSERT ON audit_events WHEN NEW.event_type='outcome_receipt_finalized' BEGIN SELECT RAISE(ABORT, 'fixture terminal failure'); END");
    expect(() => f.completion.finalizeSyntheticIncomplete(f.run, f.output, () => 6)).toThrow(INVALID);
    expect(reopen).toHaveBeenCalledOnce();
    expect(f.source.database.prepare('SELECT status FROM tool_calls WHERE id=?').pluck().get(f.run.actionId)).toBe('forwarding');
    expect(await pathExists(f.outputPath)).toBe(true);
    f.source.database.exec('DROP TRIGGER reject_terminal');
    expect(() => f.completion.finalizeSyntheticIncomplete(f.run, f.output, () => 7)).toThrow(INVALID);
    expect(reopen).toHaveBeenCalledOnce();
    expect(f.source.database.prepare("SELECT count(*) FROM audit_events WHERE event_type='outcome_receipt_finalized'").pluck().get()).toBe(0);
  });

  it('refuses a recreated DB at the owner path, even when it has a valid independent schema', async () => {
    const f = await writtenCompletionFixture();
    await rename(f.source.canonicalPath, f.source.canonicalPath + '.original');
    const replacement = openAuditDatabase(f.source.canonicalPath);
    replacement.close();
    const reopen = vi.spyOn(auditDatabaseModule, 'openAuditDatabaseReadOnly');
    expect(() => f.completion.finalizeSyntheticIncomplete(f.run, f.output, () => 6)).toThrow(INVALID);
    expect(reopen).not.toHaveBeenCalled();
    expect(await pathExists(f.outputPath)).toBe(true);
  });

  it('does not open output after revocation at the first awaited post-state recheck', async () => {
    const f = await completionFixture();
    const state = await f.completion.captureSyntheticPostState(f.run, () => 2);
    const artifact = f.completion.compileSyntheticArtifact(f.run, state, () => 3);
    const reservation = await f.completion.reserveOutput(f.run, () => 4);
    let ticks = 0; let closing: Promise<void> | undefined;
    await expect(f.completion.writeReservedArtifact(f.run, reservation, artifact, () => {
      if (++ticks === 3) closing = f.sessions.closeOutputIntent(f.output);
      return 5;
    })).rejects.toThrow();
    await closing;
    expect(await pathExists(f.outputPath)).toBe(false);
    expect(f.source.database.prepare('SELECT status FROM tool_calls WHERE id=?').pluck().get(f.run.actionId)).toBe('failed');
  });

  it.each(['output', 'context'] as const)('terminalizes an idle post-start completion immediately on %s revocation', async (kind) => {
    const f = await completionFixture();
    if (kind === 'output') await f.sessions.closeOutputIntent(f.output);
    else await f.sessions.closeContext(f.context);
    expect(f.source.database.prepare('SELECT status FROM tool_calls WHERE id=?').pluck().get(f.run.actionId)).toBe('failed');
    expect(f.source.database.prepare("SELECT count(*) FROM audit_events WHERE event_type='outcome_receipt_finalized'").pluck().get()).toBe(1);
    await expect(f.completion.captureSyntheticPostState(f.run, () => 2)).rejects.toThrow(INVALID);
  });

  it('rejects output bytes changed after durable write without issuing a proof', async () => {
    const f = await writtenCompletionFixture();
    await writeFile(f.outputPath, '{}\n');
    expect(() => f.completion.finalizeSyntheticIncomplete(f.run, f.output, () => 6)).toThrow(INVALID);
    expect(f.source.database.prepare('SELECT status FROM tool_calls WHERE id=?').pluck().get(f.run.actionId)).toBe('failed');
  });

  it('has no runtime raw completion fields or usable reflected constructor', async () => {
    const f = await completionFixture();
    expect(Object.keys(f.completion)).toEqual([]);
    expect(() => Reflect.construct(f.completion.constructor, [Symbol('forged'), {}, {}, {}, {}, {}, () => true])).toThrow(INVALID);
  });

  it.each(['issue', 'reserve'] as const)('revokes continuation after duplicate %s rather than retrying', async (kind) => {
    const f = await completionFixture();
    if (kind === 'issue') expect(() => f.completion.issueSyntheticQuiescedRun(() => 2)).toThrow(INVALID);
    else {
      const state = await f.completion.captureSyntheticPostState(f.run, () => 2);
      f.completion.compileSyntheticArtifact(f.run, state, () => 3);
      await f.completion.reserveOutput(f.run, () => 4);
      await expect(f.completion.reserveOutput(f.run, () => 5)).rejects.toThrow(INVALID);
    }
    expect(f.source.database.prepare('SELECT status FROM tool_calls WHERE id=?').pluck().get(f.run.actionId)).toBe('failed');
    expect(await pathExists(f.outputPath)).toBe(false);
  });

  it('reopens the owner-selected DB query-only and records conservative terminal facts', async () => {
    const f = await writtenCompletionFixture();
    const realOpen = auditDatabaseModule.openAuditDatabaseReadOnly;
    const reopen = vi.spyOn(auditDatabaseModule, 'openAuditDatabaseReadOnly').mockImplementation((path) => {
      expect(path).toBe(f.source.canonicalPath);
      const db = realOpen(path);
      expect(db).not.toBe(f.source.database);
      expect(db.readonly).toBe(true);
      expect(db.pragma('query_only', { simple: true })).toBe(1);
      return db;
    });
    f.completion.finalizeSyntheticIncomplete(f.run, f.output, () => 6);
    expect(reopen).toHaveBeenCalledOnce();
    const summary = JSON.parse(String(f.source.database.prepare('SELECT result_summary_json FROM tool_calls WHERE id=?').pluck().get(f.run.actionId)));
    expect(summary.cleanup.status).toBe('incomplete');
    expect(summary.terminalAudit.status).toBe('unknown');
  });

  it.each(['graph_genesis_v2_post_state_validated', 'graph_genesis_v2_candidate_compiled', 'graph_genesis_v2_candidate_output_intent', 'graph_genesis_v2_candidate_output_written'])(
    'owns a single failure terminal after %s audit failure', async (eventType) => {
      const f = await completionFixture();
      f.source.database.exec(`CREATE TEMP TRIGGER reject_completion BEFORE INSERT ON audit_events WHEN NEW.event_type = '${eventType}' BEGIN SELECT RAISE(ABORT, 'fixture failure'); END`);
      const attempt = async () => {
        const state = await f.completion.captureSyntheticPostState(f.run, () => 2);
        const artifact = f.completion.compileSyntheticArtifact(f.run, state, () => 3);
        const reservation = await f.completion.reserveOutput(f.run, () => 4);
        await f.completion.writeReservedArtifact(f.run, reservation, artifact, () => 5);
      };
      await expect(attempt()).rejects.toThrow();
      expect(f.source.database.prepare('SELECT status FROM tool_calls WHERE id=?').pluck().get(f.run.actionId)).toBe('failed');
      expect(f.source.database.prepare("SELECT count(*) FROM audit_events WHERE event_type='outcome_receipt_finalized'").pluck().get()).toBe(1);
      await expect(f.completion.captureSyntheticPostState(f.run, () => 6)).rejects.toThrow();
      if (eventType === 'graph_genesis_v2_candidate_output_written') expect(await pathExists(f.outputPath)).toBe(true);
    },
  );

  it.each(['receipt', 'order', 'duplicate', 'oversize', 'approval', 'summary'])(
    'rejects rehashed %s tampering on the independent proof connection', async (kind) => {
      const f = await writtenCompletionFixture();
      const realOpen = auditDatabaseModule.openAuditDatabaseReadOnly;
      const reopen = vi.spyOn(auditDatabaseModule, 'openAuditDatabaseReadOnly').mockImplementation((path) => {
        const rows = f.source.database.prepare('SELECT sequence,event_json FROM audit_events ORDER BY sequence').all() as Array<{sequence:number;event_json:string}>;
        let tail = '0'.repeat(64);
        for (const row of rows) {
          const event = JSON.parse(row.event_json);
          if (kind === 'receipt' && event.eventType === 'outcome_receipt_finalized') event.details.receipt.execution.observedResult.candidateArtifactDigest = `sha256:${'0'.repeat(64)}`;
          if (kind === 'order' && event.eventType === 'graph_genesis_v2_candidate_compiled') event.eventType = 'graph_genesis_v2_candidate_output_intent';
          if (kind === 'duplicate' && event.eventType === 'graph_genesis_v2_post_state_validated') event.eventType = 'execution_start_recorded';
          if (kind === 'oversize' && event.eventType === 'graph_genesis_v2_post_state_validated') event.details.padding = 'x'.repeat(512 * 1024);
          const json = canonicalJson(event);
          const hash = createHash('sha256').update(`${tail}\n${json}`).digest('hex');
          f.source.database.prepare('UPDATE audit_events SET event_json=?,event_type=?,previous_hash=?,event_hash=? WHERE sequence=?').run(json,event.eventType,tail,hash,row.sequence);
          tail = hash;
        }
        if (kind === 'approval') f.source.database.prepare("UPDATE approvals SET status='denied' WHERE tool_call_id=?").run(f.run.actionId);
        if (kind === 'summary') f.source.database.prepare("UPDATE tool_calls SET result_summary_json='{}' WHERE id=?").run(f.run.actionId);
        return realOpen(path);
      });
      expect(() => f.completion.finalizeSyntheticIncomplete(f.run, f.output, () => 6)).toThrow();
      expect(reopen).toHaveBeenCalledOnce();
      expect(() => f.completion.finalizeSyntheticIncomplete(f.run, f.output, () => 7)).toThrow();
      expect(reopen).toHaveBeenCalledOnce();
    },
  );

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

  it('continues one exact sealed Plan3/Projection3/Envelope2 tuple through synthetic post-state, Artifact2, terminal audit and read-only proof', async () => {
    const fixture = await createPreparationFixture();
    const prepared = await fixture.sessions.prepare(fixture.snapshot, fixture.context, fixture.output);
    const pending = fixture.sessions.authorize(prepared);
    const request = await waitForGraphApproval(fixture);
    expect(dashboardApprovals(fixture).decide(request.id, 'approved')).toBe('approved');
    const authorized = await pending;
    if (authorized.status !== 'authorized') throw new Error('Expected sealed authorization');
    await writeSyntheticLock(fixture.bundle.workspace.rootRealpath);

    const completion = fixture.sessions.createSyntheticCompletion(prepared, authorized.sealedAuthorization);
    const run = completion.issueSyntheticQuiescedRun(() => 1);
    const postState = await completion.captureSyntheticPostState(run, () => 2);
    const artifact = completion.compileSyntheticArtifact(run, postState, () => 3);
    const reservation = await completion.reserveOutput(run, () => 4);
    const output = await completion.writeReservedArtifact(run, reservation, artifact, () => 5);
    const proof = completion.finalizeSyntheticIncomplete(run, output, () => 6);

    expect(artifact.binding.planHash).toBe(prepared.plan.planHash);
    expect(artifact.binding.executionEnvelopeHash).toBe(prepared.envelope.executionEnvelopeHash);
    expect(artifact.binding.postStateDigest).toBe(postState.postStateDigest);
    expect(proof).toEqual({ actionId: authorized.actionId, artifactDigest: artifact.artifactDigest, evidenceOrigin: 'synthetic_fixture', terminalStatus: 'incomplete_external_read' });
    expect(await readFile(fixture.outputPath, 'utf8')).toContain('artifactSchemaVersion');
    expect(() => fixture.sessions.createSyntheticCompletion(prepared, authorized.sealedAuthorization)).toThrow(INVALID);
  });

  it('consumes one exact sealed tuple through the opaque mocked execution-to-terminal proof and rejects replay', async () => {
    const fixture = await createPreparationFixture();
    const prepared = await fixture.sessions.prepare(fixture.snapshot, fixture.context, fixture.output);
    const pending = fixture.sessions.authorize(prepared);
    const request = await waitForGraphApproval(fixture);
    dashboardApprovals(fixture).decide(request.id, 'approved');
    const authorized = await pending;
    if (authorized.status !== 'authorized') throw new Error('Expected sealed authorization');

    await writeSyntheticLock(fixture.bundle.workspace.rootRealpath);
    const execution = fixture.sessions.createDormantMockedExecution(prepared, authorized.sealedAuthorization);
    // TypeScript private fields are ECMAScript private fields; attempts to relabel
    // public properties cannot change the sealed clock/binding held by the owner.
    expect(() => Object.assign(execution as object, { startBy: Number.MAX_SAFE_INTEGER, binding: {} })).toThrow();
    const proof = await execution.execute();
    expect(proof).toEqual(expect.objectContaining({ actionId: authorized.actionId, evidenceOrigin: 'synthetic_fixture' }));
    await expect(execution.execute()).rejects.toThrow(INVALID);
    expect(() => fixture.sessions.createSyntheticCompletion(prepared, authorized.sealedAuthorization)).toThrow(INVALID);
    expect(() => fixture.sessions.createDormantMockedExecution(prepared, authorized.sealedAuthorization)).toThrow(INVALID);
  });

  it('latches an expired sealed execution before dispatch, so a rejected start cannot be retried or advanced', async () => {
    const fixture = await createPreparationFixture();
    const prepared = await fixture.sessions.prepare(fixture.snapshot, fixture.context, fixture.output);
    const pending = fixture.sessions.authorize(prepared);
    const request = await waitForGraphApproval(fixture);
    dashboardApprovals(fixture).decide(request.id, 'approved');
    const authorized = await pending;
    if (authorized.status !== 'authorized') throw new Error('Expected sealed authorization');

    const execution = fixture.sessions.createDormantMockedExecution(prepared, authorized.sealedAuthorization);
    // The public API accepts no clock. The test mocks the owner-selected
    // monotonic boundary; a terminally invalid reading cannot be rewritten
    // into a later arm/spawn sequence.
    vi.spyOn(performance, 'now').mockReturnValue(Number.MAX_SAFE_INTEGER);
    await expect(execution.execute()).rejects.toThrow(INVALID);
    await expect(execution.execute()).rejects.toThrow(INVALID);
    expect(await pathExists(fixture.outputPath)).toBe(false);
  });

  it('records dispatch before its internally owned fake broker/child/listener quiescence without publishing listener authority', async () => {
    const fixture = await createPreparationFixture();
    const prepared = await fixture.sessions.prepare(fixture.snapshot, fixture.context, fixture.output);
    const pending = fixture.sessions.authorize(prepared);
    const request = await waitForGraphApproval(fixture);
    expect(dashboardApprovals(fixture).decide(request.id, 'approved')).toBe('approved');
    const authorized = await pending;
    if (authorized.status !== 'authorized') throw new Error('Expected sealed authorization');
    const completion = fixture.sessions.createSyntheticCompletion(prepared, authorized.sealedAuthorization);

    completion.issueSyntheticQuiescedRun(() => 1);
    const rows = fixture.source.database.prepare(`
      SELECT event_type,event_json FROM audit_events WHERE tool_call_id=? ORDER BY sequence
    `).all(authorized.actionId) as Array<{ event_type: string; event_json: string }>;
    const started = rows.findIndex((row) => row.event_type === 'execution_start_recorded');
    const quiesced = rows.findIndex((row) => row.event_type === 'graph_genesis_v2_synthetic_quiesced_fixture');
    expect(started).toBeGreaterThanOrEqual(0);
    expect(quiesced).toBeGreaterThan(started);
    const details = JSON.parse(rows[quiesced]!.event_json).details;
    expect(details.quiescence).toEqual({ childCloseObserved: true, exitCode: 0, requestCount: 0, responseBytes: 0 });
    expect(JSON.stringify(details)).not.toContain('listenerIdentityDigest');
    expect(JSON.stringify(details)).not.toContain('brokerPort');
  });

  it('revokes a session-owned synthetic completion on context close before any forward effect', async () => {
    const fixture = await createPreparationFixture();
    const prepared = await fixture.sessions.prepare(fixture.snapshot, fixture.context, fixture.output);
    const pending = fixture.sessions.authorize(prepared);
    const request = await waitForGraphApproval(fixture);
    expect(dashboardApprovals(fixture).decide(request.id, 'approved')).toBe('approved');
    const authorized = await pending;
    if (authorized.status !== 'authorized') throw new Error('Expected sealed authorization');
    const completion = fixture.sessions.createSyntheticCompletion(prepared, authorized.sealedAuthorization);

    await fixture.sessions.closeContext(fixture.context);
    expect(() => completion.issueSyntheticQuiescedRun(() => 1)).toThrow(INVALID);
    expect(await pathExists(fixture.outputPath)).toBe(false);
  });

  it('honors the approval caller cancellation signal after the sealed handoff', async () => {
    const fixture = await createPreparationFixture();
    const prepared = await fixture.sessions.prepare(fixture.snapshot, fixture.context, fixture.output);
    const controller = new AbortController();
    const pending = fixture.sessions.authorize(prepared, { signal: controller.signal });
    const request = await waitForGraphApproval(fixture);
    expect(dashboardApprovals(fixture).decide(request.id, 'approved')).toBe('approved');
    const authorized = await pending;
    if (authorized.status !== 'authorized') throw new Error('Expected sealed authorization');
    const completion = fixture.sessions.createSyntheticCompletion(prepared, authorized.sealedAuthorization);

    controller.abort();
    expect(() => completion.issueSyntheticQuiescedRun(() => 1)).toThrow(INVALID);
    expect(await pathExists(fixture.outputPath)).toBe(false);
  });

  it('revokes an already-reserved output when its owned intent closes', async () => {
    const fixture = await createPreparationFixture();
    const prepared = await fixture.sessions.prepare(fixture.snapshot, fixture.context, fixture.output);
    const pending = fixture.sessions.authorize(prepared);
    const request = await waitForGraphApproval(fixture);
    expect(dashboardApprovals(fixture).decide(request.id, 'approved')).toBe('approved');
    const authorized = await pending;
    if (authorized.status !== 'authorized') throw new Error('Expected sealed authorization');
    await writeSyntheticLock(fixture.bundle.workspace.rootRealpath);
    const completion = fixture.sessions.createSyntheticCompletion(prepared, authorized.sealedAuthorization);
    const run = completion.issueSyntheticQuiescedRun(() => 1);
    const state = await completion.captureSyntheticPostState(run, () => 2);
    const artifact = completion.compileSyntheticArtifact(run, state, () => 3);
    const reservation = await completion.reserveOutput(run, () => 4);

    await fixture.sessions.closeOutputIntent(fixture.output);
    await expect(completion.writeReservedArtifact(run, reservation, artifact, () => 5)).rejects.toThrow(INVALID);
    expect(await pathExists(fixture.outputPath)).toBe(false);
  });

  it('preserves a written test artifact as an orphan when terminal audit fails', async () => {
    const fixture = await createPreparationFixture();
    const prepared = await fixture.sessions.prepare(fixture.snapshot, fixture.context, fixture.output);
    const pending = fixture.sessions.authorize(prepared);
    const request = await waitForGraphApproval(fixture);
    expect(dashboardApprovals(fixture).decide(request.id, 'approved')).toBe('approved');
    const authorized = await pending;
    if (authorized.status !== 'authorized') throw new Error('Expected sealed authorization');
    await writeSyntheticLock(fixture.bundle.workspace.rootRealpath);
    const completion = fixture.sessions.createSyntheticCompletion(prepared, authorized.sealedAuthorization);
    const run = completion.issueSyntheticQuiescedRun(() => 1);
    const state = await completion.captureSyntheticPostState(run, () => 2);
    const artifact = completion.compileSyntheticArtifact(run, state, () => 3);
    const output = await completion.writeReservedArtifact(run, await completion.reserveOutput(run, () => 4), artifact, () => 5);

    fixture.source.database.close();
    expect(() => completion.finalizeSyntheticIncomplete(run, output, () => 6)).toThrow();
    expect(() => completion.finalizeSyntheticIncomplete(run, output, () => 7)).toThrow(INVALID);
    expect(await readFile(fixture.outputPath, 'utf8')).toContain(artifact.artifactDigest);
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
