import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { networkInterfaces, tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer, type Server } from 'node:net';
import { promisify } from 'node:util';

import { afterEach, describe, expect, it } from 'vitest';

import { ARCHIVE_WORKER_PROTOCOL_VERSION } from '../../src/stage/archive-worker-protocol.js';
import { ExactGraphCandidateAuthority } from '../../src/stage/exact-production-graph.js';
import {
  MetadataBrokerAuthority,
  type PublicPackumentRequest,
  type PublicPackumentTransport,
} from '../../src/stage/graph-genesis-broker.js';
import { SeatbeltLoopbackContainmentAuthority, seatbeltProfileText } from '../../src/stage/graph-genesis-containment.js';
import {
  ControlledGraphGenesisAuthority,
  GraphGenesisPlanAuthority,
  GraphGenesisWorkspaceAuthority,
  RuntimeTreeSnapshotAuthority,
  REQUIRED_COMPLETE_EVENTS,
  CANONICAL_EXACT_GRAPH_GENESIS_MANIFEST_BYTES,
  SyntheticGraphGenesisApprovalAuthority,
  SyntheticGraphGenesisAuditAuthority,
  buildGraphGenesisLaunch,
  compileSyntheticGenesisLock,
} from '../../src/stage/graph-genesis.js';
import { PACKAGE_STAGE_HARD_CEILINGS } from '../../src/stage/profile.js';

const paths: string[] = [];
const NOW = new Date('2026-09-08T00:00:00.000Z');
const TARGET = '@modelcontextprotocol/server-filesystem';
const VERSION = '2026.7.10';
const execFileAsync = promisify(execFile);

afterEach(() => {
  for (const path of paths.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe('bounded metadata-only graph genesis network-free foundation', () => {
  it('binds exact snapshots, containment, workspace, launch, plan and one-time approval', async () => {
    const fixture = await genesisFixture();
    const manifestDescriptor = fixture.workspace.protectedFiles.find((file) => file.name === 'package.json');
    expect(readFileSync(join(fixture.workspace.rootRealpath, 'package.json'), 'utf8'))
      .toBe(CANONICAL_EXACT_GRAPH_GENESIS_MANIFEST_BYTES);
    expect(manifestDescriptor).toMatchObject({
      mode: 0o600,
      size: Buffer.byteLength(CANONICAL_EXACT_GRAPH_GENESIS_MANIFEST_BYTES),
      sha256: createHash('sha256').update(CANONICAL_EXACT_GRAPH_GENESIS_MANIFEST_BYTES).digest('hex'),
    });
    expect(fixture.plan).toMatchObject({
      targetName: TARGET,
      exactTargetVersion: VERSION,
      brokerAddress: '127.0.0.1',
      npmVersion: '11.16.0',
      consequence: 'bounded_public_metadata_graph_genesis',
    });
    expect(fixture.plan.launch.args).toContain('--package-lock-only');
    expect(fixture.plan.launch.args.filter((argument) => argument === '--save-prod')).toHaveLength(1);
    expect(fixture.plan.launch.args.indexOf('--save-prod'))
      .toBe(fixture.plan.launch.args.indexOf('--save-exact') + 1);
    expect(fixture.plan.launch.args.filter((argument) => argument === '--maxsockets=4')).toHaveLength(1);
    expect(fixture.plan.launch.args.indexOf('--maxsockets=4'))
      .toBe(fixture.plan.launch.args.indexOf('--save-prod') + 1);
    expect(fixture.plan.launch.args.indexOf('--ignore-scripts'))
      .toBe(fixture.plan.launch.args.indexOf('--maxsockets=4') + 1);
    expect(fixture.plan.launch.args).toContain('--ignore-scripts');
    expect(fixture.plan.launch.args.filter((argument) => argument.startsWith('--prefix=')))
      .toEqual([`--prefix=${fixture.workspace.rootRealpath}`]);
    expect(fixture.plan.launch.args).not.toContain('--allow-child-process');
    expect(fixture.plan.launch.env).toEqual({
      HOME: fixture.workspace.rootRealpath,
      TMPDIR: join(fixture.workspace.rootRealpath, 'tmp'),
      LANG: 'C.UTF-8',
      LC_ALL: 'C.UTF-8',
    });

    const approval = fixture.approvals.issueForTest(fixture.plan, '2026-09-08T00:05:00.000Z', 'd'.repeat(32));
    const authorized = fixture.approvals.consume(fixture.plan, approval, NOW);
    expect(authorized.plan.planHash).toBe(fixture.plan.planHash);
    expect(() => fixture.approvals.consume(fixture.plan, approval, NOW))
      .toThrowError(expect.objectContaining({ code: 'approval_invalid' }));
    expect(() => fixture.planAuthority.assertAuthenticates({ ...fixture.plan }))
      .toThrowError(expect.objectContaining({ code: 'artifact_plan_invalid' }));
  });

  it('keeps npm project state at the workspace root and rejects the legacy nested prefix', async () => {
    const fixture = await genesisFixture();
    expect(existsSync(join(fixture.workspace.rootRealpath, 'prefix'))).toBe(false);
    writeFileSync(join(fixture.workspace.rootRealpath, 'package-lock.json'), JSON.stringify(lockFixture()));
    mkdirSync(join(fixture.workspace.rootRealpath, 'prefix'), { mode: 0o700 });
    await expect(fixture.workspaceAuthority.validateSyntheticPostState(fixture.workspace, lockFixture()))
      .rejects.toMatchObject({ code: 'artifact_plan_invalid' });
  });

  it('accepts only the canonical broker route, constructs the registry URL, and retains a safe ledger', async () => {
    const fixture = await genesisFixture();
    const authorized = fixture.approvals.consume(
      fixture.plan,
      fixture.approvals.issueForTest(fixture.plan, '2026-09-08T00:05:00.000Z'),
      NOW,
    );
    const broker = new MetadataBrokerAuthority();
    const authorization = broker.authorize(authorized, fixture.approvals);
    expect(() => broker.authorize({ ...authorized }, fixture.approvals))
      .toThrowError(expect.objectContaining({ code: 'graph_metadata_invalid' }));
    const session = broker.arm(authorization, { routeToken: fixture.routeToken, limits: brokerLimits() });
    expect(() => broker.arm(authorization, { routeToken: fixture.routeToken, limits: brokerLimits() }))
      .toThrowError(expect.objectContaining({ code: 'graph_metadata_invalid' }));
    let observed: PublicPackumentRequest | undefined;
    const body = await broker.handle(session, {
      method: 'GET',
      path: `/${fixture.routeToken}/@modelcontextprotocol%2fserver-filesystem`,
      headers: { accept: 'application/vnd.npm.install-v1+json', host: '127.0.0.1' },
    }, transport((request) => { observed = request; return packument(TARGET); }));
    expect(JSON.parse(Buffer.from(body).toString('utf8'))).toMatchObject({ name: TARGET });
    expect(observed).toEqual({
      url: 'https://registry.npmjs.org/@modelcontextprotocol%2fserver-filesystem',
      headers: {
        accept: 'application/vnd.npm.install-v1+json, application/json',
        acceptEncoding: 'identity',
      },
    });
    const ledger = broker.disarmComplete(session);
    expect(ledger).toMatchObject({ requestCount: 1, uniquePackageCount: 1, rejectedRequestCount: 0 });
    expect(JSON.stringify(ledger)).not.toContain(fixture.routeToken);
    expect(JSON.stringify(ledger)).not.toContain('versions');
  });

  it('fails closed for methods, noncanonical routes, tarballs, redirects, malformed JSON and duplicate keys', async () => {
    const requests = [
      { method: 'POST', suffix: 'fixture' },
      { method: 'GET', suffix: '@scope%2Fname' },
      { method: 'GET', suffix: 'fixture/-/fixture-1.0.0.tgz' },
      { method: 'GET', suffix: 'fixture?write=true' },
    ];
    for (const request of requests) {
      const fixture = await armedBroker();
      await expect(fixture.broker.handle(fixture.session, {
        method: request.method,
        path: `/${fixture.routeToken}/${request.suffix}`,
        headers: {},
      }, transport(() => packument('fixture')))).rejects.toMatchObject({ code: 'graph_metadata_invalid' });
      expect(fixture.calls()).toBe(0);
    }

    for (const response of [
      { ...packument('fixture'), redirected: true },
      { ...packument('fixture'), finalUrl: 'https://registry.npmjs.org/substitute' },
      { ...packument('fixture'), body: Buffer.from('{"name":"fixture","name":"substitute"}') },
      { ...packument('fixture'), body: Buffer.from('{broken') },
      packument('substitute'),
    ]) {
      const fixture = await armedBroker();
      await expect(fixture.broker.handle(fixture.session, {
        method: 'GET', path: `/${fixture.routeToken}/fixture`, headers: {},
      }, transport(() => response))).rejects.toMatchObject({ code: 'graph_metadata_invalid' });
    }
  });

  it('requires successful exact containment observations and rejects forged evidence', () => {
    const authority = new SeatbeltLoopbackContainmentAuthority();
    const profile = authority.prepare({ osBuild: '25G83', sandboxExecSha256: 'b'.repeat(64), allowedPort: 45454 });
    expect(profile.profileText).toContain('localhost:45454');
    const evidence = authority.authenticateObservedSelfTest(profile, containmentObservations());
    expect(authority.authenticatesSelfTest(evidence)).toBe(true);
    expect(() => authority.assertSelfTest({ ...evidence }))
      .toThrowError(expect.objectContaining({ code: 'artifact_plan_invalid' }));
    expect(() => authority.authenticateObservedSelfTest(profile, {
      ...containmentObservations(), alternateLoopbackPortDenied: false,
    })).toThrowError(expect.objectContaining({ code: 'artifact_plan_invalid' }));
  });

  it.runIf(process.platform === 'darwin')('proves exact-port Seatbelt and Node permission behavior with local-only fixtures', async () => {
    const localAddress = Object.values(networkInterfaces()).flat()
      .find((item) => item?.family === 'IPv4' && !item.internal)?.address;
    if (localAddress === undefined) return;
    const approved = await listener('127.0.0.1');
    const alternate = await listener('127.0.0.1');
    const nonLoopback = await listener(localAddress);
    const ipv6 = await listener('::1');
    const workspace = temp('apg-seatbelt-probe-');
    const profilePath = join(workspace, 'profile.sb');
    const outsidePath = join(tmpdir(), `apg-seatbelt-denied-${process.pid}-${Date.now()}`);
    writeFileSync(profilePath, seatbeltProfileText(approved.port), { mode: 0o600 });
    try {
      const fixturePath = join(process.cwd(), 'test/fixtures/graph-genesis-containment-probe.mjs');
      const { stdout, stderr } = await execFileAsync('/usr/bin/sandbox-exec', [
        '-f', profilePath,
        process.execPath,
        '--permission', '--allow-net',
        `--allow-fs-read=${fixturePath}`,
        `--allow-fs-read=${workspace}`,
        `--allow-fs-write=${workspace}`,
        fixturePath,
        String(approved.port), String(alternate.port), localAddress, String(nonLoopback.port),
        String(ipv6.port), outsidePath,
      ], { cwd: workspace, env: {}, timeout: 10_000, maxBuffer: 64 * 1024 });
      expect(Buffer.byteLength(stderr)).toBeLessThanOrEqual(64 * 1024);
      expect(stderr).not.toContain(outsidePath);
      const observations = JSON.parse(stdout) as ReturnType<typeof containmentObservations>;
      expect(observations).toEqual(containmentObservations());
      const authority = new SeatbeltLoopbackContainmentAuthority();
      const profile = authority.prepare({ osBuild: '25G83', sandboxExecSha256: 'b'.repeat(64), allowedPort: approved.port });
      expect(authority.authenticatesSelfTest(authority.authenticateObservedSelfTest(profile, observations))).toBe(true);
    } finally {
      await Promise.all([approved.close(), alternate.close(), nonLoopback.close(), ipv6.close()]);
      rmSync(outsidePath, { force: true });
    }
  }, 15_000);

  it('disarms when a fake public transport exceeds the request deadline', async () => {
    const fixture = await genesisFixture();
    const authorized = fixture.approvals.consume(
      fixture.plan,
      fixture.approvals.issueForTest(fixture.plan, '2026-09-08T00:05:00.000Z'),
      NOW,
    );
    const broker = new MetadataBrokerAuthority();
    const session = broker.arm(broker.authorize(authorized, fixture.approvals), {
      routeToken: fixture.routeToken,
      limits: { ...brokerLimits(), requestTimeoutMs: 5 },
    });
    await expect(broker.handle(session, {
      method: 'GET', path: `/${fixture.routeToken}/fixture`, headers: {},
    }, { async fetch() { return new Promise<never>(() => undefined); } }))
      .rejects.toMatchObject({ code: 'graph_metadata_incomplete' });
    expect(() => broker.disarmComplete(session))
      .toThrowError(expect.objectContaining({ code: 'graph_metadata_invalid' }));
  });

  it('rejects escaping runtime links and post-state substitutions', async () => {
    const authority = new RuntimeTreeSnapshotAuthority();
    const internalRoot = temp('apg-runtime-internal-link-');
    writeFileSync(join(internalRoot, 'target'), 'runtime');
    symlinkSync('target', join(internalRoot, 'link'));
    const internalSnapshot = await authority.capture(internalRoot);
    expect(internalSnapshot.entries.find((entry) => entry.relativePath === 'link'))
      .toMatchObject({ type: 'symlink', linkTarget: 'target' });

    const parent = temp('apg-runtime-negative-');
    const root = join(parent, 'root');
    mkdirSync(root);
    writeFileSync(join(parent, 'outside'), 'secret');
    symlinkSync(join(parent, 'outside'), join(root, 'escape'));
    await expect(authority.capture(root)).rejects.toMatchObject({ code: 'artifact_plan_invalid' });

    const fixture = await genesisFixture();
    writeFileSync(join(fixture.workspace.rootRealpath, 'package-lock.json'), JSON.stringify(lockFixture()));
    mkdirSync(join(fixture.workspace.rootRealpath, 'node_modules'));
    await expect(fixture.workspaceAuthority.validateSyntheticPostState(fixture.workspace, lockFixture()))
      .rejects.toMatchObject({ code: 'artifact_plan_invalid' });
    rmSync(join(fixture.workspace.rootRealpath, 'node_modules'), { recursive: true });
    writeFileSync(join(fixture.workspace.rootRealpath, 'package.json'),
      `{"name":"apg-graph-genesis","name":"substitute","version":"0.0.0","private":true,"dependencies":{"${TARGET}":"${VERSION}"}}`);
    await expect(fixture.workspaceAuthority.validateSyntheticPostState(fixture.workspace, lockFixture()))
      .rejects.toMatchObject({ code: 'artifact_plan_invalid' });
  });

  it('hands a synthetic lock to the closed compiler and authenticates only after ledger, cleanup and audit', async () => {
    const fixture = await genesisFixture();
    const approval = fixture.approvals.issueForTest(fixture.plan, '2026-09-08T00:05:00.000Z');
    const authorized = fixture.approvals.consume(fixture.plan, approval, NOW);
    const broker = new MetadataBrokerAuthority();
    const session = broker.arm(
      broker.authorize(authorized, fixture.approvals),
      { routeToken: fixture.routeToken, limits: brokerLimits() },
    );
    await broker.handle(session, {
      method: 'GET', path: `/${fixture.routeToken}/@modelcontextprotocol%2fserver-filesystem`, headers: {},
    }, transport(() => packument(TARGET)));
    const ledger = broker.disarmComplete(session);
    const lock = lockFixture();
    writeFileSync(join(fixture.workspace.rootRealpath, 'package-lock.json'), JSON.stringify(lock));
    await fixture.workspaceAuthority.validateSyntheticPostState(fixture.workspace, lock);
    const candidates = new ExactGraphCandidateAuthority();
    const candidate = compileSyntheticGenesisLock(candidates, fixture.plan, lock, {
      profileId: 'filesystem-2026-7-10-candidate', profileVersion: 1,
      materializationRulesVersion: 1, archiveRulesVersion: 1,
      workerProtocolVersion: ARCHIVE_WORKER_PROTOCOL_VERSION,
      limits: PACKAGE_STAGE_HARD_CEILINGS,
    });
    const audits = new SyntheticGraphGenesisAuditAuthority(fixture.approvals);
    const terminalAudit = audits.completeForTest(authorized, REQUIRED_COMPLETE_EVENTS);
    const completion = new ControlledGraphGenesisAuthority(
      candidates, broker, fixture.workspaceAuthority, fixture.approvals, audits,
    );
    expect(() => completion.complete({
      authorization: authorized, candidate, ledger, workspace: fixture.workspace, terminalAudit,
    })).toThrowError(expect.objectContaining({ code: 'artifact_plan_invalid' }));
    await fixture.workspaceAuthority.cleanup(fixture.workspace);
    const evidence = completion.complete({
      authorization: authorized, candidate, ledger, workspace: fixture.workspace, terminalAudit,
    });
    expect(completion.authenticates(evidence)).toBe(true);
    expect(completion.authenticates({ ...evidence })).toBe(false);
    expect(evidence.report).toMatchObject({ nodeCount: 1, edgeCount: 0, cleanupComplete: true });
  });
});

async function genesisFixture() {
  const runtimeAuthority = new RuntimeTreeSnapshotAuthority();
  const nodeRoot = temp('apg-node-runtime-');
  writeFileSync(join(nodeRoot, 'node'), 'synthetic node runtime');
  const npmRoot = temp('apg-npm-runtime-');
  mkdirSync(join(npmRoot, 'bin'));
  writeFileSync(join(npmRoot, 'bin/npm-cli.js'), 'synthetic npm cli');
  const nodeSnapshot = await runtimeAuthority.capture(nodeRoot);
  const npmSnapshot = await runtimeAuthority.capture(npmRoot);
  const nodeExecutable = join(nodeSnapshot.rootRealpath, 'node');
  const npmCliEntrypoint = join(npmSnapshot.rootRealpath, 'bin/npm-cli.js');
  const workspaceAuthority = new GraphGenesisWorkspaceAuthority();
  const parent = temp('apg-genesis-parent-');
  const workspace = await workspaceAuthority.initialize(join(parent, 'workspace'));
  const containment = new SeatbeltLoopbackContainmentAuthority();
  const profile = containment.prepare({ osBuild: '25G83', sandboxExecSha256: 'b'.repeat(64), allowedPort: 45454 });
  const selfTest = containment.authenticateObservedSelfTest(profile, containmentObservations());
  const routeToken = 'a'.repeat(32);
  const launch = buildGraphGenesisLaunch({
    sandboxExecPath: '/usr/bin/sandbox-exec',
    profilePath: join(workspace.rootRealpath, 'broker-profile.sb'),
    nodePath: nodeExecutable,
    npmCliPath: npmCliEntrypoint,
    npmRuntimeRoot: npmSnapshot.rootRealpath,
    workspaceRoot: workspace.rootRealpath,
    brokerPort: 45454,
    routeToken,
  });
  const planAuthority = new GraphGenesisPlanAuthority(runtimeAuthority, workspaceAuthority, containment);
  const plan = planAuthority.create({
    sessionId: 'c'.repeat(32), osBuild: '25G83', nodeVersion: '26.3.1',
    nodeExecutable, npmCliEntrypoint,
    nodeSnapshot, npmSnapshot, brokerRuntimeDigest: 'e'.repeat(64), sandboxExecSha256: 'b'.repeat(64),
    containmentProfile: profile, containmentSelfTest: selfTest, workspace, brokerPort: 45454,
    routeTokenDigest: sha256(routeToken), launch, limits: genesisLimits(),
  });
  return {
    routeToken, workspace, workspaceAuthority, plan, planAuthority,
    approvals: new SyntheticGraphGenesisApprovalAuthority(planAuthority),
  };
}

async function armedBroker() {
  const fixture = await genesisFixture();
  const authorized = fixture.approvals.consume(
    fixture.plan,
    fixture.approvals.issueForTest(fixture.plan, '2026-09-08T00:05:00.000Z'),
    NOW,
  );
  const broker = new MetadataBrokerAuthority();
  const session = broker.arm(
    broker.authorize(authorized, fixture.approvals),
    { routeToken: fixture.routeToken, limits: brokerLimits() },
  );
  let callCount = 0;
  return { broker, session, routeToken: fixture.routeToken, calls: () => callCount, count: () => { callCount += 1; } };
}

function transport(response: (request: PublicPackumentRequest) => ReturnType<typeof packument>): PublicPackumentTransport {
  return { async fetch(request) { return response(request); } };
}

function packument(name: string) {
  const url = `https://registry.npmjs.org/${name.replace('/', '%2f')}`;
  return {
    status: 200, contentType: 'application/json', redirected: false, finalUrl: url,
    body: Buffer.from(JSON.stringify({ name, versions: {} })),
  };
}

function containmentObservations() {
  return {
    approvedLoopbackPortConnected: true,
    alternateLoopbackPortDenied: true,
    nonLoopbackLocalAddressDenied: true,
    ipv6LoopbackDenied: true,
    outsideWorkspaceWriteDenied: true,
    childProcessDenied: true,
    workerThreadDenied: true,
    addonGrantAbsent: true,
    publicNetworkAttempted: false as const,
  };
}

function brokerLimits() {
  return {
    uniquePackageNames: 256, totalRequests: 512, concurrentRequests: 8,
    responseBytes: 8 * 1024 * 1024, aggregateResponseBytes: 128 * 1024 * 1024,
    requestTimeoutMs: 15_000,
  };
}

function genesisLimits() {
  return {
    broker: brokerLimits(), completeTimeoutMs: 120_000,
    stdoutBytes: 256 * 1024, stderrBytes: 256 * 1024,
    packageJsonBytes: 4 * 1024 * 1024, packageLockBytes: 4 * 1024 * 1024,
  };
}

function lockFixture() {
  const integrity = `sha512-${createHash('sha512').update('synthetic').digest('base64')}`;
  return {
    name: 'apg-graph-genesis', version: '0.0.0', lockfileVersion: 3, requires: true,
    packages: {
      '': { name: 'apg-graph-genesis', version: '0.0.0', dependencies: { [TARGET]: VERSION } },
      [`node_modules/${TARGET}`]: {
        version: VERSION,
        resolved: `https://registry.npmjs.org/@modelcontextprotocol/server-filesystem/-/server-filesystem-${VERSION}.tgz`,
        integrity,
      },
    },
  };
}

function temp(prefix: string): string {
  const path = mkdtempSync(join(tmpdir(), prefix));
  paths.push(path);
  return path;
}

async function listener(host: string): Promise<{ port: number; close: () => Promise<void> }> {
  const server = createServer((socket) => socket.destroy());
  await new Promise<void>((resolvePromise, reject) => {
    server.once('error', reject);
    server.listen(0, host, () => resolvePromise());
  });
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('local listener unavailable');
  return { port: address.port, close: () => closeServer(server) };
}

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((resolvePromise, reject) => server.close((error) => error === undefined ? resolvePromise() : reject(error)));
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}
