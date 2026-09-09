import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { createServer, type Server } from 'node:net';
import { createServer as createHttpsServer, type Server as HttpsServer } from 'node:https';

import { afterEach, describe, expect, it } from 'vitest';

import { LocalApprovalService } from '../../src/approval/service.js';
import { ExactGraphCandidateAuthority } from '../../src/stage/exact-production-graph.js';
import { HardenedControlledGraphGenesisAuthority } from '../../src/stage/graph-genesis-completion.js';
import {
  HardenedGraphGenesisCandidateCompiler,
  HardenedGraphGenesisPostStateAuthority,
} from '../../src/stage/graph-genesis-workspace.js';
import {
  GraphGenesisAuditGate,
  FinalizedGraphGenesisWorkspaceAuthority,
  HardenedGraphGenesisPlanAuthority,
  NoFollowWorkspaceCleanupAuthority,
  NodeHostPlatformProbeExecutor,
  OwnedContainmentProbeAuthority,
  OwnedHostPlatformAuthority,
  OwnedRuntimeVersionAuthority,
  RuntimeFileSnapshotAuthority,
  computeWorkspaceBinding,
  type ContainmentProbeExecutor,
  type GraphGenesisDurableAuditSink,
  type HostPlatformProbeExecutor,
  type RuntimeVersionProbeExecutor,
} from '../../src/stage/graph-genesis-hardening.js';
import { SyntheticGraphGenesisStartLeaseAuthority } from '../../src/stage/graph-genesis-composition.js';
import {
  BoundedNpmPublicMetadataTransport,
  createLocalTlsPinnedHttpsClientForTest,
  HardenedLoopbackBrokerListener,
  HardenedMetadataBrokerAuthority,
  isPublicAddress,
  type HardenedPublicMetadataTransport,
  type PinnedHttpsClient,
  type PinnedHttpsRequest,
  type RegistryAddressResolver,
} from '../../src/stage/graph-genesis-network.js';
import {
  GraphGenesisProcessSupervisor,
  type GraphGenesisSpawnAdapter,
} from '../../src/stage/graph-genesis-supervisor.js';
import { SeatbeltLoopbackContainmentAuthority } from '../../src/stage/graph-genesis-containment.js';
import { LocalSeatbeltContainmentProbeExecutor } from '../../src/stage/graph-genesis-containment-runner.js';
import {
  RuntimeTreeSnapshotAuthority,
  buildGraphGenesisLaunch,
} from '../../src/stage/graph-genesis.js';

const temporaryPaths: string[] = [];
const NOW = new Date('2026-09-08T00:00:00.000Z');

afterEach(() => {
  for (const path of temporaryPaths.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe('exact real metadata-only graph genesis network-free hardening', () => {
  it('separates a safe public plan from its authenticated memory-only execution capsule', async () => {
    const fixture = await planFixture();
    const projection = JSON.stringify(fixture.prepared.projection);
    expect(projection).not.toContain(fixture.routeToken);
    expect(projection).not.toContain(fixture.parent);
    expect(projection).not.toContain('npm-cli.js');
    expect(JSON.stringify(fixture.prepared.plan)).not.toContain(fixture.routeToken);
    expect(JSON.stringify(fixture.prepared.capsule)).toContain(fixture.routeToken);
    expect(fixture.planAuthority.authenticatesPair(fixture.prepared.plan, fixture.prepared.capsule)).toBe(true);
    expect(fixture.planAuthority.authenticatesPair(fixture.prepared.plan, { ...fixture.prepared.capsule })).toBe(false);
    expect(fixture.prepared.projection.statements).toContain('direct_npm_npx_outside_apg_protection');
  });

  it('requires authority-owned snapshots and rejects synthetic containment for production preparation', async () => {
    const fixture = await planFixture();
    expect(fixture.files.authenticates(fixture.snapshots.node, 'node')).toBe(true);
    expect(fixture.files.authenticates({ ...fixture.snapshots.node }, 'node')).toBe(false);
    await expect(fixture.files.revalidate(fixture.snapshots.node)).resolves.toBeUndefined();
    writeFileSync(fixture.snapshots.node.absolutePath, 'changed runtime bytes');
    await expect(fixture.files.revalidate(fixture.snapshots.node)).rejects.toMatchObject({ code: 'artifact_plan_invalid' });

    expect(() => fixture.planAuthority.prepare({ ...fixture.prepareInput, allowSynthetic: false }))
      .toThrowError(expect.objectContaining({ code: 'artifact_plan_invalid' }));
  });

  it('revalidates the exact sealed runtime and workspace before spawn', async () => {
    const fixture = await planFixture();
    const leaseAuthority = new SyntheticGraphGenesisStartLeaseAuthority(fixture.planAuthority);
    const startLease = leaseAuthority.createForTest(fixture.prepared.plan, 10_000);
    writeFileSync(fixture.snapshots.brokerRuntime.absolutePath, 'substituted broker runtime');
    let spawnCalls = 0;
    const supervisor = new GraphGenesisProcessSupervisor(fixture.planAuthority, {
      implementationKind: 'synthetic',
      spawn() { spawnCalls += 1; throw new Error('must not spawn'); },
    });
    await expect(supervisor.run({
      plan: fixture.prepared.plan,
      capsule: fixture.prepared.capsule,
      audit: new GraphGenesisAuditGate(fixture.prepared.plan.planHash, new MemoryAuditSink()),
      startLease, startLeaseVerifier: leaseAuthority, monotonicNow: () => 1,
      onFailure: () => undefined,
      mode: 'synthetic',
    })).rejects.toMatchObject({ code: 'artifact_plan_invalid' });
    expect(spawnCalls).toBe(0);
  });

  it.runIf(process.platform === 'darwin' && process.arch === 'arm64')(
    'captures the host build through the owned production platform probe',
    async () => {
      const authority = new OwnedHostPlatformAuthority(new NodeHostPlatformProbeExecutor());
      const evidence = await authority.observe();
      expect(authority.authenticates(evidence, 'local_observed')).toBe(true);
      expect(evidence).toMatchObject({ platform: 'darwin', architecture: 'arm64' });
      expect(evidence.osBuild).toMatch(/^[0-9A-Z]+$/u);
    },
  );

  it.runIf(process.platform === 'darwin' && process.arch === 'arm64')(
    'runs the owned production containment probe against local-only listeners',
    async () => {
      const approved = await localListener();
      const parent = temp('apg-owned-probe-');
      const files = new RuntimeFileSnapshotAuthority();
      const trees = new RuntimeTreeSnapshotAuthority();
      const workspaces = new FinalizedGraphGenesisWorkspaceAuthority(trees);
      const node = await files.capture('node', process.execPath);
      const sandboxExec = await files.capture('sandbox_exec', '/usr/bin/sandbox-exec');
      const probe = await files.capture('probe_runtime', join(process.cwd(), 'test/fixtures/graph-genesis-containment-probe.mjs'));
      const hostAuthority = new OwnedHostPlatformAuthority(new NodeHostPlatformProbeExecutor());
      const host = await hostAuthority.observe();
      const containment = new SeatbeltLoopbackContainmentAuthority();
      const profile = containment.prepare({ osBuild: host.osBuild, sandboxExecSha256: sandboxExec.sha256, allowedPort: approved.port });
      const workspace = await workspaces.initialize(join(parent, 'workspace'), profile.profileText);
      const binding = {
        osBuild: host.osBuild, hostEvidenceDigest: host.evidenceDigest,
        nodeSnapshotDigest: node.snapshotDigest, probeSnapshotDigest: probe.snapshotDigest,
        sandboxExecSnapshotDigest: sandboxExec.snapshotDigest, workspaceBinding: computeWorkspaceBinding(workspace),
        profileDigest: profile.profileDigest, allowedPort: approved.port,
      };
      try {
        const authority = new OwnedContainmentProbeAuthority(
          files, workspaces, new LocalSeatbeltContainmentProbeExecutor(),
        );
        const evidence = await authority.observe(binding, profile, { node, probe, sandboxExec, workspace });
        expect(authority.authenticates(evidence, 'local_observed')).toBe(true);
        expect(evidence.observations).toEqual(containmentObservations());
      } finally { await closeLocalListener(approved.server); }
    },
    15_000,
  );

  it('classifies public destinations and rejects private, local, documentation, mapped and mixed DNS results', async () => {
    expect(isPublicAddress({ address: '104.16.0.1', family: 4 })).toBe(true);
    expect(isPublicAddress({ address: '2606:4700::1111', family: 6 })).toBe(true);
    for (const item of [
      { address: '127.0.0.1', family: 4 as const },
      { address: '10.0.0.1', family: 4 as const },
      { address: '169.254.1.1', family: 4 as const },
      { address: '192.0.2.1', family: 4 as const },
      { address: '198.51.100.1', family: 4 as const },
      { address: '203.0.113.1', family: 4 as const },
      { address: '::1', family: 6 as const },
      { address: 'fc00::1', family: 6 as const },
      { address: 'fe80::1', family: 6 as const },
      { address: '2001:db8::1', family: 6 as const },
      { address: '::ffff:127.0.0.1', family: 6 as const },
    ]) expect(isPublicAddress(item)).toBe(false);

    let clientCalls = 0;
    const transport = new BoundedNpmPublicMetadataTransport(
      resolver([{ address: '104.16.0.1', family: 4 }, { address: '127.0.0.1', family: 4 }]),
      client(() => { clientCalls += 1; return packument('fixture'); }),
    );
    await expect(transport.fetchPackage('fixture', { timeoutMs: 100, maximumBytes: 1024 }, new AbortController().signal))
      .rejects.toMatchObject({ code: 'graph_metadata_invalid' });
    expect(clientCalls).toBe(0);
  });

  it('pins the accepted address, owns headers and rejects redirected or mismatched responses', async () => {
    let request: PinnedHttpsRequest | undefined;
    const transport = new BoundedNpmPublicMetadataTransport(
      resolver([{ address: '104.16.0.1', family: 4 }]),
      client((input) => { request = input; return packument('@scope/name'); }),
    );
    const response = await transport.fetchPackage('@scope/name', { timeoutMs: 100, maximumBytes: 1024 }, new AbortController().signal);
    expect(request).toMatchObject({
      url: 'https://registry.npmjs.org/@scope%2fname',
      hostname: 'registry.npmjs.org',
      address: '104.16.0.1',
      headers: { acceptEncoding: 'identity' },
    });
    expect(response.body.byteLength).toBeGreaterThan(0);

    const redirected = new BoundedNpmPublicMetadataTransport(
      resolver([{ address: '104.16.0.1', family: 4 }]),
      client(() => ({ ...packument('fixture'), status: 302 })),
    );
    await expect(redirected.fetchPackage('fixture', { timeoutMs: 100, maximumBytes: 1024 }, new AbortController().signal))
      .rejects.toMatchObject({ code: 'graph_metadata_invalid' });
  });

  it('exercises pinned TLS hostname verification and streaming limits on a memory-only local fixture', async () => {
    const identity = ephemeralTlsIdentity('registry.npmjs.org');
    let observedHost = '';
    const server = createHttpsServer({ key: identity.privateKeyPem, cert: identity.certificate }, (request, response) => {
      observedHost = request.headers.host ?? '';
      const body = request.url === '/overflow' ? Buffer.alloc(2048, 1) : Buffer.from('{"name":"fixture"}');
      response.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': body.byteLength });
      response.end(body);
    });
    const port = await listenHttps(server);
    try {
      const pinned = createLocalTlsPinnedHttpsClientForTest(port, identity.certificate);
      const response = await pinned.request({
        url: 'https://registry.npmjs.org/fixture', hostname: 'registry.npmjs.org',
        address: '127.0.0.1', family: 4,
        headers: { accept: 'application/vnd.npm.install-v1+json, application/json', acceptEncoding: 'identity' },
        timeoutMs: 1_000, maximumBytes: 1024,
      }, new AbortController().signal);
      expect(Buffer.from(response.body).toString('utf8')).toBe('{"name":"fixture"}');
      expect(observedHost).toBe('registry.npmjs.org');
      await expect(pinned.request({
        url: 'https://registry.npmjs.org/overflow', hostname: 'registry.npmjs.org',
        address: '127.0.0.1', family: 4,
        headers: { accept: 'application/vnd.npm.install-v1+json, application/json', acceptEncoding: 'identity' },
        timeoutMs: 1_000, maximumBytes: 1024,
      }, new AbortController().signal)).rejects.toMatchObject({ code: 'graph_metadata_incomplete' });
    } finally { await closeHttps(server); }
  });

  it('records durable request intent before transport and produces a bounded terminal ledger', async () => {
    const fixture = await brokerFixture();
    let sawIntent = false;
    const transport: HardenedPublicMetadataTransport = {
      implementationKind: 'synthetic',
      async fetchPackage(name) {
        sawIntent = fixture.sink.events.some((event) => event.name === 'metadata_request_started');
        return packument(name);
      },
    };
    const session = fixture.broker.prepareSession({
      plan: fixture.plan.prepared.plan,
      capsule: fixture.plan.prepared.capsule,
      startLease: fixture.startLease,
      startLeaseVerifier: fixture.leaseAuthority,
      audit: fixture.audit,
      transport,
      onFailure: () => undefined,
      mode: 'synthetic',
      monotonicNow: () => 1,
    });
    await fixture.broker.arm(session);
    const body = await fixture.broker.handle(session, 'GET', `/${fixture.plan.routeToken}/fixture`, {});
    expect(sawIntent).toBe(true);
    expect(JSON.parse(Buffer.from(body).toString('utf8'))).toMatchObject({ name: 'fixture' });
    const ledger = await fixture.broker.complete(session);
    expect(fixture.broker.authenticatesLedger(ledger)).toBe(true);
    expect(fixture.broker.claimFailure(session)).toBeUndefined();
    expect(ledger).toMatchObject({ startedRequestCount: 1, uniquePackageCount: 1, aggregateResponseBytes: body.byteLength });
    expect(JSON.stringify(ledger)).not.toContain(fixture.plan.routeToken);
  });

  it('reserves concurrent budgets before dispatch, aborts all work and never reuses authorization', async () => {
    const fixture = await brokerFixture({ concurrentRequests: 1, responseBytes: 1024, aggregateResponseBytes: 1024 });
    let aborted = false;
    let release!: () => void;
    let started!: () => void;
    const pending = new Promise<void>((resolvePromise) => { release = resolvePromise; });
    const transportStarted = new Promise<void>((resolvePromise) => { started = resolvePromise; });
    const transport: HardenedPublicMetadataTransport = {
      implementationKind: 'synthetic',
      async fetchPackage(name, _limits, signal) {
        signal.addEventListener('abort', () => { aborted = true; release(); }, { once: true });
        started();
        await pending;
        if (signal.aborted) throw new Error('aborted');
        return packument(name);
      },
    };
    let failures = 0;
    const input = {
      plan: fixture.plan.prepared.plan,
      capsule: fixture.plan.prepared.capsule,
      startLease: fixture.startLease,
      startLeaseVerifier: fixture.leaseAuthority,
      audit: fixture.audit,
      transport,
      onFailure: () => { failures += 1; },
      mode: 'synthetic' as const,
      monotonicNow: () => 1,
    };
    const session = fixture.broker.prepareSession(input);
    expect(() => fixture.broker.prepareSession(input)).toThrowError(expect.objectContaining({ code: 'graph_metadata_invalid' }));
    await fixture.broker.arm(session);
    const first = fixture.broker.handle(session, 'GET', `/${fixture.plan.routeToken}/fixture`, {});
    await transportStarted;
    await expect(fixture.broker.handle(session, 'GET', `/${fixture.plan.routeToken}/second`, {}))
      .rejects.toMatchObject({ code: 'graph_metadata_invalid' });
    await expect(first).rejects.toMatchObject({ code: 'graph_metadata_invalid' });
    expect(aborted).toBe(true);
    expect(failures).toBe(1);
    await expect(fixture.broker.complete(session)).rejects.toMatchObject({ code: 'graph_metadata_invalid' });
  });

  it('latches one private broker failure without closing the shared audit gate', async () => {
    const fixture = await brokerFixture({ uniquePackageNames: 4, concurrentRequests: 4, responseBytes: 1024, aggregateResponseBytes: 4096 });
    let onFailureCalls = 0;
    let startedCount = 0;
    let allStarted!: () => void;
    const allStartedPromise = new Promise<void>((resolvePromise) => { allStarted = resolvePromise; });
    const transport: HardenedPublicMetadataTransport = {
      implementationKind: 'synthetic',
      async fetchPackage(name, _limits, signal) {
        startedCount += 1;
        if (startedCount === 4) allStarted();
        await allStartedPromise;
        if (name === 'fixture') throw new Error('deterministic private transport failure');
        if (!signal.aborted) {
          await new Promise<void>((resolvePromise) => signal.addEventListener('abort', () => resolvePromise(), { once: true }));
        }
        throw new Error('in-flight request aborted');
      },
    };
    const session = fixture.broker.prepareSession({
      plan: fixture.plan.prepared.plan,
      capsule: fixture.plan.prepared.capsule,
      startLease: fixture.startLease,
      startLeaseVerifier: fixture.leaseAuthority,
      audit: fixture.audit,
      transport,
      onFailure: () => { onFailureCalls += 1; },
      mode: 'synthetic',
      monotonicNow: () => 1,
    });
    await fixture.broker.arm(session);
    const outcomes = await Promise.allSettled(['fixture', 'second', 'third', 'fourth'].map((name) =>
      fixture.broker.handle(session, 'GET', `/${fixture.plan.routeToken}/${name}`, {}),
    ));

    expect(outcomes.every((outcome) => outcome.status === 'rejected')).toBe(true);
    expect(onFailureCalls).toBe(1);
    await fixture.broker.abort(session);
    await expect(fixture.broker.complete(session)).rejects.toMatchObject({ code: 'graph_metadata_invalid' });
    const failure = fixture.broker.claimFailure(session);
    expect(failure).toMatchObject({
      causeCode: 'graph_metadata_invalid', reservedRequestCount: 4, activeRequestCount: 4,
      committedResponseCount: 0, committedResponseBytes: 0,
    });
    expect(failure?.reservedRequestCount).toBeLessThanOrEqual(fixture.plan.prepared.plan.limits.broker.totalRequests);
    expect(failure?.activeRequestCount).toBeLessThanOrEqual(failure?.reservedRequestCount ?? 0);
    expect(failure?.committedResponseCount).toBeLessThanOrEqual(failure?.reservedRequestCount ?? 0);
    expect(failure?.committedResponseBytes).toBeLessThanOrEqual(fixture.plan.prepared.plan.limits.broker.aggregateResponseBytes);
    expect(fixture.broker.authenticatesFailure(failure)).toBe(true);
    expect(fixture.broker.authenticatesFailure({ ...failure! })).toBe(false);
    expect(fixture.broker.claimFailure(session)).toBeUndefined();
    expect(() => fixture.broker.claimFailure({})).toThrowError(expect.objectContaining({ code: 'graph_metadata_invalid' }));
    expect(fixture.audit.events).not.toContain('genesis_incomplete');
    expect(fixture.sink.events.map((event) => event.name)).not.toContain('genesis_incomplete');
    await fixture.audit.record('npm_terminal_observed', { status: 'cancelled', exitCode: -1, stdoutBytes: 0, stderrBytes: 0 });
    await fixture.audit.record('listener_drained', { acceptedHandlerCount: 4 });
    expect(fixture.audit.events.slice(-2)).toEqual(['npm_terminal_observed', 'listener_drained']);
    expect(JSON.stringify(failure)).not.toContain(fixture.plan.routeToken);
    expect(JSON.stringify(failure)).not.toContain('deterministic private transport failure');
  });

  it('keeps a loopback listener disarmed until authorization and forwards only the exact route', async () => {
    const files = new RuntimeFileSnapshotAuthority();
    const trees = new RuntimeTreeSnapshotAuthority();
    const versionExecutor = syntheticVersionExecutor();
    const versions = new OwnedRuntimeVersionAuthority(files, trees, versionExecutor);
    const workspaces = new FinalizedGraphGenesisWorkspaceAuthority(trees);
    const probes = new OwnedContainmentProbeAuthority(files, workspaces, syntheticContainmentExecutor());
    const hosts = new OwnedHostPlatformAuthority(syntheticHostExecutor());
    const planAuthority = new HardenedGraphGenesisPlanAuthority(files, trees, probes, versions, workspaces, hosts);
    const broker = new HardenedMetadataBrokerAuthority(planAuthority);
    const listener = new HardenedLoopbackBrokerListener(broker);
    const port = await listener.listen();
    try {
      const before = await fetch(`http://127.0.0.1:${port}/not-armed`);
      expect(before.status).toBe(404);
      const plan = await planFixture({ files, trees, probes, versions, workspaces, hosts, planAuthority, brokerPort: port });
      const leaseAuthority = new SyntheticGraphGenesisStartLeaseAuthority(planAuthority);
      const startLease = leaseAuthority.createForTest(plan.prepared.plan, 10_000);
      const sink = new MemoryAuditSink();
      const audit = new GraphGenesisAuditGate(plan.prepared.plan.planHash, sink);
      await audit.record('authorization_finalized');
      const session = broker.prepareSession({
        plan: plan.prepared.plan, capsule: plan.prepared.capsule, startLease,
        startLeaseVerifier: leaseAuthority, audit,
        transport: { implementationKind: 'synthetic', async fetchPackage(name) { return packument(name); } },
        onFailure: () => undefined, mode: 'synthetic', monotonicNow: () => 1,
      });
      await broker.arm(session);
      listener.arm(session);
      const accepted = await fetch(`http://127.0.0.1:${port}/${plan.routeToken}/fixture`, { headers: { Connection: 'close' } });
      expect(accepted.status).toBe(200);
      expect(await accepted.json()).toMatchObject({ name: 'fixture' });
      const rejected = await fetch(`http://127.0.0.1:${port}/${plan.routeToken}/fixture/-/fixture.tgz`);
      expect(rejected.status).toBe(502);
      const afterFailure = await fetch(`http://127.0.0.1:${port}/${plan.routeToken}/fixture`);
      expect(afterFailure.status).toBe(404);
      const drained = await listener.closeAndDrain();
      expect(drained).toMatchObject({ outstandingHandlerCount: 0, openSocketCount: 0 });
      expect(drained.acceptedHandlerCount).toBeGreaterThanOrEqual(4);
    } finally { await listener.close(); }
  });

  it('drains the disarmed broker listener after denied, expired, or cancelled approval outcomes', async () => {
    for (const expected of ['denied', 'expired', 'cancelled'] as const) {
      const listener = new HardenedLoopbackBrokerListener({} as HardenedMetadataBrokerAuthority);
      const approvals = new LocalApprovalService();
      await listener.listen();
      try {
        const ticket = approvals.request({
          kind: 'graph_genesis', serverId: 'synthetic', toolName: 'synthetic', arguments: {},
          risk: { score: 1, band: 'low', signals: [] }, reasonCodes: [],
        }, expected === 'expired' ? 15 : 1_000);
        if (expected === 'denied') approvals.decide(ticket.request.id, 'denied');
        if (expected === 'cancelled') ticket.cancel();
        await expect(ticket.outcome).resolves.toBe(expected);
        await expect(listener.closeAndDrain()).resolves.toMatchObject({
          acceptedHandlerCount: 0, outstandingHandlerCount: 0, openSocketCount: 0,
        });
      } finally {
        approvals.close();
        await listener.close();
      }
    }
  });

  it('supervises only an authenticated capsule and records bounded terminal process evidence', async () => {
    const fixture = await planFixture();
    const leaseAuthority = new SyntheticGraphGenesisStartLeaseAuthority(fixture.planAuthority);
    const sink = new MemoryAuditSink();
    const audit = new GraphGenesisAuditGate(fixture.prepared.plan.planHash, sink);
    const supervisor = new GraphGenesisProcessSupervisor(fixture.planAuthority, fakeSpawn('completed'));
    const result = await supervisor.run({
      plan: fixture.prepared.plan,
      capsule: fixture.prepared.capsule,
      audit,
      startLease: leaseAuthority.createForTest(fixture.prepared.plan, 10_000),
      startLeaseVerifier: leaseAuthority,
      monotonicNow: () => 1,
      onFailure: () => undefined,
      mode: 'synthetic',
    });
    expect(supervisor.authenticates(result)).toBe(true);
    expect(result).toMatchObject({ status: 'completed', exitCode: 0, childClosed: true });
    expect(sink.events.map((event) => event.name)).toEqual([
      'npm_spawn_intent_recorded', 'npm_spawn_started', 'npm_terminal_observed',
    ]);

    const overflowAudit = new GraphGenesisAuditGate(fixture.prepared.plan.planHash, new MemoryAuditSink());
    const overflow = new GraphGenesisProcessSupervisor(fixture.planAuthority, fakeSpawn('overflow'));
    const overflowLeaseAuthority = new SyntheticGraphGenesisStartLeaseAuthority(fixture.planAuthority);
    const overflowResult = await overflow.run({
      plan: fixture.prepared.plan, capsule: fixture.prepared.capsule, audit: overflowAudit,
      startLease: overflowLeaseAuthority.createForTest(fixture.prepared.plan, 10_000),
      startLeaseVerifier: overflowLeaseAuthority, monotonicNow: () => 1,
      onFailure: () => undefined, mode: 'synthetic',
    });
    expect(overflowResult.status).toBe('output_overflow');
  });

  it('fails closed when durable terminal audit persistence fails', async () => {
    const fixture = await planFixture();
    const leaseAuthority = new SyntheticGraphGenesisStartLeaseAuthority(fixture.planAuthority);
    const audit = new GraphGenesisAuditGate(fixture.prepared.plan.planHash, new FailingAuditSink('npm_terminal_observed'));
    const supervisor = new GraphGenesisProcessSupervisor(fixture.planAuthority, fakeSpawn('completed'));
    let failures = 0;
    await expect(supervisor.run({
      plan: fixture.prepared.plan, capsule: fixture.prepared.capsule, audit,
      startLease: leaseAuthority.createForTest(fixture.prepared.plan, 10_000),
      startLeaseVerifier: leaseAuthority, monotonicNow: () => 1,
      onFailure: () => { failures += 1; }, mode: 'synthetic',
    })).rejects.toMatchObject({ code: 'stage_audit_incomplete' });
    expect(failures).toBe(1);
  });

  it('prepares one atomic product terminal only after durable candidate output and cleanup evidence', async () => {
    const fixture = await planFixture();
    const audit = new GraphGenesisAuditGate(fixture.prepared.plan.planHash, new MemoryAuditSink());
    await audit.record('runtime_snapshot_complete', { runtimeManifestDigest: '1'.repeat(64) });
    await audit.record('containment_probe_complete', { containmentEvidenceDigest: '2'.repeat(64) });
    await audit.record('plan_ready', { executionEnvelopeHash: '3'.repeat(64) });
    await audit.record('authorization_finalized');
    await audit.record('broker_armed');
    await audit.record('npm_spawn_intent_recorded');
    await audit.record('npm_spawn_started');
    await audit.record('metadata_request_started', { sequence: 1, packageName: 'fixture' });
    await audit.record('metadata_response_validated', { sequence: 1, packageName: 'fixture', responseBytes: 32 });
    await audit.record('npm_terminal_observed', { status: 'completed', exitCode: 0, stdoutBytes: 0, stderrBytes: 0 });
    await audit.record('lock_validation_started');
    await audit.record('candidate_compiled');
    expect(() => audit.prepareAtomicTerminalSuccess()).toThrow(/stage_audit_incomplete/);

    const successEvents = [
      ['runtime_snapshot_complete', { runtimeManifestDigest: '1'.repeat(64) }],
      ['containment_probe_complete', { containmentEvidenceDigest: '2'.repeat(64) }],
      ['plan_ready', { executionEnvelopeHash: '3'.repeat(64) }],
      ['authorization_finalized', {}],
      ['broker_armed', {}],
      ['npm_spawn_intent_recorded', {}],
      ['npm_spawn_started', {}],
      ['metadata_request_started', { sequence: 1, packageName: 'fixture' }],
      ['metadata_response_validated', { sequence: 1, packageName: 'fixture', responseBytes: 32 }],
      ['npm_terminal_observed', { status: 'completed', exitCode: 0, stdoutBytes: 0, stderrBytes: 0 }],
      ['listener_drained', { acceptedHandlerCount: 1 }],
      ['lock_validation_started', {}],
      ['post_state_validated', { postStateDigest: '4'.repeat(64) }],
      ['candidate_compiled', {}],
      ['candidate_output_intent', { artifactDigest: 'a'.repeat(64), candidateDigest: 'b'.repeat(64) }],
      ['candidate_output_written', { artifactDigest: 'a'.repeat(64), candidateDigest: 'b'.repeat(64), bytes: 128 }],
      ['cleanup_complete', {}],
    ] as const;
    const completeAudit = new GraphGenesisAuditGate(fixture.prepared.plan.planHash, new MemoryAuditSink());
    for (const [event, payload] of successEvents) await completeAudit.record(event, payload);
    const preparation = completeAudit.prepareAtomicTerminalSuccess();
    expect(completeAudit.authenticatesTerminalPreparation(preparation)).toBe(true);
    expect(preparation).toMatchObject({ terminalState: 'ready_for_atomic_product_commit' });
    await expect(completeAudit.record('cleanup_complete')).rejects.toMatchObject({ code: 'stage_audit_incomplete' });
    const mismatchedOutputAudit = new GraphGenesisAuditGate(fixture.prepared.plan.planHash, new MemoryAuditSink());
    for (const [event, payload] of successEvents) {
      await mismatchedOutputAudit.record(event, event === 'candidate_output_written'
        ? { ...payload, candidateDigest: 'c'.repeat(64) } : payload);
    }
    expect(() => mismatchedOutputAudit.prepareAtomicTerminalSuccess()).toThrow(/stage_audit_incomplete/);
  });

  it('rejects archive residue before post-state evidence or candidate compilation', async () => {
    const fixture = await planFixture();
    const lock = exactTargetLock();
    writeFileSync(join(fixture.workspace.rootRealpath, 'package.json'), JSON.stringify({
      name: 'apg-graph-genesis', version: '0.0.0', private: true,
      dependencies: { '@modelcontextprotocol/server-filesystem': '2026.7.10' },
    }));
    writeFileSync(join(fixture.workspace.rootRealpath, 'package-lock.json'), JSON.stringify(lock));
    writeFileSync(join(fixture.workspace.rootRealpath, 'cache/unexpected.tgz'), Buffer.from([0x1f, 0x8b, 0x00]));
    const postStates = new HardenedGraphGenesisPostStateAuthority(fixture.planAuthority, fixture.workspaceAuthority);
    await expect(postStates.inspect({
      plan: fixture.prepared.plan,
      executionCapsule: fixture.prepared.capsule,
      workspace: fixture.workspace,
    })).rejects.toMatchObject({ code: 'acceptance_incomplete' });
  });

  it('authenticates completion only after process, broker, candidate, cleanup and ordered audit all agree', async () => {
    const fixture = await planFixture();
    const leaseAuthority = new SyntheticGraphGenesisStartLeaseAuthority(fixture.planAuthority);
    const startLease = leaseAuthority.createForTest(fixture.prepared.plan, 10_000);
    const sink = new MemoryAuditSink();
    const audit = new GraphGenesisAuditGate(fixture.prepared.plan.planHash, sink);
    await audit.record('runtime_snapshot_complete', { runtimeManifestDigest: '1'.repeat(64) });
    await audit.record('containment_probe_complete', { containmentEvidenceDigest: '2'.repeat(64) });
    await audit.record('plan_ready', { executionEnvelopeHash: '3'.repeat(64) });
    await audit.record('authorization_finalized');
    const broker = new HardenedMetadataBrokerAuthority(fixture.planAuthority);
    const session = broker.prepareSession({
      plan: fixture.prepared.plan, capsule: fixture.prepared.capsule, startLease,
      startLeaseVerifier: leaseAuthority, audit,
      transport: { implementationKind: 'synthetic', async fetchPackage(name) { return packument(name); } },
      onFailure: () => undefined, mode: 'synthetic', monotonicNow: () => 1,
    });
    await broker.arm(session);
    const child = controlledSpawn();
    const supervisor = new GraphGenesisProcessSupervisor(fixture.planAuthority, child.adapter);
    const processPromise = supervisor.run({
      plan: fixture.prepared.plan, capsule: fixture.prepared.capsule, audit,
      startLease, startLeaseVerifier: leaseAuthority, monotonicNow: () => 1,
      onFailure: () => undefined, mode: 'synthetic',
    });
    await waitUntil(() => sink.events.some((event) => event.name === 'npm_spawn_started'));
    await broker.handle(session, 'GET', `/${fixture.routeToken}/@modelcontextprotocol%2fserver-filesystem`, {});
    const ledger = await broker.complete(session);
    child.close(0, null);
    const processResult = await processPromise;
    await audit.record('listener_drained', { acceptedHandlerCount: 1 });
    const lock = exactTargetLock();
    writeFileSync(join(fixture.workspace.rootRealpath, 'package.json'), JSON.stringify({
      name: 'apg-graph-genesis', version: '0.0.0', private: true,
      dependencies: { '@modelcontextprotocol/server-filesystem': '2026.7.10' },
    }));
    writeFileSync(join(fixture.workspace.rootRealpath, 'package-lock.json'), JSON.stringify(lock));
    await audit.record('lock_validation_started');
    const candidates = new ExactGraphCandidateAuthority();
    const postStates = new HardenedGraphGenesisPostStateAuthority(fixture.planAuthority, fixture.workspaceAuthority);
    const inspected = await postStates.inspect({
      plan: fixture.prepared.plan,
      executionCapsule: fixture.prepared.capsule,
      workspace: fixture.workspace,
    });
    await audit.record('post_state_validated', { postStateDigest: inspected.evidence.evidenceDigest });
    const candidateCompiler = new HardenedGraphGenesisCandidateCompiler(postStates, candidates);
    const candidate = candidateCompiler.compile({
      plan: fixture.prepared.plan,
      postState: inspected.evidence,
      privatePostStateCapsule: inspected.privateCapsule,
    });
    await audit.record('candidate_compiled');
    const cleanupAuthority = new NoFollowWorkspaceCleanupAuthority(fixture.workspaceAuthority);
    const cleanup = await cleanupAuthority.cleanup(fixture.workspace, computeWorkspaceBinding(fixture.workspace));
    await audit.record('cleanup_complete');
    const completionAuthority = new HardenedControlledGraphGenesisAuthority(
      fixture.planAuthority, candidateCompiler, postStates, broker, supervisor, cleanupAuthority,
    );
    const completion = await completionAuthority.complete({
      plan: fixture.prepared.plan, capsule: fixture.prepared.capsule, candidate,
      postState: inspected.evidence, ledger, process: processResult, cleanup, auditGate: audit,
    });
    expect(completionAuthority.authenticates(completion)).toBe(true);
    expect(completionAuthority.authenticates({ ...completion })).toBe(false);
    expect(completion).toMatchObject({ status: 'complete', nodeCount: 1, edgeCount: 0 });
    expect(JSON.stringify(completion)).not.toContain(fixture.routeToken);
    expect(sink.events.at(-1)?.name).toBe('genesis_complete');
  });

  it('performs exact no-follow cleanup and quarantines a workspace containing a symlink', async () => {
    const trees = new RuntimeTreeSnapshotAuthority();
    const workspaceAuthority = new FinalizedGraphGenesisWorkspaceAuthority(trees);
    const cleanup = new NoFollowWorkspaceCleanupAuthority(workspaceAuthority);
    const parent = temp('apg-cleanup-');
    const workspace = await workspaceAuthority.initialize(join(parent, 'clean'), '(version 1)\n(deny default)\n');
    const binding = computeWorkspaceBinding(workspace);
    const evidence = await cleanup.cleanup(workspace, binding);
    expect(cleanup.authenticates(evidence)).toBe(true);
    expect(existsSync(workspace.rootRealpath)).toBe(false);

    const quarantine = await workspaceAuthority.initialize(join(parent, 'quarantine'), '(version 1)\n(deny default)\n');
    symlinkSync('/private/tmp', join(quarantine.rootRealpath, 'unexpected-link'));
    await expect(cleanup.cleanup(quarantine, computeWorkspaceBinding(quarantine)))
      .rejects.toMatchObject({ code: 'artifact_cleanup_incomplete' });
    expect(existsSync(quarantine.rootRealpath)).toBe(true);
  });
});

class MemoryAuditSink implements GraphGenesisDurableAuditSink {
  readonly implementationKind = 'synthetic' as const;
  readonly events: Array<{ name: string; payload: Readonly<Record<string, string | number | boolean>> }> = [];
  async append(name: Parameters<GraphGenesisDurableAuditSink['append']>[0], payload: Readonly<Record<string, string | number | boolean>>): Promise<void> {
    this.events.push({ name, payload });
  }
}

class FailingAuditSink implements GraphGenesisDurableAuditSink {
  readonly implementationKind = 'synthetic' as const;
  constructor(private readonly failureEvent: Parameters<GraphGenesisDurableAuditSink['append']>[0]) {}
  async append(event: Parameters<GraphGenesisDurableAuditSink['append']>[0]): Promise<void> {
    if (event === this.failureEvent) throw new Error('synthetic private sink failure');
  }
}

async function planFixture(options: Readonly<{
  files?: RuntimeFileSnapshotAuthority;
  trees?: RuntimeTreeSnapshotAuthority;
  probes?: OwnedContainmentProbeAuthority;
  versions?: OwnedRuntimeVersionAuthority;
  workspaces?: FinalizedGraphGenesisWorkspaceAuthority;
  hosts?: OwnedHostPlatformAuthority;
  planAuthority?: HardenedGraphGenesisPlanAuthority;
  brokerPort?: number;
  brokerLimits?: ReturnType<typeof limits>['broker'];
}> = {}) {
  const parent = temp('apg-hardened-plan-');
  const files = options.files ?? new RuntimeFileSnapshotAuthority();
  const trees = options.trees ?? new RuntimeTreeSnapshotAuthority();
  const versions = options.versions ?? new OwnedRuntimeVersionAuthority(files, trees, syntheticVersionExecutor());
  const workspaces = options.workspaces ?? new FinalizedGraphGenesisWorkspaceAuthority(trees);
  const probes = options.probes ?? new OwnedContainmentProbeAuthority(files, workspaces, syntheticContainmentExecutor());
  const hosts = options.hosts ?? new OwnedHostPlatformAuthority(syntheticHostExecutor());
  const planAuthority = options.planAuthority ?? new HardenedGraphGenesisPlanAuthority(files, trees, probes, versions, workspaces, hosts);
  const runtime = join(parent, 'runtime');
  mkdirSync(join(runtime, 'npm/bin'), { recursive: true });
  mkdirSync(join(runtime, 'broker'), { recursive: true });
  const paths = {
    node: join(runtime, 'node'), npmCli: join(runtime, 'npm/bin/npm-cli.js'),
    sandboxExec: join(runtime, 'sandbox-exec'), broker: join(runtime, 'broker/broker.js'), probe: join(runtime, 'probe.js'),
  };
  for (const [name, path] of Object.entries(paths)) writeFileSync(path, `synthetic ${name} runtime`);
  writeFileSync(join(runtime, 'npm/package.json'), JSON.stringify({ name: 'npm', version: '11.16.0' }));
  const snapshots = {
    node: await files.capture('node', paths.node),
    npmCli: await files.capture('npm_cli', paths.npmCli),
    sandboxExec: await files.capture('sandbox_exec', paths.sandboxExec),
    brokerRuntime: await files.capture('broker_runtime', paths.broker),
    probeRuntime: await files.capture('probe_runtime', paths.probe),
  };
  const npmTree = await trees.capture(join(runtime, 'npm'));
  const brokerTree = await trees.capture(join(runtime, 'broker'));
  const runtimeVersions = await versions.observe({
    node: snapshots.node, npmCli: snapshots.npmCli, npmTree,
  });
  const host = await hosts.observe();
  const brokerPort = options.brokerPort ?? 45454;
  const containment = new SeatbeltLoopbackContainmentAuthority();
  const profile = containment.prepare({ osBuild: '25G83', sandboxExecSha256: snapshots.sandboxExec.sha256, allowedPort: brokerPort });
  const workspaceAuthority = workspaces;
  const workspace = await workspaceAuthority.initialize(join(parent, 'workspace'), profile.profileText);
  const workspaceBinding = computeWorkspaceBinding(workspace);
  const binding = {
    osBuild: '25G83', hostEvidenceDigest: host.evidenceDigest,
    nodeSnapshotDigest: snapshots.node.snapshotDigest,
    probeSnapshotDigest: snapshots.probeRuntime.snapshotDigest,
    sandboxExecSnapshotDigest: snapshots.sandboxExec.snapshotDigest,
    workspaceBinding, profileDigest: profile.profileDigest, allowedPort: brokerPort,
  };
  const containmentEvidence = await probes.observe(binding, profile, {
    node: snapshots.node, probe: snapshots.probeRuntime, sandboxExec: snapshots.sandboxExec, workspace,
  });
  const routeToken = 'a'.repeat(32);
  const launch = buildGraphGenesisLaunch({
    sandboxExecPath: snapshots.sandboxExec.absolutePath,
    profilePath: join(workspace.rootRealpath, 'broker-profile.sb'),
    nodePath: snapshots.node.absolutePath,
    npmCliPath: snapshots.npmCli.absolutePath,
    npmRuntimeRoot: npmTree.rootRealpath,
    workspaceRoot: workspace.rootRealpath,
    brokerPort,
    routeToken,
  });
  const prepareInput = {
    planId: 'b'.repeat(32), host, ...snapshots, npmTree, brokerTree, runtimeVersions,
    containmentEvidence, workspace, brokerPort, routeToken, launch,
    limits: { ...limits(), ...(options.brokerLimits === undefined ? {} : { broker: options.brokerLimits }) },
    allowSynthetic: true,
  } as const;
  const prepared = planAuthority.prepare(prepareInput);
  return { parent, files, trees, probes, versions, hosts, planAuthority, snapshots, workspaceAuthority, workspace, routeToken, prepareInput, prepared };
}

async function brokerFixture(overrides: Partial<ReturnType<typeof limits>['broker']> = {}) {
  const brokerLimits = { ...limits().broker, ...overrides };
  const plan = await planFixture({ brokerLimits });
  const leaseAuthority = new SyntheticGraphGenesisStartLeaseAuthority(plan.planAuthority);
  const startLease = leaseAuthority.createForTest(plan.prepared.plan, 10_000);
  const sink = new MemoryAuditSink();
  const audit = new GraphGenesisAuditGate(plan.prepared.plan.planHash, sink);
  await audit.record('authorization_finalized');
  return { plan, leaseAuthority, startLease, sink, audit, broker: new HardenedMetadataBrokerAuthority(plan.planAuthority) };
}

function limits() {
  return {
    broker: { uniquePackageNames: 2, totalRequests: 4, concurrentRequests: 2, responseBytes: 1024, aggregateResponseBytes: 4096, requestTimeoutMs: 100 },
    completeTimeoutMs: 1_000, stdoutBytes: 1024, stderrBytes: 1024,
    packageJsonBytes: 4096, packageLockBytes: 4096,
  };
}

function containmentObservations() {
  return {
    approvedLoopbackPortConnected: true, alternateLoopbackPortDenied: true,
    nonLoopbackLocalAddressDenied: true, ipv6LoopbackDenied: true,
    outsideWorkspaceWriteDenied: true, childProcessDenied: true,
    workerThreadDenied: true, addonGrantAbsent: true, publicNetworkAttempted: false as const,
  };
}

function syntheticVersionExecutor(): RuntimeVersionProbeExecutor {
  return {
    implementationKind: 'synthetic',
    async observe() { return { nodeVersion: '26.3.1', npmVersion: '11.16.0' }; },
  };
}

function syntheticContainmentExecutor(): ContainmentProbeExecutor {
  return {
    implementationKind: 'synthetic',
    async run() { return containmentObservations(); },
  };
}

function syntheticHostExecutor(): HostPlatformProbeExecutor {
  return {
    implementationKind: 'synthetic',
    async observe() {
      return {
        platform: 'darwin', architecture: 'arm64', osBuild: '25G83',
        bootSessionId: '00000000-0000-0000-0000-000000000001',
      };
    },
  };
}

function resolver(addresses: readonly { address: string; family: 4 | 6 }[]): RegistryAddressResolver {
  return { async resolve() { return addresses; } };
}

function client(response: (input: PinnedHttpsRequest) => ReturnType<typeof packument>): PinnedHttpsClient {
  return { implementationKind: 'synthetic', async request(input) { return response(input); } };
}

function packument(name: string) {
  return {
    status: 200, contentType: 'application/json', contentEncoding: 'identity',
    finalUrl: `https://registry.npmjs.org/${name.replace('/', '%2f')}`,
    redirected: false as const,
    body: Buffer.from(JSON.stringify({ name, versions: {} })),
  };
}

function fakeSpawn(mode: 'completed' | 'overflow'): GraphGenesisSpawnAdapter {
  return {
    implementationKind: 'synthetic',
    spawn() {
      const child = new EventEmitter() as EventEmitter & {
        pid: number;
        stdout: PassThrough;
        stderr: PassThrough;
        kill: () => boolean;
      };
      child.pid = 99_999_999;
      child.stdout = new PassThrough();
      child.stderr = new PassThrough();
      let closed = false;
      const close = (code: number | null, signal: NodeJS.Signals | null) => {
        if (closed) return;
        closed = true;
        child.emit('close', code, signal);
      };
      child.kill = () => { queueMicrotask(() => close(null, 'SIGTERM')); return true; };
      queueMicrotask(() => {
        if (mode === 'overflow') child.stdout.write(Buffer.alloc(2048));
        else close(0, null);
      });
      return child as unknown as import('node:child_process').ChildProcess;
    },
  };
}

function controlledSpawn(): Readonly<{
  adapter: GraphGenesisSpawnAdapter;
  close: (code: number | null, signal: NodeJS.Signals | null) => void;
}> {
  let closeChild!: (code: number | null, signal: NodeJS.Signals | null) => void;
  const adapter: GraphGenesisSpawnAdapter = {
    implementationKind: 'synthetic',
    spawn() {
      const child = new EventEmitter() as EventEmitter & {
        pid: number;
        stdout: PassThrough;
        stderr: PassThrough;
        kill: () => boolean;
      };
      child.pid = 99_999_998;
      child.stdout = new PassThrough();
      child.stderr = new PassThrough();
      let closed = false;
      closeChild = (code, signal) => {
        if (closed) return;
        closed = true;
        child.emit('close', code, signal);
      };
      child.kill = () => { queueMicrotask(() => closeChild(null, 'SIGTERM')); return true; };
      return child as unknown as import('node:child_process').ChildProcess;
    },
  };
  return Object.freeze({ adapter, close: (code, signal) => closeChild(code, signal) });
}

function exactTargetLock() {
  const target = '@modelcontextprotocol/server-filesystem';
  const version = '2026.7.10';
  return {
    name: 'apg-graph-genesis', version: '0.0.0', lockfileVersion: 3, requires: true,
    packages: {
      '': { name: 'apg-graph-genesis', version: '0.0.0', dependencies: { [target]: version } },
      [`node_modules/${target}`]: {
        version,
        resolved: `https://registry.npmjs.org/@modelcontextprotocol/server-filesystem/-/server-filesystem-${version}.tgz`,
        integrity: `sha512-${createHash('sha512').update('synthetic').digest('base64')}`,
      },
    },
  };
}

async function waitUntil(predicate: () => boolean): Promise<void> {
  const deadline = Date.now() + 2_000;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise<void>((resolvePromise) => setTimeout(resolvePromise, 5));
  }
  throw new Error('condition not reached');
}

async function localListener(): Promise<Readonly<{ server: Server; port: number }>> {
  const server = createServer((socket) => socket.destroy());
  await new Promise<void>((resolvePromise, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolvePromise());
  });
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('listener unavailable');
  return Object.freeze({ server, port: address.port });
}

async function closeLocalListener(server: Server): Promise<void> {
  await new Promise<void>((resolvePromise) => server.close(() => resolvePromise()));
}

async function listenHttps(server: HttpsServer): Promise<number> {
  await new Promise<void>((resolvePromise, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolvePromise());
  });
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('TLS listener unavailable');
  return address.port;
}

async function closeHttps(server: HttpsServer): Promise<void> {
  server.closeAllConnections();
  await new Promise<void>((resolvePromise) => server.close(() => resolvePromise()));
}

function ephemeralTlsIdentity(hostname: string) {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const algorithm = sequence(oid('1.2.840.113549.1.1.11'), der(0x05, Buffer.alloc(0)));
  const name = sequence(set(sequence(oid('2.5.4.3'), der(0x0c, Buffer.from(hostname)))));
  const now = Date.now();
  const validity = sequence(utcTime(new Date(now - 60_000)), utcTime(new Date(now + 86_400_000)));
  const basicConstraints = sequence(
    oid('2.5.29.19'), der(0x01, Buffer.from([0xff])), der(0x04, sequence()),
  );
  const keyUsage = sequence(
    oid('2.5.29.15'), der(0x01, Buffer.from([0xff])), der(0x04, der(0x03, Buffer.from([7, 0x80]))),
  );
  const extendedKeyUsage = sequence(
    oid('2.5.29.37'), der(0x04, sequence(oid('1.3.6.1.5.5.7.3.1'))),
  );
  const subjectAltName = sequence(
    oid('2.5.29.17'), der(0x04, sequence(der(0x82, Buffer.from(hostname)))),
  );
  const serial = Buffer.from(randomBytes(16));
  serial[0] = (serial[0] ?? 0) & 0x7f;
  const tbs = sequence(
    der(0xa0, integer(Buffer.from([2]))), integer(serial), algorithm, name, validity, name,
    publicKey.export({ type: 'spki', format: 'der' }),
    der(0xa3, sequence(basicConstraints, keyUsage, extendedKeyUsage, subjectAltName)),
  );
  const signature = sign('RSA-SHA256', tbs, privateKey);
  const certificateDer = sequence(tbs, algorithm, der(0x03, Buffer.concat([Buffer.from([0]), signature])));
  const base64 = certificateDer.toString('base64').match(/.{1,64}/gu)?.join('\n') ?? '';
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  return Object.freeze({ privateKeyPem, certificate: `-----BEGIN CERTIFICATE-----\n${base64}\n-----END CERTIFICATE-----\n` });
}

function sequence(...parts: Buffer[]): Buffer { return der(0x30, Buffer.concat(parts)); }
function set(...parts: Buffer[]): Buffer { return der(0x31, Buffer.concat(parts)); }
function integer(bytes: Buffer): Buffer {
  let value = bytes;
  while (value.length > 1 && value[0] === 0) value = value.subarray(1);
  if (((value[0] ?? 0) & 0x80) !== 0) value = Buffer.concat([Buffer.from([0]), value]);
  return der(0x02, value);
}
function utcTime(date: Date): Buffer {
  const year = String(date.getUTCFullYear() % 100).padStart(2, '0');
  const field = (value: number) => String(value).padStart(2, '0');
  const text = `${year}${field(date.getUTCMonth() + 1)}${field(date.getUTCDate())}${field(date.getUTCHours())}${field(date.getUTCMinutes())}${field(date.getUTCSeconds())}Z`;
  return der(0x17, Buffer.from(text));
}
function oid(value: string): Buffer {
  const arcs = value.split('.').map(Number);
  const output = [40 * arcs[0]! + arcs[1]!];
  for (const arc of arcs.slice(2)) {
    const encoded = [arc & 0x7f];
    for (let remaining = Math.floor(arc / 128); remaining > 0; remaining = Math.floor(remaining / 128)) {
      encoded.unshift((remaining & 0x7f) | 0x80);
    }
    output.push(...encoded);
  }
  return der(0x06, Buffer.from(output));
}
function der(tag: number, content: Buffer): Buffer {
  const length = content.length < 128
    ? Buffer.from([content.length])
    : (() => {
      const bytes: number[] = [];
      for (let value = content.length; value > 0; value = Math.floor(value / 256)) bytes.unshift(value & 0xff);
      return Buffer.from([0x80 | bytes.length, ...bytes]);
    })();
  return Buffer.concat([Buffer.from([tag]), length, content]);
}

function temp(prefix: string): string {
  const path = mkdtempSync(join(tmpdir(), prefix));
  temporaryPaths.push(path);
  return path;
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}
