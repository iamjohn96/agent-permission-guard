import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { openAuditDatabase, type AuditDatabase } from '../../src/db/database.js';
import { emitGraphGenesisDiagnostic } from '../../src/stage/graph-genesis-diagnostics.js';
import type { AuthenticatedHardenedBrokerFailure } from '../../src/stage/graph-genesis-network.js';
import {
  GRAPH_GENESIS_LIVE_PHASES,
  classifyGraphGenesisFailure,
  GraphGenesisLivePhaseAuthority,
  selectGraphGenesisFailureTerminalStatus,
  SyntheticGraphGenesisFullFlowTwin,
  type GraphGenesisLivePhase,
  type SyntheticGraphGenesisFullFlowAdapter,
} from '../../src/stage/graph-genesis-live-state.js';

const temporaryPaths: string[] = [];

afterEach(() => {
  for (const path of temporaryPaths.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe('Exact Production Graph Genesis owner boundary', () => {
  it('runs the exact full phase order with disposable SQLite, fake metadata, inert child and temporary output', async () => {
    const root = mkdtempSync(join(tmpdir(), 'apg-synthetic-live-'));
    temporaryPaths.push(root);
    chmodSync(root, 0o700);
    const adapter = new SyntheticFullFlowFixture(root);
    try {
      const result = await new SyntheticGraphGenesisFullFlowTwin(adapter).run();
      expect(result).toEqual({ status: 'synthetic_complete', phases: GRAPH_GENESIS_LIVE_PHASES });
      expect(adapter.childRuns).toBe(1);
      expect(adapter.metadataRequests).toEqual(['@modelcontextprotocol/server-filesystem']);
      expect(readFileSync(adapter.outputPath, 'utf8')).toContain('synthetic-candidate-digest');
      expect(adapter.persistedPhases()).toEqual(GRAPH_GENESIS_LIVE_PHASES);
      expect(existsSync(adapter.workspacePath)).toBe(false);
    } finally { adapter.close(); }
  });

  it('rejects out-of-order transitions and replay', async () => {
    const authority = new GraphGenesisLivePhaseAuthority();
    expect(() => authority.advance('PLAN_READY')).toThrow(/acceptance_incomplete/);
    const adapter: SyntheticGraphGenesisFullFlowAdapter = {
      implementationKind: 'synthetic', perform() {},
    };
    const twin = new SyntheticGraphGenesisFullFlowTwin(adapter);
    await expect(twin.run()).resolves.toMatchObject({ status: 'synthetic_complete' });
    await expect(twin.run()).rejects.toThrow(/acceptance_incomplete/);
  });

  it('stops at cancellation without running later phases', async () => {
    const controller = new AbortController();
    const observed: GraphGenesisLivePhase[] = [];
    const adapter: SyntheticGraphGenesisFullFlowAdapter = {
      implementationKind: 'synthetic',
      perform(phase) {
        observed.push(phase);
        if (phase === 'BROKER_ARMED') controller.abort();
      },
    };
    await expect(new SyntheticGraphGenesisFullFlowTwin(adapter).run(controller.signal))
      .rejects.toThrow(/acceptance_incomplete/);
    expect(observed.at(-1)).toBe('BROKER_ARMED');
    expect(observed).not.toContain('NPM_RUNNING');
  });

  it('classifies approved pre-spawn cancellation as not started without external or package effects', () => {
    expect(classifyGraphGenesisFailure({
      cancelled: true, externalReadMayHaveOccurred: false, processSpawned: false,
      cleanupComplete: true, cleanupFailed: false, rootPreserved: false, terminalUnknown: false,
    })).toEqual({
      status: 'not_started', exitCode: 2, reasonCode: 'pre_dispatch_cancelled',
      externalReadMayHaveOccurred: false, installationOccurred: false, packageDownloadOccurred: false,
    });
  });

  it('does not downgrade external/process effects, quarantine, or terminal ambiguity to not started', () => {
    const base = {
      cancelled: true, externalReadMayHaveOccurred: false, processSpawned: false,
      cleanupComplete: true, cleanupFailed: false, rootPreserved: false, terminalUnknown: false,
    };
    expect(classifyGraphGenesisFailure({ ...base, externalReadMayHaveOccurred: true }))
      .toMatchObject({ status: 'incomplete', exitCode: 4 });
    expect(classifyGraphGenesisFailure({ ...base, processSpawned: true }))
      .toMatchObject({ status: 'failed', exitCode: 3 });
    expect(classifyGraphGenesisFailure({ ...base, cleanupFailed: true }))
      .toMatchObject({ status: 'quarantined', exitCode: 5 });
    expect(classifyGraphGenesisFailure({ ...base, terminalUnknown: true }))
      .toMatchObject({ status: 'outcome_unknown', exitCode: 6 });
  });

  it.each([
    ['incomplete metadata takes precedence over cancellation', 'incomplete', true, 'incomplete_external_read'],
    ['incomplete metadata without cancellation', 'incomplete', false, 'incomplete_external_read'],
    ['validated metadata and cancellation', 'validated', true, 'cancelled'],
    ['validated metadata and downstream failure', 'validated', false, 'execution_error'],
    ['no metadata and cancellation', 'not_started', true, 'cancelled'],
    ['no metadata and downstream failure', 'not_started', false, 'execution_error'],
  ] as const)('selects the exact Graph terminal for %s', (_name, externalReadStatus, cancelled, expected) => {
    expect(selectGraphGenesisFailureTerminalStatus({ externalReadStatus, cancelled })).toBe(expected);
  });

  it('keeps the synthetic twin free of production network and spawn capabilities', () => {
    const source = readFileSync(join(process.cwd(), 'src/stage/graph-genesis-live-state.ts'), 'utf8');
    expect(source).not.toMatch(/node:dns|node:https|node:child_process|SystemRegistryAddressResolver|NodePinnedHttpsClient|NodeGraphGenesisSpawnAdapter/);
    const tests = readFileSync(join(process.cwd(), 'test/unit/graph-genesis-live-owner.test.ts'), 'utf8');
    expect(tests).not.toMatch(/from\s+['"][^'"]*graph-genesis-live\.js['"]/u);
  });

  it('keeps production evidence and cancellation gates in durable effect order without invoking the owner', () => {
    const source = readFileSync(join(process.cwd(), 'src/stage/graph-genesis-live.ts'), 'utf8');
    const ordered = [
      "record('runtime_snapshot_complete'", "record('containment_probe_complete'", "record('plan_ready'",
      "record('listener_drained'", "record('post_state_validated'", "record('candidate_output_intent'",
      'artifacts.writeExclusive', "record('candidate_output_written'", "record('cleanup_complete'",
      'await root.cleanup()', 'prepareAtomicTerminalSuccess()',
    ];
    let previous = -1;
    for (const marker of ordered) {
      const index = source.indexOf(marker, previous + 1);
      expect(index).toBeGreaterThan(previous);
      previous = index;
    }
    expect(source).toContain('setTimeout(() => controller.abort(), 60_000)');
    expect(source).toContain("const supervisor = new GraphGenesisProcessSupervisor(plans, new NodeGraphGenesisSpawnAdapter());\n    throwIfAborted(controller.signal);\n    spawned = true;");
    const rejectedApproval = source.indexOf("if (authorization.status !== 'authorized')");
    const listenerDrain = source.indexOf('await listener.closeAndDrain();', rejectedApproval);
    const dashboardShutdown = source.indexOf('await shutdownDashboard(approvals, dashboard, dashboardState);', rejectedApproval);
    expect(listenerDrain).toBeGreaterThan(rejectedApproval);
    expect(dashboardShutdown).toBeGreaterThan(listenerDrain);
  });

  it('leaves terminal audit ownership with the live owner after a broker latch', () => {
    const source = readFileSync(join(process.cwd(), 'src/stage/graph-genesis-live.ts'), 'utf8');
    const supervisorObserved = source.indexOf('processResult = await supervisor.run({');
    const failureClaimed = source.indexOf('const claimedBrokerFailure = broker.claimFailure(brokerSession);');
    const listenerRecorded = source.indexOf("await authorization.executionAudit.record('listener_drained'");
    const brokerCauseRaised = source.indexOf('if (brokerFailure !== undefined) fail(brokerFailure.causeCode);');
    const terminalOutcome = source.indexOf('audit.finalizeGraphGenesisOutcome({');
    expect(supervisorObserved).toBeGreaterThan(-1);
    expect(failureClaimed).toBeGreaterThan(supervisorObserved);
    expect(listenerRecorded).toBeGreaterThan(failureClaimed);
    expect(brokerCauseRaised).toBeGreaterThan(listenerRecorded);
    expect(terminalOutcome).toBeGreaterThan(brokerCauseRaised);
    expect(source).toContain('broker.authenticatesFailure(claimedBrokerFailure)');
    expect(source).toContain('errorCode: brokerFailure?.causeCode ?? safeErrorCode(error)');
    expect(source).toContain("const auditPersistenceFailure = safeErrorCode(error) === 'stage_audit_incomplete';");
    expect(source).toContain('selectGraphGenesisFailureTerminalStatus({');
    expect(source).not.toContain("externalRead ? 'incomplete_external_read' : controller.signal.aborted ? 'cancelled' : 'execution_error'");
  });

  it('emits one bounded redacted diagnostic only through the owner failure path', () => {
    const writes: string[] = [];
    const failure = diagnosticFailure({
      requestOrdinal: 7,
      // Deliberately foreign fields must never be projected by the allowlist.
      url: 'https://registry.example.invalid/secret', message: 'secret stack', packageName: 'private-package',
    });
    expect(emitGraphGenesisDiagnostic(failure, (line) => writes.push(line))).toBe(true);
    expect(writes).toHaveLength(1);
    expect(writes[0]).toMatch(/^\[apg\] graph-genesis-diagnostic /u);
    expect(Buffer.byteLength(writes[0]!, 'utf8')).toBeLessThanOrEqual(1024);
    expect(writes[0]).not.toContain('registry.example.invalid');
    expect(writes[0]).not.toContain('private-package');
    expect(writes[0]).not.toContain('secret stack');
    expect(emitGraphGenesisDiagnostic(failure, () => { throw new Error('synthetic broken pipe'); })).toBe(false);
    expect(emitGraphGenesisDiagnostic(diagnosticFailure({ planHash: 'a'.repeat(2_000) }), (line) => writes.push(line))).toBe(false);
    expect(writes).toHaveLength(1);

    const source = readFileSync(join(process.cwd(), 'src/stage/graph-genesis-live.ts'), 'utf8');
    const terminalAttempt = source.indexOf('failureTerminalAttempted = true;');
    const diagnostic = source.indexOf('emitGraphGenesisDiagnostic(brokerFailure');
    const postStateDiagnostic = source.indexOf('postStates?.emitFailureDiagnostic(postStateFailure');
    expect(terminalAttempt).toBeGreaterThan(-1);
    expect(diagnostic).toBeGreaterThan(terminalAttempt);
    expect(postStateDiagnostic).toBeGreaterThan(terminalAttempt);
    expect(postStateDiagnostic).toBeGreaterThan(source.indexOf("executionAudit.events.includes('listener_drained')", terminalAttempt));
  });

  it.runIf(existsSync(join(process.cwd(), 'dist/src/stage/graph-genesis-diagnostics.js')))(
    'keeps a synthetic diagnostic child naturally exiting with a closed stderr descriptor',
    () => {
      const fixture = join(process.cwd(), 'test/fixtures/graph-genesis-diagnostic-child.mjs');
      const normal = spawnSync(process.execPath, [fixture], { encoding: 'utf8' });
      expect(normal.status).toBe(0);
      expect(normal.stderr).toContain('[apg] graph-genesis-diagnostic ');
      const broken = spawnSync(process.execPath, [fixture, 'closed-fd'], { encoding: 'utf8' });
      expect(broken.status).toBe(0);
      expect(broken.stderr).toBe('');
    },
  );

  it.runIf(existsSync(join(process.cwd(), 'dist/src/stage/graph-genesis-diagnostics.js')))(
    'keeps a synthetic diagnostic child naturally exiting after its stderr pipe closes',
    async () => {
      const fixture = join(process.cwd(), 'test/fixtures/graph-genesis-diagnostic-child.mjs');
      const child = spawn(process.execPath, [fixture, 'broken-pipe'], { stdio: ['ignore', 'ignore', 'pipe'] });
      child.stderr?.destroy();
      const exitCode = await new Promise<number | null>((resolveExit) => child.once('close', (code) => resolveExit(code)));
      expect(exitCode).toBe(0);
    },
  );
});

function diagnosticFailure(extra: Record<string, unknown> = {}): AuthenticatedHardenedBrokerFailure {
  return {
    failureVersion: 2,
    planHash: 'a'.repeat(64),
    causeCode: 'graph_metadata_invalid',
    diagnosticVersion: 1,
    predicate: 'http_status_rejected',
    requestOrdinal: null,
    reservedRequestCount: 10,
    activeRequestCount: 4,
    committedResponseCount: 6,
    committedResponseBytes: 644145,
    failureDigest: 'b'.repeat(64),
    ...extra,
  } as AuthenticatedHardenedBrokerFailure;
}

class SyntheticFullFlowFixture implements SyntheticGraphGenesisFullFlowAdapter {
  readonly implementationKind = 'synthetic' as const;
  readonly outputPath: string;
  readonly workspacePath: string;
  readonly metadataRequests: string[] = [];
  childRuns = 0;
  readonly #database: AuditDatabase;
  readonly #fakeMetadata = Object.freeze({
    name: '@modelcontextprotocol/server-filesystem',
    version: '2026.7.10',
    dist: { integrity: `sha512-${'a'.repeat(86)}==` },
  });

  constructor(root: string) {
    this.outputPath = join(root, 'candidate.json');
    this.workspacePath = join(root, 'workspace');
    this.#database = openAuditDatabase(join(root, 'synthetic.sqlite'));
    this.#database.exec('CREATE TABLE synthetic_graph_flow (sequence INTEGER PRIMARY KEY, phase TEXT NOT NULL)');
  }

  perform(phase: GraphGenesisLivePhase): void {
    const sequence = GRAPH_GENESIS_LIVE_PHASES.indexOf(phase) + 1;
    this.#database.prepare('INSERT INTO synthetic_graph_flow (sequence, phase) VALUES (?, ?)').run(sequence, phase);
    if (phase === 'LOCAL_RESOURCES_CREATED') mkdirSync(this.workspacePath, { mode: 0o700 });
    if (phase === 'BROKER_ARMED') {
      expect(this.#fakeMetadata.version).toBe('2026.7.10');
      this.metadataRequests.push(this.#fakeMetadata.name);
    }
    if (phase === 'NPM_RUNNING') this.childRuns += 1;
    if (phase === 'OUTPUT_DURABLE') {
      writeFileSync(this.outputPath, '{"candidateDigest":"synthetic-candidate-digest"}\n', { flag: 'wx', mode: 0o600 });
    }
    if (phase === 'WORKSPACE_CLEANED') rmSync(this.workspacePath, { recursive: true, force: false });
  }

  persistedPhases(): readonly string[] {
    return (this.#database.prepare('SELECT phase FROM synthetic_graph_flow ORDER BY sequence').all() as Array<{ phase: string }>)
      .map((row) => row.phase);
  }

  close(): void { this.#database.close(); }
}
