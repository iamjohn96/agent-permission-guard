import { spawn, type ChildProcess } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import { resolve } from 'node:path';

import {
  FinalizedGraphGenesisWorkspaceAuthority,
  OwnedContainmentProbeAuthority,
  RuntimeFileSnapshotAuthority,
} from '../../src/stage/graph-genesis-hardening.js';
import { PreflightSqliteAudit } from '../../src/stage/graph-genesis-preflight-audit.js';
import { captureLocalGraphGenesisPreflight } from '../../src/stage/graph-genesis-preflight.js';
import { PreflightRoot } from '../../src/stage/graph-genesis-preflight-root.js';

const MAX_DIAGNOSTICS = 8;
const LABEL = /^[a-z][a-z0-9_]{0,47}$/u;
const CHILD_RESULT_MAX_BYTES = 1_024;
const CHILD_CLOSE_GRACE_MS = 1_000;
export const PREFLIGHT_OPERATION_DEADLINE_MS = 20_000;
export const PREFLIGHT_PHASE_TEST_TIMEOUT_MS = 25_000;

export type PreflightCancellationPhase = 'runtime' | 'workspace' | 'containment' | 'audit' | 'cleanup';
type FixtureMode = PreflightCancellationPhase | 'exit_before_result';
type Cleanup = Readonly<{ label: string; close: () => Promise<void> }>;
type ChildExit = Readonly<{ code: number | null; signal: NodeJS.Signals | null }>;
type ClosedPreflightProjection = Readonly<{
  phase: PreflightCancellationPhase;
  status: 'local_preflight_failed';
  executionAuthorized: false;
  planReusable: false;
  sessionClosed: true;
  cleanup: 'passed' | 'not_needed';
  publicDns: 'not_attempted';
  registry: 'not_attempted';
  npmCli: 'not_attempted';
  failureCode: 'preflight_cancelled_or_deadline';
}>;

export type TestLifecycleDiagnostic = Readonly<{ label: string; code: 'aborted' | 'deadline' | 'error' | 'unknown' }>;

/** Test-only owner for one monotonic deadline, immediate rejection observation, and registered cleanup. */
export class BoundedTestLifecycle {
  readonly #controller = new AbortController();
  readonly #deadline: number;
  readonly #timer: NodeJS.Timeout;
  readonly #cleanup: Cleanup[] = [];
  readonly #diagnostics: TestLifecycleDiagnostic[] = [];
  #armed = true;
  #closed = false;
  #closePromise: Promise<void> | undefined;

  constructor(deadlineMs: number) {
    if (!Number.isSafeInteger(deadlineMs) || deadlineMs < 1 || deadlineMs > 30_000) fail();
    this.#deadline = performance.now() + deadlineMs;
    this.#timer = setTimeout(() => this.abort('deadline'), deadlineMs);
    this.#timer.unref();
  }

  get signal(): AbortSignal { return this.#controller.signal; }
  get diagnostics(): readonly TestLifecycleDiagnostic[] { return Object.freeze([...this.#diagnostics]); }

  register(label: string, close: () => Promise<void>): void {
    this.#live(label);
    this.#cleanup.push(Object.freeze({ label, close }));
  }

  observe<T>(label: string, pending: Promise<T>): Promise<T> {
    this.#live(label);
    const observed = Promise.resolve(pending);
    void observed.then(
      () => undefined,
      (error: unknown) => { this.#record(label, error); },
    );
    return observed;
  }

  async wait<T>(label: string, pending: Promise<T>): Promise<T> {
    return this.waitObserved(label, this.observe(label, pending));
  }

  async waitObserved<T>(label: string, observed: Promise<T>): Promise<T> {
    this.#live(label);
    return new Promise<T>((resolveValue, rejectValue) => {
      let settled = false;
      const finish = (callback: () => void) => {
        if (settled) return;
        settled = true;
        this.signal.removeEventListener('abort', onAbort);
        callback();
      };
      const onAbort = () => finish(() => rejectValue(new Error('test_lifecycle_aborted')));
      this.signal.addEventListener('abort', onAbort, { once: true });
      observed.then((value) => finish(() => resolveValue(value)), (error: unknown) => finish(() => rejectValue(error)));
      if (this.signal.aborted) onAbort();
    });
  }

  /** Startup owners disarm only after their complete readiness contract has settled. */
  disarm(): void {
    if (this.#closed || this.signal.aborted || !this.#armed) fail();
    this.#armed = false;
    clearTimeout(this.#timer);
  }

  abort(reason: 'aborted' | 'deadline' = 'aborted'): void {
    if (this.signal.aborted) return;
    this.#record('lifecycle', reason);
    this.#controller.abort();
  }

  async close(): Promise<void> {
    if (this.#closePromise !== undefined) return this.#closePromise;
    this.#closed = true;
    clearTimeout(this.#timer);
    if (this.#armed) this.abort();
    this.#armed = false;
    this.#closePromise = (async () => {
      let failed = false;
      for (const entry of this.#cleanup.splice(0).reverse()) {
        try {
          await entry.close();
        } catch (error) {
          failed = true;
          this.#record(entry.label, error);
        }
      }
      if (failed) throw new Error('test_lifecycle_cleanup_failed');
    })();
    return this.#closePromise;
  }

  #live(label: string): void {
    if (!LABEL.test(label) || this.#closed || this.signal.aborted || !Number.isFinite(performance.now())
      || this.#armed && performance.now() >= this.#deadline) fail();
  }
  #record(label: string, error: unknown): void {
    if (this.#diagnostics.length >= MAX_DIAGNOSTICS || !LABEL.test(label)) return;
    const code: TestLifecycleDiagnostic['code'] = error === 'deadline' ? 'deadline'
      : error === 'aborted' ? 'aborted'
        : error instanceof Error ? 'error' : 'unknown';
    this.#diagnostics.push(Object.freeze({ label, code }));
  }
}

/** A failing operation cannot return control until its registered owner has completed cleanup. */
export async function waitForOwnedOperation<T>(
  lifecycle: BoundedTestLifecycle,
  label: string,
  pending: Promise<T>,
): Promise<T> {
  try {
    return await lifecycle.wait(label, pending);
  } catch (error) {
    await lifecycle.close();
    throw error;
  }
}

export async function runFixedPreflightCancellationFixture(phase: FixtureMode): Promise<Readonly<ClosedPreflightProjection & {
  childClosed: true;
  diagnostics: readonly TestLifecycleDiagnostic[];
}>> {
  const lifecycle = new BoundedTestLifecycle(PREFLIGHT_OPERATION_DEADLINE_MS);
  const child = spawn(process.execPath, [resolve('dist/test/fixtures/preflight-cancellation-lifecycle.js'), '--child', phase], {
    stdio: ['ignore', 'ignore', 'pipe'], env: {},
  });
  const exited = observeChildExit(child);
  lifecycle.register('fixture_child', async () => { await closeChild(child, exited); });
  const result = observeChildResult(child, exited);
  try {
    const projection = await waitForOwnedOperation(lifecycle, 'fixture_result', lifecycle.observe('fixture_result', result));
    await waitForOwnedOperation(lifecycle, 'fixture_exit', exited);
    lifecycle.disarm();
    await lifecycle.close();
    return Object.freeze({ ...projection, childClosed: true as const, diagnostics: lifecycle.diagnostics });
  } catch {
    try { await lifecycle.close(); } catch { /* preserve the original closed failure code below */ }
    throw new Error('fixture_child_result_invalid');
  }
}

function observeChildExit(child: ChildProcess): Promise<ChildExit> {
  return new Promise<ChildExit>((resolveExit, rejectExit) => {
    child.once('exit', (code, signal) => resolveExit(Object.freeze({ code, signal })));
    child.once('error', () => rejectExit(new Error('fixture_child_exit_error')));
  });
}

function observeChildResult(child: ChildProcess, exited: Promise<ChildExit>): Promise<ClosedPreflightProjection> {
  return new Promise<ClosedPreflightProjection>((resolveResult, rejectResult) => {
    let bytes = 0;
    let output = '';
    let settled = false;
    const finish = (callback: () => void) => {
      if (settled) return;
      settled = true;
      child.stderr?.off('data', onData);
      callback();
    };
    const rejectClosed = () => finish(() => rejectResult(new Error('fixture_child_result_invalid')));
    const onData = (chunk: Buffer) => {
      bytes += chunk.byteLength;
      if (bytes > CHILD_RESULT_MAX_BYTES) { rejectClosed(); return; }
      output += chunk.toString('utf8');
      const newline = output.indexOf('\n');
      if (newline < 0) return;
      const line = output.slice(0, newline);
      if (output.slice(newline + 1).trim().length !== 0) { rejectClosed(); return; }
      const projection = parseClosedProjection(line);
      if (projection === undefined) { rejectClosed(); return; }
      finish(() => resolveResult(projection));
    };
    child.stderr?.on('data', onData);
    void exited.then(() => rejectClosed(), () => rejectClosed());
  });
}

function parseClosedProjection(value: string): ClosedPreflightProjection | undefined {
  try {
    const parsed: unknown = JSON.parse(value);
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return undefined;
    const record = parsed as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    const expected = ['cleanup', 'executionAuthorized', 'failureCode', 'npmCli', 'phase', 'planReusable', 'publicDns', 'registry', 'sessionClosed', 'status'];
    if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) return undefined;
    if (!isPhase(record.phase) || record.status !== 'local_preflight_failed' || record.executionAuthorized !== false
      || record.planReusable !== false || record.sessionClosed !== true
      || record.cleanup !== (record.phase === 'runtime' ? 'not_needed' : 'passed')
      || record.publicDns !== 'not_attempted' || record.registry !== 'not_attempted' || record.npmCli !== 'not_attempted'
      || record.failureCode !== 'preflight_cancelled_or_deadline') return undefined;
    return Object.freeze(record as unknown as ClosedPreflightProjection);
  } catch { return undefined; }
}

async function closeChild(child: ChildProcess, exited: Promise<ChildExit>): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) {
    await exited;
    return;
  }
  try {
    if (!child.kill('SIGTERM')) throw new Error('fixture_child_signal_failed');
    await within(exited, CHILD_CLOSE_GRACE_MS);
  } catch {
    if (child.exitCode === null && child.signalCode === null && !child.kill('SIGKILL')) throw new Error('fixture_child_signal_failed');
    await within(exited, CHILD_CLOSE_GRACE_MS);
  }
}

function within<T>(pending: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise<T>((resolveValue, rejectValue) => {
    const timer = setTimeout(() => rejectValue(new Error('fixture_child_close_timeout')), timeoutMs);
    timer.unref();
    void pending.then(
      (value) => { clearTimeout(timer); resolveValue(value); },
      () => { clearTimeout(timer); rejectValue(new Error('fixture_child_exit_error')); },
    );
  });
}

function isPhase(value: unknown): value is PreflightCancellationPhase {
  return value === 'runtime' || value === 'workspace' || value === 'containment' || value === 'audit' || value === 'cleanup';
}

type PatchedMethod = (this: object, ...args: unknown[]) => Promise<unknown>;

async function runChild(phase: FixtureMode): Promise<void> {
  if (phase === 'exit_before_result') return;
  const target = phase === 'runtime' ? RuntimeFileSnapshotAuthority.prototype
    : phase === 'workspace' ? FinalizedGraphGenesisWorkspaceAuthority.prototype
      : phase === 'containment' ? OwnedContainmentProbeAuthority.prototype
        : phase === 'audit' ? PreflightSqliteAudit.prototype : PreflightRoot.prototype;
  const method = phase === 'runtime' ? 'capture' : phase === 'workspace' ? 'initialize'
    : phase === 'containment' ? 'observe' : phase === 'audit' ? 'verifyReopened' : 'cleanup';
  const record = target as unknown as Record<string, unknown>;
  const original = record[method];
  if (typeof original !== 'function') throw new Error('fixture_child_patch_invalid');
  const controller = new AbortController();
  let calls = 0;
  record[method] = async function (this: object, ...args: unknown[]): Promise<unknown> {
    const value = await (original as PatchedMethod).apply(this, args);
    calls += 1;
    controller.abort();
    return value;
  };
  try {
    const report = await captureLocalGraphGenesisPreflight({ signal: controller.signal });
    const projection: ClosedPreflightProjection = Object.freeze({
      phase,
      status: report.status === 'local_preflight_failed' ? report.status : failChild(),
      executionAuthorized: report.executionAuthorized,
      planReusable: report.planReusable,
      sessionClosed: report.sessionClosed === true ? report.sessionClosed : failChild(),
      cleanup: report.cleanup === (phase === 'runtime' ? 'not_needed' : 'passed') ? report.cleanup : failChild(),
      publicDns: report.publicDns,
      registry: report.registry,
      npmCli: report.npmCli,
      failureCode: report.failureCode === 'preflight_cancelled_or_deadline' ? report.failureCode : failChild(),
    });
    if (calls < 1 || projection.executionAuthorized !== false || projection.planReusable !== false) failChild();
    process.stderr.write(`${JSON.stringify(projection)}\n`);
  } finally {
    record[method] = original;
  }
}

function fail(): never { throw new Error('test_lifecycle_invalid'); }
function failChild(): never { throw new Error('fixture_child_projection_invalid'); }

if (process.argv[2] === '--child') {
  const mode = process.argv[3];
  if (!isPhase(mode) && mode !== 'exit_before_result') process.exitCode = 1;
  else void runChild(mode).catch(() => { process.exitCode = 1; });
}
