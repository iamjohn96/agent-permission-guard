import { spawn, type ChildProcess } from 'node:child_process';
import { createHash } from 'node:crypto';

import { canonicalJson } from '../audit/canonical-json.js';

import type {
  AuthenticatedGraphGenesisExecutionCapsule,
  GraphGenesisAuditGate,
  HardenedGraphGenesisPlan,
  HardenedGraphGenesisPlanAuthority,
} from './graph-genesis-hardening.js';
import { PackageStageError } from './profile.js';

const NODE_SPAWN_ADAPTERS = new WeakSet<object>();

export interface GraphGenesisSpawnAdapter {
  readonly implementationKind: 'production' | 'synthetic';
  spawn(capsule: AuthenticatedGraphGenesisExecutionCapsule): ChildProcess;
}

export class NodeGraphGenesisSpawnAdapter implements GraphGenesisSpawnAdapter {
  readonly implementationKind = 'production' as const;

  constructor() { NODE_SPAWN_ADAPTERS.add(this); }

  spawn(capsule: AuthenticatedGraphGenesisExecutionCapsule): ChildProcess {
    return spawn(capsule.launch.executable, capsule.launch.args, {
      cwd: capsule.launch.cwd,
      env: { ...capsule.launch.env },
      shell: false,
      detached: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  }
}

export type AuthenticatedGraphGenesisProcessResult = Readonly<{
  resultVersion: 1;
  planHash: string;
  status: 'completed' | 'failed' | 'timed_out' | 'cancelled' | 'output_overflow';
  exitCode: number | null;
  signal?: NodeJS.Signals;
  stdoutBytes: number;
  stderrBytes: number;
  childClosed: true;
  resultDigest: string;
}>;

export class GraphGenesisProcessSupervisor {
  readonly #authenticated = new WeakSet<object>();

  constructor(
    private readonly plans: HardenedGraphGenesisPlanAuthority,
    private readonly spawnAdapter: GraphGenesisSpawnAdapter,
  ) {}

  async run(input: Readonly<{
    plan: HardenedGraphGenesisPlan;
    capsule: AuthenticatedGraphGenesisExecutionCapsule;
    audit: GraphGenesisAuditGate;
    onFailure: () => void | Promise<void>;
    signal?: AbortSignal;
    allowSynthetic?: boolean;
  }>): Promise<AuthenticatedGraphGenesisProcessResult> {
    if (!this.plans.authenticatesPair(input.plan, input.capsule)
      || input.audit.planHash !== input.plan.planHash
      || (!input.allowSynthetic && !NODE_SPAWN_ADAPTERS.has(this.spawnAdapter))) failProcess();
    if (input.signal?.aborted === true) {
      await safeFailure(input);
      return this.#result(input.plan, 'cancelled', null, undefined, 0, 0);
    }
    await this.plans.revalidatePair(input.plan, input.capsule);
    await input.audit.record('npm_spawn_intent_recorded');
    let child: ChildProcess;
    try { child = this.spawnAdapter.spawn(input.capsule); } catch {
      await safeFailure(input);
      return this.#result(input.plan, 'failed', null, undefined, 0, 0);
    }
    let status: AuthenticatedGraphGenesisProcessResult['status'] | undefined;
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let forceTimer: ReturnType<typeof setTimeout> | undefined;
    let failureNotified = false;
    const notifyFailure = async () => {
      if (failureNotified) return;
      failureNotified = true;
      await safeFailure(input);
    };
    const terminate = (next: NonNullable<typeof status>) => {
      if (status !== undefined) return;
      status = next;
      signalGroup(child, 'SIGTERM');
      forceTimer = setTimeout(() => signalGroup(child, 'SIGKILL'), 2_000);
      forceTimer.unref();
      void notifyFailure();
    };
    const closed = new Promise<Readonly<{ exitCode: number | null; signal?: NodeJS.Signals }>>((resolveClose) => {
      child.once('close', (exitCode, exitSignal) => resolveClose(Object.freeze({
        exitCode,
        ...(exitSignal === null ? {} : { signal: exitSignal }),
      })));
    });
    child.stdout?.on('data', (chunk: Buffer) => {
      const next = stdoutBytes + chunk.byteLength;
      stdoutBytes = Math.min(next, input.plan.limits.stdoutBytes);
      if (next > input.plan.limits.stdoutBytes) terminate('output_overflow');
    });
    child.stderr?.on('data', (chunk: Buffer) => {
      const next = stderrBytes + chunk.byteLength;
      stderrBytes = Math.min(next, input.plan.limits.stderrBytes);
      if (next > input.plan.limits.stderrBytes) terminate('output_overflow');
    });
    child.once('error', () => terminate('failed'));
    const timeout = setTimeout(() => terminate('timed_out'), input.plan.limits.completeTimeoutMs);
    timeout.unref();
    const abort = () => terminate('cancelled');
    input.signal?.addEventListener('abort', abort, { once: true });
    try {
      await input.audit.record('npm_spawn_started');
    } catch (error) {
      terminate('failed');
      const observed = await waitForClose(closed, 4_000);
      clearTimeout(timeout);
      if (forceTimer !== undefined) clearTimeout(forceTimer);
      input.signal?.removeEventListener('abort', abort);
      await notifyFailure();
      if (observed === undefined) throw new PackageStageError('graph_metadata_incomplete');
      throw error;
    }
    const observed = await waitForClose(closed, input.plan.limits.completeTimeoutMs + 4_000);
    clearTimeout(timeout);
    if (forceTimer !== undefined) clearTimeout(forceTimer);
    input.signal?.removeEventListener('abort', abort);
    if (observed === undefined) {
      terminate('failed');
      await notifyFailure();
      throw new PackageStageError('graph_metadata_incomplete');
    }
    const terminal = status ?? (observed.exitCode === 0 ? 'completed' : 'failed');
    if (terminal !== 'completed') await notifyFailure();
    try {
      await input.audit.record('npm_terminal_observed', {
        status: terminal,
        exitCode: observed.exitCode ?? -1,
        stdoutBytes,
        stderrBytes,
      });
    } catch (error) {
      await notifyFailure();
      throw error;
    }
    return this.#result(input.plan, terminal, observed.exitCode, observed.signal, stdoutBytes, stderrBytes);
  }

  authenticates(value: unknown): value is AuthenticatedGraphGenesisProcessResult {
    return typeof value === 'object' && value !== null && this.#authenticated.has(value);
  }

  #result(
    plan: HardenedGraphGenesisPlan,
    status: AuthenticatedGraphGenesisProcessResult['status'],
    exitCode: number | null,
    signal: NodeJS.Signals | undefined,
    stdoutBytes: number,
    stderrBytes: number,
  ): AuthenticatedGraphGenesisProcessResult {
    const unsigned = Object.freeze({
      resultVersion: 1 as const,
      planHash: plan.planHash,
      status,
      exitCode,
      ...(signal === undefined ? {} : { signal }),
      stdoutBytes,
      stderrBytes,
      childClosed: true as const,
    });
    const result = Object.freeze({ ...unsigned, resultDigest: digest(unsigned) });
    this.#authenticated.add(result);
    return result;
  }
}

async function waitForClose<T>(closed: Promise<T>, timeoutMs: number): Promise<T | undefined> {
  return await new Promise<T | undefined>((resolvePromise) => {
    const timeout = setTimeout(() => resolvePromise(undefined), timeoutMs);
    timeout.unref();
    void closed.then((value) => {
      clearTimeout(timeout);
      resolvePromise(value);
    });
  });
}

async function safeFailure(input: Readonly<{ onFailure: () => void | Promise<void> }>): Promise<void> {
  try { await input.onFailure(); } catch { /* preserve original terminal failure */ }
}

function signalGroup(child: ChildProcess, signal: NodeJS.Signals): void {
  if (child.pid === undefined) return;
  try { process.kill(-child.pid, signal); } catch {
    try { child.kill(signal); } catch { /* process already closed */ }
  }
}

function digest(value: unknown): string {
  return createHash('sha256').update(canonicalJson(value)).digest('hex');
}

function failProcess(): never { throw new PackageStageError('artifact_plan_invalid'); }
