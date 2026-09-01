import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { validateInstallPlanPreconditions, verifyInstallExecution } from './verifier.js';
import type {
  InstallExecutionPlan,
  InstallExecutionResult,
  InstallRunnerAdapter,
} from './types.js';

const MAX_CAPTURE_BYTES = 65_536;
const TERMINATION_GRACE_MS = 2_000;

export class ControlledLocalInstallRunner implements InstallRunnerAdapter {
  async run(plan: InstallExecutionPlan, signal?: AbortSignal): Promise<InstallExecutionResult> {
    const startedAt = Date.now();
    if (process.platform === 'win32') throw new Error('Controlled install execution preview is not supported on Windows');
    await validateInstallPlanPreconditions(plan);
    if (signal?.aborted === true) {
      return await resultWithoutProcess(plan, 'cancelled', startedAt);
    }

    const privateDirectory = await mkdtemp(join(tmpdir(), 'apg-install-'));
    try {
      const userConfig = join(privateDirectory, 'user.npmrc');
      const globalConfig = join(privateDirectory, 'global.npmrc');
      const cache = join(privateDirectory, 'cache');
      await Promise.all([
        writeFile(userConfig, '', { mode: 0o600 }),
        writeFile(globalConfig, '', { mode: 0o600 }),
      ]);
      return await execute(plan, signal, startedAt, minimalInstallEnvironment(plan.environmentPath, {
        privateDirectory,
        userConfig,
        globalConfig,
        cache,
      }));
    } finally {
      await rm(privateDirectory, { recursive: true, force: true }).catch(() => undefined);
    }
  }
}

async function execute(
  plan: InstallExecutionPlan,
  externalSignal: AbortSignal | undefined,
  startedAt: number,
  environment: NodeJS.ProcessEnv,
): Promise<InstallExecutionResult> {
  return await new Promise((resolve) => {
    const stdout = new BoundedOutput();
    const stderr = new BoundedOutput();
    let termination: 'timed_out' | 'cancelled' | undefined;
    let settled = false;
    let forceTimer: ReturnType<typeof setTimeout> | undefined;
    let child: ChildProcess;
    try {
      child = spawn(plan.executable.path, plan.arguments, {
        cwd: plan.workingDirectory,
        env: environment,
        shell: false,
        detached: process.platform !== 'win32',
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch {
      resolve(failedResult(startedAt, 'runner could not start'));
      return;
    }

    child.stdout?.on('data', (chunk: Buffer) => stdout.add(chunk));
    child.stderr?.on('data', (chunk: Buffer) => stderr.add(chunk));
    const timeout = setTimeout(() => terminate('timed_out'), plan.timeoutMs);
    timeout.unref();
    const abort = () => terminate('cancelled');
    externalSignal?.addEventListener('abort', abort, { once: true });

    child.once('error', () => finish(null, undefined, 'failed'));
    child.once('close', (code, signal) => finish(code, signal, termination));

    function terminate(reason: 'timed_out' | 'cancelled'): void {
      if (termination !== undefined || settled) return;
      termination = reason;
      signalProcess(child, 'SIGTERM');
      forceTimer = setTimeout(() => signalProcess(child, 'SIGKILL'), TERMINATION_GRACE_MS);
      forceTimer.unref();
    }

    function finish(
      exitCode: number | null,
      exitSignal: NodeJS.Signals | null | undefined,
      forcedStatus: 'timed_out' | 'cancelled' | 'failed' | undefined,
    ): void {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (forceTimer !== undefined) clearTimeout(forceTimer);
      externalSignal?.removeEventListener('abort', abort);
      const status = forcedStatus ?? (exitCode === 0 ? 'completed' : 'failed');
      void verifyInstallExecution(plan, status === 'completed').then((verification) => {
        resolve({
          status,
          exitCode,
          ...(exitSignal === null || exitSignal === undefined ? {} : { signal: exitSignal }),
          durationMs: Math.max(0, Date.now() - startedAt),
          summary: status === 'completed' ? 'controlled execution completed' : `controlled execution ${status}`,
          output: {
            stdoutBytes: stdout.totalBytes,
            stderrBytes: stderr.totalBytes,
            stdoutPreview: stdout.preview(),
            stderrPreview: stderr.preview(),
            truncated: stdout.truncated || stderr.truncated,
          },
          verification,
        });
      }, () => resolve(failedResult(startedAt, 'post-execution verification failed')));
    }
  });
}

function minimalInstallEnvironment(environmentPath: string, paths: Readonly<{
  privateDirectory: string;
  userConfig: string;
  globalConfig: string;
  cache: string;
}>): NodeJS.ProcessEnv {
  return {
    PATH: environmentPath,
    HOME: paths.privateDirectory,
    TMPDIR: paths.privateDirectory,
    TEMP: paths.privateDirectory,
    TMP: paths.privateDirectory,
    NPM_CONFIG_USERCONFIG: paths.userConfig,
    NPM_CONFIG_GLOBALCONFIG: paths.globalConfig,
    NPM_CONFIG_CACHE: paths.cache,
    NPM_CONFIG_UPDATE_NOTIFIER: 'false',
    NPM_CONFIG_AUDIT: 'false',
    NPM_CONFIG_FUND: 'false',
    ...(process.env.SystemRoot === undefined ? {} : { SystemRoot: process.env.SystemRoot }),
    ...(process.env.ComSpec === undefined ? {} : { ComSpec: process.env.ComSpec }),
    ...(process.env.PATHEXT === undefined ? {} : { PATHEXT: process.env.PATHEXT }),
  };
}

function signalProcess(child: ChildProcess, signal: NodeJS.Signals): void {
  if (child.pid === undefined) return;
  try {
    if (process.platform !== 'win32') process.kill(-child.pid, signal);
    else child.kill(signal);
  } catch {
    try {
      child.kill(signal);
    } catch {
      // The process may have exited between observation and signalling.
    }
  }
}

class BoundedOutput {
  totalBytes = 0;
  truncated = false;
  readonly #chunks: Buffer[] = [];
  #captured = 0;

  add(chunk: Buffer): void {
    this.totalBytes += chunk.byteLength;
    const remaining = MAX_CAPTURE_BYTES - this.#captured;
    if (remaining <= 0) {
      this.truncated = true;
      return;
    }
    const kept = chunk.subarray(0, remaining);
    this.#chunks.push(kept);
    this.#captured += kept.byteLength;
    if (kept.byteLength !== chunk.byteLength) this.truncated = true;
  }

  preview(): string {
    return redactProcessOutput(Buffer.concat(this.#chunks).toString('utf8'));
  }
}

function redactProcessOutput(value: string): string {
  return value
    .replace(/\b(Bearer\s+)[A-Za-z0-9._~+/=-]+/gi, '$1[REDACTED]')
    .replace(/\b(npm_[A-Za-z0-9]{8,})\b/g, '[REDACTED]')
    .replace(/(https?:\/\/)[^\s/@:]+:[^\s/@]+@/gi, '$1[REDACTED]@')
    .replace(/\b(api[_-]?key|authorization|cookie|credential|password|private[_-]?key|secret|token)\s*[:=]\s*[^\s]+/gi, '$1=[REDACTED]');
}

async function resultWithoutProcess(
  plan: InstallExecutionPlan,
  status: 'cancelled',
  startedAt: number,
): Promise<InstallExecutionResult> {
  return {
    status,
    exitCode: null,
    durationMs: Math.max(0, Date.now() - startedAt),
    summary: 'controlled execution cancelled',
    verification: await verifyInstallExecution(plan, false),
  };
}

function failedResult(startedAt: number, summary: string): InstallExecutionResult {
  return { status: 'failed', exitCode: null, durationMs: Math.max(0, Date.now() - startedAt), summary };
}
