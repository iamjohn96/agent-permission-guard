import { afterEach, describe, expect, it } from 'vitest';

import {
  BoundedTestLifecycle,
  PREFLIGHT_OPERATION_DEADLINE_MS,
  PREFLIGHT_PHASE_TEST_TIMEOUT_MS,
  runFixedPreflightCancellationFixture,
  type PreflightCancellationPhase,
  waitForOwnedOperation,
} from '../fixtures/preflight-cancellation-lifecycle.js';

const lifecycles: BoundedTestLifecycle[] = [];

afterEach(async () => { await Promise.all(lifecycles.splice(0).map((lifecycle) => lifecycle.close())); });

describe.runIf(process.platform === 'darwin' && process.arch === 'arm64' && process.version === 'v26.3.1')(
  'compiled preparation cancellation at await boundaries', () => {
  it.each<PreflightCancellationPhase>(['runtime', 'workspace', 'containment', 'audit', 'cleanup'])(
    'preserves compiled fail-closed cancellation at the %s boundary in one owned child',
    async (phase) => {
      const result = await runFixedPreflightCancellationFixture(phase);
      expect(result).toEqual({
        phase,
        status: 'local_preflight_failed',
        executionAuthorized: false,
        planReusable: false,
        sessionClosed: true,
        cleanup: phase === 'runtime' ? 'not_needed' : 'passed',
        publicDns: 'not_attempted',
        registry: 'not_attempted',
        npmCli: 'not_attempted',
        failureCode: 'preflight_cancelled_or_deadline',
        childClosed: true,
        diagnostics: [],
      });
    },
    PREFLIGHT_PHASE_TEST_TIMEOUT_MS,
  );
  },
);

describe('test-only preflight cancellation lifecycle fixture', () => {
  it('installs a rejection observer before caller awaits and emits bounded redacted diagnostics', async () => {
    const lifecycle = new BoundedTestLifecycle(1_000); lifecycles.push(lifecycle);
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => unhandled.push(reason);
    process.on('unhandledRejection', onUnhandled);
    try {
      await expect(lifecycle.wait('dashboard_ready', Promise.reject(new Error('token=must-not-escape'))))
        .rejects.toThrow('token=must-not-escape');
      await new Promise<void>((resolve) => setImmediate(resolve));
      expect(unhandled).toEqual([]);
      expect(lifecycle.diagnostics).toEqual([{ label: 'dashboard_ready', code: 'error' }]);
      expect(JSON.stringify(lifecycle.diagnostics)).not.toContain('token');
    } finally {
      process.removeListener('unhandledRejection', onUnhandled);
    }
  });

  it('uses one monotonic deadline and aborts a pending condition without waiting for a second timeout', async () => {
    const lifecycle = new BoundedTestLifecycle(1); lifecycles.push(lifecycle);
    await expect(lifecycle.wait('pending_ready', new Promise<never>(() => undefined))).rejects.toThrow('test_lifecycle_aborted');
    expect(lifecycle.signal.aborted).toBe(true);
    expect(lifecycle.diagnostics).toEqual([{ label: 'lifecycle', code: 'deadline' }]);
  });

  it('reserves teardown margin and awaits registered cleanup before a failed operation returns', async () => {
    expect(PREFLIGHT_OPERATION_DEADLINE_MS).toBeLessThan(PREFLIGHT_PHASE_TEST_TIMEOUT_MS);
    const lifecycle = new BoundedTestLifecycle(1_000);
    let cleanupStarted = false;
    let releaseCleanup!: () => void;
    const cleanupGate = new Promise<void>((resolveGate) => { releaseCleanup = resolveGate; });
    lifecycle.register('teardown_probe', async () => {
      cleanupStarted = true;
      await cleanupGate;
    });
    const operation = waitForOwnedOperation(lifecycle, 'pending_ready', new Promise<never>(() => undefined));
    let rejected = false;
    void operation.catch(() => { rejected = true; });
    lifecycle.abort();
    await new Promise<void>((resolveTurn) => setImmediate(resolveTurn));
    expect(cleanupStarted).toBe(true);
    expect(rejected).toBe(false);
    releaseCleanup();
    await expect(operation).rejects.toThrow('test_lifecycle_aborted');
    expect(rejected).toBe(true);
  });

  it('attempts every registered cleanup and rejects with a closed code when one cleanup fails', async () => {
    const lifecycle = new BoundedTestLifecycle(1_000);
    let secondAttempted = false;
    lifecycle.register('second_cleanup', async () => { secondAttempted = true; });
    lifecycle.register('failing_cleanup', async () => { throw new Error('must_not_escape'); });
    await expect(lifecycle.close()).rejects.toThrow('test_lifecycle_cleanup_failed');
    expect(secondAttempted).toBe(true);
    expect(lifecycle.diagnostics).toContainEqual({ label: 'failing_cleanup', code: 'error' });
    expect(JSON.stringify(lifecycle.diagnostics)).not.toContain('must_not_escape');
  });

  it('never reports childClosed when the owned child exits before its closed result', async () => {
    await expect(runFixedPreflightCancellationFixture('exit_before_result')).rejects.toThrow('fixture_child_result_invalid');
  });
});
