import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';

afterEach(() => vi.restoreAllMocks());

// Exercise the built preparation path. Spies interrupt owned observations, never provide fake authority.
describe.runIf(process.platform === 'darwin' && process.arch === 'arm64' && process.version === 'v26.3.1')(
  'compiled preparation cancellation at await boundaries', () => {
    it.each(['runtime', 'workspace', 'containment', 'audit', 'cleanup'])(
      'invalidates the session when cancelled after %s', async (phase) => {
        const stage = join(process.cwd(), 'dist/src/stage');
        const preparation = await import(/* @vite-ignore */ join(stage, 'graph-genesis-preflight.js'));
        const hardening = await import(/* @vite-ignore */ join(stage, 'graph-genesis-hardening.js'));
        const audits = await import(/* @vite-ignore */ join(stage, 'graph-genesis-preflight-audit.js'));
        const roots = await import(/* @vite-ignore */ join(stage, 'graph-genesis-preflight-root.js'));
        const target = phase === 'runtime' ? hardening.RuntimeFileSnapshotAuthority.prototype
          : phase === 'workspace' ? hardening.FinalizedGraphGenesisWorkspaceAuthority.prototype
          : phase === 'containment' ? hardening.OwnedContainmentProbeAuthority.prototype
          : phase === 'audit' ? audits.PreflightSqliteAudit.prototype : roots.PreflightRoot.prototype;
        const method = phase === 'runtime' ? 'capture' : phase === 'workspace' ? 'initialize'
          : phase === 'containment' ? 'observe' : phase === 'audit' ? 'verifyReopened' : 'cleanup';
        const original = target[method];
        const controller = new AbortController();
        let calls = 0;
        vi.spyOn(target, method).mockImplementation(async function (this: object, ...args: unknown[]) {
          const result = await original.apply(this, args);
          calls += 1;
          controller.abort();
          return result;
        });
        // Vitest's own worker flags are not part of the fixed Node subprocess we model here.
        const saved = process.execArgv;
        process.execArgv = [];
        try {
          const report = await preparation.captureLocalGraphGenesisPreflight({ signal: controller.signal });
          expect(calls).toBeGreaterThan(0);
          expect(report).toMatchObject({ status: 'local_preflight_failed', executionAuthorized: false,
            planReusable: false, sessionClosed: true, publicDns: 'not_attempted', registry: 'not_attempted',
            npmCli: 'not_attempted', failureCode: 'preflight_cancelled_or_deadline' });
          expect(report.cleanup).toBe(phase === 'runtime' ? 'not_needed' : 'passed');
        } finally { process.execArgv = saved; }
      }, 20_000,
    );
  },
);
