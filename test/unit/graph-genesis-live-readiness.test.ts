import { chmodSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { LocalApprovalService } from '../../src/approval/service.js';
import { AuditQueryService } from '../../src/audit/query-service.js';
import { SqliteAuditRecorder } from '../../src/audit/recorder.js';
import {
  graphGenesisUsage,
  parseGraphGenesisArguments,
  runGraphGenesisReadiness,
} from '../../src/cli/graph-genesis.js';
import { startDashboard } from '../../src/dashboard/server.js';
import { writeExclusiveDashboardStateFile } from '../../src/dashboard/state-file.js';
import { openAuditDatabase } from '../../src/db/database.js';

const temporaryPaths: string[] = [];

afterEach(() => {
  for (const path of temporaryPaths.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe('exact production Graph Genesis live-run readiness', () => {
  it('accepts only the closed exact command grammar', () => {
    const parsed = parseGraphGenesisArguments([
      'graph', 'genesis', 'filesystem',
      '--audit-db', '/private/tmp/apg-audit.sqlite',
      '--output', '/private/tmp/apg-candidate.json',
      '--dashboard-port', '47831',
      '--dashboard-state', '/private/tmp/apg-dashboard.json',
    ]);
    expect(parsed).toEqual({
      kind: 'run',
      auditDbPath: '/private/tmp/apg-audit.sqlite',
      outputPath: '/private/tmp/apg-candidate.json',
      dashboardPort: 47831,
      dashboardStatePath: '/private/tmp/apg-dashboard.json',
    });
    expect(parseGraphGenesisArguments(['graph', 'genesis', 'filesystem', '--help'])).toEqual({ kind: 'help' });
    for (const argv of [
      ['graph', 'genesis', 'filesystem'],
      ['graph', 'genesis', 'filesystem', '--audit-db', 'relative.sqlite', '--output', '/private/tmp/out.json'],
      ['graph', 'genesis', 'filesystem', '--audit-db', '/private/tmp/a', '--audit-db', '/private/tmp/b', '--output', '/private/tmp/o'],
      ['graph', 'genesis', 'filesystem', '--audit-db', '/private/tmp/a', '--output', '/private/tmp/a'],
      ['graph', 'genesis', 'filesystem', '--audit-db', '/private/tmp/a', '--output', '/private/tmp/o', '--dashboard-port', '80'],
      ['graph', 'genesis', 'filesystem', '--audit-db', '/private/tmp/a', '--output', '/private/tmp/o', '--registry', 'https://example.test/'],
      ['graph', 'genesis', 'filesystem', '--audit-db', '/private/tmp/a', '--output', '/private/tmp/o', '--'],
    ]) {
      try { parseGraphGenesisArguments(argv); throw new Error('expected usage error'); } catch (error) {
        expect(error).toMatchObject({ message: graphGenesisUsage(), exitCode: 64 });
      }
    }
  });

  it('fails closed without opening the DB, creating output, starting listeners, or external reads', async () => {
    const parent = temporaryDirectory('apg-live-readiness-');
    const auditPath = join(parent, 'audit.sqlite');
    const outputPath = join(parent, 'candidate.json');
    writeFileSync(auditPath, 'not a sqlite database', { mode: 0o600 });
    chmodSync(auditPath, 0o600);
    const result = await runGraphGenesisReadiness({
      kind: 'run', auditDbPath: auditPath, outputPath, dashboardPort: 0,
    });
    expect(result).toMatchObject({
      status: 'blocked', exitCode: 3, externalReadMayHaveOccurred: false,
      installationOccurred: false, packageDownloadOccurred: false,
    });
    expect(result.bypassWarning).toContain('Direct npm/npx commands bypass APG');
  });

  it('keeps Graph Dashboard health-only until one action is bound and never enumerates other actions', async () => {
    const parent = temporaryDirectory('apg-graph-dashboard-');
    const database = openAuditDatabase(join(parent, 'audit.sqlite'));
    const recorder = new SqliteAuditRecorder(database);
    const approvals = new LocalApprovalService();
    const first = recorder.begin({
      serverId: 'graph', toolName: 'first', arguments: { executionEnvelopeHash: 'a'.repeat(64) },
    }, { action: 'deny' });
    const second = recorder.begin({ serverId: 'other', toolName: 'second', arguments: {} }, { action: 'deny' });
    const matching = approvals.request({
      kind: 'graph_genesis', serverId: 'graph', toolName: 'first',
      arguments: { executionEnvelopeHash: 'a'.repeat(64) },
      risk: { score: 70, band: 'high', signals: [] }, reasonCodes: ['fixture'],
    }, 60_000);
    const unrelated = approvals.request({
      kind: 'graph_genesis', serverId: 'graph', toolName: 'other',
      arguments: { executionEnvelopeHash: 'b'.repeat(64) },
      risk: { score: 70, band: 'high', signals: [] }, reasonCodes: ['fixture'],
    }, 60_000);
    const dashboard = await startDashboard({
      approvals,
      audit: new AuditQueryService(database, recorder),
      token: 'g'.repeat(48),
      port: 0,
      mode: 'graph_run',
    });
    try {
      const url = new URL(dashboard.url);
      const headers = { Origin: url.origin, Authorization: `Bearer ${'g'.repeat(48)}` };
      expect(await (await fetch(`${url.origin}/api/health`, { headers })).json()).toMatchObject({ capabilities: [] });
      expect((await fetch(`${url.origin}/api/approvals`, { headers })).status).toBe(409);
      expect((await fetch(`${url.origin}/api/audit`, { headers })).status).toBe(409);
      dashboard.bindGraphAction(first.actionId);
      expect(() => dashboard.bindGraphAction(second.actionId)).toThrow(/binding is invalid/);
      const pending = await (await fetch(`${url.origin}/api/approvals`, { headers })).json() as { approvals: Array<{ id: string }> };
      expect(pending.approvals.map((request) => request.id)).toEqual([matching.request.id]);
      expect((await fetch(`${url.origin}/api/approvals/${unrelated.request.id}/approve`, { method: 'POST', headers })).status).toBe(404);
      const audit = await (await fetch(`${url.origin}/api/audit`, { headers })).json() as { calls: Array<{ id: string }> };
      expect(audit.calls.map((call) => call.id)).toEqual([first.actionId]);
      expect(await (await fetch(`${url.origin}/api/health`, { headers })).json())
        .toMatchObject({ capabilities: ['approvals', 'current_action_audit'] });
    } finally {
      approvals.close();
      await dashboard.close();
      database.close();
    }
  });

  it('creates Graph Dashboard state only at an absent path under an existing private parent', () => {
    const parent = temporaryDirectory('apg-graph-state-');
    const path = join(parent, 'dashboard.json');
    const state = writeExclusiveDashboardStateFile(
      path,
      `http://127.0.0.1:47831/#token=${'s'.repeat(48)}`,
      '11111111-1111-4111-8111-111111111111',
      123,
      new Date('2026-09-09T00:00:00.000Z'),
    );
    expect(() => writeExclusiveDashboardStateFile(
      path,
      `http://127.0.0.1:47831/#token=${'s'.repeat(48)}`,
      '11111111-1111-4111-8111-111111111111',
    )).toThrow(/exclusively create/);
    state.remove();
  });
});

function temporaryDirectory(prefix: string): string {
  const path = realpathSync(mkdtempSync(join(tmpdir(), prefix)));
  temporaryPaths.push(path);
  chmodSync(path, 0o700);
  return path;
}
