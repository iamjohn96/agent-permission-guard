import { describe, expect, it } from 'vitest';

import { SqliteAuditRecorder } from '../../src/audit/recorder.js';
import { openAuditDatabase } from '../../src/db/database.js';
import type { InterceptorDecision, ToolCallContext } from '../../src/gateway/call-interceptor.js';

describe('SQLite audit recorder', () => {
  it('migrates, redacts secrets, records lifecycle events, and verifies its hash chain', () => {
    const database = openAuditDatabase(':memory:');
    const recorder = new SqliteAuditRecorder(database);
    const context: ToolCallContext = {
      serverId: 'local-upstream',
      toolName: 'read_file',
      arguments: { path: '/tmp/example', apiKey: 'never-store-this' },
    };
    const decision: InterceptorDecision = { action: 'forward' };

    const call = recorder.begin(context, decision);
    call.markForwarding();
    call.markCompleted({ content: [{ type: 'text', text: 'file contents are not retained' }] });

    const row = database.prepare(`
      SELECT arguments_json, status, result_summary_json FROM tool_calls
    `).get() as { arguments_json: string; status: string; result_summary_json: string };
    expect(row.arguments_json).toContain('[REDACTED]');
    expect(row.arguments_json).not.toContain('never-store-this');
    expect(row.status).toBe('completed');
    expect(row.result_summary_json).not.toContain('file contents are not retained');
    expect(recorder.verifyHashChain()).toBe(true);

    database.prepare("UPDATE audit_events SET event_json = '{\"tampered\":true}' WHERE sequence = 1").run();
    expect(recorder.verifyHashChain()).toBe(false);
    database.close();
  });

  it('stores bounded argument previews', () => {
    const database = openAuditDatabase(':memory:');
    const recorder = new SqliteAuditRecorder(database);
    const call = recorder.begin(
      { serverId: 's', toolName: 't', arguments: { value: 'x'.repeat(2_000) } },
      { action: 'deny', reason: 'test' },
    );
    call.markBlocked('denied');

    const row = database.prepare('SELECT arguments_json FROM tool_calls').get() as { arguments_json: string };
    expect(row.arguments_json.length).toBeLessThan(700);
    expect(row.arguments_json).toContain('[TRUNCATED]');
    database.close();
  });

  it('records the complete approval lifecycle in the database and hash chain', () => {
    const database = openAuditDatabase(':memory:');
    const recorder = new SqliteAuditRecorder(database);
    const call = recorder.begin(
      { serverId: 'filesystem', toolName: 'write_file', arguments: { path: '/tmp/a' } },
      { action: 'ask', reason: 'matched_rule' },
    );
    const approval = {
      id: '11111111-1111-4111-8111-111111111111',
      serverId: 'filesystem',
      toolName: 'write_file',
      arguments: { path: '/tmp/a' },
      risk: { score: 45, band: 'medium' as const, signals: [] },
      reasonCodes: ['matched_rule'],
      requestedAt: '2026-08-20T00:00:00.000Z',
      expiresAt: '2026-08-20T00:02:00.000Z',
    };

    call.markApprovalRequested(approval);
    call.markApprovalResolved(approval.id, 'approved');
    call.markForwarding();
    call.markCompleted({ content: [{ type: 'text', text: 'done' }] });

    const row = database.prepare('SELECT status FROM approvals').get() as { status: string };
    const migration = database.prepare('SELECT MAX(version) AS version FROM schema_migrations').get() as { version: number };
    expect(row.status).toBe('approved');
    expect(migration.version).toBe(2);
    const queryPlan = database.prepare(`
      EXPLAIN QUERY PLAN
      SELECT * FROM approvals WHERE status = 'pending' AND expires_at <= ?
    `).all('2026-08-20T00:03:00.000Z') as Array<{ detail: string }>;
    expect(queryPlan.some((step) => step.detail.includes('idx_approvals_pending_expires_at'))).toBe(true);
    expect(recorder.verifyHashChain()).toBe(true);
    database.close();
  });
});
