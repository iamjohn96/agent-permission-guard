import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { LocalApprovalService } from '../../src/approval/service.js';
import { AuditQueryService } from '../../src/audit/query-service.js';
import { SqliteAuditRecorder } from '../../src/audit/recorder.js';
import { startDashboard } from '../../src/dashboard/server.js';
import { openAuditDatabase } from '../../src/db/database.js';
import { LivePolicyController } from '../../src/policy/live-controller.js';

const safeRequest = {
  serverId: 'filesystem',
  toolName: 'write_file',
  arguments: { path: '/tmp/file', token: 'must-not-leak' },
  risk: { score: 45, band: 'medium' as const, signals: [] },
  reasonCodes: ['matched_rule'],
};

describe('local approval service', () => {
  it('redacts request data and resolves a decision only once', async () => {
    const service = new LocalApprovalService();
    const ticket = service.request(safeRequest, 1_000);

    expect(JSON.stringify(ticket.request.arguments)).not.toContain('must-not-leak');
    expect(service.decide(ticket.request.id, 'approved')).toBe('approved');
    expect(service.decide(ticket.request.id, 'denied')).toBeUndefined();
    await expect(ticket.outcome).resolves.toBe('approved');
    service.close();
  });

  it('expires requests and cancels all pending work on close', async () => {
    const service = new LocalApprovalService();
    const expiring = service.request(safeRequest, 15);
    await expect(expiring.outcome).resolves.toBe('expired');

    const cancelled = service.request(safeRequest, 1_000);
    service.close();
    await expect(cancelled.outcome).resolves.toBe('cancelled');
  });
});

describe('dashboard API security', () => {
  it('supports authenticated browser and native clients while rejecting foreign origins', async () => {
    const service = new LocalApprovalService();
    const token = 't'.repeat(43);
    const directory = mkdtempSync(join(tmpdir(), 'apg-dashboard-unit-'));
    const policyPath = join(directory, 'policy.yaml');
    writeFileSync(policyPath, 'version: 1\nrules: []\n', { mode: 0o600 });
    const database = openAuditDatabase(':memory:');
    const recorder = new SqliteAuditRecorder(database);
    const audit = new AuditQueryService(database, recorder);
    const policies = new LivePolicyController(policyPath);
    const dashboard = await startDashboard({ approvals: service, audit, auditRecorder: recorder, policies, token, port: 0 });
    expect(dashboard.instanceId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    const url = new URL(dashboard.url);
    const ticket = service.request(safeRequest, 1_000);

    try {
      const page = await fetch(url.origin);
      expect(page.status).toBe(200);
      expect(page.headers.get('content-security-policy')).toContain("default-src 'self'");

      const unauthenticated = await fetch(`${url.origin}/api/approvals`, {
        headers: { Origin: url.origin },
      });
      expect(unauthenticated.status).toBe(401);

      const nativeUnauthenticated = await fetch(`${url.origin}/api/health`);
      expect(nativeUnauthenticated.status).toBe(401);

      const nativeHealth = await fetch(`${url.origin}/api/health`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      expect(nativeHealth.status).toBe(200);
      expect(await nativeHealth.json()).toEqual({
        status: 'ok',
        api_version: 1,
        instance_id: dashboard.instanceId,
      });

      const wrongOrigin = await fetch(`${url.origin}/api/approvals`, {
        headers: { Origin: 'https://malicious.example', Authorization: `Bearer ${token}` },
      });
      expect(wrongOrigin.status).toBe(403);

      const installTicket = service.request({
        ...safeRequest,
        kind: 'install',
        serverId: 'install-guard',
        toolName: 'npm install',
        arguments: { package: 'yaml@2.9.0' },
      }, 1_000);
      const approvalList = await fetch(`${url.origin}/api/approvals`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const approvalPayload = await approvalList.json() as { approvals: Array<{ id: string; kind?: string }> };
      expect(approvalPayload.approvals).toContainEqual(expect.objectContaining({
        id: installTicket.request.id,
        kind: 'install',
      }));
      expect(service.decide(installTicket.request.id, 'denied')).toBe('denied');
      await expect(installTicket.outcome).resolves.toBe('denied');

      const approved = await fetch(`${url.origin}/api/approvals/${ticket.request.id}/approve`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      expect(approved.status).toBe(200);
      await expect(ticket.outcome).resolves.toBe('approved');

      const replay = await fetch(`${url.origin}/api/approvals/${ticket.request.id}/approve`, {
        method: 'POST',
        headers: { Origin: url.origin, Authorization: `Bearer ${token}` },
      });
      expect(replay.status).toBe(404);

      const auditCall = recorder.begin(
        { serverId: 'filesystem', toolName: 'read_file', arguments: { apiKey: 'never-return' } },
        { action: 'forward' },
      );
      auditCall.markForwarding();
      auditCall.markCompleted({ content: [{ type: 'text', text: 'private result body' }] });
      const auditResponse = await fetch(`${url.origin}/api/audit?limit=10`, {
        headers: { Origin: url.origin, Authorization: `Bearer ${token}` },
      });
      const auditBody = await auditResponse.text();
      expect(auditResponse.status).toBe(200);
      expect(auditBody).not.toContain('never-return');
      expect(auditBody).not.toContain('private result body');
      expect(auditBody).toContain('[REDACTED]');

      const policyResponse = await fetch(`${url.origin}/api/policy`, {
        headers: { Origin: url.origin, Authorization: `Bearer ${token}` },
      });
      const policy = await policyResponse.json() as { source: string; revision: string };
      const invalid = await updatePolicy(url.origin, token, 'version: [1\n', policy.revision);
      expect(invalid.status).toBe(400);
      expect(readFileSync(policyPath, 'utf8')).toBe(policy.source);

      const nextSource = 'version: 1\nrules:\n  - id: deny-write\n    match: { server: "*", tools: [write_file] }\n    decision: deny\n';
      const updated = await updatePolicy(url.origin, token, nextSource, policy.revision);
      expect(updated.status).toBe(200);
      expect(readFileSync(policyPath, 'utf8')).toBe(nextSource);
      const stale = await updatePolicy(url.origin, token, policy.source, policy.revision);
      expect(stale.status).toBe(409);

      const finalAudit = await fetch(`${url.origin}/api/audit?limit=10`, {
        headers: { Origin: url.origin, Authorization: `Bearer ${token}` },
      });
      const finalAuditBody = await finalAudit.text();
      expect(finalAuditBody).toContain('update_policy');
      expect(finalAuditBody).not.toContain('deny-write');
      expect(finalAuditBody).toContain('"hashChainValid":true');

      const invalidLimit = await fetch(`${url.origin}/api/audit?limit=101`, {
        headers: { Origin: url.origin, Authorization: `Bearer ${token}` },
      });
      expect(invalidLimit.status).toBe(400);
    } finally {
      service.close();
      await dashboard.close();
      database.close();
      rmSync(directory, { recursive: true, force: true });
    }
  });
});

function updatePolicy(origin: string, token: string, source: string, revision: string): Promise<Response> {
  return fetch(`${origin}/api/policy`, {
    method: 'PUT',
    headers: {
      Origin: origin,
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ source, revision }),
  });
}
