import { randomUUID } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resolve } from 'node:path';

import { Client, type CallToolResult } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { afterAll, afterEach, describe, expect, it } from 'vitest';

type ClientMode = 'legacy' | 'auto';

const openClients: Client[] = [];
const fixtureServer = resolve('dist/test/fixtures/mock-mcp-server.js');
const gatewayCli = resolve('dist/src/cli/main.js');
const denyGateway = resolve('dist/test/fixtures/deny-gateway.js');
const auditFailureGateway = resolve('dist/test/fixtures/audit-failure-gateway.js');
const allowPolicy = resolve('test/fixtures/allow-all-policy.yaml');
const askPolicy = resolve('test/fixtures/ask-policy.yaml');
const denyPolicy = resolve('test/fixtures/deny-policy.yaml');
const riskEscalationPolicy = resolve('test/fixtures/risk-escalation-policy.yaml');
const testDirectory = mkdtempSync(join(tmpdir(), 'apg-integration-'));

afterEach(async () => {
  await Promise.allSettled(openClients.splice(0).map((client) => client.close()));
});

afterAll(() => {
  rmSync(testDirectory, { recursive: true, force: true });
});

describe.each<ClientMode>(['legacy', 'auto'])('stdio proxy with %s client', (mode) => {
  it('proxies tools/list', async () => {
    const client = await connectGateway(gatewayCli, mode);
    const result = await client.listTools();

    expect(result.tools.map((tool) => tool.name)).toEqual([
      'echo',
      'dangerous_write',
      'get_dangerous_call_count',
      'wait_for_cancel',
      'get_started_wait_count',
      'get_cancelled_wait_count',
    ]);
  });

  it('forwards an allowed tools/call result', async () => {
    const client = await connectGateway(gatewayCli, mode);
    const result = await client.callTool({
      name: 'echo',
      arguments: { message: 'through-apg' },
    });

    expect(textOf(result)).toBe('through-apg');
    expect(result.isError).not.toBe(true);
  });

  it('does not call upstream when the interceptor denies', async () => {
    const client = await connectGateway(denyGateway, mode);
    const denied = await client.callTool({
      name: 'dangerous_write',
      arguments: { value: 'blocked' },
    });
    const count = await client.callTool({
      name: 'get_dangerous_call_count',
      arguments: {},
    });

    expect(denied.isError).toBe(true);
    expect(textOf(denied)).toContain('fixture policy');
    expect(textOf(count)).toBe('0');
  });

  it('enforces an Ask policy without calling upstream', async () => {
    const { client, dashboard } = await connectGatewayWithDashboard(mode, askPolicy);
    const pending = client.callTool({ name: 'dangerous_write', arguments: { value: 'blocked' } });
    const approval = await waitForApproval(dashboard);
    await decideApproval(dashboard, approval.id, 'deny');
    const result = await pending;
    const count = await client.callTool({ name: 'get_dangerous_call_count', arguments: {} });

    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain('approval was denied');
    expect(textOf(count)).toBe('0');
  });

  it('executes an Ask tool exactly once after one-time approval', async () => {
    const { client, dashboard } = await connectGatewayWithDashboard(mode, askPolicy);
    const pending = client.callTool({ name: 'dangerous_write', arguments: { value: 'approved' } });
    const approval = await waitForApproval(dashboard);
    await decideApproval(dashboard, approval.id, 'approve');
    const result = await pending;
    const count = await client.callTool({ name: 'get_dangerous_call_count', arguments: {} });

    expect(textOf(result)).toBe('wrote:approved');
    expect(textOf(count)).toBe('1');
    await expect(decideApproval(dashboard, approval.id, 'approve')).rejects.toThrow(/404/);
  });

  it('cancels a pending approval when the downstream request is cancelled', async () => {
    const { client, dashboard } = await connectGatewayWithDashboard(mode, askPolicy);
    const controller = new AbortController();
    const pending = client.callTool(
      { name: 'dangerous_write', arguments: { value: 'cancelled' } },
      { signal: controller.signal },
    );
    await waitForApproval(dashboard);
    controller.abort();
    await expect(pending).rejects.toBeDefined();

    const approvals = await dashboardFetch(dashboard, '/api/approvals');
    const payload = await approvals.json() as { approvals: unknown[] };
    const count = await client.callTool({ name: 'get_dangerous_call_count', arguments: {} });
    expect(payload.approvals).toHaveLength(0);
    expect(textOf(count)).toBe('0');
  });

  it('enforces a Deny policy without calling upstream', async () => {
    const client = await connectGateway(gatewayCli, mode, denyPolicy);
    const result = await client.callTool({ name: 'dangerous_write', arguments: { value: 'blocked' } });
    const count = await client.callTool({ name: 'get_dangerous_call_count', arguments: {} });

    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain('denied this tool call');
    expect(textOf(count)).toBe('0');
  });

  it('elevates a high-risk Allow to Ask without calling upstream', async () => {
    const client = await connectGateway(gatewayCli, mode, riskEscalationPolicy);
    const result = await client.callTool({ name: 'dangerous_write', arguments: { value: 'blocked' } });
    const count = await client.callTool({ name: 'get_dangerous_call_count', arguments: {} });

    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain('approval expired');
    expect(textOf(result)).toContain('risk_escalation');
    expect(textOf(count)).toBe('0');
  });

  it('does not call upstream when the audit pre-write fails', async () => {
    const client = await connectGateway(auditFailureGateway, mode);
    await expect(client.callTool({
      name: 'dangerous_write',
      arguments: { value: 'must-not-run' },
    })).rejects.toBeDefined();

    const count = await client.callTool({ name: 'get_dangerous_call_count', arguments: {} });
    expect(textOf(count)).toBe('0');
  });
});

it('keeps stdout pure enough for an MCP client to connect and exchange messages', async () => {
  const client = await connectGateway(gatewayCli, 'auto');
  const result = await client.callTool({ name: 'echo', arguments: { message: 'valid-jsonrpc' } });

  expect(textOf(result)).toBe('valid-jsonrpc');
});

it('propagates downstream cancellation to the upstream tool call', async () => {
  const client = await connectGateway(gatewayCli, 'auto');
  const controller = new AbortController();
  const pending = client.callTool(
    { name: 'wait_for_cancel', arguments: { delayMs: 5_000 } },
    { signal: controller.signal },
  );

  const started = await waitForToolCount(client, 'get_started_wait_count', '1');
  expect(started).toBe('1');
  controller.abort();
  await expect(pending).rejects.toBeDefined();

  const count = await waitForToolCount(client, 'get_cancelled_wait_count', '1');
  expect(count).toBe('1');
});

it('applies a validated dashboard policy update to the next tool call', async () => {
  const editablePolicy = join(testDirectory, `${randomUUID()}.yaml`);
  writeFileSync(editablePolicy, readFileSync(allowPolicy, 'utf8'), { mode: 0o600 });
  const { client, dashboard } = await connectGatewayWithDashboard('auto', editablePolicy);
  const first = await client.callTool({ name: 'dangerous_write', arguments: { value: 'first' } });
  expect(textOf(first)).toBe('wrote:first');

  const currentResponse = await dashboardFetch(dashboard, '/api/policy');
  const current = await currentResponse.json() as { revision: string };
  const nextSource = `version: 1
rules:
  - id: deny-dangerous
    priority: 100
    match: { server: local-upstream, tools: [dangerous_write] }
    decision: deny
  - id: allow-count
    priority: 50
    match: { server: local-upstream, tools: [get_dangerous_call_count] }
    decision: allow
    risk_tags: [local_read]
`;
  const updateResponse = await dashboardFetch(dashboard, '/api/policy', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ source: nextSource, revision: current.revision }),
  });
  expect(updateResponse.status).toBe(200);

  const denied = await client.callTool({ name: 'dangerous_write', arguments: { value: 'second' } });
  const count = await client.callTool({ name: 'get_dangerous_call_count', arguments: {} });
  expect(denied.isError).toBe(true);
  expect(textOf(count)).toBe('1');
});

async function connectGateway(
  entryPoint: string,
  mode: ClientMode,
  policyPath: string = allowPolicy,
): Promise<Client> {
  const client = new Client(
    { name: `apg-test-${mode}`, version: '0.1.0' },
    { versionNegotiation: { mode } },
  );
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      entryPoint,
      'proxy',
      '--policy',
      policyPath,
      '--audit-db',
      join(testDirectory, `${randomUUID()}.sqlite`),
      '--dashboard-port',
      '0',
      '--',
      process.execPath,
      fixtureServer,
    ],
    env: process.env.PATH === undefined ? {} : { PATH: process.env.PATH },
    stderr: 'pipe',
  });

  await client.connect(transport);
  openClients.push(client);
  return client;
}

type DashboardAccess = Readonly<{ origin: string; token: string }>;

async function connectGatewayWithDashboard(
  mode: ClientMode,
  policyPath: string,
): Promise<{ client: Client; dashboard: DashboardAccess }> {
  const client = new Client(
    { name: `apg-dashboard-test-${mode}`, version: '0.1.0' },
    { versionNegotiation: { mode } },
  );
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      gatewayCli,
      'proxy',
      '--policy', policyPath,
      '--audit-db', join(testDirectory, `${randomUUID()}.sqlite`),
      '--dashboard-port', '0',
      '--', process.execPath, fixtureServer,
    ],
    env: process.env.PATH === undefined ? {} : { PATH: process.env.PATH },
    stderr: 'pipe',
  });
  const dashboardPromise = new Promise<DashboardAccess>((resolveDashboard, reject) => {
    let output = '';
    const timeout = setTimeout(() => reject(new Error('Dashboard URL was not announced')), 3_000);
    transport.stderr?.on('data', (chunk) => {
      output += String(chunk);
      const match = /approval dashboard: (http:\/\/127\.0\.0\.1:\d+\/#token=[^\s]+)/.exec(output);
      if (match?.[1] === undefined) return;
      clearTimeout(timeout);
      const url = new URL(match[1]);
      const token = new URLSearchParams(url.hash.slice(1)).get('token');
      if (token === null) return reject(new Error('Dashboard token missing'));
      resolveDashboard({ origin: url.origin, token });
    });
  });
  await client.connect(transport);
  openClients.push(client);
  return { client, dashboard: await dashboardPromise };
}

async function waitForApproval(dashboard: DashboardAccess): Promise<{ id: string }> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const response = await dashboardFetch(dashboard, '/api/approvals');
    const payload = await response.json() as { approvals: Array<{ id: string }> };
    if (payload.approvals[0] !== undefined) return payload.approvals[0];
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 20));
  }
  throw new Error('Approval request did not appear');
}

async function decideApproval(
  dashboard: DashboardAccess,
  id: string,
  action: 'approve' | 'deny',
): Promise<void> {
  const response = await dashboardFetch(dashboard, `/api/approvals/${id}/${action}`, { method: 'POST' });
  if (!response.ok) throw new Error(`Approval API returned ${response.status}`);
}

function dashboardFetch(
  dashboard: DashboardAccess,
  path: string,
  init: RequestInit = {},
): Promise<Response> {
  return fetch(`${dashboard.origin}${path}`, {
    ...init,
    headers: {
      ...(init.headers ?? {}),
      Origin: dashboard.origin,
      Authorization: `Bearer ${dashboard.token}`,
    },
  });
}

function textOf(result: CallToolResult): string {
  const text = result.content.find((item) => item.type === 'text');
  if (text?.type !== 'text') throw new Error('Expected text tool result');
  return text.text;
}

async function waitForToolCount(
  client: Client,
  toolName: string,
  expected: string,
): Promise<string> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const result = await client.callTool({ name: toolName, arguments: {} });
    const count = textOf(result);
    if (count === expected) return count;
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 25));
  }

  return '0';
}
