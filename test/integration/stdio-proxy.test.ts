import { randomUUID } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resolve } from 'node:path';

import { Client, type CallToolResult } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { afterAll, afterEach, describe, expect, it } from 'vitest';

import { FILESYSTEM_LIST_ALLOWED_DIRECTORIES_PROFILE_ID } from '../../src/identity/builtin-profiles.js';
import { BoundedTestLifecycle } from '../fixtures/preflight-cancellation-lifecycle.js';

type ClientMode = 'legacy' | 'auto';

const openClients: Array<Readonly<{ client: Client; lifecycle?: BoundedTestLifecycle }>> = [];
const fixtureServer = resolve('dist/test/fixtures/mock-mcp-server.js');
const exactFilesystemFixtureServer = resolve('dist/test/fixtures/exact-filesystem-mcp-server.js');
const gatewayCli = resolve('dist/src/cli/main.js');
const denyGateway = resolve('dist/test/fixtures/deny-gateway.js');
const auditFailureGateway = resolve('dist/test/fixtures/audit-failure-gateway.js');
const allowPolicy = resolve('test/fixtures/allow-all-policy.yaml');
const askPolicy = resolve('test/fixtures/ask-policy.yaml');
const denyPolicy = resolve('test/fixtures/deny-policy.yaml');
const denyListAllowedPolicy = resolve('test/fixtures/deny-list-allowed-policy.yaml');
const riskEscalationPolicy = resolve('test/fixtures/risk-escalation-policy.yaml');
const testDirectory = mkdtempSync(join(tmpdir(), 'apg-integration-'));
const GATEWAY_CONDITION_DEADLINE_MS = 15_000;
const STATE_ROTATION_CONDITION_DEADLINE_MS = 25_000;
const STATE_ROTATION_TEST_TIMEOUT_MS = 30_000;
const DASHBOARD_CONDITION_DEADLINE_MS = 10_000;
const POLICY_UPDATE_TEST_TIMEOUT_MS = 15_000;

afterEach(async () => {
  await Promise.all(openClients.splice(0).map(({ client, lifecycle }) => lifecycle === undefined ? client.close() : lifecycle.close()));
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
      'list_allowed_directories',
      'get_list_allowed_directories_call_count',
    ]);
  });

  it('activates the exact Filesystem profile only when explicitly selected', async () => {
    const client = await connectGateway(
      gatewayCli,
      mode,
      allowPolicy,
      undefined,
      FILESYSTEM_LIST_ALLOWED_DIRECTORIES_PROFILE_ID,
    );
    const result = await client.callTool({ name: 'list_allowed_directories', arguments: {} });
    const count = await client.callTool({
      name: 'get_list_allowed_directories_call_count',
      arguments: {},
    });
    const other = await client.callTool({ name: 'echo', arguments: { message: 'still-structural' } });

    expect(textOf(result)).toBe('/private/synthetic/allowed-root');
    expect(textOf(count)).toBe('1');
    expect(textOf(other)).toBe('still-structural');
  });

  it('blocks profile argument drift before the upstream tool call', async () => {
    const client = await connectGateway(
      gatewayCli,
      mode,
      allowPolicy,
      undefined,
      FILESYSTEM_LIST_ALLOWED_DIRECTORIES_PROFILE_ID,
    );
    const blocked = await client.callTool({
      name: 'list_allowed_directories',
      arguments: { path: '/private/must-not-forward' },
    });
    const count = await client.callTool({
      name: 'get_list_allowed_directories_call_count',
      arguments: {},
    });

    expect(blocked.isError).toBe(true);
    expect(textOf(blocked)).toContain('required reviewed identity profile');
    expect(textOf(blocked)).toContain('No upstream tool call was made');
    expect(textOf(blocked)).not.toContain('/private/must-not-forward');
    expect(textOf(count)).toBe('0');
  });

  it('does not let exact identity lower a Deny policy decision', async () => {
    const client = await connectGateway(
      gatewayCli,
      mode,
      denyListAllowedPolicy,
      undefined,
      FILESYSTEM_LIST_ALLOWED_DIRECTORIES_PROFILE_ID,
    );
    const denied = await client.callTool({ name: 'list_allowed_directories', arguments: {} });

    expect(denied.isError).toBe(true);
    expect(textOf(denied)).toContain('denied this tool call');
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

it('rotates an opt-in dashboard state file without an older process removing newer state', async () => {
  const lifecycle = new BoundedTestLifecycle(STATE_ROTATION_CONDITION_DEADLINE_MS);
  const statePath = join(testDirectory, `${randomUUID()}.dashboard.json`);
  try {
    const firstClient = await connectGateway(gatewayCli, 'auto', allowPolicy, statePath);
    await waitForStateCreation(statePath, lifecycle);
    const firstState = readDashboardState(statePath);
    const firstUrl = new URL(firstState.url);
    const firstToken = new URLSearchParams(firstUrl.hash.slice(1)).get('token');

    const secondClient = await connectGateway(gatewayCli, 'auto', allowPolicy, statePath);
    await waitForStateChange(statePath, firstState.url, lifecycle);
    const state = readDashboardState(statePath);

    expect(state.url).not.toBe(firstState.url);
    const stateUrl = new URL(state.url);
    const stateToken = new URLSearchParams(stateUrl.hash.slice(1)).get('token');
    const health = await fetch(`${stateUrl.origin}/api/health`, {
      headers: { Authorization: `Bearer ${stateToken}` },
    });
    expect(health.status).toBe(200);
    expect(await health.json()).toEqual({
      status: 'ok', api_version: 1, instance_id: state.instance_id,
      capabilities: ['approvals', 'audit', 'policy'],
    });

    const staleCredential = await fetch(`${stateUrl.origin}/api/health`, {
      headers: { Authorization: `Bearer ${firstToken}` },
    });
    expect(staleCredential.status).toBe(401);

    await firstClient.close();
    expect(readDashboardState(statePath)).toEqual(state);

    await secondClient.close();
    await waitForStateRemoval(statePath, lifecycle);
    expect(existsSync(statePath)).toBe(false);
  } finally {
    await lifecycle.close();
  }
}, STATE_ROTATION_TEST_TIMEOUT_MS);

function readDashboardState(path: string): {
  version: number;
  url: string;
  pid: number;
  started_at: string;
  instance_id: string;
} {
  const state = JSON.parse(readFileSync(path, 'utf8')) as {
    version: number;
    url: string;
    pid: number;
    started_at: string;
    instance_id: string;
  };

  expect(state.version).toBe(1);
  const dashboardUrl = new URL(state.url);
  expect(dashboardUrl.hostname).toBe('127.0.0.1');
  expect(dashboardUrl.protocol).toBe('http:');
  expect(new URLSearchParams(dashboardUrl.hash.slice(1)).get('token')?.length).toBeGreaterThanOrEqual(32);
  expect(state.pid).toBeGreaterThan(0);
  expect(Number.isNaN(Date.parse(state.started_at))).toBe(false);
  expect(state.instance_id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  return state;
}

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
}, POLICY_UPDATE_TEST_TIMEOUT_MS);

async function connectGateway(
  entryPoint: string,
  mode: ClientMode,
  policyPath: string = allowPolicy,
  dashboardStatePath?: string,
  identityProfileId?: string,
): Promise<Client> {
  const client = new Client(
    { name: `apg-test-${mode}`, version: '0.1.0' },
    { versionNegotiation: { mode } },
  );
  const args = [
    entryPoint, 'proxy',
    '--policy', policyPath,
    '--audit-db', join(testDirectory, `${randomUUID()}.sqlite`),
    '--dashboard-port', '0',
  ];
  if (dashboardStatePath !== undefined) {
    args.push('--dashboard-state', dashboardStatePath);
  }
  if (identityProfileId !== undefined) {
    args.push('--identity-profile', identityProfileId);
  }
  args.push(
    '--',
    process.execPath,
    identityProfileId === undefined ? fixtureServer : exactFilesystemFixtureServer,
  );

  const transport = new StdioClientTransport({
    command: process.execPath,
    args,
    env: process.env.PATH === undefined ? {} : { PATH: process.env.PATH },
    stderr: 'pipe',
  });

  const lifecycle = new BoundedTestLifecycle(GATEWAY_CONDITION_DEADLINE_MS);
  lifecycle.register('gateway_client', async () => { await client.close(); });
  try {
    await lifecycle.wait('gateway_connect', client.connect(transport));
    lifecycle.disarm();
    openClients.push(Object.freeze({ client, lifecycle }));
    return client;
  } catch (error) {
    await lifecycle.close();
    throw error;
  }
}

async function waitForStateRemoval(path: string, lifecycle: BoundedTestLifecycle): Promise<void> {
  await waitForCondition(lifecycle, 'state_removal', () => !existsSync(path));
}

async function waitForStateCreation(path: string, lifecycle: BoundedTestLifecycle): Promise<void> {
  await waitForCondition(lifecycle, 'state_creation', () => existsSync(path));
}

async function waitForStateChange(path: string, previousUrl: string, lifecycle: BoundedTestLifecycle): Promise<void> {
  await waitForCondition(lifecycle, 'state_change', () => existsSync(path) && readDashboardState(path).url !== previousUrl);
}

async function waitForCondition(lifecycle: BoundedTestLifecycle, label: string, predicate: () => boolean): Promise<void> {
  while (!predicate()) {
    await lifecycle.wait(label, new Promise<void>((resolveDelay) => setTimeout(resolveDelay, 20)));
  }
}

type DashboardAccess = Readonly<{ origin: string; token: string }>;

async function connectGatewayWithDashboard(
  mode: ClientMode,
  policyPath: string,
): Promise<{ client: Client; dashboard: DashboardAccess }> {
  const lifecycle = new BoundedTestLifecycle(DASHBOARD_CONDITION_DEADLINE_MS);
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
  lifecycle.register('dashboard_client', async () => { await client.close(); });
  let output = '';
  let announced = false;
  let settled = false;
  let resolveDashboard!: (dashboard: DashboardAccess) => void;
  let rejectDashboard!: (reason: Error) => void;
  const dashboardPromise = new Promise<DashboardAccess>((resolveValue, rejectValue) => {
    resolveDashboard = resolveValue;
    rejectDashboard = rejectValue;
  });
  const detachStderr = () => {
    transport.stderr?.off('data', onStderr);
    transport.stderr?.off('end', onStderrEnded);
    transport.stderr?.off('error', onStderrError);
  };
  const rejectClosed = (code: string) => {
    if (settled) return;
    settled = true;
    detachStderr();
    rejectDashboard!(new Error(code));
  };
  const resolveClosed = (dashboard: DashboardAccess) => {
    if (settled) return;
    settled = true;
    detachStderr();
    resolveDashboard!(dashboard);
  };
  const onStderrEnded = () => rejectClosed('dashboard_stderr_ended_before_ready');
  const onStderrError = () => rejectClosed('dashboard_stderr_error_before_ready');
  const onStderr = (chunk: Buffer) => {
    output = (output + String(chunk)).slice(-4_096);
    let candidate: DashboardAccess | undefined;
    for (;;) {
      const newline = output.indexOf('\n');
      if (newline < 0) break;
      const line = output.slice(0, newline).replace(/\r$/u, '');
      output = output.slice(newline + 1);
      if (!line.includes('approval dashboard:')) continue;
      const match = /^\[apg\] approval dashboard: (http:\/\/127\.0\.0\.1:\d+\/#token=[A-Za-z0-9_-]{43})$/u.exec(line);
      if (match?.[1] === undefined || announced || candidate !== undefined) { rejectClosed('dashboard_announcement_invalid'); return; }
      let url: URL;
      try { url = new URL(match[1]); } catch { rejectClosed('dashboard_announcement_invalid'); return; }
      const token = new URLSearchParams(url.hash.slice(1)).get('token');
      if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || url.pathname !== '/' || url.search !== ''
        || token === null || !/^[A-Za-z0-9_-]{43}$/u.test(token)) { rejectClosed('dashboard_announcement_invalid'); return; }
      candidate = Object.freeze({ origin: url.origin, token });
    }
    if (candidate === undefined) return;
    announced = true;
    resolveClosed(candidate);
  };
  lifecycle.register('dashboard_stderr', async () => { detachStderr(); });
  // Observe this promise before connect: timeout/rejection is never left unhandled while stdio negotiates.
  const observedDashboard = lifecycle.observe('dashboard_ready', dashboardPromise);
  transport.stderr?.on('data', onStderr);
  transport.stderr?.once('end', onStderrEnded);
  transport.stderr?.once('error', onStderrError);
  try {
    await lifecycle.wait('dashboard_connect', client.connect(transport));
    const dashboard = await lifecycle.waitObserved('dashboard_ready', observedDashboard);
    lifecycle.disarm();
    openClients.push(Object.freeze({ client, lifecycle }));
    return { client, dashboard };
  } catch (error) {
    await lifecycle.close();
    throw error;
  }
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
