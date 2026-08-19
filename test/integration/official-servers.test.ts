import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { Client, type CallToolResult } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { afterAll, afterEach, describe, expect, it } from 'vitest';

const runOfficialServers = process.env.APG_REAL_MCP_E2E === '1';
const describeOfficial = runOfficialServers ? describe : describe.skip;
const testDirectory = mkdtempSync(join(tmpdir(), 'apg-official-mcp-'));
const gatewayCli = resolve('dist/src/cli/main.js');
const allowPolicy = resolve('test/fixtures/allow-all-policy.yaml');
const openClients: Client[] = [];

afterEach(async () => {
  await Promise.allSettled(openClients.splice(0).map((client) => client.close()));
});

afterAll(() => {
  rmSync(testDirectory, { recursive: true, force: true });
});

describeOfficial('official MCP reference servers through APG', () => {
  it('negotiates with the Everything reference server and lists tools', async () => {
    const client = await connectThroughGateway([
      '-y',
      '@modelcontextprotocol/server-everything@2026.8.18',
    ]);

    const result = await client.listTools();
    expect(result.tools.length).toBeGreaterThan(0);
    expect(result.tools.some((tool) => tool.name === 'echo')).toBe(true);
  }, 60_000);

  it('reads only a disposable file through the Filesystem reference server', async () => {
    const allowedDirectory = join(testDirectory, 'filesystem-root');
    const filePath = join(allowedDirectory, 'read-me.txt');
    mkdirSync(allowedDirectory, { mode: 0o700 });
    writeFileSync(filePath, 'through-official-filesystem', { encoding: 'utf8', flag: 'wx' });
    const client = await connectThroughGateway([
      '-y',
      '@modelcontextprotocol/server-filesystem@2026.7.10',
      allowedDirectory,
    ]);

    const result = await client.callTool({
      name: 'read_text_file',
      arguments: { path: filePath },
    }) as CallToolResult;

    expect(result.isError).not.toBe(true);
    expect(textOf(result)).toContain('through-official-filesystem');
  }, 60_000);
});

async function connectThroughGateway(upstreamArgs: readonly string[]): Promise<Client> {
  const client = new Client(
    { name: 'apg-official-server-test', version: '0.1.0' },
    { versionNegotiation: { mode: 'auto' } },
  );
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      gatewayCli,
      'proxy',
      '--policy', allowPolicy,
      '--audit-db', join(testDirectory, `${crypto.randomUUID()}.sqlite`),
      '--dashboard-port', '0',
      '--', 'npx', ...upstreamArgs,
    ],
    env: process.env.PATH === undefined ? {} : { PATH: process.env.PATH },
    stderr: 'pipe',
  });

  let stderr = '';
  transport.stderr?.on('data', (chunk) => {
    stderr = `${stderr}${String(chunk)}`.slice(-4_000);
  });
  try {
    await client.connect(transport);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Official server connection failed: ${message}\n${stderr.trim()}`);
  }
  openClients.push(client);
  return client;
}

function textOf(result: CallToolResult): string {
  const text = result.content.find((item) => item.type === 'text');
  if (text?.type !== 'text') throw new Error('Expected text tool result');
  return text.text;
}
