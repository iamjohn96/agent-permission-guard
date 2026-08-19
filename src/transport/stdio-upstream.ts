import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

import type { StdioUpstreamConfig } from './types.js';

export type ConnectedUpstream = Readonly<{
  client: Client;
  close(): Promise<void>;
}>;

export async function connectStdioUpstream(
  config: StdioUpstreamConfig,
): Promise<ConnectedUpstream> {
  const client = new Client(
    { name: 'agent-permission-guard', version: '0.1.0' },
    { versionNegotiation: { mode: 'auto' } },
  );
  const transport = new StdioClientTransport({
    command: config.command,
    args: [...config.args],
    env: { ...config.env },
    stderr: 'inherit',
    ...(config.cwd === undefined ? {} : { cwd: config.cwd }),
  });

  await client.connect(transport);

  return {
    client,
    async close() {
      await client.close();
    },
  };
}
