import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

import {
  assertPreparedUpstreamLaunch,
  revalidatePreparedUpstreamLaunch,
  type PreparedUpstreamLaunch,
} from '../launch/upstream-launch.js';

export type ConnectedUpstream = Readonly<{
  client: Client;
  close(): Promise<void>;
}>;

export async function connectStdioUpstream(
  prepared: PreparedUpstreamLaunch,
): Promise<ConnectedUpstream> {
  assertPreparedUpstreamLaunch(prepared);
  const client = new Client(
    { name: 'agent-permission-guard', version: '0.1.0' },
    { versionNegotiation: { mode: 'auto' } },
  );
  const transport = new StdioClientTransport({
    command: prepared.executable.resolvedPath,
    args: [...prepared.arguments],
    env: { ...prepared.environment },
    stderr: 'inherit',
    cwd: prepared.cwd,
  });

  await revalidatePreparedUpstreamLaunch(prepared);
  await client.connect(transport);

  return {
    client,
    async close() {
      await client.close();
    },
  };
}
