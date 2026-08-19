import type { McpServerFactory } from '@modelcontextprotocol/server';

export type GatewayServer = Readonly<{
  serverFactory: McpServerFactory;
  close(): Promise<void>;
}>;
