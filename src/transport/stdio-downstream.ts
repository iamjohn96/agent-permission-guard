import { serveStdio, type StdioServerHandle } from '@modelcontextprotocol/server/stdio';

import type { GatewayServer } from '../gateway/types.js';

export function serveStdioGateway(gateway: GatewayServer): StdioServerHandle {
  return serveStdio(gateway.serverFactory, {
    legacy: 'serve',
    onerror(error) {
      process.stderr.write(`[apg] downstream error: ${error.message}\n`);
    },
  });
}
