import type { CallInterceptor } from '../../src/gateway/call-interceptor.js';
import { createGateway } from '../../src/gateway/gateway.js';
import { parseProxyArguments } from '../../src/cli/main.js';
import { serveStdioGateway } from '../../src/transport/stdio-downstream.js';

const denyDangerousWrite: CallInterceptor = {
  async evaluate(context) {
    return context.toolName === 'dangerous_write'
      ? { action: 'deny', reason: 'fixture policy' }
      : { action: 'forward' };
  },
};

const parsed = parseProxyArguments(process.argv.slice(2));
const gateway = await createGateway(
  {
    serverId: 'fixture-upstream',
    command: parsed.command,
    args: parsed.args,
    env: process.env.PATH === undefined ? {} : { PATH: process.env.PATH },
  },
  denyDangerousWrite,
);

serveStdioGateway(gateway);
