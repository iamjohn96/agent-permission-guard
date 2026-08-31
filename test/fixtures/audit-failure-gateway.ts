import type { AuditRecorder } from '../../src/audit/recorder.js';
import { createGateway } from '../../src/gateway/gateway.js';
import { parseProxyArguments } from '../../src/cli/main.js';
import { serveStdioGateway } from '../../src/transport/stdio-downstream.js';

const audit: AuditRecorder = {
  begin(context) {
    if (context.toolName === 'dangerous_write') throw new Error('fixture audit unavailable');
    return {
      markForwarding() {},
      markApprovalRequested() {},
      markApprovalResolved() {},
      markBlocked() {},
      markCompleted() {},
      markExecutionResult() {},
      markFailed() {},
    };
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
  undefined,
  audit,
);

serveStdioGateway(gateway);
