import {
  Server,
  type CallToolResult,
  type McpServerFactory,
  type RequestId,
  type Tool,
} from '@modelcontextprotocol/server';

import {
  ForwardAllInterceptor,
  prepareToolCall,
  type CallInterceptor,
} from './call-interceptor.js';
import { NoopAuditRecorder, type AuditRecorder } from '../audit/recorder.js';
import type { ApprovalCoordinator, ApprovalOutcome } from '../approval/types.js';
import type { PreparedUpstreamLaunch } from '../launch/upstream-launch.js';
import type { GatewayServer } from './types.js';
import { connectStdioUpstream } from '../transport/stdio-upstream.js';
import { McpIdentityAuthority } from '../identity/mcp-identity.js';
import { APG_VERSION } from '../version.js';

export async function createGateway(
  preparedLaunch: PreparedUpstreamLaunch,
  interceptor: CallInterceptor = new ForwardAllInterceptor(),
  audit: AuditRecorder = new NoopAuditRecorder(),
  approval?: Readonly<{ coordinator: ApprovalCoordinator; getTtlMs(): number }>,
  identityAuthority: McpIdentityAuthority = new McpIdentityAuthority(),
): Promise<GatewayServer> {
  const upstream = await connectStdioUpstream(preparedLaunch);
  const listedTools = await (async () => {
    try {
      const result = await upstream.client.listTools();
      identityAuthority.preflight(preparedLaunch.serverId, result.tools);
      return result;
    } catch (error) {
      try {
        await upstream.close();
      } catch {
        // Preserve the original startup/preflight failure.
      }
      throw error;
    }
  })();
  const toolsByName = new Map(listedTools.tools.map((tool) => [tool.name, tool]));

  const serverFactory: McpServerFactory = () => {
    const activeCalls = new Map<RequestId, AbortController>();
    const server = new Server(
      { name: 'agent-permission-guard', version: APG_VERSION },
      { capabilities: { tools: {} } },
    );

    server.setNotificationHandler('notifications/cancelled', async (notification) => {
      const requestId = notification.params.requestId;
      if (requestId !== undefined) {
        activeCalls.get(requestId)?.abort(notification.params.reason);
      }
    });
    server.setRequestHandler('tools/list', async () => listedTools);
    server.setRequestHandler('tools/call', async (request, handlerContext) => {
      const callAbort = new AbortController();
      const onHandlerAbort = () => callAbort.abort(handlerContext.mcpReq.signal.reason);
      handlerContext.mcpReq.signal.addEventListener('abort', onHandlerAbort, { once: true });
      activeCalls.set(handlerContext.mcpReq.id, callAbort);

      try {
        const tool = toolsByName.get(request.params.name);
        const prepared = prepareToolCall(
          preparedLaunch.serverId,
          request.params,
          tool?.annotations,
          tool?.inputSchema,
          identityAuthority,
        );
        const context = prepared.context;
        if (
          identityAuthority.isExactRequired(context.serverId, context.toolName)
          && context.identity?.assurance !== 'adapter_action_exact'
        ) {
          const failureCode = context.identity?.approvalView.failureCode;
          const auditCall = audit.begin(context, exactIdentityRequiredDecision(failureCode));
          auditCall.markBlocked('denied');
          return projectResult(server, exactIdentityRequiredResult(), tool);
        }
        const decision = await interceptor.evaluate(context);
        const auditCall = audit.begin(context, decision);

        if (decision.action === 'deny') {
          auditCall.markBlocked('denied');
          return projectResult(server, deniedResult(decision.reason), tool);
        }
        if (decision.action === 'ask') {
          if (approval === undefined) {
            auditCall.markBlocked('approval_unavailable');
            return projectResult(server, approvalUnavailableResult(decision.reason), tool);
          }

          const ticket = approval.coordinator.request({
            serverId: context.serverId,
            toolName: context.toolName,
            arguments: context.arguments,
            ...(context.identity === undefined ? {} : { identity: context.identity.approvalView }),
            risk: decision.evaluation?.risk ?? { score: 0, band: 'low', signals: [] },
            reasonCodes: decision.evaluation?.reasonCodes ?? ['interceptor_decision'],
          }, approval.getTtlMs());
          try {
            auditCall.markApprovalRequested(ticket.request);
          } catch (error) {
            ticket.cancel();
            throw error;
          }

          const cancelPendingApproval = () => ticket.cancel();
          callAbort.signal.addEventListener('abort', cancelPendingApproval, { once: true });
          let outcome: ApprovalOutcome;
          try {
            if (callAbort.signal.aborted) ticket.cancel();
            outcome = await ticket.outcome;
          } finally {
            callAbort.signal.removeEventListener('abort', cancelPendingApproval);
          }
          auditCall.markApprovalResolved(ticket.request.id, outcome);

          if (outcome !== 'approved') {
            auditCall.markBlocked(`approval_${outcome}`);
            if (outcome === 'cancelled') throw new Error('Tool call cancelled while awaiting approval');
            return projectResult(server, approvalResult(outcome, decision.reason), tool);
          }
          if (callAbort.signal.aborted) {
            auditCall.markFailed('cancelled_before_execution');
            throw new Error('Tool call cancelled before approved execution');
          }
        }

        // This durable pre-execution event is the fail-closed boundary. If it
        // cannot be written, the upstream tool is never invoked.
        auditCall.markForwarding();

        let result: CallToolResult;
        try {
          result = await upstream.client.callTool(prepared.dispatchParams, {
            signal: callAbort.signal,
          });
        } catch (error) {
          auditCall.markFailed(callAbort.signal.aborted ? 'cancelled' : 'upstream_error');
          throw error;
        }
        try {
          auditCall.markCompleted(result);
          return projectResult(server, result, tool);
        } catch (error) {
          try {
            auditCall.markFailed('audit_completion_failed');
          } catch {
            // The upstream action may already have produced effects; never retry it.
          }
          throw error;
        }
      } finally {
        activeCalls.delete(handlerContext.mcpReq.id);
        handlerContext.mcpReq.signal.removeEventListener('abort', onHandlerAbort);
      }
    });

    return server;
  };

  return {
    serverFactory,
    async close() {
      await upstream.close();
    },
  };
}

function exactIdentityRequiredDecision(failureCode: string | undefined) {
  return {
    action: 'deny' as const,
    reason: 'exact_identity_required',
    evaluation: {
      baseDecision: 'deny' as const,
      effectiveDecision: 'deny' as const,
      reasonCodes: [
        'exact_identity_required',
        ...(failureCode === undefined ? [] : [`identity_${failureCode}`]),
      ],
      risk: { score: 0, band: 'low' as const, signals: [] },
    },
  };
}

function exactIdentityRequiredResult(): CallToolResult {
  return {
    content: [{
      type: 'text',
      text: 'Agent Permission Guard blocked this tool call: the request did not match the required reviewed identity profile. No upstream tool call was made.',
    }],
    isError: true,
  };
}

function approvalUnavailableResult(reason: string): CallToolResult {
  return {
    content: [{
      type: 'text',
      text: `Agent Permission Guard requires human approval, but approval is unavailable: ${reason}`,
    }],
    isError: true,
  };
}

function approvalResult(outcome: Exclude<ApprovalOutcome, 'approved' | 'cancelled'>, reason: string): CallToolResult {
  const explanation = outcome === 'denied' ? 'Human approval was denied' : 'Human approval expired';
  return {
    content: [{ type: 'text', text: `Agent Permission Guard blocked this tool call: ${explanation}. ${reason}` }],
    isError: true,
  };
}

function deniedResult(reason: string): CallToolResult {
  return {
    content: [{ type: 'text', text: `Agent Permission Guard denied this tool call: ${reason}` }],
    isError: true,
  };
}

function projectResult(
  server: Server,
  result: CallToolResult,
  tool: Tool | undefined,
): CallToolResult {
  return server.projectCallToolResult(result, tool?.outputSchema);
}
