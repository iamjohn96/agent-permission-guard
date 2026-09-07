import type { CallToolRequestParams, Tool } from '@modelcontextprotocol/server';

import type { ReceiptContext } from '../audit/receipt.js';
import {
  McpIdentityAuthority,
  type McpIdentityResult,
  type PreparedMcpIdentity,
} from '../identity/mcp-identity.js';
import type { PolicyEvaluation } from '../policy/evaluator.js';

export type ToolCallContext = Readonly<{
  serverId: string;
  toolName: string;
  arguments: Readonly<Record<string, unknown>>;
  annotations?: NonNullable<Tool['annotations']>;
  identity?: McpIdentityResult;
}>;

export type PreparedToolCall = Readonly<{
  context: ToolCallContext;
  dispatchParams: CallToolRequestParams;
}>;

export type InterceptorDecision =
  | Readonly<{ action: 'forward'; evaluation?: PolicyEvaluation; receipt?: ReceiptContext }>
  | Readonly<{ action: 'ask'; reason: string; evaluation?: PolicyEvaluation; receipt?: ReceiptContext }>
  | Readonly<{ action: 'deny'; reason: string; evaluation?: PolicyEvaluation; receipt?: ReceiptContext }>;

export interface CallInterceptor {
  evaluate(context: ToolCallContext): Promise<InterceptorDecision>;
}

export class ForwardAllInterceptor implements CallInterceptor {
  async evaluate(_context: ToolCallContext): Promise<InterceptorDecision> {
    return { action: 'forward' };
  }
}

export function createToolCallContext(
  serverId: string,
  params: CallToolRequestParams,
  annotations?: NonNullable<Tool['annotations']>,
): ToolCallContext {
  return prepareToolCall(serverId, params, annotations).context;
}

export function prepareToolCall(
  serverId: string,
  params: CallToolRequestParams,
  annotations?: NonNullable<Tool['annotations']>,
  inputSchema?: Tool['inputSchema'],
  identityAuthority: McpIdentityAuthority = new McpIdentityAuthority(),
  identityRequirement: 'any' | 'exact' = 'any',
): PreparedToolCall {
  const prepared: PreparedMcpIdentity = identityAuthority.prepare(
    serverId,
    params,
    inputSchema,
    identityRequirement,
  );
  const clonedArguments = prepared.dispatchParams.arguments ?? {};

  const context = Object.freeze({
    serverId,
    toolName: prepared.dispatchParams.name,
    arguments: clonedArguments,
    ...(annotations === undefined ? {} : { annotations }),
    identity: prepared.result,
  });
  return Object.freeze({ context, dispatchParams: prepared.dispatchParams });
}
