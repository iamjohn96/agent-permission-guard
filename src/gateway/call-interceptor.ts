import type { CallToolRequestParams, ToolAnnotations } from '@modelcontextprotocol/server';

import type { PolicyEvaluation } from '../policy/evaluator.js';

export type ToolCallContext = Readonly<{
  serverId: string;
  toolName: string;
  arguments: Readonly<Record<string, unknown>>;
  annotations?: ToolAnnotations;
}>;

export type InterceptorDecision =
  | Readonly<{ action: 'forward'; evaluation?: PolicyEvaluation }>
  | Readonly<{ action: 'ask'; reason: string; evaluation?: PolicyEvaluation }>
  | Readonly<{ action: 'deny'; reason: string; evaluation?: PolicyEvaluation }>;

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
  annotations?: ToolAnnotations,
): ToolCallContext {
  const clonedArguments = structuredClone(params.arguments ?? {});

  return Object.freeze({
    serverId,
    toolName: params.name,
    arguments: deepFreeze(clonedArguments),
    ...(annotations === undefined ? {} : { annotations }),
  });
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== 'object' || value === null || Object.isFrozen(value)) {
    return value;
  }

  for (const nested of Object.values(value)) {
    deepFreeze(nested);
  }

  return Object.freeze(value);
}
