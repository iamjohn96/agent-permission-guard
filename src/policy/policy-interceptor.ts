import type {
  CallInterceptor,
  InterceptorDecision,
  ToolCallContext,
} from '../gateway/call-interceptor.js';
import { evaluatePolicy } from './evaluator.js';
import { policyIdentity } from './identity.js';
import type { PolicyDocument } from './schema.js';

export class PolicyInterceptor implements CallInterceptor {
  constructor(private readonly policy: PolicyDocument) {}

  async evaluate(context: ToolCallContext): Promise<InterceptorDecision> {
    const evaluation = evaluatePolicy(this.policy, context);
    const receipt = {
      adapter: 'mcp_proxy',
      adapterVersion: '1',
      operation: context.toolName,
      boundary: 'mcp_proxy_call' as const,
      identityAssurance: 'structural_only' as const,
      identityMaterial: { serverId: context.serverId, toolName: context.toolName },
      subject: context.serverId,
      policy: policyIdentity(this.policy),
    };
    if (evaluation.effectiveDecision === 'allow') return { action: 'forward', evaluation, receipt };

    const reason = evaluation.reasonCodes.join(', ');
    return evaluation.effectiveDecision === 'deny'
      ? { action: 'deny', reason, evaluation, receipt }
      : { action: 'ask', reason, evaluation, receipt };
  }
}
