import type {
  CallInterceptor,
  InterceptorDecision,
  ToolCallContext,
} from '../gateway/call-interceptor.js';
import { evaluatePolicy } from './evaluator.js';
import type { PolicyDocument } from './schema.js';

export class PolicyInterceptor implements CallInterceptor {
  constructor(private readonly policy: PolicyDocument) {}

  async evaluate(context: ToolCallContext): Promise<InterceptorDecision> {
    const evaluation = evaluatePolicy(this.policy, context);
    if (evaluation.effectiveDecision === 'allow') return { action: 'forward', evaluation };

    const reason = evaluation.reasonCodes.join(', ');
    return evaluation.effectiveDecision === 'deny'
      ? { action: 'deny', reason, evaluation }
      : { action: 'ask', reason, evaluation };
  }
}
