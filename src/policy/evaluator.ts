import type { ToolAnnotations } from '@modelcontextprotocol/server';

import { scoreRisk } from '../risk/scorer.js';
import type { RiskAssessment } from '../risk/types.js';
import { matchPolicy } from './matcher.js';
import type { Decision, PolicyDocument } from './schema.js';

export type PolicyEvaluationInput = Readonly<{
  serverId: string;
  toolName: string;
  arguments: Readonly<Record<string, unknown>>;
  annotations?: ToolAnnotations;
}>;

export type PolicyEvaluation = Readonly<{
  baseDecision: Decision;
  effectiveDecision: Decision;
  matchedRuleId?: string;
  reasonCodes: readonly string[];
  risk: RiskAssessment;
}>;

export function evaluatePolicy(
  policy: PolicyDocument,
  input: PolicyEvaluationInput,
): PolicyEvaluation {
  const match = matchPolicy(policy, input.serverId, input.toolName);
  const risk = scoreRisk({
    toolName: input.toolName,
    arguments: input.arguments,
    policyTags: match.rule?.risk_tags ?? [],
    ...(input.annotations === undefined ? {} : { annotations: input.annotations }),
  });
  const shouldEscalate = match.decision === 'allow' && risk.score >= 60;

  return {
    baseDecision: match.decision,
    effectiveDecision: shouldEscalate ? 'ask' : match.decision,
    ...(match.rule === undefined ? {} : { matchedRuleId: match.rule.id }),
    reasonCodes: [
      match.reason,
      ...(shouldEscalate ? ['risk_escalation'] : []),
    ],
    risk,
  };
}
