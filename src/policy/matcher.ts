import type { Decision, PolicyDocument, PolicyRule } from './schema.js';

export type PolicyMatch = Readonly<{
  decision: Decision;
  rule?: PolicyRule;
  reason: 'matched_rule' | 'default_ask';
}>;

type RankedRule = Readonly<{
  rule: PolicyRule;
  specificity: number;
}>;

const DECISION_RANK: Readonly<Record<Decision, number>> = {
  allow: 0,
  ask: 1,
  deny: 2,
};

export function matchPolicy(
  policy: PolicyDocument,
  serverId: string,
  toolName: string,
): PolicyMatch {
  const matches = policy.rules.flatMap((rule): RankedRule[] => {
    const serverSpecificity = matchSpecificity(rule.match.server, serverId);
    if (serverSpecificity === undefined) return [];

    const toolSpecificities = rule.match.tools
      .map((pattern) => matchSpecificity(pattern, toolName))
      .filter((value): value is number => value !== undefined);
    if (toolSpecificities.length === 0) return [];

    return [{
      rule,
      specificity: serverSpecificity + Math.max(...toolSpecificities),
    }];
  });

  matches.sort(compareRankedRules);
  const winner = matches[0];

  if (winner === undefined) {
    return { decision: 'ask', reason: 'default_ask' };
  }

  return {
    decision: winner.rule.decision,
    rule: winner.rule,
    reason: 'matched_rule',
  };
}

function compareRankedRules(left: RankedRule, right: RankedRule): number {
  return right.rule.priority - left.rule.priority
    || right.specificity - left.specificity
    || DECISION_RANK[right.rule.decision] - DECISION_RANK[left.rule.decision]
    || left.rule.id.localeCompare(right.rule.id);
}

function matchSpecificity(pattern: string, value: string): number | undefined {
  if (pattern === value) return 2;
  if (!pattern.includes('*')) return undefined;

  const regex = new RegExp(`^${escapeRegex(pattern).replaceAll('*', '.*')}$`);
  return regex.test(value) ? 1 : undefined;
}

function escapeRegex(value: string): string {
  return value.replace(/[|\\{}()[\]^$+?.-]/g, '\\$&');
}
