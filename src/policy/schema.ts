import { z } from 'zod';

export const DecisionSchema = z.enum(['allow', 'ask', 'deny']);
export type Decision = z.infer<typeof DecisionSchema>;

export const RiskTagSchema = z.enum([
  'local_read',
  'local_write',
  'destructive',
  'external_side_effect',
  'credential_access',
  'privileged_target',
  'broad_target',
  'shell_execution',
  'open_world',
]);
export type RiskTag = z.infer<typeof RiskTagSchema>;

const MatchSchema = z.object({
  server: z.string().min(1).max(256),
  tools: z.array(z.string().min(1).max(256)).min(1).max(256),
}).strict();

export const PolicyRuleSchema = z.object({
  id: z.string().regex(/^[a-z0-9][a-z0-9._-]*$/),
  priority: z.number().int().default(0),
  description: z.string().min(1).max(1_000).optional(),
  match: MatchSchema,
  decision: DecisionSchema,
  risk_tags: z.array(RiskTagSchema).default([]),
}).strict();
export type PolicyRule = z.infer<typeof PolicyRuleSchema>;

const DefaultsSchema = z.object({
  decision: z.literal('ask').default('ask'),
  approval_ttl_seconds: z.number().int().positive().max(3_600).default(120),
  tool_timeout_seconds: z.number().int().positive().max(3_600).default(60),
}).strict().default({
  decision: 'ask',
  approval_ttl_seconds: 120,
  tool_timeout_seconds: 60,
});

export const PolicyDocumentSchema = z.object({
  version: z.literal(1),
  defaults: DefaultsSchema,
  rules: z.array(PolicyRuleSchema).max(1_000).default([]),
}).strict().superRefine((policy, context) => {
  const seenIds = new Set<string>();

  policy.rules.forEach((rule, index) => {
    if (seenIds.has(rule.id)) {
      context.addIssue({
        code: 'custom',
        path: ['rules', index, 'id'],
        message: `Duplicate rule id: ${rule.id}`,
      });
    }
    seenIds.add(rule.id);
  });
});
export type PolicyDocument = z.infer<typeof PolicyDocumentSchema>;
