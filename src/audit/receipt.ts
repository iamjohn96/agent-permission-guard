import { createHash, randomUUID } from 'node:crypto';

import { z } from 'zod';

import { canonicalJson } from './canonical-json.js';
import { APG_VERSION } from '../version.js';

const MAX_DEPTH = 32;
const MAX_COLLECTION_ITEMS = 1_000;
const MAX_STRING_LENGTH = 16_384;
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/;
const SHA256_HASH = /^[0-9a-f]{64}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/;
const REASON_CODE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;

const DigestSchema = z.string().regex(SHA256_DIGEST);
const HashSchema = z.string().regex(SHA256_HASH);
const IdentifierSchema = z.string().regex(IDENTIFIER);
const ReasonCodeSchema = z.string().regex(REASON_CODE);
const TimestampSchema = z.iso.datetime({ offset: true });

const SchemaIdentitySchema = z.object({
  name: z.literal('apg-action-receipt'),
  majorVersion: z.literal(1),
  minorVersion: z.literal(0),
  canonicalization: z.literal('apg-canonical-json-v1'),
}).strict();

const ReceiptIdentitySchema = z.object({
  id: z.uuid(),
  type: z.enum(['authorization', 'outcome']),
  issuedAt: TimestampSchema,
  assuranceLevel: z.literal('portable_unsigned'),
}).strict();

const ActionSchema = z.object({
  id: z.uuid(),
  adapter: IdentifierSchema,
  adapterVersion: IdentifierSchema,
  operation: IdentifierSchema,
  identityAssurance: z.enum(['structural_only', 'adapter_scoped', 'execution_plan_exact']),
  intentDigest: DigestSchema,
  subject: z.string().min(1).max(512).optional(),
  executionPlanHash: HashSchema.optional(),
}).strict();

const CoverageSchema = z.object({
  routedThroughApg: z.literal(true),
  boundary: z.enum(['mcp_proxy_call', 'install_guard_plan', 'apg_local_control']),
  observed: z.array(IdentifierSchema).max(20),
  notObserved: z.array(IdentifierSchema).max(20),
}).strict();

const PolicySchema = z.object({
  schemaVersion: z.number().int().min(0).max(1_000_000),
  contentDigest: DigestSchema,
  evaluatorName: IdentifierSchema,
  evaluatorVersion: IdentifierSchema,
  matchedRuleId: IdentifierSchema.optional(),
}).strict();

const DecisionSchema = z.object({
  base: z.enum(['allow', 'ask', 'deny']),
  effective: z.enum(['allow', 'ask', 'deny']),
  reasonCodes: z.array(ReasonCodeSchema).min(1).max(100),
  riskScore: z.number().int().min(0).max(100),
  riskBand: z.enum(['low', 'medium', 'high', 'critical']),
}).strict();

const ApprovalSchema = z.object({
  required: z.boolean(),
  outcome: z.enum(['not_required', 'not_requested', 'pending', 'approved', 'denied', 'expired', 'cancelled', 'unavailable']),
  requestId: z.uuid().optional(),
  requestedAt: TimestampSchema.optional(),
  decidedAt: TimestampSchema.optional(),
  expiresAt: TimestampSchema.optional(),
  principalAssurance: z.enum(['not_applicable', 'local_dashboard_session', 'local_cli_session', 'unknown']),
}).strict().superRefine((approval, context) => {
  if (!approval.required) {
    if (
      approval.outcome !== 'not_required'
      || approval.principalAssurance !== 'not_applicable'
      || approval.requestId !== undefined
      || approval.requestedAt !== undefined
      || approval.decidedAt !== undefined
      || approval.expiresAt !== undefined
    ) {
      context.addIssue({ code: 'custom', message: 'Non-required approval evidence is inconsistent' });
    }
    return;
  }
  if (approval.outcome === 'not_required') {
    context.addIssue({ code: 'custom', message: 'Required approval cannot be not_required' });
  }
  if (approval.outcome === 'not_requested' && (
    approval.requestId !== undefined
    || approval.requestedAt !== undefined
    || approval.decidedAt !== undefined
    || approval.expiresAt !== undefined
  )) {
    context.addIssue({ code: 'custom', message: 'Unrequested approval cannot contain request evidence' });
  }
  if (approval.outcome === 'pending' && (
    approval.requestId === undefined
    || approval.requestedAt === undefined
    || approval.expiresAt === undefined
    || approval.decidedAt !== undefined
  )) {
    context.addIssue({ code: 'custom', message: 'Pending approval evidence is incomplete' });
  }
  if (
    approval.outcome !== 'not_required'
    && approval.outcome !== 'not_requested'
    && approval.outcome !== 'pending'
    && approval.outcome !== 'unavailable'
    && (
      approval.requestId === undefined
      || approval.requestedAt === undefined
      || approval.expiresAt === undefined
      || approval.decidedAt === undefined
    )
  ) {
    context.addIssue({ code: 'custom', message: 'Resolved approval evidence is incomplete' });
  }
});

const IssuerSchema = z.object({
  softwareName: z.literal('agent-permission-guard'),
  softwareVersion: IdentifierSchema,
  buildIdentityAssurance: z.literal('package_version_only'),
}).strict();

const LimitationsSchema = z.object({
  directBypassUnprotected: z.literal(true),
  unobservedEffects: z.literal(true),
  clockAssurance: z.literal('local_system_clock'),
  issuerAuthentication: z.literal('none'),
}).strict();

const AuthorizationSchema = z.object({
  status: z.enum(['authorized', 'blocked', 'failed_pre_dispatch']),
  reasonCode: ReasonCodeSchema,
}).strict();

const ObservedResultSchema = z.object({
  kind: z.enum(['mcp', 'install', 'generic']),
  isError: z.boolean(),
  contentTypes: z.array(IdentifierSchema).max(20).optional(),
  contentCount: z.number().int().min(0).max(1_000_000).optional(),
  executionStatus: z.enum(['completed', 'failed', 'timed_out', 'cancelled']).optional(),
  exitCode: z.number().int().nullable().optional(),
  durationMs: z.number().int().min(0).max(86_400_000).optional(),
  stdoutBytes: z.number().int().min(0).optional(),
  stderrBytes: z.number().int().min(0).optional(),
  outputTruncated: z.boolean().optional(),
  verificationStatus: z.enum(['verified', 'failed', 'limited']).optional(),
  exactPackageVersionObserved: z.boolean().optional(),
  approvedIntegrityObserved: z.boolean().optional(),
  changedFiles: z.array(z.enum(['package.json', 'package-lock.json', 'npm-shrinkwrap.json'])).max(3).optional(),
  verificationReasonCodes: z.array(ReasonCodeSchema).max(100).optional(),
  errorCode: ReasonCodeSchema.optional(),
}).strict();

const RecoverySchema = z.object({
  capability: z.enum(['none', 'manual', 'bounded_automatic']),
  reference: IdentifierSchema.optional(),
}).strict();

export const AuthorizationReceiptSchema = z.object({
  schema: SchemaIdentitySchema,
  receipt: ReceiptIdentitySchema.extend({ type: z.literal('authorization') }).strict(),
  action: ActionSchema,
  coverage: CoverageSchema,
  policy: PolicySchema,
  decision: DecisionSchema,
  approval: ApprovalSchema,
  authorization: AuthorizationSchema,
  issuer: IssuerSchema,
  limitations: LimitationsSchema,
}).strict().superRefine((receipt, context) => {
  if (
    receipt.authorization.status === 'authorized'
    && (
      receipt.decision.effective === 'deny'
      || (receipt.approval.required && receipt.approval.outcome !== 'approved')
    )
  ) {
    context.addIssue({ code: 'custom', message: 'Authorized receipt lacks a valid authorization decision' });
  }
  if (
    receipt.authorization.status === 'blocked'
    && receipt.decision.effective !== 'deny'
    && !['denied', 'expired', 'cancelled', 'unavailable'].includes(receipt.approval.outcome)
  ) {
    context.addIssue({ code: 'custom', message: 'Blocked receipt lacks a blocking decision or approval outcome' });
  }
});

export const OutcomeReceiptSchema = z.object({
  schema: SchemaIdentitySchema,
  receipt: ReceiptIdentitySchema.extend({ type: z.literal('outcome') }).strict(),
  action: ActionSchema,
  coverage: CoverageSchema,
  authorizationReceiptDigest: DigestSchema,
  execution: z.object({
    startedAt: TimestampSchema,
    terminalStatus: z.enum([
      'completed',
      'execution_error',
      'upstream_error',
      'cancelled',
      'failed',
      'audit_failed',
      'outcome_unknown_after_interruption',
    ]),
    completedAt: TimestampSchema.optional(),
    observedResult: ObservedResultSchema.optional(),
  }).strict(),
  recovery: RecoverySchema,
  issuer: IssuerSchema,
  limitations: LimitationsSchema,
}).strict();

export type AuthorizationReceipt = z.infer<typeof AuthorizationReceiptSchema>;
export type OutcomeReceipt = z.infer<typeof OutcomeReceiptSchema>;
export type ObservedReceiptResult = z.infer<typeof ObservedResultSchema>;

export type ReceiptPolicyIdentity = Readonly<{
  schemaVersion: number;
  contentDigest: string;
  evaluatorName: string;
  evaluatorVersion: string;
}>;

export type ReceiptContext = Readonly<{
  adapter: string;
  adapterVersion: string;
  operation: string;
  boundary: z.infer<typeof CoverageSchema>['boundary'];
  identityAssurance: z.infer<typeof ActionSchema>['identityAssurance'];
  identityMaterial: unknown;
  subject?: string;
  executionPlanHash?: string;
  policy: ReceiptPolicyIdentity;
}>;

export type ReceiptApproval = Readonly<{
  required: boolean;
  outcome: z.infer<typeof ApprovalSchema>['outcome'];
  requestId?: string;
  requestedAt?: string;
  decidedAt?: string;
  expiresAt?: string;
  principalAssurance: z.infer<typeof ApprovalSchema>['principalAssurance'];
}>;

export function createAuthorizationReceipt(input: Readonly<{
  receiptId?: string;
  actionId: string;
  issuedAt: string;
  context: ReceiptContext;
  baseDecision: 'allow' | 'ask' | 'deny';
  effectiveDecision: 'allow' | 'ask' | 'deny';
  matchedRuleId?: string;
  reasonCodes: readonly string[];
  riskScore: number;
  riskBand: 'low' | 'medium' | 'high' | 'critical';
  approval: ReceiptApproval;
  status: z.infer<typeof AuthorizationSchema>['status'];
  reasonCode: string;
}>): AuthorizationReceipt {
  const action = actionFor(input.actionId, input.context);
  return AuthorizationReceiptSchema.parse({
    schema: schemaIdentity(),
    receipt: {
      id: input.receiptId ?? randomUUID(),
      type: 'authorization',
      issuedAt: input.issuedAt,
      assuranceLevel: 'portable_unsigned',
    },
    action,
    coverage: coverageFor(input.context.boundary),
    policy: {
      ...input.context.policy,
      ...(input.matchedRuleId === undefined ? {} : { matchedRuleId: input.matchedRuleId }),
    },
    decision: {
      base: input.baseDecision,
      effective: input.effectiveDecision,
      reasonCodes: [...input.reasonCodes],
      riskScore: input.riskScore,
      riskBand: input.riskBand,
    },
    approval: input.approval,
    authorization: { status: input.status, reasonCode: input.reasonCode },
    issuer: issuer(),
    limitations: limitations(),
  });
}

export function createOutcomeReceipt(input: Readonly<{
  receiptId?: string;
  issuedAt: string;
  authorization: AuthorizationReceipt;
  authorizationReceiptDigest: string;
  startedAt: string;
  terminalStatus: z.infer<typeof OutcomeReceiptSchema>['execution']['terminalStatus'];
  completedAt?: string;
  observedResult?: ObservedReceiptResult;
}>): OutcomeReceipt {
  return OutcomeReceiptSchema.parse({
    schema: schemaIdentity(),
    receipt: {
      id: input.receiptId ?? randomUUID(),
      type: 'outcome',
      issuedAt: input.issuedAt,
      assuranceLevel: 'portable_unsigned',
    },
    action: input.authorization.action,
    coverage: input.authorization.coverage,
    authorizationReceiptDigest: input.authorizationReceiptDigest,
    execution: {
      startedAt: input.startedAt,
      terminalStatus: input.terminalStatus,
      ...(input.completedAt === undefined ? {} : { completedAt: input.completedAt }),
      ...(input.observedResult === undefined ? {} : { observedResult: input.observedResult }),
    },
    recovery: { capability: 'none' },
    issuer: issuer(),
    limitations: limitations(),
  });
}

export function receiptDigest(receipt: AuthorizationReceipt | OutcomeReceipt): string {
  return `sha256:${createHash('sha256').update(canonicalReceiptJson(receipt)).digest('hex')}`;
}

export function canonicalReceiptJson(value: unknown): string {
  validateJsonValue(value, 0, new WeakSet<object>());
  return canonicalJson(value);
}

function actionFor(actionId: string, context: ReceiptContext): z.infer<typeof ActionSchema> {
  return ActionSchema.parse({
    id: actionId,
    adapter: context.adapter,
    adapterVersion: context.adapterVersion,
    operation: context.operation,
    identityAssurance: context.identityAssurance,
    intentDigest: `sha256:${createHash('sha256').update(canonicalReceiptJson({
      format: 'apg-portable-intent-v1',
      adapter: context.adapter,
      adapterVersion: context.adapterVersion,
      operation: context.operation,
      material: context.identityMaterial,
    })).digest('hex')}`,
    ...(context.subject === undefined ? {} : { subject: context.subject }),
    ...(context.executionPlanHash === undefined ? {} : { executionPlanHash: context.executionPlanHash }),
  });
}

function schemaIdentity(): z.infer<typeof SchemaIdentitySchema> {
  return {
    name: 'apg-action-receipt',
    majorVersion: 1,
    minorVersion: 0,
    canonicalization: 'apg-canonical-json-v1',
  };
}

function issuer(): z.infer<typeof IssuerSchema> {
  return {
    softwareName: 'agent-permission-guard',
    softwareVersion: APG_VERSION,
    buildIdentityAssurance: 'package_version_only',
  };
}

function limitations(): z.infer<typeof LimitationsSchema> {
  return {
    directBypassUnprotected: true,
    unobservedEffects: true,
    clockAssurance: 'local_system_clock',
    issuerAuthentication: 'none',
  };
}

function coverageFor(boundary: ReceiptContext['boundary']): z.infer<typeof CoverageSchema> {
  if (boundary === 'install_guard_plan') {
    return {
      routedThroughApg: true,
      boundary,
      observed: ['policy_evaluation', 'local_approval', 'process_dispatch', 'bounded_postcondition_verification'],
      notObserved: ['direct_npm_npx', 'complete_child_process_effects', 'complete_network_effects', 'automatic_rollback'],
    };
  }
  if (boundary === 'apg_local_control') {
    return {
      routedThroughApg: true,
      boundary,
      observed: ['local_control_request', 'bounded_result'],
      notObserved: ['same_user_process_identity', 'human_identity', 'complete_filesystem_effects'],
    };
  }
  return {
    routedThroughApg: true,
    boundary,
    observed: ['policy_evaluation', 'local_approval', 'upstream_dispatch', 'bounded_result'],
    notObserved: ['direct_tool_bypass', 'complete_upstream_effects', 'complete_child_process_effects'],
  };
}

function validateJsonValue(value: unknown, depth: number, ancestors: WeakSet<object>): void {
  if (depth > MAX_DEPTH) throw new Error('Receipt value exceeds the depth limit');
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    if (typeof value === 'string' && value.length > MAX_STRING_LENGTH) {
      throw new Error('Receipt string exceeds the length limit');
    }
    return;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('Receipt numbers must be finite');
    return;
  }
  if (typeof value !== 'object' || value === undefined) {
    throw new Error('Receipt values must use the JSON data model');
  }
  if (ancestors.has(value)) throw new Error('Receipt values must not be cyclic');
  const prototype = Object.getPrototypeOf(value);
  if (!Array.isArray(value) && prototype !== Object.prototype && prototype !== null) {
    throw new Error('Receipt objects must be plain objects');
  }
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      if (value.length > MAX_COLLECTION_ITEMS) throw new Error('Receipt array exceeds the item limit');
      for (const nested of value) validateJsonValue(nested, depth + 1, ancestors);
      return;
    }
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length > MAX_COLLECTION_ITEMS) throw new Error('Receipt object exceeds the field limit');
    for (const [key, nested] of entries) {
      if (key.length > 256) throw new Error('Receipt key exceeds the length limit');
      validateJsonValue(nested, depth + 1, ancestors);
    }
  } finally {
    ancestors.delete(value);
  }
}
