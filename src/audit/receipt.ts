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
  minorVersion: z.union([z.literal(0), z.literal(1), z.literal(2)]),
  canonicalization: z.literal('apg-canonical-json-v1'),
}).strict();

const ReceiptIdentitySchema = z.object({
  id: z.uuid(),
  type: z.enum(['authorization', 'outcome']),
  issuedAt: TimestampSchema,
  assuranceLevel: z.literal('portable_unsigned'),
}).strict();

const SafeIdentityScalarSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('string'), value: z.string().max(512) }).strict(),
  z.object({ type: z.literal('enum'), value: IdentifierSchema }).strict(),
  z.object({ type: z.literal('integer'), value: z.number().int().safe() }).strict(),
  z.object({ type: z.literal('boolean'), value: z.boolean() }).strict(),
  z.object({ type: z.literal('null') }).strict(),
]);

const SafeIdentityValueSchema = z.union([
  SafeIdentityScalarSchema,
  z.object({
    type: z.literal('ordered_list'),
    items: z.array(SafeIdentityScalarSchema).max(100),
  }).strict(),
]);

const SafeIdentityClaimSchema = z.object({
  name: IdentifierSchema,
  value: SafeIdentityValueSchema,
}).strict();

const ReceiptIdentityEvidenceSchema = z.object({
  profileStatus: z.enum(['projected', 'rejected']),
  profileId: IdentifierSchema,
  profileVersion: z.number().int().min(1).max(1_000_000),
  profileManifestDigest: DigestSchema,
  serverProvenanceAssurance: z.literal('configured_label_only'),
  parameterCoverage: z.enum(['none', 'declared_subset', 'complete_action_parameters']),
  safeClaims: z.array(SafeIdentityClaimSchema).max(64),
  omittedCategories: z.array(IdentifierSchema).max(32),
  observedSchemaDigest: DigestSchema.optional(),
  failureCode: ReasonCodeSchema.optional(),
}).strict().superRefine((evidence, context) => {
  const claimNames = evidence.safeClaims.map((claim) => claim.name);
  if (new Set(claimNames).size !== claimNames.length || claimNames.join('\0') !== [...claimNames].sort().join('\0')) {
    context.addIssue({ code: 'custom', message: 'Identity claims must be unique and sorted' });
  }
  const omitted = evidence.omittedCategories;
  if (new Set(omitted).size !== omitted.length || omitted.join('\0') !== [...omitted].sort().join('\0')) {
    context.addIssue({ code: 'custom', message: 'Omitted identity categories must be unique and sorted' });
  }
  if (evidence.profileStatus === 'projected' && evidence.failureCode !== undefined) {
    context.addIssue({ code: 'custom', message: 'Projected identity evidence cannot contain a failure code' });
  }
  if (
    evidence.profileStatus === 'projected'
    && (
      evidence.parameterCoverage === 'none'
      || (evidence.parameterCoverage === 'complete_action_parameters' && evidence.omittedCategories.length !== 0)
      || (evidence.parameterCoverage === 'declared_subset' && evidence.omittedCategories.length === 0)
    )
  ) {
    context.addIssue({ code: 'custom', message: 'Projected identity coverage is inconsistent' });
  }
  if (
    evidence.profileStatus === 'rejected'
    && (
      evidence.failureCode === undefined
      || evidence.parameterCoverage !== 'none'
      || evidence.safeClaims.length !== 0
      || evidence.omittedCategories.length === 0
    )
  ) {
    context.addIssue({ code: 'custom', message: 'Rejected identity evidence is inconsistent' });
  }
});

const ActionSchema = z.object({
  id: z.uuid(),
  adapter: IdentifierSchema,
  adapterVersion: IdentifierSchema,
  operation: IdentifierSchema,
  identityAssurance: z.enum(['structural_only', 'adapter_scoped', 'adapter_action_exact', 'execution_plan_exact']),
  intentDigest: DigestSchema,
  subject: z.string().min(1).max(512).optional(),
  executionPlanHash: HashSchema.optional(),
  identityEvidence: ReceiptIdentityEvidenceSchema.optional(),
}).strict().superRefine((action, context) => {
  const evidence = action.identityEvidence;
  if (action.identityAssurance === 'adapter_action_exact') {
    if (
      evidence === undefined
      || evidence.profileStatus !== 'projected'
      || evidence.parameterCoverage !== 'complete_action_parameters'
      || evidence.omittedCategories.length !== 0
    ) {
      context.addIssue({ code: 'custom', message: 'Exact adapter identity lacks complete profile evidence' });
    }
  }
  if (evidence === undefined) return;
  if (action.identityAssurance === 'structural_only' && evidence.profileStatus !== 'rejected') {
    context.addIssue({ code: 'custom', message: 'Structural identity can contain only rejected profile evidence' });
  }
  if (
    action.identityAssurance === 'adapter_scoped'
    && (evidence.profileStatus !== 'projected' || evidence.parameterCoverage !== 'declared_subset')
  ) {
    context.addIssue({ code: 'custom', message: 'Adapter-scoped identity lacks partial profile evidence' });
  }
  if (action.identityAssurance === 'execution_plan_exact') {
    context.addIssue({ code: 'custom', message: 'Execution-plan identity cannot contain MCP profile evidence' });
  }
});

const CoverageSchema = z.object({
  routedThroughApg: z.literal(true),
  boundary: z.enum(['mcp_proxy_call', 'install_guard_plan', 'apg_local_control', 'graph_genesis_plan']),
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
  kind: z.enum(['mcp', 'install', 'generic', 'graph_genesis']),
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
  externalReadStatus: z.enum(['not_started', 'started', 'validated', 'incomplete']).optional(),
  metadataRequestCount: z.number().int().min(0).max(512).optional(),
  metadataUniquePackageCount: z.number().int().min(0).max(256).optional(),
  metadataResponseBytes: z.number().int().min(0).max(134_217_728).optional(),
  lockDigest: DigestSchema.optional(),
  candidateDigest: DigestSchema.optional(),
  candidateArtifactDigest: DigestSchema.optional(),
  cleanupStatus: z.enum(['not_needed', 'complete', 'quarantined', 'incomplete']).optional(),
  quarantineReferenceDigest: DigestSchema.optional(),
  terminalAuditStatus: z.enum(['complete', 'failed', 'unknown']).optional(),
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
  validateReceiptIdentityVersion(receipt.schema, receipt.action, context);
  if ((receipt.schema.minorVersion === 2) !== (receipt.coverage.boundary === 'graph_genesis_plan')) {
    context.addIssue({ code: 'custom', message: 'Receipt schema 1.2 is reserved for the Graph Genesis boundary' });
  }
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
      'incomplete_external_read',
      'outcome_unknown_after_interruption',
    ]),
    completedAt: TimestampSchema.optional(),
    observedResult: ObservedResultSchema.optional(),
  }).strict(),
  recovery: RecoverySchema,
  issuer: IssuerSchema,
  limitations: LimitationsSchema,
}).strict().superRefine((receipt, context) => {
  validateReceiptIdentityVersion(receipt.schema, receipt.action, context);
  if ((receipt.schema.minorVersion === 2) !== (receipt.coverage.boundary === 'graph_genesis_plan')) {
    context.addIssue({ code: 'custom', message: 'Receipt schema 1.2 is reserved for the Graph Genesis boundary' });
  }
  if (receipt.schema.minorVersion === 2 && receipt.execution.observedResult !== undefined
    && receipt.execution.observedResult.kind !== 'graph_genesis') {
    context.addIssue({ code: 'custom', message: 'Graph Genesis outcome requires a Graph Genesis observed result' });
  }
});

export type AuthorizationReceipt = z.infer<typeof AuthorizationReceiptSchema>;
export type OutcomeReceipt = z.infer<typeof OutcomeReceiptSchema>;
export type ObservedReceiptResult = z.infer<typeof ObservedResultSchema>;
export type ReceiptSafeIdentityScalar =
  | Readonly<{ type: 'string'; value: string }>
  | Readonly<{ type: 'enum'; value: string }>
  | Readonly<{ type: 'integer'; value: number }>
  | Readonly<{ type: 'boolean'; value: boolean }>
  | Readonly<{ type: 'null' }>;
export type ReceiptSafeIdentityValue = ReceiptSafeIdentityScalar | Readonly<{
  type: 'ordered_list';
  items: readonly ReceiptSafeIdentityScalar[];
}>;
export type ReceiptIdentityEvidence = Readonly<{
  profileStatus: 'projected' | 'rejected';
  profileId: string;
  profileVersion: number;
  profileManifestDigest: string;
  serverProvenanceAssurance: 'configured_label_only';
  parameterCoverage: 'none' | 'declared_subset' | 'complete_action_parameters';
  safeClaims: readonly Readonly<{
    name: string;
    value: ReceiptSafeIdentityValue;
  }>[];
  omittedCategories: readonly string[];
  observedSchemaDigest?: string;
  failureCode?: string;
}>;

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
  identityEvidence?: ReceiptIdentityEvidence;
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
    schema: schemaIdentity(input.context),
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
    schema: input.authorization.schema,
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
    ...(context.identityEvidence === undefined ? {} : { identityEvidence: context.identityEvidence }),
  });
}

function schemaIdentity(context: ReceiptContext): z.infer<typeof SchemaIdentitySchema> {
  return {
    name: 'apg-action-receipt',
    majorVersion: 1,
    minorVersion: context.boundary === 'graph_genesis_plan' ? 2 : context.identityEvidence === undefined ? 0 : 1,
    canonicalization: 'apg-canonical-json-v1',
  };
}

function validateReceiptIdentityVersion(
  schema: z.infer<typeof SchemaIdentitySchema>,
  action: z.infer<typeof ActionSchema>,
  context: z.RefinementCtx,
): void {
  if (schema.minorVersion === 0 && action.identityEvidence !== undefined) {
    context.addIssue({ code: 'custom', message: 'Receipt schema 1.0 cannot contain identity profile evidence' });
  }
  if (schema.minorVersion === 1 && action.identityEvidence === undefined) {
    context.addIssue({ code: 'custom', message: 'Receipt schema 1.1 requires identity profile evidence' });
  }
  if (schema.minorVersion === 2 && (
    action.identityAssurance !== 'execution_plan_exact'
    || action.executionPlanHash === undefined
    || action.identityEvidence !== undefined
  )) {
    context.addIssue({ code: 'custom', message: 'Receipt schema 1.2 requires an exact non-MCP execution plan identity' });
  }
  if (schema.minorVersion === 0 && action.identityAssurance === 'adapter_action_exact') {
    context.addIssue({ code: 'custom', message: 'Receipt schema 1.0 cannot claim exact adapter identity' });
  }
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
  if (boundary === 'graph_genesis_plan') {
    return {
      routedThroughApg: true,
      boundary,
      observed: [
        'exact_execution_envelope', 'local_approval', 'bounded_public_metadata_requests',
        'exact_process_dispatch', 'bounded_post_state', 'candidate_artifact', 'terminal_audit',
      ],
      notObserved: [
        'registry_publisher_honesty', 'package_safety', 'source_build_equivalence', 'kernel_integrity',
        'same_user_containment', 'later_artifact_bytes', 'materialization', 'startup', 'direct_npm_npx',
      ],
    };
  }
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
