import { createHash, randomUUID } from 'node:crypto';

import type { CallToolResult } from '@modelcontextprotocol/server';

import type { ToolCallContext } from '../gateway/call-interceptor.js';
import type { ApprovalOutcome, ApprovalRequestView } from '../approval/types.js';
import type { Decision } from '../policy/schema.js';
import type { RiskBand } from '../risk/types.js';
import type { AuditDatabase } from '../db/database.js';
import { isTrustedMcpIdentityResult } from '../identity/mcp-identity.js';
import { canonicalJson } from './canonical-json.js';
import { redactForAudit } from './redaction.js';
import {
  canonicalReceiptJson,
  createAuthorizationReceipt,
  createOutcomeReceipt,
  receiptDigest,
  type AuthorizationReceipt,
  type ObservedReceiptResult,
  type ReceiptApproval,
  type ReceiptContext,
} from './receipt.js';

const GENESIS_HASH = '0'.repeat(64);

export interface AuditCall {
  markForwarding(): void;
  markApprovalRequested(request: ApprovalRequestView): void;
  markApprovalResolved(approvalId: string, outcome: ApprovalOutcome): void;
  markBlocked(status: 'denied' | 'approval_unavailable' | 'approval_denied' | 'approval_expired' | 'approval_cancelled'): void;
  markCompleted(result: CallToolResult): void;
  markExecutionResult(summary: unknown, isError: boolean): void;
  markFailed(code: string): void;
}

export interface AuditRecorder {
  begin(context: ToolCallContext, decision: AuditDecision): AuditCall;
}

export type AuditDecision = Readonly<{
  action: 'forward' | 'ask' | 'deny';
  reason?: string;
  receipt?: ReceiptContext;
  evaluation?: Readonly<{
    baseDecision: Decision;
    effectiveDecision: Decision;
    matchedRuleId?: string;
    reasonCodes: readonly string[];
    risk: Readonly<{
      score: number;
      band: RiskBand;
      signals: readonly unknown[];
    }>;
  }>;
}>;

export class NoopAuditRecorder implements AuditRecorder {
  begin(_context: ToolCallContext, _decision: AuditDecision): AuditCall {
    return {
      markForwarding() {},
      markApprovalRequested() {},
      markApprovalResolved() {},
      markBlocked() {},
      markCompleted() {},
      markExecutionResult() {},
      markFailed() {},
    };
  }
}

export class SqliteAuditRecorder implements AuditRecorder {
  constructor(
    private readonly database: AuditDatabase,
    private readonly now: () => Date = () => new Date(),
  ) {}

  begin(context: ToolCallContext, decision: AuditDecision): AuditCall {
    const id = randomUUID();
    const startedAt = this.now();
    const evaluation = normalizeEvaluation(decision);
    const receiptContext = trustedReceiptContext(context, decision.receipt);
    const redactedArguments = redactForAudit(context.arguments);
    const insert = this.database.transaction(() => {
      this.database.prepare(`
        INSERT INTO tool_calls (
          id, server_id, tool_name, arguments_json, request_hash,
          base_decision, effective_decision, matched_rule_id, reason_codes_json,
          risk_score, risk_band, risk_signals_json, status, started_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id,
        context.serverId,
        context.toolName,
        canonicalJson(redactedArguments),
        sha256(canonicalJson({
          serverId: context.serverId,
          toolName: context.toolName,
          arguments: redactedArguments,
        })),
        evaluation.baseDecision,
        evaluation.effectiveDecision,
        evaluation.matchedRuleId ?? null,
        canonicalJson(evaluation.reasonCodes),
        evaluation.risk.score,
        evaluation.risk.band,
        canonicalJson(redactForAudit(evaluation.risk.signals)),
        'evaluated',
        startedAt.toISOString(),
      );
      this.appendEvent(id, 'decision_recorded', {
        serverId: context.serverId,
        toolName: context.toolName,
        baseDecision: evaluation.baseDecision,
        effectiveDecision: evaluation.effectiveDecision,
        matchedRuleId: evaluation.matchedRuleId,
        reasonCodes: evaluation.reasonCodes,
        risk: evaluation.risk,
        receiptEvidence: {
          adapter: receiptContext.adapter,
          adapterVersion: receiptContext.adapterVersion,
          boundary: receiptContext.boundary,
          identityAssurance: receiptContext.identityAssurance,
          policy: receiptContext.policy,
        },
      });
    });
    insert();

    let terminal = false;
    let dispatched = false;
    let executionStartedAt: string | undefined;
    let authorization: Readonly<{
      receipt: AuthorizationReceipt;
      digest: string;
    }> | undefined;
    let approval: ReceiptApproval = decision.action === 'ask'
      ? { required: true, outcome: 'not_requested', principalAssurance: 'unknown' }
      : { required: false, outcome: 'not_required', principalAssurance: 'not_applicable' };

    const buildAuthorization = (
      status: 'authorized' | 'blocked' | 'failed_pre_dispatch',
      reasonCode: string,
      issuedAt: string,
    ) => {
      const receipt = createAuthorizationReceipt({
        actionId: id,
        issuedAt,
        context: receiptContext,
        baseDecision: evaluation.baseDecision,
        effectiveDecision: evaluation.effectiveDecision,
        ...(evaluation.matchedRuleId === undefined ? {} : { matchedRuleId: evaluation.matchedRuleId }),
        reasonCodes: evaluation.reasonCodes,
        riskScore: evaluation.risk.score,
        riskBand: evaluation.risk.band,
        approval,
        status,
        reasonCode,
      });
      return { receipt, digest: receiptDigest(receipt) };
    };

    return {
      markForwarding: () => {
        if (terminal) throw new Error('Audit call is already terminal');
        if (dispatched) throw new Error('Execution dispatch is already recorded');
        if (approval.required && approval.outcome !== 'approved') {
          throw new Error('Required approval is not approved');
        }
        const timestamp = this.now().toISOString();
        const nextAuthorization = buildAuthorization(
          'authorized',
          approval.outcome === 'approved' ? 'approval_approved' : 'policy_allowed',
          timestamp,
        );
        this.database.transaction(() => {
          this.updateStatus(id, 'forwarding');
          this.appendEvent(id, 'authorization_receipt_finalized', {
            receipt: nextAuthorization.receipt,
            receiptDigest: nextAuthorization.digest,
          });
          this.appendEvent(id, 'execution_start_recorded', {
            receiptDigest: nextAuthorization.digest,
          });
        })();
        authorization = nextAuthorization;
        executionStartedAt = timestamp;
        dispatched = true;
      },
      markApprovalRequested: (request) => {
        if (terminal) throw new Error('Audit call is already terminal');
        this.database.transaction(() => {
          this.database.prepare(`
            INSERT INTO approvals (
              id, tool_call_id, status, requested_at, expires_at
            ) VALUES (?, ?, 'pending', ?, ?)
          `).run(request.id, id, request.requestedAt, request.expiresAt);
          this.updateStatus(id, 'approval_pending');
          this.appendEvent(id, 'approval_requested', {
            approvalId: request.id,
            expiresAt: request.expiresAt,
          });
        })();
        approval = {
          required: true,
          outcome: 'pending',
          requestId: request.id,
          requestedAt: request.requestedAt,
          expiresAt: request.expiresAt,
          principalAssurance: 'local_dashboard_session',
        };
      },
      markApprovalResolved: (approvalId, outcome) => {
        if (terminal) throw new Error('Audit call is already terminal');
        const decidedAt = this.now().toISOString();
        this.database.transaction(() => {
          const result = this.database.prepare(`
            UPDATE approvals
            SET status = ?, decided_at = ?
            WHERE id = ? AND tool_call_id = ? AND status = 'pending'
          `).run(outcome, decidedAt, approvalId, id);
          if (result.changes !== 1) throw new Error('Approval is not pending');
          this.updateStatus(id, `approval_${outcome}`);
          this.appendEvent(id, `approval_${outcome}`, { approvalId });
        })();
        approval = {
          ...approval,
          required: true,
          outcome,
          requestId: approvalId,
          decidedAt,
          principalAssurance: 'local_dashboard_session',
        };
      },
      markBlocked: (status) => {
        if (terminal) throw new Error('Audit call is already terminal');
        if (dispatched) throw new Error('A dispatched action cannot be marked as pre-execution blocked');
        approval = blockedApproval(approval, status);
        const completedAt = this.now();
        const nextAuthorization = buildAuthorization('blocked', status, completedAt.toISOString());
        this.database.transaction(() => {
          this.finish(id, status, startedAt, completedAt, undefined, undefined);
          this.appendEvent(id, status, {});
          this.appendEvent(id, 'authorization_receipt_finalized', {
            receipt: nextAuthorization.receipt,
            receiptDigest: nextAuthorization.digest,
          });
        })();
        authorization = nextAuthorization;
        terminal = true;
      },
      markCompleted: (result) => {
        if (terminal) throw new Error('Audit call is already terminal');
        if (!dispatched || authorization === undefined || executionStartedAt === undefined) {
          throw new Error('Execution was not durably authorized');
        }
        const summary = summarizeResult(result);
        const completedAt = this.now();
        const outcome = createOutcomeReceipt({
          issuedAt: completedAt.toISOString(),
          authorization: authorization.receipt,
          authorizationReceiptDigest: authorization.digest,
          startedAt: executionStartedAt,
          terminalStatus: result.isError === true ? 'upstream_error' : 'completed',
          completedAt: completedAt.toISOString(),
          observedResult: summarizeMcpReceiptResult(result),
        });
        this.database.transaction(() => {
          this.finish(
            id,
            result.isError === true ? 'upstream_error' : 'completed',
            startedAt,
            completedAt,
            summary,
            undefined,
          );
          this.appendEvent(id, 'execution_completed', summary);
          this.appendEvent(id, 'outcome_receipt_finalized', {
            receipt: outcome,
            receiptDigest: receiptDigest(outcome),
          });
        })();
        terminal = true;
      },
      markExecutionResult: (summary, isError) => {
        if (terminal) throw new Error('Audit call is already terminal');
        if (!dispatched || authorization === undefined || executionStartedAt === undefined) {
          throw new Error('Execution was not durably authorized');
        }
        const redactedSummary = redactForAudit(summary);
        const completedAt = this.now();
        const outcome = createOutcomeReceipt({
          issuedAt: completedAt.toISOString(),
          authorization: authorization.receipt,
          authorizationReceiptDigest: authorization.digest,
          startedAt: executionStartedAt,
          terminalStatus: isError ? 'execution_error' : 'completed',
          completedAt: completedAt.toISOString(),
          observedResult: summarizeInstallReceiptResult(summary, isError),
        });
        this.database.transaction(() => {
          this.finish(id, isError ? 'execution_error' : 'completed', startedAt, completedAt, redactedSummary, undefined);
          this.appendEvent(id, 'execution_completed', redactedSummary);
          this.appendEvent(id, 'outcome_receipt_finalized', {
            receipt: outcome,
            receiptDigest: receiptDigest(outcome),
          });
        })();
        terminal = true;
      },
      markFailed: (code) => {
        if (terminal) return;
        const completedAt = this.now();
        if (approval.required && (approval.outcome === 'not_requested' || approval.outcome === 'pending') && code.includes('approval_unavailable')) {
          approval = { ...approval, outcome: 'unavailable' };
        }
        const nextAuthorization = authorization ?? buildAuthorization(
          dispatched ? 'authorized' : 'failed_pre_dispatch',
          dispatched ? 'dispatch_recorded' : code,
          completedAt.toISOString(),
        );
        const outcome = dispatched && executionStartedAt !== undefined
          ? createOutcomeReceipt({
            issuedAt: completedAt.toISOString(),
            authorization: nextAuthorization.receipt,
            authorizationReceiptDigest: nextAuthorization.digest,
            startedAt: executionStartedAt,
            terminalStatus: terminalStatusForFailure(code),
            completedAt: completedAt.toISOString(),
            observedResult: { kind: receiptResultKind(receiptContext), isError: true, errorCode: safeReasonCode(code) },
          })
          : undefined;
        this.database.transaction(() => {
          this.finish(id, 'failed', startedAt, completedAt, undefined, code);
          this.appendEvent(id, 'execution_failed', { code });
          if (authorization === undefined) {
            this.appendEvent(id, 'authorization_receipt_finalized', {
              receipt: nextAuthorization.receipt,
              receiptDigest: nextAuthorization.digest,
            });
          }
          if (outcome !== undefined) {
            this.appendEvent(id, 'outcome_receipt_finalized', {
              receipt: outcome,
              receiptDigest: receiptDigest(outcome),
            });
          }
        })();
        authorization = nextAuthorization;
        terminal = true;
      },
    };
  }

  verifyHashChain(): boolean {
    const events = this.database.prepare(`
      SELECT event_json, previous_hash, event_hash FROM audit_events ORDER BY sequence ASC
    `).all() as Array<{ event_json: string; previous_hash: string; event_hash: string }>;
    let expectedPrevious = GENESIS_HASH;
    for (const event of events) {
      if (event.previous_hash !== expectedPrevious) return false;
      if (sha256(`${event.previous_hash}\n${event.event_json}`) !== event.event_hash) return false;
      expectedPrevious = event.event_hash;
    }
    return true;
  }

  private updateStatus(id: string, status: string): void {
    this.database.prepare('UPDATE tool_calls SET status = ? WHERE id = ?').run(status, id);
  }

  private finish(
    id: string,
    status: string,
    startedAt: Date,
    completedAt: Date,
    resultSummary: unknown,
    errorCode: string | undefined,
  ): void {
    this.database.prepare(`
      UPDATE tool_calls
      SET status = ?, completed_at = ?, latency_ms = ?, result_summary_json = ?, error_code = ?
      WHERE id = ?
    `).run(
      status,
      completedAt.toISOString(),
      Math.max(0, completedAt.getTime() - startedAt.getTime()),
      resultSummary === undefined ? null : canonicalJson(resultSummary),
      errorCode ?? null,
      id,
    );
  }

  private appendEvent(toolCallId: string, eventType: string, details: unknown): void {
    const previous = this.database.prepare(`
      SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1
    `).get() as { event_hash: string } | undefined;
    const previousHash = previous?.event_hash ?? GENESIS_HASH;
    const receiptEvent = eventType === 'authorization_receipt_finalized' || eventType === 'outcome_receipt_finalized';
    const eventJson = canonicalJson({
      eventId: randomUUID(),
      toolCallId,
      eventType,
      details: receiptEvent ? details : redactForAudit(details),
      createdAt: this.now().toISOString(),
    });
    const event = JSON.parse(eventJson) as { eventId: string; createdAt: string };
    const eventHash = sha256(`${previousHash}\n${eventJson}`);
    this.database.prepare(`
      INSERT INTO audit_events (
        event_id, tool_call_id, event_type, event_json, previous_hash, event_hash, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(event.eventId, toolCallId, eventType, eventJson, previousHash, eventHash, event.createdAt);
  }
}

function normalizeEvaluation(decision: AuditDecision): NonNullable<AuditDecision['evaluation']> {
  if (decision.evaluation !== undefined) return decision.evaluation;
  const fallback = decision.action === 'forward' ? 'allow' : decision.action;
  return {
    baseDecision: fallback,
    effectiveDecision: fallback,
    reasonCodes: ['interceptor_decision'],
    risk: { score: 0, band: 'low', signals: [] },
  };
}

function summarizeResult(result: CallToolResult): unknown {
  return {
    isError: result.isError === true,
    contentTypes: result.content.map((item) => item.type),
    contentCount: result.content.length,
  };
}

function summarizeMcpReceiptResult(result: CallToolResult): ObservedReceiptResult {
  return {
    kind: 'mcp',
    isError: result.isError === true,
    contentTypes: result.content.slice(0, 20).map((item) => safeIdentifier(item.type)),
    contentCount: Math.min(result.content.length, 1_000_000),
  };
}

function summarizeInstallReceiptResult(summary: unknown, isError: boolean): ObservedReceiptResult {
  const record = asRecord(summary);
  const output = asRecord(record?.output);
  const verification = asRecord(record?.verification);
  const executionStatus = isExecutionStatus(record?.status) ? record.status : undefined;
  const exitCode = typeof record?.exitCode === 'number' && Number.isInteger(record.exitCode)
    ? record.exitCode
    : record?.exitCode === null ? null : undefined;
  const durationMs = boundedNonNegativeInteger(record?.durationMs, 86_400_000);
  const stdoutBytes = boundedNonNegativeInteger(output?.stdoutBytes, Number.MAX_SAFE_INTEGER);
  const stderrBytes = boundedNonNegativeInteger(output?.stderrBytes, Number.MAX_SAFE_INTEGER);
  const verificationStatus = isVerificationStatus(verification?.status) ? verification.status : undefined;
  const changedFiles = Array.isArray(verification?.changedFiles)
    ? verification.changedFiles.filter(isKnownInstallFile).slice(0, 3)
    : undefined;
  const verificationReasonCodes = Array.isArray(verification?.reasonCodes)
    ? verification.reasonCodes.filter((item): item is string => typeof item === 'string')
      .map(safeReasonCode)
      .slice(0, 100)
    : undefined;

  return {
    kind: 'install',
    isError,
    ...(executionStatus === undefined ? {} : { executionStatus }),
    ...(exitCode === undefined ? {} : { exitCode }),
    ...(durationMs === undefined ? {} : { durationMs }),
    ...(stdoutBytes === undefined ? {} : { stdoutBytes }),
    ...(stderrBytes === undefined ? {} : { stderrBytes }),
    ...(typeof output?.truncated !== 'boolean' ? {} : { outputTruncated: output.truncated }),
    ...(verificationStatus === undefined ? {} : { verificationStatus }),
    ...(typeof verification?.exactPackageVersionObserved !== 'boolean'
      ? {}
      : { exactPackageVersionObserved: verification.exactPackageVersionObserved }),
    ...(typeof verification?.approvedIntegrityObserved !== 'boolean'
      ? {}
      : { approvedIntegrityObserved: verification.approvedIntegrityObserved }),
    ...(changedFiles === undefined ? {} : { changedFiles }),
    ...(verificationReasonCodes === undefined ? {} : { verificationReasonCodes }),
  };
}

function fallbackReceiptContext(context: ToolCallContext): ReceiptContext {
  return {
    adapter: 'mcp_proxy',
    adapterVersion: '1',
    operation: safeIdentifier(context.toolName),
    boundary: 'mcp_proxy_call',
    identityAssurance: 'structural_only',
    identityMaterial: {
      serverId: context.serverId,
      toolName: context.toolName,
    },
    policy: {
      schemaVersion: 0,
      contentDigest: `sha256:${sha256(canonicalReceiptJson({
        format: 'apg-interceptor-fallback-v1',
        decisionSource: 'interceptor_without_policy_identity',
      }))}`,
      evaluatorName: 'interceptor_fallback',
      evaluatorVersion: '1',
    },
  };
}

function trustedReceiptContext(
  context: ToolCallContext,
  proposed: ReceiptContext | undefined,
): ReceiptContext {
  const fallback = proposed ?? fallbackReceiptContext(context);
  const trustedIdentity = isTrustedMcpIdentityResult(context.identity) ? context.identity : undefined;
  if (trustedIdentity === undefined && fallback.boundary !== 'mcp_proxy_call') return fallback;

  const identity = trustedIdentity ?? {
    assurance: 'structural_only' as const,
    identityMaterial: { serverId: context.serverId, toolName: context.toolName },
  };
  const identityEvidence = trustedIdentity?.evidence;
  return {
    adapter: 'mcp_proxy',
    adapterVersion: '1',
    operation: safeIdentifier(context.toolName),
    boundary: 'mcp_proxy_call',
    identityAssurance: identity.assurance,
    identityMaterial: identity.identityMaterial,
    subject: context.serverId,
    ...(identityEvidence === undefined ? {} : { identityEvidence }),
    policy: fallback.policy,
  };
}

function blockedApproval(
  approval: ReceiptApproval,
  status: 'denied' | 'approval_unavailable' | 'approval_denied' | 'approval_expired' | 'approval_cancelled',
): ReceiptApproval {
  if (!status.startsWith('approval_')) return approval;
  const outcome = status.slice('approval_'.length);
  if (outcome === 'unavailable' || outcome === 'denied' || outcome === 'expired' || outcome === 'cancelled') {
    return { ...approval, required: true, outcome };
  }
  return approval;
}

function receiptResultKind(context: ReceiptContext): ObservedReceiptResult['kind'] {
  if (context.boundary === 'install_guard_plan') return 'install';
  if (context.boundary === 'mcp_proxy_call') return 'mcp';
  return 'generic';
}

function safeIdentifier(value: string): string {
  return /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/.test(value)
    ? value
    : `opaque:${sha256(value).slice(0, 32)}`;
}

function safeReasonCode(value: string): string {
  return /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(value)
    ? value
    : `opaque_error_${sha256(value).slice(0, 32)}`;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function boundedNonNegativeInteger(value: unknown, maximum: number): number | undefined {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= maximum
    ? value
    : undefined;
}

function isExecutionStatus(value: unknown): value is 'completed' | 'failed' | 'timed_out' | 'cancelled' {
  return value === 'completed' || value === 'failed' || value === 'timed_out' || value === 'cancelled';
}

function isVerificationStatus(value: unknown): value is 'verified' | 'failed' | 'limited' {
  return value === 'verified' || value === 'failed' || value === 'limited';
}

function isKnownInstallFile(value: unknown): value is 'package.json' | 'package-lock.json' | 'npm-shrinkwrap.json' {
  return value === 'package.json' || value === 'package-lock.json' || value === 'npm-shrinkwrap.json';
}

function terminalStatusForFailure(
  code: string,
): 'upstream_error' | 'cancelled' | 'failed' | 'audit_failed' {
  if (code === 'upstream_error') return 'upstream_error';
  if (code === 'cancelled') return 'cancelled';
  if (code.includes('audit_completion_failed')) return 'audit_failed';
  return 'failed';
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}
