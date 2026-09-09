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
  readonly actionId: string;
  markAuthorized(): void;
  markExecutionStarted(): void;
  markForwarding(): void;
  markApprovalRequested(request: ApprovalRequestView): void;
  markApprovalResolved(approvalId: string, outcome: ApprovalOutcome): void;
  markBlocked(status: 'denied' | 'approval_unavailable' | 'approval_denied' | 'approval_expired' | 'approval_cancelled'): void;
  markCompleted(result: CallToolResult): void;
  markExecutionResult(summary: unknown, isError: boolean): void;
  finalizeGraphGenesisOutcome(summary: GraphGenesisExecutionSummary, terminalStatus: GraphGenesisTerminalStatus): void;
  markFailed(code: string): void;
  appendEvidence(eventType: string, details: unknown): void;
}

export type GraphGenesisTerminalStatus =
  | 'completed'
  | 'execution_error'
  | 'cancelled'
  | 'failed'
  | 'audit_failed'
  | 'incomplete_external_read'
  | 'outcome_unknown_after_interruption';

export type GraphGenesisExecutionSummary = Readonly<{
  metadata: Readonly<{
    externalReadStatus: 'not_started' | 'started' | 'validated' | 'incomplete';
    requestCount: number;
    uniquePackageCount: number;
    responseBytes: number;
  }>;
  process: Readonly<{
    status: 'completed' | 'failed' | 'timed_out' | 'cancelled' | 'output_overflow';
    exitCode: number | null;
    stdoutBytes: number;
    stderrBytes: number;
  }>;
  candidate?: Readonly<{
    lockDigest: string;
    candidateDigest: string;
    artifactDigest: string;
  }>;
  cleanup: Readonly<{
    status: 'not_needed' | 'complete' | 'quarantined' | 'incomplete';
    quarantineReferenceDigest?: string;
  }>;
  terminalAudit: Readonly<{ status: 'complete' | 'failed' | 'unknown' }>;
  errorCode?: string;
}>;

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
      actionId: '00000000-0000-4000-8000-000000000000',
      markAuthorized() {},
      markExecutionStarted() {},
      markForwarding() {},
      markApprovalRequested() {},
      markApprovalResolved() {},
      markBlocked() {},
      markCompleted() {},
      markExecutionResult() {},
      finalizeGraphGenesisOutcome() {},
      markFailed() {},
      appendEvidence() {},
    };
  }
}

export class SqliteAuditRecorder implements AuditRecorder {
  constructor(
    private readonly database: AuditDatabase,
    private readonly now: () => Date = () => new Date(),
    private readonly transactionMode: 'deferred' | 'immediate' = 'deferred',
  ) {}

  private transaction<T>(operation: () => T): () => T {
    const transaction = this.database.transaction(operation);
    return this.transactionMode === 'immediate'
      ? () => transaction.immediate()
      : () => transaction();
  }

  begin(context: ToolCallContext, decision: AuditDecision): AuditCall {
    const id = randomUUID();
    const startedAt = this.now();
    const evaluation = normalizeEvaluation(decision);
    const receiptContext = trustedReceiptContext(context, decision.receipt);
    const redactedArguments = redactForAudit(context.arguments);
    const insert = this.transaction(() => {
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
      actionId: id,
      markAuthorized: () => {
        if (receiptContext.boundary !== 'graph_genesis_plan') {
          throw new Error('Separate authorization is reserved for Graph Genesis');
        }
        if (terminal || authorization !== undefined) throw new Error('Authorization is already finalized');
        if (approval.required && approval.outcome !== 'approved') throw new Error('Required approval is not approved');
        const timestamp = this.now().toISOString();
        const nextAuthorization = buildAuthorization('authorized', 'approval_approved', timestamp);
        this.transaction(() => {
          this.updateStatus(id, 'authorized');
          this.appendEvent(id, 'authorization_receipt_finalized', {
            receipt: nextAuthorization.receipt,
            receiptDigest: nextAuthorization.digest,
          });
          this.appendEvent(id, 'graph_genesis_authorization_ready', {
            executionPlanHash: receiptContext.executionPlanHash,
          });
        })();
        authorization = nextAuthorization;
      },
      markExecutionStarted: () => {
        if (receiptContext.boundary !== 'graph_genesis_plan') {
          throw new Error('Separate execution start is reserved for Graph Genesis');
        }
        if (terminal || dispatched || authorization === undefined) {
          throw new Error('Graph Genesis is not ready for execution start');
        }
        const timestamp = this.now().toISOString();
        this.transaction(() => {
          this.updateStatus(id, 'forwarding');
          this.appendEvent(id, 'execution_start_recorded', {
            receiptDigest: authorization!.digest,
          });
        })();
        executionStartedAt = timestamp;
        dispatched = true;
      },
      markForwarding: () => {
        if (receiptContext.boundary === 'graph_genesis_plan') {
          throw new Error('Graph Genesis requires separate authorization and execution-start records');
        }
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
        this.transaction(() => {
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
        this.transaction(() => {
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
        this.transaction(() => {
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
        this.transaction(() => {
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
        this.transaction(() => {
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
        if (receiptContext.boundary === 'graph_genesis_plan') {
          throw new Error('Graph Genesis requires the closed terminal API');
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
          observedResult: summarizeExecutionReceiptResult(receiptContext, summary, isError),
        });
        this.transaction(() => {
          this.finish(id, isError ? 'execution_error' : 'completed', startedAt, completedAt, redactedSummary, undefined);
          if (receiptContext.boundary === 'graph_genesis_plan') {
            this.appendEvent(id, isError ? 'graph_genesis_incomplete' : 'graph_genesis_complete', {
              executionPlanHash: receiptContext.executionPlanHash,
              outcomeReceiptDigest: receiptDigest(outcome),
            });
          }
          this.appendEvent(id, 'execution_completed', redactedSummary);
          this.appendEvent(id, 'outcome_receipt_finalized', {
            receipt: outcome,
            receiptDigest: receiptDigest(outcome),
          });
        })();
        terminal = true;
      },
      finalizeGraphGenesisOutcome: (summary, terminalStatus) => {
        if (terminal) throw new Error('Audit call is already terminal');
        if (receiptContext.boundary !== 'graph_genesis_plan') {
          throw new Error('Graph Genesis terminal API requires the Graph Genesis boundary');
        }
        if (!dispatched || authorization === undefined || executionStartedAt === undefined) {
          throw new Error('Execution was not durably authorized');
        }
        assertGraphGenesisExecutionSummary(summary, terminalStatus);
        const completedAt = this.now();
        const redactedSummary = redactForAudit(summary);
        const isError = terminalStatus !== 'completed';
        const observedResult = summarizeExecutionReceiptResult(receiptContext, summary, isError);
        const outcome = createOutcomeReceipt({
          issuedAt: completedAt.toISOString(),
          authorization: authorization.receipt,
          authorizationReceiptDigest: authorization.digest,
          startedAt: executionStartedAt,
          terminalStatus,
          completedAt: completedAt.toISOString(),
          observedResult,
        });
        this.transaction(() => {
          this.finish(id, terminalStatus, startedAt, completedAt, redactedSummary, summary.errorCode);
          this.appendEvent(id, terminalStatus === 'completed' ? 'graph_genesis_complete' : 'graph_genesis_incomplete', {
            executionPlanHash: receiptContext.executionPlanHash,
            terminalStatus,
            outcomeReceiptDigest: receiptDigest(outcome),
          });
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
        this.transaction(() => {
          this.finish(id, 'failed', startedAt, completedAt, undefined, code);
          if (receiptContext.boundary === 'graph_genesis_plan') {
            this.appendEvent(id, 'graph_genesis_incomplete', {
              executionPlanHash: receiptContext.executionPlanHash,
              code,
            });
          }
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
      appendEvidence: (eventType, details) => {
        if (terminal) throw new Error('Audit call is already terminal');
        if (!/^graph_genesis_[a-z0-9_]{1,64}$/u.test(eventType)) {
          throw new Error('Graph Genesis evidence event type is invalid');
        }
        const safeDetails = redactForAudit(details);
        if (Buffer.byteLength(canonicalJson(safeDetails), 'utf8') > 65_536) {
          throw new Error('Graph Genesis evidence event exceeds the size limit');
        }
        this.transaction(() => this.appendEvent(id, eventType, safeDetails))();
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

function summarizeExecutionReceiptResult(
  context: ReceiptContext,
  summary: unknown,
  isError: boolean,
): ObservedReceiptResult {
  if (context.boundary !== 'graph_genesis_plan') return summarizeInstallReceiptResult(summary, isError);
  const record = asRecord(summary);
  const process = asRecord(record?.process);
  const metadata = asRecord(record?.metadata);
  const candidate = asRecord(record?.candidate);
  const cleanup = asRecord(record?.cleanup);
  const terminalAudit = asRecord(record?.terminalAudit);
  const externalReadStatus = isGraphExternalReadStatus(metadata?.externalReadStatus)
    ? metadata.externalReadStatus : undefined;
  const executionStatus = isExecutionStatus(process?.status) ? process.status : undefined;
  const cleanupStatus = isGraphCleanupStatus(cleanup?.status) ? cleanup.status : undefined;
  const terminalAuditStatus = isGraphTerminalAuditStatus(terminalAudit?.status) ? terminalAudit.status : undefined;
  return {
    kind: 'graph_genesis',
    isError,
    ...(externalReadStatus === undefined ? {} : { externalReadStatus }),
    ...(boundedNonNegativeInteger(metadata?.requestCount, 512) === undefined ? {} : { metadataRequestCount: metadata?.requestCount as number }),
    ...(boundedNonNegativeInteger(metadata?.uniquePackageCount, 256) === undefined ? {} : { metadataUniquePackageCount: metadata?.uniquePackageCount as number }),
    ...(boundedNonNegativeInteger(metadata?.responseBytes, 134_217_728) === undefined ? {} : { metadataResponseBytes: metadata?.responseBytes as number }),
    ...(executionStatus === undefined ? {} : { executionStatus }),
    ...(typeof process?.exitCode !== 'number' && process?.exitCode !== null ? {} : { exitCode: process.exitCode as number | null }),
    ...(boundedNonNegativeInteger(process?.stdoutBytes, Number.MAX_SAFE_INTEGER) === undefined ? {} : { stdoutBytes: process?.stdoutBytes as number }),
    ...(boundedNonNegativeInteger(process?.stderrBytes, Number.MAX_SAFE_INTEGER) === undefined ? {} : { stderrBytes: process?.stderrBytes as number }),
    ...(isReceiptDigest(candidate?.lockDigest) ? { lockDigest: candidate.lockDigest } : {}),
    ...(isReceiptDigest(candidate?.candidateDigest) ? { candidateDigest: candidate.candidateDigest } : {}),
    ...(isReceiptDigest(candidate?.artifactDigest) ? { candidateArtifactDigest: candidate.artifactDigest } : {}),
    ...(cleanupStatus === undefined ? {} : { cleanupStatus }),
    ...(isReceiptDigest(cleanup?.quarantineReferenceDigest) ? { quarantineReferenceDigest: cleanup.quarantineReferenceDigest } : {}),
    ...(terminalAuditStatus === undefined ? {} : { terminalAuditStatus }),
    ...(typeof record?.errorCode === 'string' ? { errorCode: safeReasonCode(record.errorCode) } : {}),
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
  if (context.boundary === 'graph_genesis_plan') return 'graph_genesis';
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

function isExecutionStatus(value: unknown): value is 'completed' | 'failed' | 'timed_out' | 'cancelled' | 'output_overflow' {
  return value === 'completed' || value === 'failed' || value === 'timed_out'
    || value === 'cancelled' || value === 'output_overflow';
}

function assertGraphGenesisExecutionSummary(
  summary: GraphGenesisExecutionSummary,
  terminalStatus: GraphGenesisTerminalStatus,
): void {
  const observed = summarizeExecutionReceiptResult({ boundary: 'graph_genesis_plan' } as ReceiptContext, summary, terminalStatus !== 'completed');
  if (observed.kind !== 'graph_genesis'
    || observed.externalReadStatus === undefined
    || observed.executionStatus === undefined
    || observed.cleanupStatus === undefined
    || observed.terminalAuditStatus === undefined
    || observed.metadataRequestCount === undefined
    || observed.metadataUniquePackageCount === undefined
    || observed.metadataResponseBytes === undefined
    || observed.stdoutBytes === undefined
    || observed.stderrBytes === undefined) {
    throw new Error('Graph Genesis terminal summary is incomplete or out of bounds');
  }
  if (terminalStatus === 'completed' && (
    observed.externalReadStatus !== 'validated'
    || observed.executionStatus !== 'completed'
    || observed.exitCode !== 0
    || observed.lockDigest === undefined
    || observed.candidateDigest === undefined
    || observed.candidateArtifactDigest === undefined
    || observed.cleanupStatus !== 'complete'
    || observed.terminalAuditStatus !== 'complete'
  )) throw new Error('Graph Genesis success summary is not complete');
  if (terminalStatus === 'incomplete_external_read'
    && observed.externalReadStatus !== 'started' && observed.externalReadStatus !== 'incomplete') {
    throw new Error('Incomplete external read status lacks external-read evidence');
  }
}

function isVerificationStatus(value: unknown): value is 'verified' | 'failed' | 'limited' {
  return value === 'verified' || value === 'failed' || value === 'limited';
}

function isKnownInstallFile(value: unknown): value is 'package.json' | 'package-lock.json' | 'npm-shrinkwrap.json' {
  return value === 'package.json' || value === 'package-lock.json' || value === 'npm-shrinkwrap.json';
}

function isGraphExternalReadStatus(value: unknown): value is 'not_started' | 'started' | 'validated' | 'incomplete' {
  return value === 'not_started' || value === 'started' || value === 'validated' || value === 'incomplete';
}

function isGraphCleanupStatus(value: unknown): value is 'not_needed' | 'complete' | 'quarantined' | 'incomplete' {
  return value === 'not_needed' || value === 'complete' || value === 'quarantined' || value === 'incomplete';
}

function isGraphTerminalAuditStatus(value: unknown): value is 'complete' | 'failed' | 'unknown' {
  return value === 'complete' || value === 'failed' || value === 'unknown';
}

function isReceiptDigest(value: unknown): value is string {
  return typeof value === 'string' && /^sha256:[a-f0-9]{64}$/u.test(value);
}

function terminalStatusForFailure(
  code: string,
): 'upstream_error' | 'cancelled' | 'failed' | 'audit_failed' | 'incomplete_external_read' {
  if (code === 'upstream_error') return 'upstream_error';
  if (code === 'cancelled') return 'cancelled';
  if (code.includes('audit_completion_failed')) return 'audit_failed';
  if (code === 'incomplete_external_read') return 'incomplete_external_read';
  return 'failed';
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}
