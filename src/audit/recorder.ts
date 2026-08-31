import { createHash, randomUUID } from 'node:crypto';

import type { CallToolResult } from '@modelcontextprotocol/server';

import type { ToolCallContext } from '../gateway/call-interceptor.js';
import type { ApprovalOutcome, ApprovalRequestView } from '../approval/types.js';
import type { Decision } from '../policy/schema.js';
import type { RiskBand } from '../risk/types.js';
import type { AuditDatabase } from '../db/database.js';
import { canonicalJson } from './canonical-json.js';
import { redactForAudit } from './redaction.js';

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
      });
    });
    insert();

    let terminal = false;
    return {
      markForwarding: () => {
        if (terminal) throw new Error('Audit call is already terminal');
        this.database.transaction(() => {
          this.updateStatus(id, 'forwarding');
          this.appendEvent(id, 'execution_forwarded', {});
        })();
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
      },
      markApprovalResolved: (approvalId, outcome) => {
        if (terminal) throw new Error('Audit call is already terminal');
        this.database.transaction(() => {
          const result = this.database.prepare(`
            UPDATE approvals
            SET status = ?, decided_at = ?
            WHERE id = ? AND tool_call_id = ? AND status = 'pending'
          `).run(outcome, this.now().toISOString(), approvalId, id);
          if (result.changes !== 1) throw new Error('Approval is not pending');
          this.updateStatus(id, `approval_${outcome}`);
          this.appendEvent(id, `approval_${outcome}`, { approvalId });
        })();
      },
      markBlocked: (status) => {
        if (terminal) throw new Error('Audit call is already terminal');
        this.database.transaction(() => {
          this.finish(id, status, startedAt, undefined, undefined);
          this.appendEvent(id, status, {});
        })();
        terminal = true;
      },
      markCompleted: (result) => {
        if (terminal) throw new Error('Audit call is already terminal');
        const summary = summarizeResult(result);
        this.database.transaction(() => {
          this.finish(id, result.isError === true ? 'upstream_error' : 'completed', startedAt, summary, undefined);
          this.appendEvent(id, 'execution_completed', summary);
        })();
        terminal = true;
      },
      markExecutionResult: (summary, isError) => {
        if (terminal) throw new Error('Audit call is already terminal');
        const redactedSummary = redactForAudit(summary);
        this.database.transaction(() => {
          this.finish(id, isError ? 'execution_error' : 'completed', startedAt, redactedSummary, undefined);
          this.appendEvent(id, 'execution_completed', redactedSummary);
        })();
        terminal = true;
      },
      markFailed: (code) => {
        if (terminal) return;
        this.database.transaction(() => {
          this.finish(id, 'failed', startedAt, undefined, code);
          this.appendEvent(id, 'execution_failed', { code });
        })();
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
    resultSummary: unknown,
    errorCode: string | undefined,
  ): void {
    const completedAt = this.now();
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
    const eventJson = canonicalJson(redactForAudit({
      eventId: randomUUID(),
      toolCallId,
      eventType,
      details,
      createdAt: this.now().toISOString(),
    }));
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
  return redactForAudit({
    isError: result.isError === true,
    contentTypes: result.content.map((item) => item.type),
    contentCount: result.content.length,
    structuredContent: result.structuredContent,
  });
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}
