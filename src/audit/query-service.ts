import type { AuditDatabase } from '../db/database.js';
import type { SqliteAuditRecorder } from './recorder.js';

export type AuditCallView = Readonly<{
  id: string;
  serverId: string;
  toolName: string;
  arguments: unknown;
  baseDecision: string;
  effectiveDecision: string;
  matchedRuleId?: string;
  reasonCodes: unknown;
  riskScore: number;
  riskBand: string;
  riskSignals: unknown;
  status: string;
  startedAt: string;
  completedAt?: string;
  latencyMs?: number;
  resultSummary?: unknown;
  errorCode?: string;
  approvalStatus?: string;
}>;

type AuditRow = {
  id: string;
  server_id: string;
  tool_name: string;
  arguments_json: string;
  base_decision: string;
  effective_decision: string;
  matched_rule_id: string | null;
  reason_codes_json: string;
  risk_score: number;
  risk_band: string;
  risk_signals_json: string;
  status: string;
  started_at: string;
  completed_at: string | null;
  latency_ms: number | null;
  result_summary_json: string | null;
  error_code: string | null;
  approval_status: string | null;
};

export class AuditQueryService {
  constructor(
    private readonly database: AuditDatabase,
    private readonly recorder: SqliteAuditRecorder,
  ) {}

  listRecent(limit: number): Readonly<{ calls: readonly AuditCallView[]; hashChainValid: boolean }> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
      throw new Error('Audit limit must be between 1 and 100');
    }
    const rows = this.database.prepare(`
      SELECT
        tc.*,
        approvals.status AS approval_status
      FROM tool_calls AS tc
      LEFT JOIN approvals ON approvals.tool_call_id = tc.id
      ORDER BY tc.started_at DESC, tc.id DESC
      LIMIT ?
    `).all(limit) as AuditRow[];

    return {
      calls: rows.map(toView),
      hashChainValid: this.recorder.verifyHashChain(),
    };
  }
}

function toView(row: AuditRow): AuditCallView {
  return {
    id: row.id,
    serverId: row.server_id,
    toolName: row.tool_name,
    arguments: parseStoredJson(row.arguments_json),
    baseDecision: row.base_decision,
    effectiveDecision: row.effective_decision,
    ...(row.matched_rule_id === null ? {} : { matchedRuleId: row.matched_rule_id }),
    reasonCodes: parseStoredJson(row.reason_codes_json),
    riskScore: row.risk_score,
    riskBand: row.risk_band,
    riskSignals: parseStoredJson(row.risk_signals_json),
    status: row.status,
    startedAt: row.started_at,
    ...(row.completed_at === null ? {} : { completedAt: row.completed_at }),
    ...(row.latency_ms === null ? {} : { latencyMs: row.latency_ms }),
    ...(row.result_summary_json === null ? {} : { resultSummary: parseStoredJson(row.result_summary_json) }),
    ...(row.error_code === null ? {} : { errorCode: row.error_code }),
    ...(row.approval_status === null ? {} : { approvalStatus: row.approval_status }),
  };
}

function parseStoredJson(source: string): unknown {
  return JSON.parse(source) as unknown;
}
