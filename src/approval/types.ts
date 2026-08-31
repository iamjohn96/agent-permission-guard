import type { RiskBand } from '../risk/types.js';

export type ApprovalOutcome = 'approved' | 'denied' | 'expired' | 'cancelled';

export type ApprovalRequestView = Readonly<{
  id: string;
  kind?: 'mcp_tool' | 'install';
  serverId: string;
  toolName: string;
  arguments: unknown;
  risk: Readonly<{
    score: number;
    band: RiskBand;
    signals: readonly unknown[];
  }>;
  reasonCodes: readonly string[];
  requestedAt: string;
  expiresAt: string;
}>;

export type ApprovalTicket = Readonly<{
  request: ApprovalRequestView;
  outcome: Promise<ApprovalOutcome>;
  cancel(): void;
}>;

export interface ApprovalCoordinator {
  request(input: Omit<ApprovalRequestView, 'id' | 'requestedAt' | 'expiresAt'>, ttlMs: number): ApprovalTicket;
  listPending(): readonly ApprovalRequestView[];
  decide(id: string, decision: 'approved' | 'denied'): ApprovalOutcome | undefined;
  close(): void;
}
