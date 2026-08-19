import type { RiskAssessment } from '../risk/types.js';

export type ApprovalOutcome = 'approved' | 'denied' | 'expired' | 'cancelled';

export type ApprovalRequestView = Readonly<{
  id: string;
  serverId: string;
  toolName: string;
  arguments: unknown;
  risk: RiskAssessment;
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
