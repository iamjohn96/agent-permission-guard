import { randomUUID } from 'node:crypto';

import { redactForAudit } from '../audit/redaction.js';
import type {
  ApprovalCoordinator,
  ApprovalOutcome,
  ApprovalRequestView,
  ApprovalTicket,
} from './types.js';
import type { McpIdentityApprovalView } from '../identity/mcp-identity.js';

type PendingEntry = {
  request: ApprovalRequestView;
  resolve: (outcome: ApprovalOutcome) => void;
  timer: ReturnType<typeof setTimeout>;
  visible: boolean;
};

export class LocalApprovalService implements ApprovalCoordinator {
  private readonly pending = new Map<string, PendingEntry>();
  private closed = false;

  constructor(private readonly now: () => Date = () => new Date()) {}

  request(
    input: Omit<ApprovalRequestView, 'id' | 'requestedAt' | 'expiresAt'>,
    ttlMs: number,
  ): ApprovalTicket {
    const ticket = this.requestHidden(input, ttlMs);
    this.publish(ticket.request.id);
    return ticket;
  }

  /** Used by authorities that must durably record a request before Dashboard visibility. */
  requestHidden(
    input: Omit<ApprovalRequestView, 'id' | 'requestedAt' | 'expiresAt'>,
    ttlMs: number,
  ): ApprovalTicket {
    if (this.closed) throw new Error('Approval service is closed');
    if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0) throw new Error('Approval TTL must be positive');

    const id = randomUUID();
    const requestedAt = this.now();
    const request: ApprovalRequestView = Object.freeze({
      ...input,
      arguments: redactForAudit(input.arguments),
      ...(input.identity === undefined
        ? {}
        : { identity: redactForAudit(input.identity) as McpIdentityApprovalView }),
      id,
      requestedAt: requestedAt.toISOString(),
      expiresAt: new Date(requestedAt.getTime() + ttlMs).toISOString(),
    });
    let settle!: (outcome: ApprovalOutcome) => void;
    const outcome = new Promise<ApprovalOutcome>((resolve) => { settle = resolve; });
    const timer = setTimeout(() => this.settle(id, 'expired'), ttlMs);
    timer.unref();
    this.pending.set(id, { request, resolve: settle, timer, visible: false });

    return {
      request,
      outcome,
      cancel: () => { this.settle(id, 'cancelled'); },
    };
  }

  publish(id: string): void {
    const entry = this.pending.get(id);
    if (entry === undefined) throw new Error('Approval is no longer pending');
    entry.visible = true;
  }

  listPending(): readonly ApprovalRequestView[] {
    return [...this.pending.values()]
      .filter((entry) => entry.visible)
      .map((entry) => entry.request)
      .sort((left, right) => left.requestedAt < right.requestedAt ? -1 : 1);
  }

  decide(id: string, decision: 'approved' | 'denied'): ApprovalOutcome | undefined {
    const entry = this.pending.get(id);
    if (entry === undefined || !entry.visible) return undefined;
    if (Date.parse(entry.request.expiresAt) <= this.now().getTime()) {
      this.settle(id, 'expired');
      return 'expired';
    }
    this.settle(id, decision);
    return decision;
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    for (const id of [...this.pending.keys()]) this.settle(id, 'cancelled');
  }

  private settle(id: string, outcome: ApprovalOutcome): void {
    const entry = this.pending.get(id);
    if (entry === undefined) return;
    clearTimeout(entry.timer);
    this.pending.delete(id);
    entry.resolve(outcome);
  }
}
