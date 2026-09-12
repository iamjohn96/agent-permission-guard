import type { RiskBand } from '../risk/types.js';
import type { McpIdentityApprovalView } from '../identity/mcp-identity.js';
import type { GraphGenesisV2ApprovalView } from '../stage/graph-genesis-v2-production.js';

export type ApprovalOutcome = 'approved' | 'denied' | 'expired' | 'cancelled';

export type ApprovalRequestView = Readonly<{
  id: string;
  kind?: 'mcp_tool' | 'install' | 'graph_genesis';
  serverId: string;
  toolName: string;
  arguments: unknown;
  identity?: McpIdentityApprovalView;
  graphGenesis?: GraphGenesisV1ApprovalView | GraphGenesisV2ApprovalView;
  risk: Readonly<{
    score: number;
    band: RiskBand;
    signals: readonly unknown[];
  }>;
  reasonCodes: readonly string[];
  requestedAt: string;
  expiresAt: string;
}>;

export type GraphGenesisV1ApprovalView = Readonly<{
  target: '@modelcontextprotocol/server-filesystem@2026.7.10';
  registryOrigin: 'https://registry.npmjs.org/';
  executionEnvelopeHash: string;
  planHash: string;
  host: Readonly<{ platform: 'darwin'; architecture: 'arm64'; osBuild: string }>;
  runtime: Readonly<{ nodeVersion: '26.3.1'; npmVersion: '11.16.0' }>;
  auditPath: string;
  outputPath: string;
  limits: unknown;
  consequences: readonly string[];
  exclusions: readonly string[];
  bypassWarning: 'Direct npm/npx commands bypass APG and receive none of this protection or evidence.';
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
