import { createHash } from 'node:crypto';

import { canonicalJson } from '../audit/canonical-json.js';
import type { ExactGraphCandidate } from './exact-production-graph.js';
import type {
  AuthenticatedExactCleanup,
  AuthenticatedHardenedGraphGenesisTerminalAudit,
  GraphGenesisAuditGate,
  HardenedGraphGenesisPlan,
  HardenedGraphGenesisPlanAuthority,
} from './graph-genesis-hardening.js';
import type {
  AuthenticatedHardenedBrokerLedger,
  HardenedMetadataBrokerAuthority,
} from './graph-genesis-network.js';
import type {
  AuthenticatedGraphGenesisProcessResult,
  GraphGenesisProcessSupervisor,
} from './graph-genesis-supervisor.js';
import type {
  AuthenticatedHardenedGraphGenesisPostState,
  HardenedGraphGenesisCandidateCompiler,
  HardenedGraphGenesisPostStateAuthority,
} from './graph-genesis-workspace.js';
import { PackageStageError } from './profile.js';

const TARGET = '@modelcontextprotocol/server-filesystem';
const VERSION = '2026.7.10';

export type AuthenticatedHardenedGraphGenesisCompletion = Readonly<{
  completionVersion: 1;
  planHash: string;
  candidateDigest: string;
  brokerLedgerDigest: string;
  processResultDigest: string;
  cleanupDigest: string;
  postStateDigest: string;
  auditDigest: string;
  packageNames: readonly string[];
  nodeCount: number;
  edgeCount: number;
  status: 'complete';
  completionDigest: string;
}>;

/**
 * Final fail-closed join. No individual success artifact is sufficient: every
 * authority must authenticate evidence for the same exact plan.
 */
export class HardenedControlledGraphGenesisAuthority {
  readonly #authenticated = new WeakSet<object>();

  constructor(
    private readonly plans: HardenedGraphGenesisPlanAuthority,
    private readonly candidates: HardenedGraphGenesisCandidateCompiler,
    private readonly postStates: HardenedGraphGenesisPostStateAuthority,
    private readonly brokers: HardenedMetadataBrokerAuthority,
    private readonly processes: GraphGenesisProcessSupervisor,
    private readonly cleanups: { authenticates(value: unknown): value is AuthenticatedExactCleanup },
  ) {}

  async complete(input: Readonly<{
    plan: HardenedGraphGenesisPlan;
    capsule: object;
    candidate: ExactGraphCandidate;
    postState: AuthenticatedHardenedGraphGenesisPostState;
    ledger: AuthenticatedHardenedBrokerLedger;
    process: AuthenticatedGraphGenesisProcessResult;
    cleanup: AuthenticatedExactCleanup;
    auditGate: GraphGenesisAuditGate;
  }>): Promise<AuthenticatedHardenedGraphGenesisCompletion> {
    if (!this.plans.authenticatesPair(input.plan, input.capsule)
      || !this.candidates.authenticatesPair(input.candidate, input.postState)
      || !this.postStates.authenticates(input.postState)
      || !this.brokers.authenticatesLedger(input.ledger)
      || !this.processes.authenticates(input.process)
      || !this.cleanups.authenticates(input.cleanup)
      || input.auditGate.planHash !== input.plan.planHash
      || input.process.planHash !== input.plan.planHash || input.process.status !== 'completed' || input.process.exitCode !== 0
      || input.ledger.planHash !== input.plan.planHash || input.ledger.terminalState !== 'disarmed_complete'
      || input.cleanup.workspaceBinding !== input.plan.workspaceBinding
      || input.postState.planHash !== input.plan.planHash || input.postState.workspaceBinding !== input.plan.workspaceBinding
      || input.candidate.topPackage.name !== TARGET || input.candidate.topPackage.exactVersion !== VERSION
      || input.candidate.registryOrigin !== input.plan.registryOrigin
      || input.candidate.runtimeConstraint.nodeVersion !== input.plan.nodeVersion
      || input.candidate.runtimeConstraint.npmGraphGeneratorVersion !== input.plan.npmVersion) failCompletion();
    const packageNames = Object.freeze([...new Set(input.candidate.graphNodes.map((node) => node.packageName))].sort(compareText));
    const ledgerNames = [...new Set(input.ledger.entries.map((entry) => entry.packageName))].sort(compareText);
    if (canonicalJson(packageNames) !== canonicalJson(ledgerNames)) failCompletion();
    const terminalAudit: AuthenticatedHardenedGraphGenesisTerminalAudit = await input.auditGate.finalizeSuccess();
    if (!input.auditGate.authenticatesCompletion(terminalAudit) || terminalAudit.planHash !== input.plan.planHash) failCompletion();
    const unsigned = deepFreeze({
      completionVersion: 1 as const,
      planHash: input.plan.planHash,
      candidateDigest: input.candidate.candidateDigest,
      brokerLedgerDigest: input.ledger.ledgerDigest,
      processResultDigest: input.process.resultDigest,
      cleanupDigest: input.cleanup.cleanupDigest,
      postStateDigest: input.postState.evidenceDigest,
      auditDigest: terminalAudit.auditDigest,
      packageNames,
      nodeCount: input.candidate.graphNodes.length,
      edgeCount: input.candidate.graphNodes.reduce((sum, node) => sum + node.dependencyEdges.length, 0),
      status: 'complete' as const,
    });
    const completion = deepFreeze({ ...unsigned, completionDigest: sha256(canonicalJson(unsigned)) });
    this.#authenticated.add(completion);
    return completion;
  }

  authenticates(value: unknown): value is AuthenticatedHardenedGraphGenesisCompletion {
    return typeof value === 'object' && value !== null && this.#authenticated.has(value);
  }
}

function compareText(left: string, right: string): number {
  return Buffer.from(left).compare(Buffer.from(right));
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function deepFreeze<T>(input: T): T {
  if (typeof input !== 'object' || input === null || Object.isFrozen(input)) return input;
  for (const value of Object.values(input)) deepFreeze(value);
  return Object.freeze(input);
}

function failCompletion(): never { throw new PackageStageError('acceptance_incomplete'); }
