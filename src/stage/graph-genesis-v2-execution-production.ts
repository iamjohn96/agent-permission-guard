/**
 * The production V2 execution seam intentionally exports no callable ledger,
 * constructor, clock, binding, or phase transition API. The only concrete
 * implementation is lexically owned by ProductionGraphGenesisV2SessionAuthority
 * in graph-genesis-v2-production.ts. This type-only boundary prevents a future
 * adapter from accidentally turning mocked observations into a capability.
 */
export type DormantV2MockedTerminalProof = Readonly<{
  evidenceOrigin: 'synthetic_fixture';
  terminalStatus: 'incomplete_external_read';
  actionId: string;
  artifactDigest: string;
}>;

export type DormantV2ConcreteTerminalProof = Readonly<{
  terminalStatus: 'execution_error' | 'outcome_unknown_after_interruption';
  actionId: string;
  childAttempted: boolean;
  childCreated: boolean;
  childCloseObserved: boolean;
  exitCode: number | null;
  stdoutBytes: number;
  stderrBytes: number;
  listenerClosed: boolean;
  reconciliation: 'proven' | 'unknown';
}>;

export type DormantV2MockedExecution = Readonly<{
  execute(): Promise<DormantV2MockedTerminalProof>;
}>;

export type DormantV2ConcreteExecution = Readonly<{
  execute(): Promise<DormantV2ConcreteTerminalProof>;
}>;
