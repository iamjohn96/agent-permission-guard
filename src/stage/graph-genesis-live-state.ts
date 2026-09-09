import { PackageStageError } from './profile.js';

export const GRAPH_GENESIS_LIVE_PHASES = Object.freeze([
  'INPUT_VALIDATED',
  'LOCAL_RESOURCES_CREATED',
  'RUNTIME_SNAPSHOTTED',
  'CONTAINMENT_PROBED',
  'PLAN_READY',
  'AUDIT_SESSION_READY',
  'APPROVAL_PENDING',
  'AUTHORIZED',
  'BROKER_ARMED',
  'NPM_RUNNING',
  'LISTENER_DRAINING',
  'BROKER_FINALIZED',
  'POST_STATE_VALIDATED',
  'CANDIDATE_COMPILED',
  'OUTPUT_DURABLE',
  'WORKSPACE_CLEANED',
  'TERMINAL_COMMITTED',
  'COMPLETE',
] as const);

export type GraphGenesisLivePhase = typeof GRAPH_GENESIS_LIVE_PHASES[number];

export class GraphGenesisLivePhaseAuthority {
  #index = -1;
  #terminal = false;

  advance(phase: GraphGenesisLivePhase): void {
    if (this.#terminal || GRAPH_GENESIS_LIVE_PHASES[this.#index + 1] !== phase) fail();
    this.#index += 1;
    if (phase === 'COMPLETE') this.#terminal = true;
  }

  fail(): void { this.#terminal = true; }

  get current(): GraphGenesisLivePhase | 'NOT_STARTED' {
    return this.#index < 0 ? 'NOT_STARTED' : GRAPH_GENESIS_LIVE_PHASES[this.#index]!;
  }

  get complete(): boolean { return this.#terminal && this.current === 'COMPLETE'; }
}

export interface SyntheticGraphGenesisFullFlowAdapter {
  readonly implementationKind: 'synthetic';
  perform(phase: GraphGenesisLivePhase, signal: AbortSignal): void | Promise<void>;
}

/** Test-only full-flow twin. It owns the same closed phase order but no production capability. */
export class SyntheticGraphGenesisFullFlowTwin {
  #used = false;

  constructor(private readonly adapter: SyntheticGraphGenesisFullFlowAdapter) {
    if (adapter.implementationKind !== 'synthetic') fail();
  }

  async run(signal: AbortSignal = new AbortController().signal): Promise<Readonly<{
    status: 'synthetic_complete';
    phases: readonly GraphGenesisLivePhase[];
  }>> {
    if (this.#used || signal.aborted) fail();
    this.#used = true;
    const authority = new GraphGenesisLivePhaseAuthority();
    const observed: GraphGenesisLivePhase[] = [];
    try {
      for (const phase of GRAPH_GENESIS_LIVE_PHASES) {
        if (signal.aborted) fail();
        await this.adapter.perform(phase, signal);
        if (signal.aborted) fail();
        authority.advance(phase);
        observed.push(phase);
      }
      if (!authority.complete) fail();
      return Object.freeze({ status: 'synthetic_complete' as const, phases: Object.freeze(observed) });
    } catch (error) {
      authority.fail();
      if (error instanceof PackageStageError) throw error;
      fail();
    }
  }
}

function fail(): never { throw new PackageStageError('acceptance_incomplete'); }
