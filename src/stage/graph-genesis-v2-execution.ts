import { createHash } from 'node:crypto';

/** Fixture-only data mechanics: no socket, child, network, filesystem, audit, or production authority. */

const SHA256 = /^[a-f0-9]{64}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const MAX_ACTIVE_TRANSPORTS = 4;
const BINDING_KEYS = [
  'actionId', 'approvalId', 'planHash', 'executionEnvelopeHash', 'listenerProfileDigest', 'routeDigest', 'capsuleDigest',
] as const;

export type SyntheticGraphGenesisV2ExecutionBinding = Readonly<{
  actionId: string;
  approvalId: string;
  planHash: string;
  executionEnvelopeHash: string;
  listenerProfileDigest: string;
  routeDigest: string;
  capsuleDigest: string;
}>;
export type SyntheticGraphGenesisV2Listener = Readonly<{ listenerVersion: 2; listenerIdentityDigest: string }>;
export type SyntheticGraphGenesisV2Run = Readonly<{ runVersion: 2 }>;
export type SyntheticGraphGenesisV2Transport = Readonly<{ transportVersion: 2 }>;
export type SyntheticGraphGenesisV2Quiescence = Readonly<{
  evidenceOrigin: 'synthetic_fixture'; listenerIdentityDigest: string; childCloseObserved: true; exitCode: 0;
  requestCount: number; responseBytes: number; activeTransports: 0;
}>;
export type SyntheticGraphGenesisV2UnknownTerminal = Readonly<{
  evidenceOrigin: 'synthetic_fixture'; terminalStatus: 'outcome_unknown_after_interruption'; childCloseObserved: false; exitCode: null;
}>;

type ListenerState = 'prepared' | 'consumed' | 'closed';
type RunPhase = 'reserved' | 'started' | 'intent-recorded' | 'armed' | 'running' | 'drained' | 'child-closed-open' | 'child-closed' | 'terminal';
type OwnedListener = Readonly<{
  publicListener: SyntheticGraphGenesisV2Listener;
  binding: SyntheticGraphGenesisV2ExecutionBinding;
  allowedPort: number;
  state: ListenerState;
}>;
type OwnedTransport = Readonly<{ ordinal: number; completed: boolean }>;
type OwnedRun = {
  readonly publicRun: SyntheticGraphGenesisV2Run;
  readonly binding: SyntheticGraphGenesisV2ExecutionBinding;
  readonly listener: SyntheticGraphGenesisV2Listener;
  readonly startBy: number;
  readonly deadline: number;
  lastNow: number;
  phase: RunPhase;
  nextOrdinal: number;
  responseBytes: number;
  readonly transports: WeakMap<object, OwnedTransport>;
  activeTransports: number;
};

/** Opaque-token ordering model only. Its values cannot start I/O or prove production completion. */
export class SyntheticGraphGenesisV2ExecutionAuthority {
  readonly #listeners = new WeakMap<object, OwnedListener>();
  readonly #runs = new WeakMap<object, OwnedRun>();

  prepareListener(binding: SyntheticGraphGenesisV2ExecutionBinding, allowedPort: number): SyntheticGraphGenesisV2Listener {
    const ownedBinding = snapshotBinding(binding);
    if (!Number.isSafeInteger(allowedPort) || allowedPort < 1 || allowedPort > 65_535) fail();
    const publicListener = Object.freeze({ listenerVersion: 2 as const, listenerIdentityDigest: listenerDigest(ownedBinding, allowedPort) });
    this.#listeners.set(publicListener, Object.freeze({ publicListener, binding: ownedBinding, allowedPort, state: 'prepared' }));
    return publicListener;
  }

  closeListener(listener: SyntheticGraphGenesisV2Listener): void {
    const owned = this.#listeners.get(listener);
    if (owned === undefined || owned.state !== 'prepared') fail();
    this.#listeners.set(listener, Object.freeze({ ...owned, state: 'closed' }));
  }

  reserve(binding: SyntheticGraphGenesisV2ExecutionBinding, listener: SyntheticGraphGenesisV2Listener,
    now: number, startBy: number, deadline: number): SyntheticGraphGenesisV2Run {
    const input = snapshotBinding(binding);
    const ownedListener = this.#listeners.get(listener);
    if (ownedListener === undefined || ownedListener.state !== 'prepared' || !sameBinding(ownedListener.binding, input)
      || !validTime(now) || !validTime(startBy) || !validTime(deadline) || now >= startBy || startBy >= deadline) fail();
    // Consume synchronously before a public run exists: no replay, fallback, or second reservation.
    this.#listeners.set(listener, Object.freeze({ ...ownedListener, state: 'consumed' }));
    const publicRun = Object.freeze({ runVersion: 2 as const });
    this.#runs.set(publicRun, {
      publicRun, binding: input, listener, startBy, deadline, lastNow: now, phase: 'reserved', nextOrdinal: 0,
      responseBytes: 0, transports: new WeakMap(), activeTransports: 0,
    });
    return publicRun;
  }

  markExecutionStarted(run: SyntheticGraphGenesisV2Run, now: number): void {
    const owned = this.#run(run, now);
    if (owned.phase !== 'reserved' || now >= owned.startBy) fail();
    owned.phase = 'started';
  }
  recordBrokerIntent(run: SyntheticGraphGenesisV2Run, now: number): void {
    const owned = this.#run(run, now);
    if (owned.phase !== 'started') fail();
    owned.phase = 'intent-recorded';
  }
  commitBrokerArm(run: SyntheticGraphGenesisV2Run, now: number): void {
    const owned = this.#run(run, now);
    if (owned.phase !== 'intent-recorded') fail();
    owned.phase = 'armed';
  }
  recordSpawnAttempt(run: SyntheticGraphGenesisV2Run, now: number): void {
    const owned = this.#run(run, now);
    if (owned.phase !== 'armed') fail();
    owned.phase = 'running';
  }

  reserveTransport(run: SyntheticGraphGenesisV2Run, ordinal: number, now: number): SyntheticGraphGenesisV2Transport {
    const owned = this.#run(run, now);
    if (owned.phase !== 'running' || !Number.isSafeInteger(ordinal) || ordinal !== owned.nextOrdinal
      || owned.activeTransports >= MAX_ACTIVE_TRANSPORTS) fail();
    const transport = Object.freeze({ transportVersion: 2 as const });
    owned.transports.set(transport, Object.freeze({ ordinal, completed: false }));
    owned.nextOrdinal += 1;
    owned.activeTransports += 1;
    return transport;
  }

  completeTransport(run: SyntheticGraphGenesisV2Run, transport: SyntheticGraphGenesisV2Transport,
    responseBytes: number, now: number): void {
    const owned = this.#run(run, now);
    const item = owned.transports.get(transport);
    if (owned.phase !== 'running' || item === undefined || item.completed || !Number.isSafeInteger(responseBytes) || responseBytes < 0
      || owned.responseBytes > Number.MAX_SAFE_INTEGER - responseBytes) fail();
    owned.transports.set(transport, Object.freeze({ ...item, completed: true }));
    owned.activeTransports -= 1;
    owned.responseBytes += responseBytes;
  }

  observeChildClose(run: SyntheticGraphGenesisV2Run, now: number, exitCode: number): void {
    const owned = this.#run(run, now);
    if ((owned.phase !== 'running' && owned.phase !== 'drained') || owned.activeTransports !== 0 || exitCode !== 0) fail();
    owned.phase = owned.phase === 'drained' ? 'child-closed' : 'child-closed-open';
  }
  observeListenerQuiesced(run: SyntheticGraphGenesisV2Run, listener: SyntheticGraphGenesisV2Listener, now: number): void {
    const owned = this.#run(run, now);
    const ownedListener = this.#listeners.get(listener);
    if ((owned.phase !== 'running' && owned.phase !== 'child-closed-open') || owned.activeTransports !== 0
      || owned.listener !== listener || ownedListener === undefined || ownedListener.state !== 'consumed'
      || !sameBinding(owned.binding, ownedListener.binding)) fail();
    owned.phase = owned.phase === 'child-closed-open' ? 'child-closed' : 'drained';
  }
  quiesce(run: SyntheticGraphGenesisV2Run, now: number): SyntheticGraphGenesisV2Quiescence {
    const owned = this.#run(run, now);
    if (owned.phase !== 'child-closed' || owned.activeTransports !== 0) fail();
    owned.phase = 'terminal';
    return Object.freeze({ evidenceOrigin: 'synthetic_fixture' as const, listenerIdentityDigest: owned.listener.listenerIdentityDigest,
      childCloseObserved: true as const, exitCode: 0 as const, requestCount: owned.nextOrdinal,
      responseBytes: owned.responseBytes, activeTransports: 0 as const });
  }
  unknownTerminal(run: SyntheticGraphGenesisV2Run, now: number): SyntheticGraphGenesisV2UnknownTerminal {
    const owned = this.#run(run, now);
    if (owned.phase !== 'drained' || owned.activeTransports !== 0) fail();
    owned.phase = 'terminal';
    return Object.freeze({ evidenceOrigin: 'synthetic_fixture' as const,
      terminalStatus: 'outcome_unknown_after_interruption' as const, childCloseObserved: false as const, exitCode: null });
  }

  #run(run: SyntheticGraphGenesisV2Run, now: number): OwnedRun {
    const owned = this.#runs.get(run);
    if (owned === undefined || owned.phase === 'terminal' || !validTime(now) || now < owned.lastNow || now >= owned.deadline) fail();
    owned.lastNow = now;
    return owned;
  }
}

function snapshotBinding(value: unknown): SyntheticGraphGenesisV2ExecutionBinding {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) fail();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== 'string') || JSON.stringify([...keys].sort()) !== JSON.stringify([...BINDING_KEYS].sort())) fail();
  const clone = {} as Record<(typeof BINDING_KEYS)[number], string>;
  for (const key of BINDING_KEYS) {
    const descriptor = descriptors[key];
    if (descriptor === undefined || !descriptor.enumerable || !('value' in descriptor) || typeof descriptor.value !== 'string') fail();
    clone[key] = descriptor.value;
  }
  if (!UUID.test(clone.actionId) || !UUID.test(clone.approvalId)
    || !SHA256.test(clone.planHash) || !SHA256.test(clone.executionEnvelopeHash) || !SHA256.test(clone.listenerProfileDigest)
    || !SHA256.test(clone.routeDigest) || !SHA256.test(clone.capsuleDigest)) fail();
  return Object.freeze(clone) as SyntheticGraphGenesisV2ExecutionBinding;
}
function sameBinding(left: SyntheticGraphGenesisV2ExecutionBinding, right: SyntheticGraphGenesisV2ExecutionBinding): boolean {
  return left.actionId === right.actionId && left.approvalId === right.approvalId && left.planHash === right.planHash
    && left.executionEnvelopeHash === right.executionEnvelopeHash && left.listenerProfileDigest === right.listenerProfileDigest
    && left.routeDigest === right.routeDigest && left.capsuleDigest === right.capsuleDigest;
}
function validTime(value: number): boolean { return Number.isFinite(value) && !Object.is(value, -0) && value >= 0 && value <= Number.MAX_SAFE_INTEGER; }
function listenerDigest(binding: SyntheticGraphGenesisV2ExecutionBinding, allowedPort: number): string {
  return createHash('sha256').update(JSON.stringify([
    binding.actionId, binding.approvalId, binding.planHash, binding.executionEnvelopeHash,
    binding.listenerProfileDigest, binding.routeDigest, binding.capsuleDigest, allowedPort,
  ])).digest('hex');
}
function fail(): never { throw new Error('graph_genesis_v2_execution_invalid'); }
