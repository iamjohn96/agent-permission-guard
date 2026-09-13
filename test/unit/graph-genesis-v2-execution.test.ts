import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { SyntheticGraphGenesisV2ExecutionAuthority } from '../../src/stage/graph-genesis-v2-execution.js';

const INVALID = 'graph_genesis_v2_execution_invalid';
const digest = (value: string) => createHash('sha256').update(value).digest('hex');
const binding = Object.freeze({
  actionId: '11111111-1111-4111-8111-111111111111',
  approvalId: '22222222-2222-4222-8222-222222222222',
  planHash: digest('plan'), executionEnvelopeHash: digest('envelope'), listenerProfileDigest: digest('profile'),
  routeDigest: digest('route'), capsuleDigest: digest('capsule'),
});

function reserved() {
  const execution = new SyntheticGraphGenesisV2ExecutionAuthority();
  const listener = execution.prepareListener(binding, 43121);
  return { execution, listener, run: execution.reserve(binding, listener, 1, 10, 100) };
}
function spawned() {
  const value = reserved();
  value.execution.markExecutionStarted(value.run, 2);
  value.execution.recordBrokerIntent(value.run, 3);
  value.execution.commitBrokerArm(value.run, 4);
  value.execution.recordSpawnAttempt(value.run, 5);
  return value;
}

describe('V2 synthetic execution mechanics', () => {
  it('requires start recording before fake effects and emits only synthetic quiescence', () => {
    const { execution, listener, run } = reserved();
    expect(() => execution.recordBrokerIntent(run, 2)).toThrow(INVALID);
    execution.markExecutionStarted(run, 2);
    execution.recordBrokerIntent(run, 3);
    execution.commitBrokerArm(run, 4);
    execution.recordSpawnAttempt(run, 5);
    const request = execution.reserveTransport(run, 0, 6);
    execution.completeTransport(run, request, 8, 7);
    execution.observeChildClose(run, 8, 0);
    execution.observeListenerQuiesced(run, listener, 9);
    const quiesced = execution.quiesce(run, 10);
    expect(quiesced).toMatchObject({ evidenceOrigin: 'synthetic_fixture', childCloseObserved: true, exitCode: 0 });
    expect(quiesced.listenerIdentityDigest).toBe(listener.listenerIdentityDigest);
    expect(Object.keys(quiesced)).not.toContain('port');
  });

  it.each([10, 11])('rejects start at or after startBy (%s) before every broker/spawn effect', (now) => {
    const { execution, run } = reserved();
    expect(() => execution.markExecutionStarted(run, now)).toThrow(INVALID);
    expect(() => execution.recordBrokerIntent(run, now + 1)).toThrow(INVALID);
    expect(() => execution.recordSpawnAttempt(run, now + 2)).toThrow(INVALID);
  });

  it('rejects deadline equality, backwards time, and NaN without advancing the state', () => {
    const { execution, run } = reserved();
    expect(() => execution.markExecutionStarted(run, Number.NaN)).toThrow(INVALID);
    execution.markExecutionStarted(run, 2);
    expect(() => execution.recordBrokerIntent(run, 1)).toThrow(INVALID);
    expect(() => execution.recordBrokerIntent(run, Number.NaN)).toThrow(INVALID);
    execution.recordBrokerIntent(run, 3);
    expect(() => execution.commitBrokerArm(run, 100)).toThrow(INVALID);
    execution.commitBrokerArm(run, 4);
  });

  it('snapshots an exact closed binding and consumes its listener once', () => {
    const execution = new SyntheticGraphGenesisV2ExecutionAuthority();
    const mutable = { ...binding };
    const listener = execution.prepareListener(mutable, 43121);
    mutable.planHash = digest('changed');
    const run = execution.reserve(binding, listener, 1, 10, 100);
    expect(() => execution.reserve(binding, listener, 2, 10, 100)).toThrow(INVALID);
    expect(() => execution.closeListener(listener)).toThrow(INVALID);
    expect(run).toMatchObject({ runVersion: 2 });
  });

  it('rejects accessor/extra binding keys and foreign or copied opaque values', () => {
    const execution = new SyntheticGraphGenesisV2ExecutionAuthority();
    const accessor = Object.defineProperty({ ...binding }, 'planHash', { enumerable: true, get: () => binding.planHash });
    expect(() => execution.prepareListener(accessor, 43121)).toThrow(INVALID);
    expect(() => execution.prepareListener({ ...binding, extra: true } as unknown as typeof binding, 43121)).toThrow(INVALID);
    const listener = execution.prepareListener(binding, 43121);
    expect(() => new SyntheticGraphGenesisV2ExecutionAuthority().reserve(binding, listener, 1, 10, 100)).toThrow(INVALID);
    expect(() => execution.reserve(binding, { ...listener }, 1, 10, 100)).toThrow(INVALID);
    const run = execution.reserve(binding, listener, 1, 10, 100);
    expect(() => execution.markExecutionStarted({ ...run }, 2)).toThrow(INVALID);
  });

  it('requires spawned admission for transports, closes admission at listener drain, and rejects active unknown terminal', () => {
    const { execution, listener, run } = reserved();
    execution.markExecutionStarted(run, 2);
    execution.recordBrokerIntent(run, 3);
    execution.commitBrokerArm(run, 4);
    expect(() => execution.reserveTransport(run, 0, 5)).toThrow(INVALID);
    execution.recordSpawnAttempt(run, 5);
    const active = execution.reserveTransport(run, 0, 6);
    expect(() => execution.unknownTerminal(run, 7)).toThrow(INVALID);
    execution.completeTransport(run, active, 8, 7);
    execution.observeListenerQuiesced(run, listener, 8);
    expect(() => execution.reserveTransport(run, 1, 9)).toThrow(INVALID);
    expect(() => execution.unknownTerminal(run, 9)).not.toThrow();
  });

  it('rejects duplicate close/quiesce/terminal and nonzero exit never becomes success', () => {
    const complete = spawned();
    complete.execution.observeChildClose(complete.run, 6, 0);
    complete.execution.observeListenerQuiesced(complete.run, complete.listener, 7);
    complete.execution.quiesce(complete.run, 8);
    expect(() => complete.execution.observeListenerQuiesced(complete.run, complete.listener, 9)).toThrow(INVALID);
    expect(() => complete.execution.quiesce(complete.run, 9)).toThrow(INVALID);
    const nonzero = spawned();
    expect(() => nonzero.execution.observeChildClose(nonzero.run, 6, 1)).toThrow(INVALID);
    nonzero.execution.observeListenerQuiesced(nonzero.run, nonzero.listener, 7);
    expect(() => nonzero.execution.quiesce(nonzero.run, 8)).toThrow(INVALID);
    expect(nonzero.execution.unknownTerminal(nonzero.run, 8)).toMatchObject({ exitCode: null, childCloseObserved: false });
  });

  it('bounds four spawned fake transports, preserves same-tick completions, and rejects a fifth without queueing', () => {
    const { execution, listener, run } = spawned();
    const requests = [0, 1, 2, 3].map((ordinal) => execution.reserveTransport(run, ordinal, 6));
    expect(() => execution.reserveTransport(run, 4, 6)).toThrow(INVALID);
    for (const request of requests) execution.completeTransport(run, request, 8, 8);
    execution.observeChildClose(run, 9, 0);
    execution.observeListenerQuiesced(run, listener, 10);
    expect(execution.quiesce(run, 11)).toMatchObject({ requestCount: 4, responseBytes: 32, activeTransports: 0 });
  });
});
