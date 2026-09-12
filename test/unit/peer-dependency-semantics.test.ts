import { describe, expect, it } from 'vitest';

import {
  analyzePeerDependencySemantics,
  PeerDependencySemanticsError,
  type PeerSemanticsInput,
} from '../../src/stage/peer-dependency-semantics.js';

const node = (installPath: string, packageName: string, version = '1.0.0', extra: Record<string, unknown> = {}) => ({
  installPath, packageName, version, ...extra,
});
const input = (nodes: unknown[], rootDependencies: unknown = { host: '1.0.0', plugin: '1.0.0' }): PeerSemanticsInput => ({ nodes, rootDependencies });
const valid = () => input([
  node('node_modules/host', 'host'),
  node('node_modules/plugin', 'plugin', '1.0.0', { peerDependencies: { host: '^1.0.0', missing: '^1.0.0' }, peerDependenciesMeta: { missing: { optional: true } } }),
]);
const predicate = (value: unknown): string => {
  try { analyzePeerDependencySemantics(value as PeerSemanticsInput); } catch (error) {
    expect(error).toBeInstanceOf(PeerDependencySemanticsError);
    return (error as PeerDependencySemanticsError).predicate;
  }
  throw new Error('expected rejection');
};

describe('pure peer dependency semantics', () => {
  it('accepts a required peer and records explicit optional absence without mutating input', () => {
    const fixture = valid();
    const before = JSON.stringify(fixture);
    const result = analyzePeerDependencySemantics(fixture);
    expect(result.productionPaths).toEqual(['node_modules/host', 'node_modules/plugin']);
    expect(result.requiredPaths).toEqual(['node_modules/host', 'node_modules/plugin']);
    expect(result.peerRequirements).toEqual([
      { from: 'node_modules/plugin', name: 'host', optional: false, targetPath: 'node_modules/host' },
      { from: 'node_modules/plugin', name: 'missing', optional: true },
    ]);
    expect(Object.isFrozen(result)).toBe(true);
    expect(JSON.stringify(fixture)).toBe(before);
  });

  it('rejects malformed peer maps, metadata, overlap, flags, and accessors deterministically', () => {
    expect(predicate(input([node('node_modules/a', 'a', '1.0.0', { peerDependencies: [] })], { a: '1.0.0' }))).toBe('peer_shape');
    expect(predicate(input([node('node_modules/a', 'a', '1.0.0', { peerDependencies: { x: '1.0.0' }, peerDependenciesMeta: { y: {} } })], { a: '1.0.0' }))).toBe('peer_meta');
    expect(predicate(input([node('node_modules/a', 'a', '1.0.0', { peerDependencies: { x: '1.0.0' }, peerDependenciesMeta: { x: { optional: undefined } } })], { a: '1.0.0' }))).toBe('peer_meta');
    expect(predicate(input([node('node_modules/a', 'a', '1.0.0', { dependencies: { x: '1.0.0' }, peerDependencies: { x: '1.0.0' } })], { a: '1.0.0' }))).toBe('overlap');
    expect(predicate(input([node('node_modules/a', 'a', '1.0.0', { dev: 'true' })], { a: '1.0.0' }))).toBe('role_type');
    expect(predicate(input([node('node_modules/a', 'a', '1.0.0', { optional: true })], { a: '1.0.0' }))).toBe('prohibited_role');
    expect(predicate(input([node('node_modules/a', 'a', '1.0.0', { hasInstallScript: false })], { a: '1.0.0' }))).toBe('prohibited_field');
    expect(predicate(input([node('node_modules/a', 'a', '1.0.0', { unexpected: false })], { a: '1.0.0' }))).toBe('shape');
    expect(predicate(input([node('node_modules/a', 'other')], { a: '1.0.0' }))).toBe('shape');
    expect(predicate(input([node('node_modules/a/node_modules/b', 'b')], { a: '1.0.0' }))).toBe('shape');
    expect(predicate(input([node('node_modules/a', 'a')], { '@bad': '1.0.0' }))).toBe('shape');
    const accessor = node('node_modules/a', 'a');
    Object.defineProperty(accessor, 'dependencies', { enumerable: true, get: () => ({}) });
    expect(predicate(input([accessor], { a: '1.0.0' }))).toBe('shape');
    expect(analyzePeerDependencySemantics(input([node('node_modules/constructor', 'constructor')], { constructor: '1.0.0' })).requiredPaths).toEqual(['node_modules/constructor']);
  });

  it('enforces the bounded supported SemVer grammar and boundaries', () => {
    const withRange = (range: string, version = '1.2.3') => input([node('node_modules/a', 'a', version)], { a: range });
    expect(analyzePeerDependencySemantics(withRange('=1.2.3')).requiredPaths).toHaveLength(1);
    expect(analyzePeerDependencySemantics(withRange('>=1.0.0 <2.0.0', '1.5.0')).requiredPaths).toHaveLength(1);
    expect(analyzePeerDependencySemantics(withRange('1.0.0 || 1.2.3')).requiredPaths).toHaveLength(1);
    expect(analyzePeerDependencySemantics(withRange('*')).requiredPaths).toHaveLength(1);
    expect(predicate(withRange('~1.2.3', '1.3.0'))).toBe('ordinary_range');
    expect(predicate(withRange('^0.2.3', '0.3.0'))).toBe('ordinary_range');
    expect(predicate(withRange('^0.0.3', '0.0.4'))).toBe('ordinary_range');
    for (const range of ['1.2', '1.x.0', '1.2.3-beta', 'v1.2.3', '^ 1.2.3', '1.2.3 || wat', '99999999999999999.0.0']) {
      expect(predicate(withRange(range))).toMatch(/^(specifier|version)$/);
    }
  });

  it('uses nearest ancestors, rejects local/farther bypass and self peers, and distinguishes absent optional peers', () => {
    const nearest = input([
      node('node_modules/host', 'host', '1.0.0'),
      node('node_modules/a', 'a', '1.0.0', { dependencies: { plugin: '1.0.0' } }),
      node('node_modules/a/node_modules/plugin', 'plugin', '1.0.0', { peerDependencies: { host: '2.0.0' } }),
      node('node_modules/a/node_modules/host', 'host', '1.0.0'),
    ], { a: '1.0.0' });
    expect(predicate(nearest)).toBe('peer_conflict');
    const local = valid();
    (local.nodes as unknown[]).push(node('node_modules/plugin/node_modules/host', 'host'));
    expect(predicate(local)).toBe('peer_local');
    const self = input([node('node_modules/a', 'a', '1.0.0', { peerDependencies: { a: '1.0.0' } })], { a: '1.0.0' });
    expect(predicate(self)).toBe('self_peer');
    const missing = input([node('node_modules/a', 'a', '1.0.0', { peerDependencies: { x: '1.0.0' } })], { a: '1.0.0' });
    expect(predicate(missing)).toBe('peer_missing');
  });

  it('validates ordinary ranges, P/R closure, cycles, peer backreferences, ceilings, and repeatability', () => {
    expect(predicate(input([node('node_modules/a', 'a', '2.0.0')], { a: '1.0.0' }))).toBe('ordinary_range');
    const peerOnly = input([
      node('node_modules/a', 'a', '1.0.0', { peerDependencies: { host: '1.0.0' } }),
      node('node_modules/host', 'host'),
    ], { a: '1.0.0' });
    expect(analyzePeerDependencySemantics(peerOnly).requiredPaths).toEqual(['node_modules/a', 'node_modules/host']);
    const optionalOnly = input([
      node('node_modules/a', 'a', '1.0.0', { peerDependencies: { host: '1.0.0' }, peerDependenciesMeta: { host: { optional: true } } }),
      node('node_modules/host', 'host'),
    ], { a: '1.0.0' });
    expect(predicate(optionalOnly)).toBe('closure');
    const cycle = input([node('node_modules/a', 'a', '1.0.0', { dependencies: { b: '1.0.0' } }), node('node_modules/a/node_modules/b', 'b', '1.0.0', { dependencies: { a: '1.0.0' } })], { a: '1.0.0' });
    expect(predicate(cycle)).toBe('ordinary_cycle');
    const tooMany = Array.from({ length: 257 }, (_, index) => node(`node_modules/a${index}`, `a${index}`));
    expect(predicate(input(tooMany, { a0: '1.0.0' }))).toBe('budget');
    expect(analyzePeerDependencySemantics(valid())).toEqual(analyzePeerDependencySemantics(valid()));
  });

  it('allows peer role only for a required peer-only node and rejects a mismatched role', () => {
    const allowed = input([
      node('node_modules/a', 'a', '1.0.0', { peerDependencies: { host: '1.0.0' } }),
      node('node_modules/host', 'host', '1.0.0', { peer: true }),
    ], { a: '1.0.0' });
    expect(analyzePeerDependencySemantics(allowed).requiredPaths).toEqual(['node_modules/a', 'node_modules/host']);
    const mismatch = input([
      node('node_modules/a', 'a', '1.0.0', { peer: true }),
    ], { a: '1.0.0' });
    expect(predicate(mismatch)).toBe('role');
  });

  it('distinguishes optional absence from present conflict and shares compatible targets', () => {
    const absent = input([node('node_modules/a', 'a', '1.0.0', { peerDependencies: { host: '^1.0.0' }, peerDependenciesMeta: { host: { optional: true } } })], { a: '1.0.0' });
    expect(analyzePeerDependencySemantics(absent).peerRequirements).toEqual([{ from: 'node_modules/a', name: 'host', optional: true }]);
    const presentBad = input([
      node('node_modules/a', 'a', '1.0.0', { peerDependencies: { host: '^1.0.0' }, peerDependenciesMeta: { host: { optional: true } } }),
      node('node_modules/host', 'host', '2.0.0'),
    ], { a: '1.0.0', host: '2.0.0' });
    expect(predicate(presentBad)).toBe('peer_conflict');
    const shared = input([
      node('node_modules/a', 'a', '1.0.0', { peerDependencies: { host: '^1.0.0' } }),
      node('node_modules/b', 'b', '1.0.0', { peerDependencies: { host: '>=1.0.0 <2.0.0' } }),
      node('node_modules/host', 'host'),
    ], { a: '1.0.0', b: '1.0.0', host: '1.0.0' });
    expect(analyzePeerDependencySemantics(shared).peerRequirements).toHaveLength(2);
    (shared.nodes as unknown[])[1] = node('node_modules/b', 'b', '1.0.0', { peerDependencies: { host: '^2.0.0' } });
    expect(predicate(shared)).toBe('peer_conflict');
  });

  it('resolves distinct nested scopes independently and rejects range grammar budgets', () => {
    const scoped = input([
      node('node_modules/a', 'a', '1.0.0', { dependencies: { plugin: '1.0.0' } }),
      node('node_modules/a/node_modules/plugin', 'plugin', '1.0.0', { peerDependencies: { host: '^2.0.0' } }),
      node('node_modules/a/node_modules/host', 'host', '2.0.0'),
      node('node_modules/host', 'host', '1.0.0'),
    ], { a: '1.0.0', host: '1.0.0' });
    expect(analyzePeerDependencySemantics(scoped).peerRequirements[0]).toMatchObject({ targetPath: 'node_modules/a/node_modules/host' });
    const withRange = (range: string) => input([node('node_modules/a', 'a')], { a: range });
    expect(predicate(withRange(Array(10).fill('1.0.0').join(' || ')))).toBe('specifier');
    expect(predicate(withRange(Array(17).fill('1.0.0').join(' ')))).toBe('budget');
    expect(predicate(withRange('^9007199254740991.0.0'))).toBe('specifier');
    for (const range of [' 1.0.0', '1.0.0 ', '1.0.0 || ', '1.0.0  1.0.0']) expect(predicate(withRange(range))).toBe('specifier');
  });
});
