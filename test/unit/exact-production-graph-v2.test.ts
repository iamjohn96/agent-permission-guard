import { Buffer } from 'node:buffer';
import { describe, expect, it } from 'vitest';

import { ARCHIVE_WORKER_PROTOCOL_VERSION } from '../../src/stage/archive-worker-protocol.js';
import {
  ExactGraphCandidateV2Authority,
  PEER_SEMANTICS_V2_CONTRACT,
  type ExactGraphCandidateV2Input,
} from '../../src/stage/exact-production-graph-v2.js';
import { PACKAGE_STAGE_HARD_CEILINGS } from '../../src/stage/profile.js';

const integrity = `sha512-${Buffer.alloc(64, 1).toString('base64')}`;
const packageRecord = (name: string, version = '1.0.0', extra: Record<string, unknown> = {}) => ({
  version,
  resolved: `https://registry.npmjs.org/${name}/-/${name.replace('/', '-')}-${version}.tgz`,
  integrity,
  ...extra,
});
const fixture = (
  packages: Record<string, unknown> = { 'node_modules/a': packageRecord('a') },
  overrides: Record<string, unknown> = {},
): ExactGraphCandidateV2Input => ({
  profileId: 'fixture',
  profileVersion: 1,
  topPackage: { name: 'a', exactVersion: '1.0.0', exactEntrypointRelativePath: 'index.js' },
  registryOrigin: 'https://registry.npmjs.org/',
  runtimeConstraint: {
    os: 'darwin', architecture: 'arm64', nodeMajor: 26,
    nodeVersion: '26.0.0', npmGraphGeneratorVersion: '11.0.0', lockfileVersion: 3,
  },
  materializationRulesVersion: 1,
  archiveRulesVersion: 1,
  workerProtocolVersion: ARCHIVE_WORKER_PROTOCOL_VERSION,
  limits: { ...PACKAGE_STAGE_HARD_CEILINGS },
  packageLock: {
    name: 'fixture', version: '1.0.0', lockfileVersion: 3, requires: true,
    packages: {
      '': { name: 'fixture', version: '1.0.0', dependencies: { a: '1.0.0' } },
      ...packages,
    },
  },
  ...overrides,
});
const reject = (value: unknown): void => {
  expect(() => new ExactGraphCandidateV2Authority().compile(value as ExactGraphCandidateV2Input)).toThrow('exact_candidate_v2_invalid');
};

describe('memory-only exact candidate v2 authority', () => {
  it('preserves explicit v1-compatible metadata and artifact identity without authenticating copies', () => {
    const authority = new ExactGraphCandidateV2Authority();
    const candidate = authority.compile(fixture());

    expect(candidate).toMatchObject({
      candidateSchemaVersion: 2,
      semanticContract: PEER_SEMANTICS_V2_CONTRACT,
      profileId: 'fixture',
      profileVersion: 1,
      topPackage: { name: 'a', exactVersion: '1.0.0', exactEntrypointRelativePath: 'index.js' },
      registryOrigin: 'https://registry.npmjs.org/',
      runtimeConstraint: { os: 'darwin', architecture: 'arm64', nodeMajor: 26, lockfileVersion: 3 },
      rootDependencies: { a: '1.0.0' },
    });
    expect(candidate.graphNodes[0]).toMatchObject({
      installPath: 'node_modules/a', packageName: 'a', exactVersion: '1.0.0',
      tarballUrl: 'https://registry.npmjs.org/a/-/a-1.0.0.tgz', sha512Integrity: integrity,
      expectedLifecycleScriptNames: [], dependencyEdges: [], peerRequirements: [],
    });
    expect(authority.authenticates(candidate)).toBe(true);
    expect(authority.authenticates({ ...candidate })).toBe(false);
    expect(new ExactGraphCandidateV2Authority().authenticates(candidate)).toBe(false);
    expect(Object.isFrozen(candidate.graphNodes[0])).toBe(true);
  });

  it('binds raw field presence while canonicalizing dictionary and node order', () => {
    const authority = new ExactGraphCandidateV2Authority();
    const absent = authority.compile(fixture());
    const emptyDependencies = authority.compile(fixture({ 'node_modules/a': packageRecord('a', '1.0.0', { dependencies: {} }) }));
    const emptyPeers = authority.compile(fixture({ 'node_modules/a': packageRecord('a', '1.0.0', { peerDependencies: {} }) }));
    const explicitPeerFalse = authority.compile(fixture({ 'node_modules/a': packageRecord('a', '1.0.0', { peer: false }) }));
    expect(absent.candidateDigest).not.toBe(emptyDependencies.candidateDigest);
    expect(absent.candidateDigest).not.toBe(emptyPeers.candidateDigest);
    expect(absent.candidateDigest).not.toBe(explicitPeerFalse.candidateDigest);

    const peerFixture = (meta: unknown, includeMeta: boolean) => fixture({
      'node_modules/a': packageRecord('a', '1.0.0', { dependencies: { plugin: '1.0.0', host: '1.0.0' } }),
      'node_modules/a/node_modules/plugin': packageRecord('plugin', '1.0.0', {
        peerDependencies: { host: '1.0.0' }, ...(includeMeta ? { peerDependenciesMeta: meta } : {}),
      }),
      'node_modules/a/node_modules/host': packageRecord('host'),
    });
    const metaAbsent = authority.compile(peerFixture(undefined, false));
    const metaEmpty = authority.compile(peerFixture({}, true));
    const metaFalse = authority.compile(peerFixture({ host: { optional: false } }, true));
    const metaTrue = authority.compile(peerFixture({ host: { optional: true } }, true));
    expect(new Set([metaAbsent.candidateDigest, metaEmpty.candidateDigest, metaFalse.candidateDigest, metaTrue.candidateDigest]).size).toBe(4);

    const ordered = authority.compile(fixture({
      'node_modules/a': packageRecord('a', '1.0.0', { dependencies: { z: '1.0.0', b: '1.0.0' } }),
      'node_modules/b': packageRecord('b'),
      'node_modules/z': packageRecord('z'),
    }));
    const reordered = authority.compile(fixture({
      'node_modules/z': packageRecord('z'),
      'node_modules/a': packageRecord('a', '1.0.0', { dependencies: { b: '1.0.0', z: '1.0.0' } }),
      'node_modules/b': packageRecord('b'),
    }));
    expect(ordered.candidateDigest).toBe(reordered.candidateDigest);
  });

  it('derives nearest-ancestor peer evidence from the shared evaluator', () => {
    const candidate = new ExactGraphCandidateV2Authority().compile(fixture({
      'node_modules/a': packageRecord('a', '1.0.0', { dependencies: { plugin: '1.0.0' } }),
      'node_modules/a/node_modules/plugin': packageRecord('plugin', '1.0.0', { peerDependencies: { host: '^2.0.0' } }),
      'node_modules/a/node_modules/host': packageRecord('host', '2.0.0', { peer: true }),
    }));
    const plugin = candidate.graphNodes.find(({ packageName }) => packageName === 'plugin');
    expect(plugin?.peerRequirements).toEqual([{
      packageName: 'host', declaredSpecifier: '^2.0.0', optional: false,
      resolution: { kind: 'present', installPath: 'node_modules/a/node_modules/host', exactVersion: '2.0.0' },
    }]);

    const optional = new ExactGraphCandidateV2Authority().compile(fixture({
      'node_modules/a': packageRecord('a', '1.0.0', {
        peerDependencies: { absent: '1.0.0' },
        peerDependenciesMeta: { absent: { optional: true } },
      }),
    }));
    expect(optional.graphNodes[0]?.peerRequirements).toEqual([{
      packageName: 'absent', declaredSpecifier: '1.0.0', optional: true, resolution: { kind: 'absent' },
    }]);
  });

  it('rejects changed identity, malformed artifacts, extra roots, unsupported ranges, and byte limits', () => {
    reject(fixture(undefined, { profileId: 'Supervisor' }));
    reject(fixture(undefined, { runtimeConstraint: { os: 'linux' } }));
    reject(fixture(undefined, { registryOrigin: 'https://user@example.com/' }));
    reject(fixture({ 'node_modules/a': packageRecord('a', '2.0.0') }));
    reject(fixture({ 'node_modules/a': { ...packageRecord('a'), integrity: 'sha512-bad' } }));
    reject(fixture({
      'node_modules/a': packageRecord('a', '1.0.0', { dependencies: { b: 'workspace:*' } }),
      'node_modules/b': packageRecord('b'),
    }));
    const extraRoot = fixture() as unknown as { packageLock: { packages: Record<string, { dependencies?: Record<string, string> }> } };
    extraRoot.packageLock.packages['']!.dependencies = { a: '1.0.0', b: '1.0.0' };
    reject(extraRoot);
    reject(fixture(undefined, { lowerCandidateByteLimit: 1 }));
    reject(fixture(undefined, { lowerCandidateByteLimit: Number.NaN }));
  });

  it('rejects missing, unknown, legacy, and accessor-backed fields without invoking getters', () => {
    const missing = fixture() as unknown as Record<string, unknown>;
    delete missing.profileId;
    reject(missing);
    reject({ ...fixture(), unknown: true });
    reject({ topPackage: { name: 'a', exactVersion: '1.0.0' }, unsignedMetadata: {}, graph: {} });

    let invoked = 0;
    const withInputGetter = fixture() as unknown as Record<string, unknown>;
    Object.defineProperty(withInputGetter, 'profileId', { enumerable: true, get: () => { invoked += 1; return 'fixture'; } });
    reject(withInputGetter);
    expect(invoked).toBe(0);

    const withNodeGetter = fixture() as unknown as { packageLock: { packages: Record<string, Record<string, unknown>> } };
    Object.defineProperty(withNodeGetter.packageLock.packages['node_modules/a']!, 'version', { enumerable: true, get: () => { invoked += 1; return '1.0.0'; } });
    reject(withNodeGetter);
    expect(invoked).toBe(0);
  });
});
