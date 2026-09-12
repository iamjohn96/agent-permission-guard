import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { canonicalJson } from '../../src/audit/canonical-json.js';
import { ARCHIVE_WORKER_PROTOCOL_VERSION } from '../../src/stage/archive-worker-protocol.js';
import {
  ExactGraphCandidateV2Authority,
  type ExactGraphCandidateV2,
  type ExactGraphCandidateV2Input,
} from '../../src/stage/exact-production-graph-v2.js';
import { decodeExactGraphCandidateV2, encodeExactGraphCandidateV2 } from '../../src/stage/graph-genesis-candidate-codec-v2.js';
import { PACKAGE_STAGE_HARD_CEILINGS } from '../../src/stage/profile.js';

const integrity = `sha512-${Buffer.alloc(64, 2).toString('base64')}`;
const input = (withEmptyDependencies = false): ExactGraphCandidateV2Input => ({
  profileId: 'fixture', profileVersion: 1,
  topPackage: { name: 'a', exactVersion: '1.0.0', exactEntrypointRelativePath: 'index.js' },
  registryOrigin: 'https://registry.npmjs.org/',
  runtimeConstraint: {
    os: 'darwin', architecture: 'arm64', nodeMajor: 26,
    nodeVersion: '26.0.0', npmGraphGeneratorVersion: '11.0.0', lockfileVersion: 3,
  },
  materializationRulesVersion: 1, archiveRulesVersion: 1,
  workerProtocolVersion: ARCHIVE_WORKER_PROTOCOL_VERSION,
  limits: { ...PACKAGE_STAGE_HARD_CEILINGS },
  packageLock: {
    name: 'fixture', version: '1.0.0', lockfileVersion: 3, requires: true,
    packages: {
      '': { name: 'fixture', version: '1.0.0', dependencies: { a: '1.0.0' } },
      'node_modules/a': {
        version: '1.0.0', resolved: 'https://registry.npmjs.org/a/-/a-1.0.0.tgz', integrity,
        ...(withEmptyDependencies ? { dependencies: {} } : {}),
        peerDependencies: { missing: '1.0.0' }, peerDependenciesMeta: { missing: { optional: true } },
      },
    },
  },
});

describe('memory-only candidate v2 codec', () => {
  it('round-trips canonical plain evidence without transferring authority', () => {
    const authority = new ExactGraphCandidateV2Authority();
    const owned = authority.compile(input());
    const encoded = encodeExactGraphCandidateV2(owned);
    const decoded = decodeExactGraphCandidateV2(encoded);

    expect(encoded).toBe(canonicalJson(owned));
    expect(decoded).toEqual(owned);
    expect(decoded).not.toBe(owned);
    expect(authority.authenticates(decoded)).toBe(false);
    expect(Object.isFrozen(decoded.graphNodes[0])).toBe(true);
  });

  it('rejects noncanonical bytes and duplicate keys at every object depth', () => {
    const encoded = encodeExactGraphCandidateV2(new ExactGraphCandidateV2Authority().compile(input()));
    expect(() => decodeExactGraphCandidateV2(` ${encoded}`)).toThrow('candidate_codec_v2_invalid');
    const parsed = JSON.parse(encoded) as Record<string, unknown>;
    const reversed = JSON.stringify(Object.fromEntries(Object.entries(parsed).reverse()));
    expect(() => decodeExactGraphCandidateV2(reversed)).toThrow('candidate_codec_v2_invalid');
    expect(() => decodeExactGraphCandidateV2(encoded.replace(
      '"candidateSchemaVersion":2',
      '"candidateSchemaVersion":2,"candidateSchemaVersion":2',
    ))).toThrow('candidate_codec_v2_invalid');
    expect(() => decodeExactGraphCandidateV2(encoded.replace(
      '"dependenciesPresent":false',
      '"dependenciesPresent":false,"dependenciesPresent":false',
    ))).toThrow('candidate_codec_v2_invalid');
  });

  it('rejects a recomputed self-hash when retained declarations and identity are inconsistent', () => {
    const encoded = encodeExactGraphCandidateV2(new ExactGraphCandidateV2Authority().compile(input()));
    const payload = JSON.parse(encoded) as Record<string, unknown>;
    (payload.topPackage as Record<string, unknown>).exactVersion = '2.0.0';
    const unsigned = Object.fromEntries(Object.entries(payload).filter(([key]) => key !== 'candidateDigest'));
    payload.candidateDigest = createHash('sha256').update(canonicalJson(unsigned)).digest('hex');
    expect(() => decodeExactGraphCandidateV2(canonicalJson(payload))).toThrow('candidate_codec_v2_invalid');

    const changedContract = JSON.parse(encoded) as Record<string, unknown>;
    (changedContract.semanticContract as { peerSemanticsVersion: number }).peerSemanticsVersion = 2;
    expect(() => decodeExactGraphCandidateV2(canonicalJson(changedContract))).toThrow('candidate_codec_v2_invalid');
    const missingContract = JSON.parse(encoded) as Record<string, unknown>;
    delete missingContract.semanticContract;
    expect(() => decodeExactGraphCandidateV2(canonicalJson(missingContract))).toThrow('candidate_codec_v2_invalid');
  });

  it('accepts self-consistent alternate evidence without minting or transferring authority', () => {
    const originalAuthority = new ExactGraphCandidateV2Authority();
    const original = originalAuthority.compile(input());
    const alternateAuthority = new ExactGraphCandidateV2Authority();
    const alternate = alternateAuthority.compile(input(true));
    expect(alternate.candidateDigest).not.toBe(original.candidateDigest);

    const decoded = decodeExactGraphCandidateV2(encodeExactGraphCandidateV2(alternate));
    expect(decoded).toEqual(alternate);
    expect(originalAuthority.authenticates(decoded)).toBe(false);
    expect(alternateAuthority.authenticates(decoded)).toBe(false);
    expect(originalAuthority.authenticates(alternate)).toBe(false);
  });

  it('rejects forged derived edges, v1 payloads, and invalid byte limits', () => {
    const encoded = encodeExactGraphCandidateV2(new ExactGraphCandidateV2Authority().compile(input()));
    const forged = JSON.parse(encoded) as { graphNodes: Array<{ peerRequirements: unknown[] }> };
    forged.graphNodes[0]!.peerRequirements = [];
    expect(() => decodeExactGraphCandidateV2(canonicalJson(forged))).toThrow('candidate_codec_v2_invalid');
    expect(() => decodeExactGraphCandidateV2('{"candidateSchemaVersion":1}')).toThrow('candidate_codec_v2_invalid');
    for (const limit of [0, Number.NaN, Number.POSITIVE_INFINITY, 4 * 1024 * 1024 + 1]) {
      expect(() => decodeExactGraphCandidateV2(encoded, limit)).toThrow('candidate_codec_v2_invalid');
    }
    expect(() => decodeExactGraphCandidateV2(encoded, 1)).toThrow('candidate_codec_v2_invalid');
  });

  it('rejects accessor-backed encode input without invoking the accessor', () => {
    const owned = new ExactGraphCandidateV2Authority().compile(input());
    let invoked = 0;
    const tainted = { ...owned } as Record<string, unknown>;
    Object.defineProperty(tainted, 'candidateDigest', {
      enumerable: true,
      get: () => { invoked += 1; return owned.candidateDigest; },
    });
    expect(() => encodeExactGraphCandidateV2(tainted as ExactGraphCandidateV2)).toThrow('candidate_codec_v2_invalid');
    expect(invoked).toBe(0);
  });
});
