import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { canonicalJson } from '../../src/audit/canonical-json.js';
import { ARCHIVE_WORKER_PROTOCOL_VERSION } from '../../src/stage/archive-worker-protocol.js';
import {
  createGraphGenesisCandidateArtifactV2,
  decodeGraphGenesisCandidateArtifactV2,
  encodeGraphGenesisCandidateArtifactV2,
  syntheticUnavailableEvidenceV2,
  type GraphGenesisCandidateArtifactV2Binding,
} from '../../src/stage/graph-genesis-candidate-artifact-v2.js';
import { ExactGraphCandidateV2Authority } from '../../src/stage/exact-production-graph-v2.js';
import { PACKAGE_STAGE_HARD_CEILINGS } from '../../src/stage/profile.js';

const digest = (value: string) => createHash('sha256').update(value).digest('hex');
const integrity = `sha512-${Buffer.alloc(64, 4).toString('base64')}`;
const binding = (postStateDigest = digest('post')): GraphGenesisCandidateArtifactV2Binding => ({
  bindingVersion: 2,
  actionId: '11111111-1111-4111-8111-111111111111',
  approvalId: '22222222-2222-4222-8222-222222222222',
  planId: '33333333-3333-4333-8333-333333333333',
  sessionId: '44444444-4444-4444-8444-444444444444',
  planHash: digest('plan'), executionEnvelopeHash: digest('envelope'), projectionDigest: digest('projection'),
  semanticContractDigest: digest('semantic'), compilationContractDigest: digest('compilation'),
  runtimeManifestDigest: digest('runtime'), workspaceBinding: digest('workspace'), lockBytesDigest: digest('bytes'),
  lockDocumentDigest: digest('document'), postStateDigest, inventoryDigest: digest('inventory'),
  brokerLedgerDigest: syntheticUnavailableEvidenceV2('11111111-1111-4111-8111-111111111111').brokerLedgerDigest,
  processResultDigest: syntheticUnavailableEvidenceV2('11111111-1111-4111-8111-111111111111').processResultDigest,
  listenerDrainDigest: syntheticUnavailableEvidenceV2('11111111-1111-4111-8111-111111111111').listenerDrainDigest,
  hostEvidenceDigest: digest('host'), containmentProfileDigest: digest('profile'), containmentEvidenceDigest: digest('containment'),
  policyDigest: digest('policy'), auditFileIdentityDigest: digest('audit-file'), auditDurabilityProfileDigest: digest('audit-durability'),
  outputCanonicalPathDigest: digest('output'), outputParentIdentityDigest: digest('parent'),
});

function candidate() {
  return new ExactGraphCandidateV2Authority().compile({
    profileId: 'fixture', profileVersion: 1,
    topPackage: { name: 'a', exactVersion: '1.0.0', exactEntrypointRelativePath: 'index.js' },
    registryOrigin: 'https://registry.npmjs.org/',
    runtimeConstraint: { os: 'darwin', architecture: 'arm64', nodeMajor: 26, nodeVersion: '26.0.0', npmGraphGeneratorVersion: '11.0.0', lockfileVersion: 3 },
    materializationRulesVersion: 1, archiveRulesVersion: 1, workerProtocolVersion: ARCHIVE_WORKER_PROTOCOL_VERSION,
    limits: { ...PACKAGE_STAGE_HARD_CEILINGS },
    packageLock: { name: 'fixture', version: '1.0.0', lockfileVersion: 3, requires: true, packages: {
      '': { name: 'fixture', version: '1.0.0', dependencies: { a: '1.0.0' } },
      'node_modules/a': { version: '1.0.0', resolved: 'https://registry.npmjs.org/a/-/a-1.0.0.tgz', integrity },
    } },
  });
}

describe('Artifact2 canonical evidence', () => {
  it('rejects fabricated synthetic observation digests and relabelled unavailable evidence', () => {
    const b = binding();
    expect(() => createGraphGenesisCandidateArtifactV2({ evidenceOrigin: 'synthetic_fixture', binding: { ...b, processResultDigest: digest('fake-success') }, candidate: candidate() })).toThrow();
    expect(() => createGraphGenesisCandidateArtifactV2({ evidenceOrigin: 'local_observed', binding: b, candidate: candidate() })).toThrow();
    expect(syntheticUnavailableEvidenceV2(b.actionId).process).toMatchObject({ observation: 'unavailable', productionExecutionObserved: false });
  });
  it('round-trips one-LF canonical bytes and binds post-state separately from candidate', () => {
    const shared = candidate();
    const first = createGraphGenesisCandidateArtifactV2({ evidenceOrigin: 'synthetic_fixture', binding: binding(), candidate: shared });
    const second = createGraphGenesisCandidateArtifactV2({ evidenceOrigin: 'synthetic_fixture', binding: binding(digest('other-post')), candidate: shared });
    const bytes = encodeGraphGenesisCandidateArtifactV2(first);

    expect(new TextDecoder().decode(bytes).endsWith('\n')).toBe(true);
    expect(decodeGraphGenesisCandidateArtifactV2(bytes)).toEqual(first);
    expect(second.candidate.candidateDigest).toBe(first.candidate.candidateDigest);
    expect(second.artifactDigest).not.toBe(first.artifactDigest);
  });

  it('rejects noncanonical, forged digest, and copied binding payloads', () => {
    const artifact = createGraphGenesisCandidateArtifactV2({ evidenceOrigin: 'synthetic_fixture', binding: binding(), candidate: candidate() });
    const text = new TextDecoder().decode(encodeGraphGenesisCandidateArtifactV2(artifact));
    const forged = JSON.parse(text) as Record<string, unknown>;
    (forged.binding as Record<string, unknown>).postStateDigest = digest('forged');
    forged.artifactDigest = digest(canonicalJson(Object.fromEntries(Object.entries(forged).filter(([key]) => key !== 'artifactDigest'))));

    expect(() => decodeGraphGenesisCandidateArtifactV2(Buffer.from(` ${text}`))).toThrow('graph_genesis_candidate_artifact_v2_invalid');
    expect(() => decodeGraphGenesisCandidateArtifactV2(Buffer.from(canonicalJson(forged)))).toThrow('graph_genesis_candidate_artifact_v2_invalid');
  });
});
