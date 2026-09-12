import { createHash } from 'node:crypto';

import { canonicalJson } from '../audit/canonical-json.js';
import { parseStrictJsonDocument } from './graph-genesis-broker.js';
import {
  type ExactGraphCandidateV2,
  validateCandidateV2Payload,
} from './exact-production-graph-v2.js';

const MAX_ARTIFACT_BYTES = 4 * 1024 * 1024;
const SHA256 = /^[a-f0-9]{64}$/u;
/** Closed data recipe, never evidence that a broker/process/listener ran. */
export function syntheticUnavailableEvidenceV2(actionId: string) {
  const recordFor = (component: string) => Object.freeze({
    evidenceVersion: 2, evidenceOrigin: 'synthetic_fixture', actionId, component,
    observation: 'unavailable', productionExecutionObserved: false,
  });
  const broker = recordFor('broker_ledger');
  const process = recordFor('process_result');
  const listener = recordFor('listener_drain');
  return Object.freeze({ broker, process, listener,
    brokerLedgerDigest: sha256(canonicalJson(broker)),
    processResultDigest: sha256(canonicalJson(process)),
    listenerDrainDigest: sha256(canonicalJson(listener)),
  });
}
const LIMITATIONS = [
  'candidate_not_profile_or_execution_authority',
  'requires_matching_genesis_complete_and_outcome_receipt',
  'registry_publisher_honesty_not_proven',
  'package_code_not_inspected_or_executed',
] as const;
const BINDING_KEYS = [
  'bindingVersion', 'actionId', 'approvalId', 'planId', 'sessionId', 'planHash',
  'executionEnvelopeHash', 'projectionDigest', 'semanticContractDigest',
  'compilationContractDigest', 'runtimeManifestDigest', 'workspaceBinding',
  'lockBytesDigest', 'lockDocumentDigest', 'postStateDigest', 'inventoryDigest',
  'brokerLedgerDigest', 'processResultDigest', 'listenerDrainDigest', 'hostEvidenceDigest',
  'containmentProfileDigest', 'containmentEvidenceDigest', 'policyDigest',
  'auditFileIdentityDigest', 'auditDurabilityProfileDigest', 'outputCanonicalPathDigest',
  'outputParentIdentityDigest',
] as const;

export type GraphGenesisCandidateArtifactV2Binding = Readonly<{
  bindingVersion: 2;
  actionId: string;
  approvalId: string;
  planId: string;
  sessionId: string;
} & Record<(typeof BINDING_KEYS)[number], string | 2>>;

export type GraphGenesisCandidateArtifactV2 = Readonly<{
  artifactSchemaVersion: 2;
  canonicalization: 'apg-canonical-json-v1';
  evidenceOrigin: 'synthetic_fixture' | 'local_observed';
  binding: GraphGenesisCandidateArtifactV2Binding;
  candidate: ExactGraphCandidateV2;
  assurance: 'portable_unsigned_local_candidate';
  limitations: typeof LIMITATIONS;
  artifactDigest: string;
}>;

export function encodeGraphGenesisCandidateArtifactV2(value: GraphGenesisCandidateArtifactV2): Uint8Array {
  if (!validArtifact(value)) fail();
  const bytes = Buffer.from(`${canonicalJson(value)}\n`, 'utf8');
  if (bytes.byteLength > MAX_ARTIFACT_BYTES) fail();
  return bytes;
}

export function createGraphGenesisCandidateArtifactV2(input: Readonly<{
  evidenceOrigin: 'synthetic_fixture' | 'local_observed';
  binding: GraphGenesisCandidateArtifactV2Binding;
  candidate: ExactGraphCandidateV2;
}>): GraphGenesisCandidateArtifactV2 {
  if (input.evidenceOrigin !== 'synthetic_fixture' && input.evidenceOrigin !== 'local_observed'
    || !validBinding(input.binding)) fail();
  const candidate = validateCandidateV2Payload(input.candidate);
  const unsigned = {
    artifactSchemaVersion: 2 as const,
    canonicalization: 'apg-canonical-json-v1' as const,
    evidenceOrigin: input.evidenceOrigin,
    binding: Object.freeze({ ...input.binding }),
    candidate,
    assurance: 'portable_unsigned_local_candidate' as const,
    limitations: LIMITATIONS,
  };
  const artifact = Object.freeze({ ...unsigned, artifactDigest: sha256(canonicalJson(unsigned)) });
  encodeGraphGenesisCandidateArtifactV2(artifact);
  return artifact;
}

export function decodeGraphGenesisCandidateArtifactV2(bytes: Uint8Array): GraphGenesisCandidateArtifactV2 {
  try {
    if (!(bytes instanceof Uint8Array) || bytes.byteLength > MAX_ARTIFACT_BYTES) fail();
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    if (!text.endsWith('\n') || text.slice(0, -1).includes('\n\n')) fail();
    const parsed: unknown = parseStrictJsonDocument(text);
    if (!validArtifact(parsed) || `${canonicalJson(parsed)}\n` !== text) fail();
    const value = parsed as GraphGenesisCandidateArtifactV2;
    const candidate = validateCandidateV2Payload(value.candidate);
    const unsigned = Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'artifactDigest'));
    if (candidate.candidateDigest !== value.candidate.candidateDigest
      || value.artifactDigest !== sha256(canonicalJson(unsigned))) fail();
    return Object.freeze({ ...value, binding: Object.freeze({ ...value.binding }), candidate });
  } catch {
    fail();
  }
}

function validArtifact(value: unknown): value is GraphGenesisCandidateArtifactV2 {
  if (!record(value) || !exactKeys(value, [
    'artifactSchemaVersion', 'canonicalization', 'evidenceOrigin', 'binding', 'candidate',
    'assurance', 'limitations', 'artifactDigest',
  ]) || value.artifactSchemaVersion !== 2 || value.canonicalization !== 'apg-canonical-json-v1'
    || (value.evidenceOrigin !== 'synthetic_fixture' && value.evidenceOrigin !== 'local_observed')
    || value.assurance !== 'portable_unsigned_local_candidate' || !validBinding(value.binding)
    || !Array.isArray(value.limitations) || canonicalJson(value.limitations) !== canonicalJson(LIMITATIONS)
    || typeof value.artifactDigest !== 'string' || !SHA256.test(value.artifactDigest)) return false;
  try {
    validateCandidateV2Payload(value.candidate);
    const unavailable = syntheticUnavailableEvidenceV2(value.binding.actionId);
    const binding = value.binding;
    const keys = ['brokerLedgerDigest', 'processResultDigest', 'listenerDrainDigest'] as const;
    if (value.evidenceOrigin === 'synthetic_fixture'
      ? keys.some((key) => binding[key] !== unavailable[key])
      : keys.some((key) => binding[key] === unavailable[key])) return false;
    const unsigned = Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'artifactDigest'));
    if (value.artifactDigest !== sha256(canonicalJson(unsigned))) return false;
  } catch { return false; }
  return true;
}

function validBinding(value: unknown): value is GraphGenesisCandidateArtifactV2Binding {
  if (!record(value) || !exactKeys(value, BINDING_KEYS) || value.bindingVersion !== 2) return false;
  return BINDING_KEYS.every((key) => key === 'bindingVersion' || typeof value[key] === 'string'
    && (key === 'actionId' || key === 'approvalId' || key === 'planId' || key === 'sessionId'
      ? /^[a-zA-Z0-9-]{16,128}$/u.test(value[key] as string)
      : SHA256.test(value[key] as string)));
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value).sort();
  return canonicalJson(keys) === canonicalJson([...expected].sort());
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function fail(): never {
  throw new Error('graph_genesis_candidate_artifact_v2_invalid');
}
