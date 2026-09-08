import { constants } from 'node:fs';
import { link, lstat, open, realpath, unlink } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';

import { canonicalJson } from '../audit/canonical-json.js';
import type { ExactGraphCandidate, ExactGraphCandidateAuthority } from './exact-production-graph.js';
import type {
  GraphGenesisExecutionEnvelopeAuthority,
  GraphGenesisExecutionEnvelopeV1,
} from './graph-genesis-composition.js';
import { graphGenesisDirectoryIdentityDigest } from './graph-genesis-composition.js';
import { PackageStageError } from './profile.js';

const SHA256 = /^[a-f0-9]{64}$/u;
const MAX_ARTIFACT_BYTES = 4 * 1024 * 1024;

export type GraphGenesisCandidateArtifactV1 = Readonly<{
  artifactSchemaVersion: 1;
  canonicalization: 'apg-canonical-json-v1';
  actionId: string;
  executionEnvelopeHash: string;
  planHash: string;
  target: Readonly<{
    name: '@modelcontextprotocol/server-filesystem';
    exactVersion: '2026.7.10';
    registryOrigin: 'https://registry.npmjs.org/';
  }>;
  runtime: ExactGraphCandidate['runtimeConstraint'];
  graphNodes: ExactGraphCandidate['graphNodes'];
  candidateDigest: string;
  brokerLedgerDigest: string;
  postStateDigest: string;
  assurance: 'portable_unsigned_local_candidate';
  limitations: readonly [
    'candidate_not_profile_or_execution_authority',
    'requires_matching_genesis_complete_and_outcome_receipt',
    'registry_publisher_honesty_not_proven',
    'package_code_not_inspected_or_executed',
  ];
  artifactDigest: string;
}>;

export type CandidateTerminalProofQuery = Readonly<{
  actionId: string;
  executionEnvelopeHash: string;
  planHash: string;
  candidateDigest: string;
  artifactDigest: string;
}>;

export interface GraphGenesisCandidateTerminalProofSource {
  hasCompleteTerminalProof(query: CandidateTerminalProofQuery): boolean | Promise<boolean>;
}

export class GraphGenesisCandidateArtifactAuthority {
  readonly #artifacts = new WeakSet<object>();

  constructor(
    private readonly envelopes: GraphGenesisExecutionEnvelopeAuthority,
    private readonly candidates: ExactGraphCandidateAuthority,
  ) {}

  compile(input: Readonly<{
    envelope: GraphGenesisExecutionEnvelopeV1;
    privateCapsule: object;
    candidate: ExactGraphCandidate;
    actionId: string;
    brokerLedgerDigest: string;
    postStateDigest: string;
  }>): GraphGenesisCandidateArtifactV1 {
    const plan = this.envelopes.planFor(input.envelope, input.privateCapsule);
    if (!this.candidates.authenticates(input.candidate)
      || input.candidate.topPackage.name !== '@modelcontextprotocol/server-filesystem'
      || input.candidate.topPackage.exactVersion !== '2026.7.10'
      || input.candidate.registryOrigin !== plan.registryOrigin
      || !SHA256.test(input.brokerLedgerDigest) || !SHA256.test(input.postStateDigest)
      || !/^[0-9a-f-]{36}$/iu.test(input.actionId)) fail();
    const unsigned = deepFreeze({
      artifactSchemaVersion: 1 as const,
      canonicalization: 'apg-canonical-json-v1' as const,
      actionId: input.actionId,
      executionEnvelopeHash: input.envelope.executionEnvelopeHash,
      planHash: input.envelope.planHash,
      target: {
        name: '@modelcontextprotocol/server-filesystem' as const,
        exactVersion: '2026.7.10' as const,
        registryOrigin: 'https://registry.npmjs.org/' as const,
      },
      runtime: input.candidate.runtimeConstraint,
      graphNodes: input.candidate.graphNodes,
      candidateDigest: input.candidate.candidateDigest,
      brokerLedgerDigest: input.brokerLedgerDigest,
      postStateDigest: input.postStateDigest,
      assurance: 'portable_unsigned_local_candidate' as const,
      limitations: [
        'candidate_not_profile_or_execution_authority',
        'requires_matching_genesis_complete_and_outcome_receipt',
        'registry_publisher_honesty_not_proven',
        'package_code_not_inspected_or_executed',
      ] as const,
    });
    const artifact = deepFreeze({ ...unsigned, artifactDigest: sha256(canonicalJson(unsigned)) });
    this.#artifacts.add(artifact);
    return artifact;
  }

  authenticates(value: unknown): value is GraphGenesisCandidateArtifactV1 {
    return typeof value === 'object' && value !== null && this.#artifacts.has(value);
  }

  async writeExclusive(input: Readonly<{
    envelope: GraphGenesisExecutionEnvelopeV1;
    privateCapsule: object;
    artifact: GraphGenesisCandidateArtifactV1;
  }>): Promise<Readonly<{ pathDigest: string; artifactDigest: string; bytes: number }>> {
    if (!this.authenticates(input.artifact)) fail();
    const outputPath = this.envelopes.outputPathFor(input.envelope, input.privateCapsule);
    if (input.artifact.executionEnvelopeHash !== input.envelope.executionEnvelopeHash
      || sha256(canonicalJson(outputPath)) !== input.envelope.outputCanonicalPathDigest) fail();
    const parent = dirname(outputPath);
    const parentReal = await realpath(parent);
    if (parentReal !== parent) fail();
    const parentBefore = await lstat(parent);
    const currentUser = typeof process.geteuid === 'function' ? process.geteuid() : parentBefore.uid;
    if (!parentBefore.isDirectory() || parentBefore.isSymbolicLink() || parentBefore.uid !== currentUser
      || (parentBefore.mode & 0o777) !== 0o700) fail();
    if (graphGenesisDirectoryIdentityDigest({
      canonicalPath: parent,
      device: parentBefore.dev,
      inode: parentBefore.ino,
      owner: parentBefore.uid,
      mode: parentBefore.mode & 0o7777,
    }) !== input.envelope.outputParentIdentityDigest) fail();
    try { await lstat(outputPath); fail(); } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
    const pending = join(parent, `.apg-candidate-${randomBytes(16).toString('hex')}.pending`);
    const bytes = Buffer.from(`${canonicalJson(input.artifact)}\n`, 'utf8');
    if (bytes.byteLength > MAX_ARTIFACT_BYTES) fail();
    const handle = await open(pending, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
    try {
      await handle.writeFile(bytes);
      await handle.sync();
      const pendingInfo = await handle.stat();
      if (!pendingInfo.isFile() || pendingInfo.nlink !== 1 || pendingInfo.size !== bytes.byteLength
        || (pendingInfo.mode & 0o777) !== 0o600) fail();
    } finally { await handle.close(); }
    try {
      const parentAfter = await lstat(parent);
      if (parentAfter.dev !== parentBefore.dev || parentAfter.ino !== parentBefore.ino
        || (parentAfter.mode & 0o777) !== 0o700) fail();
      await link(pending, outputPath);
      const outputInfo = await lstat(outputPath);
      if (!outputInfo.isFile() || outputInfo.isSymbolicLink() || outputInfo.nlink !== 2
        || outputInfo.uid !== currentUser || (outputInfo.mode & 0o777) !== 0o600
        || outputInfo.size !== bytes.byteLength) fail();
      await unlink(pending);
      const finalInfo = await lstat(outputPath);
      if (finalInfo.nlink !== 1) fail();
      return Object.freeze({
        pathDigest: input.envelope.outputCanonicalPathDigest,
        artifactDigest: input.artifact.artifactDigest,
        bytes: bytes.byteLength,
      });
    } catch (error) {
      try { await unlink(pending); } catch { /* preserve original failure */ }
      throw error;
    }
  }
}

export class GraphGenesisCandidateArtifactImporter {
  async verify(path: string, proofs: GraphGenesisCandidateTerminalProofSource): Promise<GraphGenesisCandidateArtifactV1> {
    const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    let bytes: Buffer;
    try {
      const info = await handle.stat();
      const currentUser = typeof process.geteuid === 'function' ? process.geteuid() : info.uid;
      if (!info.isFile() || info.nlink !== 1 || (info.mode & 0o777) !== 0o600
        || info.uid !== currentUser || info.size <= 0 || info.size > MAX_ARTIFACT_BYTES) fail();
      bytes = await handle.readFile();
      const after = await handle.stat();
      if (after.dev !== info.dev || after.ino !== info.ino || after.size !== info.size
        || after.mtimeMs !== info.mtimeMs || after.ctimeMs !== info.ctimeMs) fail();
    } finally { await handle.close(); }
    let text: string;
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { fail(); }
    const document = parseArtifact(text);
    if (!await proofs.hasCompleteTerminalProof({
      actionId: document.actionId,
      executionEnvelopeHash: document.executionEnvelopeHash,
      planHash: document.planHash,
      candidateDigest: document.candidateDigest,
      artifactDigest: document.artifactDigest,
    })) fail();
    return document;
  }
}

function parseArtifact(text: string): GraphGenesisCandidateArtifactV1 {
  if (!text.endsWith('\n')) fail();
  let value: unknown;
  try { value = JSON.parse(text) as unknown; } catch { fail(); }
  if (!isRecord(value) || `${canonicalJson(value)}\n` !== text) fail();
  const artifact = value as unknown as GraphGenesisCandidateArtifactV1;
  const keys = Object.keys(artifact).sort();
  const expected = [
    'actionId', 'artifactDigest', 'artifactSchemaVersion', 'assurance', 'brokerLedgerDigest',
    'candidateDigest', 'canonicalization', 'executionEnvelopeHash', 'graphNodes', 'limitations',
    'planHash', 'postStateDigest', 'runtime', 'target',
  ].sort();
  if (canonicalJson(keys) !== canonicalJson(expected)
    || artifact.artifactSchemaVersion !== 1 || artifact.canonicalization !== 'apg-canonical-json-v1'
    || artifact.assurance !== 'portable_unsigned_local_candidate'
    || !SHA256.test(artifact.executionEnvelopeHash) || !SHA256.test(artifact.planHash)
    || !SHA256.test(artifact.candidateDigest) || !SHA256.test(artifact.brokerLedgerDigest)
    || !SHA256.test(artifact.postStateDigest) || !SHA256.test(artifact.artifactDigest)
    || artifact.target?.name !== '@modelcontextprotocol/server-filesystem'
    || artifact.target.exactVersion !== '2026.7.10'
    || artifact.target.registryOrigin !== 'https://registry.npmjs.org/'
    || !Array.isArray(artifact.graphNodes) || artifact.graphNodes.length > 10_000) fail();
  const { artifactDigest: _stored, ...unsigned } = artifact;
  if (sha256(canonicalJson(unsigned)) !== artifact.artifactDigest) fail();
  return deepFreeze(artifact);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function sha256(value: string): string { return createHash('sha256').update(value).digest('hex'); }

function deepFreeze<T>(input: T): T {
  if (typeof input !== 'object' || input === null || Object.isFrozen(input)) return input;
  for (const value of Object.values(input)) deepFreeze(value);
  return Object.freeze(input);
}

function fail(): never { throw new PackageStageError('acceptance_incomplete'); }
