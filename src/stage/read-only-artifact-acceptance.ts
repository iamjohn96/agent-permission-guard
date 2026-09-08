import { createHash } from 'node:crypto';

import { canonicalJson } from '../audit/canonical-json.js';
import type { BoundedArchiveWorker } from './bounded-archive-worker.js';
import {
  PackageStageError,
} from './profile.js';
import {
  projectAndValidatePackageManifest,
} from './package-manifest-projection.js';
import type {
  AcceptedArtifactEvidence,
  CompleteReadOnlyAcceptanceEvidence,
  ExactGraphCandidate,
  ExactGraphCandidateAuthority,
  ReadOnlyArtifactAcceptancePlan,
  ReadOnlyArtifactAcceptancePlanAuthority,
  SyntheticReadOnlyArtifactApproval,
} from './exact-production-graph.js';
import type {
  PrivateArtifactRoot,
  ReadOnlyArtifactTransport,
} from './read-only-artifact-file.js';
import {
  VerifiedArtifactFileAuthority,
} from './read-only-artifact-file.js';

export type ReadOnlyAcceptanceState =
  | 'ARTIFACT_ACCEPTANCE_APPROVAL_PENDING'
  | 'DOWNLOADING_READ_ONLY'
  | 'ARTIFACTS_VERIFIED'
  | 'PASS_A_ACCEPTING'
  | 'CLEANUP_PENDING'
  | 'ACCEPTANCE_COMPLETE'
  | 'ACCEPTANCE_INCOMPLETE_QUARANTINE';

export type ReadOnlyAcceptanceEvent =
  | 'artifact_acceptance_authorized'
  | 'artifact_download_started'
  | 'artifact_integrity_verified'
  | 'artifact_pass_a_verified'
  | 'artifact_second_pass_a_verified'
  | 'cleanup_complete'
  | 'acceptance_complete'
  | 'acceptance_incomplete';

export type SyntheticReadOnlyAcceptanceReport = Readonly<{
  reportVersion: 1;
  candidateDigest: string;
  planHash: string;
  terminalState: 'ACCEPTANCE_COMPLETE' | 'ACCEPTANCE_INCOMPLETE_QUARANTINE';
  events: readonly ReadOnlyAcceptanceEvent[];
  acceptedArtifactCount: number;
  cleanupComplete: boolean;
}>;

/** In-memory, network-free audit boundary. It performs no database or external write. */
export class SyntheticReadOnlyAcceptanceAuditAuthority {
  readonly #events = new WeakSet<object>();

  record(event: ReadOnlyAcceptanceEvent, plan: ReadOnlyArtifactAcceptancePlan): Readonly<{
    eventVersion: 1;
    event: ReadOnlyAcceptanceEvent;
    planHash: string;
  }> {
    const record = Object.freeze({ eventVersion: 1 as const, event, planHash: plan.planHash });
    this.#events.add(record);
    return record;
  }

  authenticates(candidate: unknown): boolean {
    return typeof candidate === 'object' && candidate !== null && this.#events.has(candidate);
  }
}

export class CompleteReadOnlyAcceptanceAuthority {
  readonly #authenticated = new WeakSet<object>();
  #lastReport: SyntheticReadOnlyAcceptanceReport | null = null;

  constructor(
    private readonly candidateAuthority: ExactGraphCandidateAuthority,
    private readonly planAuthority: ReadOnlyArtifactAcceptancePlanAuthority,
    private readonly fileAuthority: VerifiedArtifactFileAuthority,
    private readonly auditAuthority: SyntheticReadOnlyAcceptanceAuditAuthority,
  ) {}

  async acceptForTest(
    candidate: ExactGraphCandidate,
    plan: ReadOnlyArtifactAcceptancePlan,
    approval: SyntheticReadOnlyArtifactApproval,
    root: PrivateArtifactRoot,
    transport: ReadOnlyArtifactTransport,
    worker: BoundedArchiveWorker,
    now = new Date(),
    signal?: AbortSignal,
  ): Promise<CompleteReadOnlyAcceptanceEvidence> {
    this.candidateAuthority.assertAuthenticates(candidate);
    this.planAuthority.assertAuthenticates(plan);
    if (
      plan.candidateDigest !== candidate.candidateDigest
      || plan.runtimeDigest !== worker.runtimeDigest
      || plan.workerProtocolVersion !== candidate.workerProtocolVersion
    ) throw new PackageStageError('artifact_plan_invalid');

    const events: ReadOnlyAcceptanceEvent[] = [];
    let state: ReadOnlyAcceptanceState = 'ARTIFACT_ACCEPTANCE_APPROVAL_PENDING';
    let acceptedArtifactCount = 0;
    let cleanupComplete = false;
    let files: Awaited<ReturnType<VerifiedArtifactFileAuthority['downloadForTest']>> | undefined;
    const record = (event: ReadOnlyAcceptanceEvent): void => {
      const evidence = this.auditAuthority.record(event, plan);
      if (!this.auditAuthority.authenticates(evidence)) throw new PackageStageError('acceptance_incomplete');
      events.push(event);
    };

    try {
      record('artifact_acceptance_authorized');
      state = transition(state, 'DOWNLOADING_READ_ONLY');
      record('artifact_download_started');
      files = await this.fileAuthority.downloadForTest(plan, approval, root, transport, now, signal);
      state = transition(state, 'ARTIFACTS_VERIFIED');
      record('artifact_integrity_verified');
      state = transition(state, 'PASS_A_ACCEPTING');

      const accepted: AcceptedArtifactEvidence[] = [];
      for (const file of files.files) {
        const first = await worker.inspectSourceWithManifest(
          this.fileAuthority.sourceFor(file, signal),
          plan.limits,
          signal,
        );
        record('artifact_pass_a_verified');
        const second = await worker.inspectSourceWithManifest(
          this.fileAuthority.sourceFor(file, signal),
          plan.limits,
          signal,
        );
        if (
          canonicalJson(first) !== canonicalJson(second)
          || first.runtimeDigest !== plan.runtimeDigest
          || first.workerProtocolVersion !== plan.workerProtocolVersion
        ) throw new PackageStageError('acceptance_incomplete');
        record('artifact_second_pass_a_verified');
        const candidateNodes = candidate.graphNodes.filter((node) =>
          file.artifact.installPaths.includes(node.installPath));
        if (candidateNodes.length !== file.artifact.installPaths.length) {
          throw new PackageStageError('acceptance_incomplete');
        }
        const projection = projectAndValidatePackageManifest(
          first.packageManifestBase64,
          first.transcript,
          candidate,
          candidateNodes,
        );
        accepted.push(Object.freeze({
          installPaths: file.artifact.installPaths,
          packageName: file.artifact.packageName,
          exactVersion: file.artifact.exactVersion,
          tarballUrl: file.artifact.tarballUrl,
          sha512Integrity: file.artifact.sha512Integrity,
          compressedBytes: file.compressedBytes,
          expandedBytes: first.transcript.expandedBytes,
          archiveEntryCount: first.transcript.entryCount,
          archiveTranscriptDigest: first.transcript.transcriptDigest,
          packageJsonBodySha256: projection.packageJsonBodySha256,
          packageManifestProjectionDigest: projection.projectionDigest,
        }));
        acceptedArtifactCount += 1;
      }
      if (accepted.length !== plan.artifacts.length) throw new PackageStageError('acceptance_incomplete');
      state = transition(state, 'CLEANUP_PENDING');
      await this.fileAuthority.cleanup(files, root);
      cleanupComplete = true;
      record('cleanup_complete');
      state = transition(state, 'ACCEPTANCE_COMPLETE');
      record('acceptance_complete');
      const unsigned = deepFreeze({
        evidenceVersion: 1 as const,
        candidateDigest: candidate.candidateDigest,
        planHash: plan.planHash,
        artifacts: Object.freeze(accepted),
        cleanupComplete: true as const,
      });
      const evidence = deepFreeze({ ...unsigned, evidenceDigest: sha256(canonicalJson(unsigned)) });
      this.#authenticated.add(evidence);
      this.#lastReport = Object.freeze({
        reportVersion: 1,
        candidateDigest: candidate.candidateDigest,
        planHash: plan.planHash,
        terminalState: 'ACCEPTANCE_COMPLETE',
        events: Object.freeze([...events]),
        acceptedArtifactCount,
        cleanupComplete,
      });
      return evidence;
    } catch (error) {
      if (files !== undefined && !cleanupComplete) {
        try {
          await this.fileAuthority.cleanup(files, root);
          cleanupComplete = true;
          record('cleanup_complete');
        } catch {
          cleanupComplete = false;
        }
      }
      state = 'ACCEPTANCE_INCOMPLETE_QUARANTINE';
      try { record('acceptance_incomplete'); } catch { /* synthetic terminal evidence may itself fail */ }
      this.#lastReport = Object.freeze({
        reportVersion: 1,
        candidateDigest: candidate.candidateDigest,
        planHash: plan.planHash,
        terminalState: state,
        events: Object.freeze([...events]),
        acceptedArtifactCount,
        cleanupComplete,
      });
      if (error instanceof PackageStageError) throw error;
      throw new PackageStageError(signal?.aborted === true ? 'artifact_cancelled' : 'acceptance_incomplete');
    }
  }

  authenticates(candidate: unknown): candidate is CompleteReadOnlyAcceptanceEvidence {
    return typeof candidate === 'object' && candidate !== null && this.#authenticated.has(candidate);
  }

  get lastReport(): SyntheticReadOnlyAcceptanceReport | null {
    return this.#lastReport;
  }
}

function transition(current: ReadOnlyAcceptanceState, next: ReadOnlyAcceptanceState): ReadOnlyAcceptanceState {
  const allowed: Readonly<Record<ReadOnlyAcceptanceState, readonly ReadOnlyAcceptanceState[]>> = {
    ARTIFACT_ACCEPTANCE_APPROVAL_PENDING: ['DOWNLOADING_READ_ONLY'],
    DOWNLOADING_READ_ONLY: ['ARTIFACTS_VERIFIED'],
    ARTIFACTS_VERIFIED: ['PASS_A_ACCEPTING'],
    PASS_A_ACCEPTING: ['CLEANUP_PENDING'],
    CLEANUP_PENDING: ['ACCEPTANCE_COMPLETE'],
    ACCEPTANCE_COMPLETE: [],
    ACCEPTANCE_INCOMPLETE_QUARANTINE: [],
  };
  if (!allowed[current].includes(next)) throw new PackageStageError('state_transition_invalid');
  return next;
}

function sha256(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

function deepFreeze<T>(input: T): T {
  if (typeof input !== 'object' || input === null || Object.isFrozen(input)) return input;
  for (const value of Object.values(input)) deepFreeze(value);
  return Object.freeze(input);
}
