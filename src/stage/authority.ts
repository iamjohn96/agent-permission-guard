import type { MaterializedTreeManifest, PackageStagePlan, SealedSyntheticPackageStage } from './types.js';
import type { AuthenticatedVerifiedMcpGraphProfile } from './types.js';
import { PackageStageError, VerifiedMcpGraphProfileAuthority } from './profile.js';
import { PackageStagePlanAuthority } from './plan.js';

export type SyntheticStageCommitEvidence = Readonly<{
  evidenceVersion: 1;
  event: 'stage_committed';
  stageId: string;
  stagePlanHash: string;
  treeDigest: string;
}>;

/** Test-only audit double boundary; it performs no database or external write. */
export class SyntheticStageAuditAuthority {
  readonly #authenticated = new WeakSet<object>();

  recordCommittedForTest(
    plan: PackageStagePlan,
    planAuthority: PackageStagePlanAuthority,
    treeManifest: MaterializedTreeManifest,
  ): SyntheticStageCommitEvidence {
    planAuthority.assertAuthenticates(plan);
    if (!isTreeManifest(treeManifest)) throw new PackageStageError('tree_invalid');
    const evidence = Object.freeze({
      evidenceVersion: 1 as const,
      event: 'stage_committed' as const,
      stageId: plan.stageId,
      stagePlanHash: plan.stagePlanHash,
      treeDigest: treeManifest.treeDigest,
    });
    this.#authenticated.add(evidence);
    return evidence;
  }

  authenticates(candidate: unknown): candidate is SyntheticStageCommitEvidence {
    return typeof candidate === 'object' && candidate !== null && this.#authenticated.has(candidate);
  }
}

export class SyntheticSealedPackageStageAuthority {
  readonly #authenticated = new WeakSet<object>();

  constructor(
    private readonly profileAuthority: VerifiedMcpGraphProfileAuthority,
    private readonly planAuthority: PackageStagePlanAuthority,
    private readonly auditAuthority: SyntheticStageAuditAuthority,
  ) {}

  sealForTest(
    profile: AuthenticatedVerifiedMcpGraphProfile,
    plan: PackageStagePlan,
    treeManifest: MaterializedTreeManifest,
    commitEvidence: SyntheticStageCommitEvidence,
  ): SealedSyntheticPackageStage {
    this.profileAuthority.assertAuthenticates(profile);
    this.planAuthority.assertAuthenticates(plan);
    if (!isTreeManifest(treeManifest)) throw new PackageStageError('tree_invalid');
    if (!this.auditAuthority.authenticates(commitEvidence)) {
      throw new PackageStageError('stage_audit_incomplete');
    }
    if (
      plan.graphProfileId !== profile.profileId
      || plan.graphProfileDigest !== profile.manifestDigest
      || commitEvidence.stageId !== plan.stageId
      || commitEvidence.stagePlanHash !== plan.stagePlanHash
      || commitEvidence.treeDigest !== treeManifest.treeDigest
    ) {
      throw new PackageStageError('stage_audit_incomplete');
    }
    const stage = deepFreeze({
      manifestVersion: 1 as const,
      stageId: plan.stageId,
      profileId: profile.profileId,
      profileDigest: profile.manifestDigest,
      stagePlanHash: plan.stagePlanHash,
      treeDigest: treeManifest.treeDigest,
      packageScripts: 'disabled' as const,
      assurance: {
        packageIdentity: 'exact_registry_version' as const,
        artifactIntegrity: 'complete_for_staged_graph' as const,
        dependencyGraph: 'complete_for_materialized_stage' as const,
        materializedTree: 'sealed_local_snapshot' as const,
        publisherIdentity: 'unverified' as const,
        buildReproducibility: 'unverified' as const,
        runtimeContainment: 'none' as const,
      },
    });
    this.#authenticated.add(stage);
    return stage;
  }

  authenticates(candidate: unknown): candidate is SealedSyntheticPackageStage {
    return typeof candidate === 'object' && candidate !== null && this.#authenticated.has(candidate);
  }

  assertAuthenticates(candidate: unknown): asserts candidate is SealedSyntheticPackageStage {
    if (!this.authenticates(candidate)) throw new PackageStageError('stage_not_authenticated');
  }
}

function isTreeManifest(input: MaterializedTreeManifest): boolean {
  return typeof input === 'object'
    && input !== null
    && input.manifestVersion === 1
    && /^[0-9a-f]{64}$/u.test(input.treeDigest)
    && Array.isArray(input.records);
}

function deepFreeze<T>(input: T): T {
  if (typeof input !== 'object' || input === null || Object.isFrozen(input)) return input;
  for (const value of Object.values(input)) deepFreeze(value);
  return Object.freeze(input);
}
