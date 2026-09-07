import { PackageStageError } from './profile.js';
import {
  PackageStagePlanAuthority,
  SyntheticPackageStageApprovalAuthority,
  type PackageStageApproval,
} from './plan.js';
import {
  PackageArtifactIntegrityAuthority,
  type VerifiedPackageArtifact,
} from './integrity.js';
import type {
  ArchivePreflightResult,
  PackageArchiveInspector,
  PackageArtifactDownloader,
  PackageStagePlan,
} from './types.js';

export type SyntheticArtifactPreflight = Readonly<{
  verifiedArtifacts: readonly VerifiedPackageArtifact[];
  archivePreflights: readonly ArchivePreflightResult[];
  compressedBytes: number;
}>;

/**
 * Exercises authority ordering with injected, network-free test doubles. It
 * deliberately has no materializer, persistence, production profile, or CLI.
 */
export async function runSyntheticArtifactPreflight(
  plan: PackageStagePlan,
  approval: PackageStageApproval,
  dependencies: Readonly<{
    planAuthority: PackageStagePlanAuthority;
    approvalAuthority: SyntheticPackageStageApprovalAuthority;
    downloader: PackageArtifactDownloader;
    archiveInspector: PackageArchiveInspector<VerifiedPackageArtifact>;
  }>,
  signal?: AbortSignal,
): Promise<SyntheticArtifactPreflight> {
  dependencies.planAuthority.assertAuthenticates(plan);
  dependencies.approvalAuthority.consume(approval, plan);
  const integrityAuthority = new PackageArtifactIntegrityAuthority(plan.limits);
  const verifiedArtifacts: VerifiedPackageArtifact[] = [];
  const archivePreflights: ArchivePreflightResult[] = [];

  for (const node of plan.graphNodes) {
    let response;
    try {
      response = await dependencies.downloader.download(plan, node, signal);
    } catch {
      throw new PackageStageError(signal?.aborted === true ? 'artifact_cancelled' : 'integrity_invalid');
    }
    if (response.redirected || response.finalUrl !== node.tarballUrl) {
      throw new PackageStageError('integrity_invalid');
    }
    const verified = await integrityAuthority.verify(node, response.body, signal);
    if (!integrityAuthority.authenticates(verified)) throw new PackageStageError('integrity_invalid');
    const preflight = await dependencies.archiveInspector.preflight(verified, node, plan.limits);
    verifiedArtifacts.push(verified);
    archivePreflights.push(preflight);
  }

  return Object.freeze({
    verifiedArtifacts: Object.freeze(verifiedArtifacts),
    archivePreflights: Object.freeze(archivePreflights),
    compressedBytes: integrityAuthority.aggregateVerifiedBytes,
  });
}
