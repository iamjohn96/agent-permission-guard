export type StageAssuranceDimensions = Readonly<{
  packageIdentity: 'configured' | 'exact_registry_version';
  artifactIntegrity: 'unverified' | 'top_level_verified' | 'complete_for_staged_graph';
  dependencyGraph: 'unbound' | 'reviewed_exact_graph' | 'complete_for_materialized_stage';
  materializedTree: 'unverified' | 'sealed_local_snapshot' | 'prelaunch_revalidated';
  publisherIdentity: 'unverified' | 'registry_signature_verified' | 'provenance_attestation_verified';
  buildReproducibility: 'unverified' | 'reproducible_build_verified';
  runtimeContainment: 'none' | 'os_sandboxed' | 'remotely_attested';
}>;

export type PackageStageLimits = Readonly<{
  graphNodes: number;
  compressedArtifactBytes: number;
  totalCompressedBytes: number;
  uncompressedArtifactBytes: number;
  totalUncompressedBytes: number;
  regularFileBytes: number;
  archiveEntries: number;
  relativePathBytes: number;
  pathDepth: number;
}>;

export type PackageRuntimeConstraint = Readonly<{
  os: 'darwin' | 'linux';
  architecture: 'arm64' | 'x64';
  nodeMajor: number;
  npmGraphGeneratorVersion: string;
}>;

export type PackageDependencyEdge = Readonly<{
  packageName: string;
  installPath: string;
  declaredSpecifier: string;
}>;

export type PackageGraphNode = Readonly<{
  installPath: string;
  packageName: string;
  exactVersion: string;
  tarballUrl: string;
  sha512Integrity: string;
  dependencyEdges: readonly PackageDependencyEdge[];
  expectedLifecycleScriptNames: readonly string[];
}>;

export type UnsignedVerifiedMcpGraphProfile = Readonly<{
  profileId: string;
  profileVersion: number;
  topPackage: Readonly<{
    name: string;
    exactVersion: string;
    exactEntrypointRelativePath: string;
  }>;
  registryOrigin: string;
  runtimeConstraint: PackageRuntimeConstraint;
  graphNodes: readonly PackageGraphNode[];
  materializationRulesVersion: number;
  archiveRulesVersion: number;
  limits: PackageStageLimits;
}>;

export type VerifiedMcpGraphProfileDefinition = UnsignedVerifiedMcpGraphProfile & Readonly<{
  manifestDigest: string;
}>;

export type AuthenticatedVerifiedMcpGraphProfile = VerifiedMcpGraphProfileDefinition;

export type PackageStagePlan = Readonly<{
  planVersion: 1;
  stageId: string;
  graphProfileId: string;
  graphProfileDigest: string;
  registryOrigin: string;
  metadataObservationDigest: string;
  metadataExpiresAt: string;
  graphNodes: readonly PackageGraphNode[];
  approvedNetworkHosts: readonly string[];
  limits: PackageStageLimits;
  packageScripts: 'disabled';
  stageRootBinding: string;
  stagePlanHash: string;
}>;

export type ArchiveEntryType =
  | 'file'
  | 'directory'
  | 'symlink'
  | 'hardlink'
  | 'block_device'
  | 'character_device'
  | 'fifo'
  | 'socket';

export type ArchiveEntryDescription = Readonly<{
  path: string;
  type: ArchiveEntryType;
  size: number;
  mode: number;
  linkTarget?: string;
  sparse?: boolean;
  hasExtendedAttributes?: boolean;
}>;

export type ValidatedArchiveEntry = Readonly<{
  relativePath: string;
  type: 'file' | 'directory';
  size: number;
  normalizedMode: number;
}>;

export type ArchivePreflightResult = Readonly<{
  entries: readonly ValidatedArchiveEntry[];
  entryCount: number;
  expandedBytes: number;
}>;

export type MaterializedTreeRecord = Readonly<{
  relativePath: string;
  type: 'file' | 'directory';
  normalizedMode: number;
  size: number;
  sha256?: string;
}>;

export type MaterializedTreeManifest = Readonly<{
  manifestVersion: 1;
  records: readonly MaterializedTreeRecord[];
  treeDigest: string;
}>;

export type SealedSyntheticPackageStage = Readonly<{
  manifestVersion: 1;
  stageId: string;
  profileId: string;
  profileDigest: string;
  stagePlanHash: string;
  treeDigest: string;
  packageScripts: 'disabled';
  assurance: StageAssuranceDimensions;
}>;

export type PackageStageState =
  | 'PROFILE_SELECTED'
  | 'METADATA_CONFIRMING'
  | 'PLAN_READY'
  | 'STAGE_APPROVAL_PENDING'
  | 'DOWNLOADING'
  | 'ARTIFACTS_VERIFIED'
  | 'PASS_A_RUNNING'
  | 'ARCHIVES_PREFLIGHTED'
  | 'PASS_B_RUNNING'
  | 'MATERIALIZING'
  | 'TREE_VERIFIED'
  | 'READY_TO_COMMIT'
  | 'SEALED_PENDING_AUDIT'
  | 'READY'
  | 'STARTUP_APPROVAL_PENDING'
  | 'STARTING'
  | 'ACTIVE'
  | 'STOPPED'
  | 'FAILED_QUARANTINE'
  | 'INVALID'
  | 'ACTIVE_UNKNOWN'
  | 'TERMINATED_INCOMPLETE';

export interface PackageArtifactDownloader {
  download(
    plan: PackageStagePlan,
    node: PackageGraphNode,
    signal?: AbortSignal,
  ): Promise<Readonly<{
    finalUrl: string;
    redirected: boolean;
    body: AsyncIterable<Uint8Array>;
  }>>;
}

export interface PackageArchiveInspector<TVerifiedArtifact> {
  preflight(
    artifact: TVerifiedArtifact,
    node: PackageGraphNode,
    limits: PackageStageLimits,
  ): Promise<ArchivePreflightResult>;
}

export interface PackageStageMaterializer<TVerifiedArtifact> {
  materialize(
    artifact: TVerifiedArtifact,
    preflight: ArchivePreflightResult,
    node: PackageGraphNode,
    quarantineRoot: string,
  ): Promise<void>;
}
