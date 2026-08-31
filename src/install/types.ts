import type { Decision } from '../policy/schema.js';
import type { RiskBand } from '../risk/types.js';

export type InstallRunner = 'npm' | 'npx';

export type InstallRequest = Readonly<{
  runner: InstallRunner;
  packageName: string;
  requestedSpecifier: string;
  options: readonly string[];
  workingDirectory: string;
}>;

export type AdvisorySeverity = 'low' | 'moderate' | 'high' | 'critical';

export type ResolvedPackageMetadata = Readonly<{
  packageName: string;
  version: string;
  registry: string;
  observedAt: string;
  lifecycleScripts: readonly string[];
  advisories: readonly Readonly<{
    id: string;
    severity: AdvisorySeverity;
  }>[];
  possibleTyposquat: boolean;
  packageIsNew: boolean;
  publisherIsNew: boolean;
  repositoryMissing: boolean;
  provenanceInconsistent: boolean;
  mutableSource: boolean;
}>;

export type InstallResolution =
  | Readonly<{ status: 'resolved'; metadata: ResolvedPackageMetadata }>
  | Readonly<{ status: 'unresolved' | 'unavailable' | 'contradictory'; reason: string }>;

export interface InstallMetadataProvider {
  resolve(request: InstallRequest): Promise<InstallResolution>;
}

export type InstallRiskSignalCode =
  | 'exact_version_unresolved'
  | 'metadata_unavailable'
  | 'metadata_contradictory'
  | 'lifecycle_scripts'
  | 'high_advisory'
  | 'critical_advisory'
  | 'possible_typosquat'
  | 'new_package'
  | 'new_publisher'
  | 'repository_missing'
  | 'provenance_inconsistent'
  | 'mutable_source';

export type InstallRiskSignal = Readonly<{
  code: InstallRiskSignalCode;
  points: number;
  source: 'resolution' | 'metadata' | 'advisory' | 'heuristic';
}>;

export type InstallRiskAssessment = Readonly<{
  score: number;
  band: RiskBand;
  signals: readonly InstallRiskSignal[];
}>;

export type InstallPolicyEvaluation = Readonly<{
  effectiveDecision: Decision;
  reasonCodes: readonly string[];
  risk: InstallRiskAssessment;
}>;
