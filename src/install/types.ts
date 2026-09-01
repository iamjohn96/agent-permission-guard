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
  tarballUrl?: string;
  integrity?: string;
  executableBins?: Readonly<Record<string, string>>;
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
  evidenceComplete: boolean;
}>;

export type InstallResolution =
  | Readonly<{ status: 'resolved'; metadata: ResolvedPackageMetadata }>
  | Readonly<{ status: 'unresolved' | 'unavailable' | 'contradictory'; reason: string }>;

export interface InstallMetadataProvider {
  resolve(request: InstallRequest): Promise<InstallResolution>;
}

export type InstallExecutionResult = Readonly<{
  status: 'completed' | 'failed' | 'timed_out' | 'cancelled';
  exitCode: number | null;
  signal?: NodeJS.Signals;
  durationMs: number;
  summary: string;
  output?: Readonly<{
    stdoutBytes: number;
    stderrBytes: number;
    stdoutPreview: string;
    stderrPreview: string;
    truncated: boolean;
  }>;
  verification?: InstallVerificationResult;
}>;

export type InstallFileSnapshot = Readonly<{
  relativePath: 'package.json' | 'package-lock.json' | 'npm-shrinkwrap.json';
  exists: boolean;
  sha256?: string;
}>;

export type InstallExecutableIdentity = Readonly<{
  path: string;
  sha256: string;
}>;

export type InstallExecutionPlan = Readonly<{
  planHash: string;
  runner: InstallRunner;
  executable: InstallExecutableIdentity;
  runtimeExecutable: InstallExecutableIdentity;
  environmentPath: string;
  arguments: readonly string[];
  packageName: string;
  originalSpecifier: string;
  resolvedVersion: string;
  tarballUrl: string;
  integrity: string;
  executableBin?: string;
  options: readonly string[];
  workingDirectory: string;
  workingDirectoryDevice: number;
  workingDirectoryInode: number;
  registry: string;
  metadataObservedAt: string;
  lifecycleScripts: readonly string[];
  timeoutMs: number;
  beforeFiles: readonly InstallFileSnapshot[];
}>;

export type InstallVerificationResult = Readonly<{
  status: 'verified' | 'failed' | 'limited';
  exactPackageVersionObserved: boolean;
  approvedIntegrityObserved: boolean;
  changedFiles: readonly InstallFileSnapshot['relativePath'][];
  reasonCodes: readonly string[];
}>;

export interface InstallExecutionPlanner {
  create(
    request: InstallRequest,
    metadata: ResolvedPackageMetadata,
    timeoutMs: number,
  ): Promise<InstallExecutionPlan>;
}

export interface InstallRunnerAdapter {
  run(
    plan: InstallExecutionPlan,
    signal?: AbortSignal,
  ): Promise<InstallExecutionResult>;
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
  | 'mutable_source'
  | 'limited_registry_evidence';

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

export type InstallGuardResult = Readonly<{
  status: 'completed' | 'failed' | 'timed_out' | 'cancelled' | 'verification_failed' | 'audit_failed' | 'denied' | 'approval_denied' | 'approval_expired' | 'approval_cancelled';
  evaluation: InstallPolicyEvaluation;
  plan?: InstallExecutionPlan;
  execution?: InstallExecutionResult;
}>;
