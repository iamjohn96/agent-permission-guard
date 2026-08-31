import type { RiskBand } from '../risk/types.js';
import type {
  InstallResolution,
  InstallRiskAssessment,
  InstallRiskSignal,
  InstallRiskSignalCode,
} from './types.js';

const POINTS: Readonly<Record<InstallRiskSignalCode, number>> = {
  exact_version_unresolved: 100,
  metadata_unavailable: 50,
  metadata_contradictory: 50,
  lifecycle_scripts: 35,
  high_advisory: 60,
  critical_advisory: 75,
  possible_typosquat: 50,
  new_package: 25,
  new_publisher: 25,
  repository_missing: 20,
  provenance_inconsistent: 20,
  mutable_source: 45,
};

export function scoreInstallRisk(resolution: InstallResolution): InstallRiskAssessment {
  const signals = new Map<InstallRiskSignalCode, InstallRiskSignal>();

  if (resolution.status !== 'resolved') {
    const code = statusCode(resolution.status);
    addSignal(signals, code, 'resolution');
    return assessmentFor(signals);
  }

  const metadata = resolution.metadata;
  if (metadata.lifecycleScripts.length > 0) addSignal(signals, 'lifecycle_scripts', 'metadata');
  if (metadata.advisories.some((item) => item.severity === 'high')) {
    addSignal(signals, 'high_advisory', 'advisory');
  }
  if (metadata.advisories.some((item) => item.severity === 'critical')) {
    addSignal(signals, 'critical_advisory', 'advisory');
  }
  if (metadata.possibleTyposquat) addSignal(signals, 'possible_typosquat', 'heuristic');
  if (metadata.packageIsNew) addSignal(signals, 'new_package', 'metadata');
  if (metadata.publisherIsNew) addSignal(signals, 'new_publisher', 'metadata');
  if (metadata.repositoryMissing) addSignal(signals, 'repository_missing', 'metadata');
  if (metadata.provenanceInconsistent) addSignal(signals, 'provenance_inconsistent', 'metadata');
  if (metadata.mutableSource) addSignal(signals, 'mutable_source', 'resolution');

  return assessmentFor(signals);
}

function statusCode(status: Exclude<InstallResolution['status'], 'resolved'>): InstallRiskSignalCode {
  if (status === 'unresolved') return 'exact_version_unresolved';
  if (status === 'contradictory') return 'metadata_contradictory';
  return 'metadata_unavailable';
}

function addSignal(
  signals: Map<InstallRiskSignalCode, InstallRiskSignal>,
  code: InstallRiskSignalCode,
  source: InstallRiskSignal['source'],
): void {
  if (signals.has(code)) return;
  signals.set(code, { code, points: POINTS[code], source });
}

function assessmentFor(signals: Map<InstallRiskSignalCode, InstallRiskSignal>): InstallRiskAssessment {
  const ordered = [...signals.values()].sort((left, right) => left.code.localeCompare(right.code));
  const score = Math.min(100, ordered.reduce((sum, signal) => sum + signal.points, 0));
  return { score, band: bandForScore(score), signals: ordered };
}

function bandForScore(score: number): RiskBand {
  if (score >= 75) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 25) return 'medium';
  return 'low';
}
