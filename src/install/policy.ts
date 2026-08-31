import type { Decision } from '../policy/schema.js';
import { scoreInstallRisk } from './risk.js';
import type {
  InstallPolicyEvaluation,
  InstallResolution,
  InstallRiskSignalCode,
} from './types.js';

const DENY_SIGNALS = new Set<InstallRiskSignalCode>([
  'exact_version_unresolved',
  'critical_advisory',
]);

const ASK_SIGNALS = new Set<InstallRiskSignalCode>([
  'metadata_unavailable',
  'metadata_contradictory',
  'lifecycle_scripts',
  'high_advisory',
  'possible_typosquat',
  'mutable_source',
  'limited_registry_evidence',
]);

export function evaluateInstallPolicy(resolution: InstallResolution): InstallPolicyEvaluation {
  const risk = scoreInstallRisk(resolution);
  const codes = risk.signals.map((signal) => signal.code);
  const signalDecision = strictestSignalDecision(codes);
  const shouldEscalate = signalDecision === 'allow' && risk.score >= 50;
  const effectiveDecision = shouldEscalate ? 'ask' : signalDecision;

  return {
    effectiveDecision,
    reasonCodes: codes.length === 0
      ? ['verified_registry_package']
      : [...codes, ...(shouldEscalate ? ['install_risk_escalation'] : [])],
    risk,
  };
}

function strictestSignalDecision(codes: readonly InstallRiskSignalCode[]): Decision {
  if (codes.some((code) => DENY_SIGNALS.has(code))) return 'deny';
  if (codes.some((code) => ASK_SIGNALS.has(code))) return 'ask';
  return 'allow';
}
