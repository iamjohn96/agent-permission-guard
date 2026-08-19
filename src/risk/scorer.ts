import type { RiskTag } from '../policy/schema.js';
import type {
  RiskAssessment,
  RiskBand,
  RiskInput,
  RiskSignal,
  RiskSignalCode,
} from './types.js';

const SIGNAL_POINTS: Readonly<Record<Exclude<RiskTag, 'local_read'>, number>> = {
  local_write: 20,
  destructive: 30,
  external_side_effect: 25,
  credential_access: 25,
  privileged_target: 25,
  broad_target: 20,
  shell_execution: 20,
  open_world: 10,
};

const TOOL_NAME_PATTERNS: ReadonlyArray<Readonly<{
  code: Exclude<RiskTag, 'local_read'>;
  pattern: RegExp;
}>> = [
  { code: 'destructive', pattern: /(?:^|[._-])(delete|destroy|drop|erase|remove)(?:$|[._-])/i },
  { code: 'external_side_effect', pattern: /(?:^|[._-])(email|post|publish|push|send)(?:$|[._-])/i },
  { code: 'shell_execution', pattern: /(?:^|[._-])(exec|shell|command|script)(?:$|[._-])/i },
];

const CREDENTIAL_KEY = /(api[_-]?key|credential|password|private[_-]?key|secret|token)/i;
const PRIVILEGED_VALUE = /^(main|master|prod|production|billing|permission|permissions|role|roles|auth)$/i;
const BROAD_VALUE = /^(\/|\*|all|all[_-]?users|everyone)$/i;

export function scoreRisk(input: RiskInput): RiskAssessment {
  const signals = new Map<RiskSignalCode, RiskSignal>();
  const explicitlyLocalRead = input.policyTags.includes('local_read');

  for (const tag of input.policyTags) {
    if (tag !== 'local_read') {
      addSignal(signals, tag, SIGNAL_POINTS[tag], 'policy_tag');
    }
  }

  for (const detector of TOOL_NAME_PATTERNS) {
    if (detector.pattern.test(input.toolName)) {
      addSignal(signals, detector.code, SIGNAL_POINTS[detector.code], 'tool_name');
    }
  }

  inspectArguments(input.arguments, '$', signals);

  if (input.annotations?.destructiveHint === true) {
    addSignal(signals, 'destructive', SIGNAL_POINTS.destructive, 'annotation');
  }
  if (input.annotations?.openWorldHint === true) {
    addSignal(signals, 'open_world', SIGNAL_POINTS.open_world, 'annotation');
  }

  const base = explicitlyLocalRead ? 10 : 25;
  const orderedSignals = [...signals.values()].sort((left, right) => left.code.localeCompare(right.code));
  const score = Math.min(100, base + orderedSignals.reduce((sum, signal) => sum + signal.points, 0));

  return {
    score,
    band: bandForScore(score),
    signals: orderedSignals,
  };
}

function inspectArguments(
  value: unknown,
  path: string,
  signals: Map<RiskSignalCode, RiskSignal>,
): void {
  if (Array.isArray(value)) {
    value.forEach((item, index) => inspectArguments(item, `${path}[${index}]`, signals));
    return;
  }

  if (typeof value !== 'object' || value === null) {
    if (typeof value === 'string') {
      if (PRIVILEGED_VALUE.test(value)) {
        addSignal(signals, 'privileged_target', SIGNAL_POINTS.privileged_target, 'argument_value', path);
      }
      if (BROAD_VALUE.test(value)) {
        addSignal(signals, 'broad_target', SIGNAL_POINTS.broad_target, 'argument_value', path);
      }
    }
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const nestedPath = `${path}.${key}`;
    if (CREDENTIAL_KEY.test(key)) {
      addSignal(signals, 'credential_access', SIGNAL_POINTS.credential_access, 'argument_key', nestedPath);
    }
    inspectArguments(nested, nestedPath, signals);
  }
}

function addSignal(
  signals: Map<RiskSignalCode, RiskSignal>,
  code: RiskSignalCode,
  points: number,
  source: RiskSignal['source'],
  evidencePath?: string,
): void {
  if (signals.has(code)) return;
  signals.set(code, {
    code,
    points,
    source,
    ...(evidencePath === undefined ? {} : { evidencePath }),
  });
}

function bandForScore(score: number): RiskBand {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 30) return 'medium';
  return 'low';
}
