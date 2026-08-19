import type { ToolAnnotations } from '@modelcontextprotocol/server';

import type { RiskTag } from '../policy/schema.js';

export type RiskSignalCode = Exclude<RiskTag, 'local_read'> | 'unknown_tool';

export type RiskSignal = Readonly<{
  code: RiskSignalCode;
  points: number;
  source: 'policy_tag' | 'tool_name' | 'argument_key' | 'argument_value' | 'annotation';
  evidencePath?: string;
}>;

export type RiskBand = 'low' | 'medium' | 'high' | 'critical';

export type RiskAssessment = Readonly<{
  score: number;
  band: RiskBand;
  signals: readonly RiskSignal[];
}>;

export type RiskInput = Readonly<{
  toolName: string;
  arguments: Readonly<Record<string, unknown>>;
  policyTags: readonly RiskTag[];
  annotations?: ToolAnnotations;
}>;
