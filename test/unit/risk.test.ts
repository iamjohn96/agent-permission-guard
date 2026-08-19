import { describe, expect, it } from 'vitest';

import { scoreRisk } from '../../src/risk/scorer.js';

describe('risk scorer v0', () => {
  it('scores an explicitly classified local read as low risk', () => {
    expect(scoreRisk({
      toolName: 'read_file',
      arguments: { path: '/tmp/example.txt' },
      policyTags: ['local_read'],
    })).toMatchObject({ score: 10, band: 'low', signals: [] });
  });

  it('deduplicates risk categories across multiple sources', () => {
    const assessment = scoreRisk({
      toolName: 'delete-file',
      arguments: {},
      policyTags: ['destructive'],
      annotations: { destructiveHint: true },
    });

    expect(assessment.signals.filter((signal) => signal.code === 'destructive')).toHaveLength(1);
    expect(assessment.score).toBe(55);
  });

  it('detects credential keys without including their values as evidence', () => {
    const assessment = scoreRisk({
      toolName: 'connect',
      arguments: { apiToken: 'must-not-appear' },
      policyTags: [],
    });
    const signal = assessment.signals.find((item) => item.code === 'credential_access');

    expect(signal).toMatchObject({ source: 'argument_key', evidencePath: '$.apiToken' });
    expect(JSON.stringify(assessment)).not.toContain('must-not-appear');
  });

  it('treats broad privileged destructive actions as critical', () => {
    const assessment = scoreRisk({
      toolName: 'delete_repository',
      arguments: { branch: 'main', target: '*' },
      policyTags: ['destructive', 'external_side_effect'],
    });

    expect(assessment.score).toBe(100);
    expect(assessment.band).toBe('critical');
  });

  it('does not reduce risk from safe-looking untrusted annotations', () => {
    const withoutAnnotations = scoreRisk({
      toolName: 'unknown_tool',
      arguments: {},
      policyTags: [],
    });
    const withSafeHints = scoreRisk({
      toolName: 'unknown_tool',
      arguments: {},
      policyTags: [],
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    });

    expect(withSafeHints).toEqual(withoutAnnotations);
  });
});
