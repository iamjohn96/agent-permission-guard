import { describe, expect, it } from 'vitest';

import { InMemoryInstallMetadataProvider } from '../../src/install/metadata.js';
import { InstallParseError, parseInstallRequest } from '../../src/install/parser.js';
import { evaluateInstallPolicy } from '../../src/install/policy.js';
import { scoreInstallRisk } from '../../src/install/risk.js';
import type { ResolvedPackageMetadata } from '../../src/install/types.js';

const workingDirectory = '/tmp/apg-install-test';

describe('Install Guard parser', () => {
  it('normalizes one registry package and supported options', () => {
    expect(parseInstallRequest('npm', ['--save-exact', 'yaml@2.9.0', '--save-dev'], workingDirectory)).toEqual({
      runner: 'npm',
      packageName: 'yaml',
      requestedSpecifier: '2.9.0',
      options: ['--save-dev', '--save-exact'],
      workingDirectory,
    });
  });

  it('parses scoped packages without confusing the scope marker for a version', () => {
    expect(parseInstallRequest('npx', ['--yes', '@modelcontextprotocol/server@2.0.0'], workingDirectory)).toMatchObject({
      runner: 'npx',
      packageName: '@modelcontextprotocol/server',
      requestedSpecifier: '2.0.0',
      options: ['--yes'],
    });
  });

  it.each([
    ['npm', ['left-pad', 'yaml']],
    ['npm', ['yaml;whoami']],
    ['npm', ['https://example.com/package.tgz']],
    ['npm', ['../local-package']],
    ['npm', ['yaml', '--force']],
    ['npx', ['yaml', '--save-dev']],
  ] as const)('rejects ambiguous or unsupported %s input %j', (runner, args) => {
    expect(() => parseInstallRequest(runner, args, workingDirectory)).toThrow(InstallParseError);
  });

  it('requires an absolute working directory as part of the approval identity', () => {
    expect(() => parseInstallRequest('npm', ['yaml'], 'relative/project')).toThrow(/absolute path/);
  });
});

describe('Install Guard offline metadata', () => {
  it('resolves only an exact fixture key and fails closed for other requests', async () => {
    const request = parseInstallRequest('npm', ['yaml@2.9.0'], workingDirectory);
    const metadata = safeMetadata();
    const provider = new InMemoryInstallMetadataProvider([{
      request,
      resolution: { status: 'resolved', metadata },
    }]);

    await expect(provider.resolve(request)).resolves.toEqual({ status: 'resolved', metadata });
    await expect(provider.resolve({ ...request, requestedSpecifier: 'latest' })).resolves.toMatchObject({
      status: 'unavailable',
    });
  });
});

describe('Install Guard risk and built-in policy', () => {
  it('allows an exactly resolved registry package with no material signal', () => {
    expect(evaluateInstallPolicy({ status: 'resolved', metadata: safeMetadata() })).toEqual({
      effectiveDecision: 'allow',
      reasonCodes: ['verified_registry_package'],
      risk: { score: 0, band: 'low', signals: [] },
    });
  });

  it('asks when lifecycle scripts exist', () => {
    const evaluation = evaluateInstallPolicy({
      status: 'resolved',
      metadata: { ...safeMetadata(), lifecycleScripts: ['postinstall'] },
    });

    expect(evaluation).toMatchObject({ effectiveDecision: 'ask', risk: { score: 35, band: 'medium' } });
    expect(evaluation.reasonCodes).toContain('lifecycle_scripts');
  });

  it('denies an unresolved exact version even when no other metadata exists', () => {
    expect(evaluateInstallPolicy({ status: 'unresolved', reason: 'tag did not resolve' })).toMatchObject({
      effectiveDecision: 'deny',
      risk: { score: 100, band: 'critical' },
    });
  });

  it('never silently allows unavailable or contradictory metadata', () => {
    expect(evaluateInstallPolicy({ status: 'unavailable', reason: 'offline' }).effectiveDecision).toBe('ask');
    expect(evaluateInstallPolicy({ status: 'contradictory', reason: 'mismatch' }).effectiveDecision).toBe('ask');
  });

  it('uses the strictest decision when explain-only and blocking signals coexist', () => {
    const evaluation = evaluateInstallPolicy({
      status: 'resolved',
      metadata: {
        ...safeMetadata(),
        packageIsNew: true,
        repositoryMissing: true,
        advisories: [{ id: 'APG-TEST-1', severity: 'critical' }],
      },
    });

    expect(evaluation.effectiveDecision).toBe('deny');
    expect(evaluation.risk.score).toBe(100);
    expect(evaluation.reasonCodes).toEqual(['critical_advisory', 'new_package', 'repository_missing']);
  });

  it('escalates combined explain-only signals when their total risk is high', () => {
    const evaluation = evaluateInstallPolicy({
      status: 'resolved',
      metadata: {
        ...safeMetadata(),
        packageIsNew: true,
        publisherIsNew: true,
      },
    });

    expect(evaluation).toMatchObject({ effectiveDecision: 'ask', risk: { score: 50, band: 'high' } });
    expect(evaluation.reasonCodes).toEqual([
      'new_package',
      'new_publisher',
      'install_risk_escalation',
    ]);
  });

  it('deduplicates stable risk reason codes', () => {
    const assessment = scoreInstallRisk({
      status: 'resolved',
      metadata: {
        ...safeMetadata(),
        advisories: [
          { id: 'APG-TEST-1', severity: 'high' },
          { id: 'APG-TEST-2', severity: 'high' },
        ],
      },
    });

    expect(assessment.signals.filter((signal) => signal.code === 'high_advisory')).toHaveLength(1);
  });
});

function safeMetadata(): ResolvedPackageMetadata {
  return {
    packageName: 'yaml',
    version: '2.9.0',
    registry: 'https://registry.npmjs.org',
    observedAt: '2026-08-31T00:00:00.000Z',
    lifecycleScripts: [],
    advisories: [],
    possibleTyposquat: false,
    packageIsNew: false,
    publisherIsNew: false,
    repositoryMissing: false,
    provenanceInconsistent: false,
    mutableSource: false,
  };
}
