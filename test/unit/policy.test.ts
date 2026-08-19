import { mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { evaluatePolicy } from '../../src/policy/evaluator.js';
import { parsePolicyYaml, PolicyLoadError } from '../../src/policy/loader.js';
import { LivePolicyController, PolicyConflictError } from '../../src/policy/live-controller.js';
import { matchPolicy } from '../../src/policy/matcher.js';
import { PolicyDocumentSchema } from '../../src/policy/schema.js';

const basePolicy = PolicyDocumentSchema.parse({
  version: 1,
  rules: [
    {
      id: 'allow-search-glob',
      priority: 10,
      match: { server: '*', tools: ['search_*'] },
      decision: 'allow',
      risk_tags: ['local_read'],
    },
    {
      id: 'ask-exact-search',
      priority: 10,
      match: { server: 'repo', tools: ['search_repository'] },
      decision: 'ask',
    },
    {
      id: 'deny-main',
      priority: 100,
      match: { server: '*', tools: ['push_main'] },
      decision: 'deny',
    },
  ],
});

describe('policy loader', () => {
  it('parses a valid YAML policy and applies safe defaults', () => {
    const policy = parsePolicyYaml('version: 1\nrules: []\n');

    expect(policy.defaults.decision).toBe('ask');
    expect(policy.defaults.approval_ttl_seconds).toBe(120);
  });

  it('fails closed on malformed YAML', () => {
    expect(() => parsePolicyYaml('version: [1\n')).toThrow(PolicyLoadError);
  });

  it('rejects duplicate rule IDs', () => {
    const yaml = `
version: 1
rules:
  - id: same
    match: { server: "*", tools: [one] }
    decision: allow
  - id: same
    match: { server: "*", tools: [two] }
    decision: deny
`;

    expect(() => parsePolicyYaml(yaml)).toThrow(/Duplicate rule id/);
  });

  it('does not permit changing the unmatched default away from Ask', () => {
    const yaml = 'version: 1\ndefaults: { decision: allow }\nrules: []\n';

    expect(() => parsePolicyYaml(yaml)).toThrow(PolicyLoadError);
  });

  it('rejects oversized policy input before parsing', () => {
    const oversized = `#${'x'.repeat(1_048_576)}`;

    expect(() => parsePolicyYaml(oversized)).toThrow(/byte limit/);
  });
});

describe('policy matcher', () => {
  it('uses default Ask for unknown tools', () => {
    expect(matchPolicy(basePolicy, 'repo', 'unknown')).toMatchObject({
      decision: 'ask',
      reason: 'default_ask',
    });
  });

  it('prefers a more specific rule at the same priority', () => {
    expect(matchPolicy(basePolicy, 'repo', 'search_repository').rule?.id).toBe('ask-exact-search');
  });

  it('prefers higher priority before specificity', () => {
    expect(matchPolicy(basePolicy, 'repo', 'push_main').decision).toBe('deny');
  });

  it('treats regex metacharacters as literal text inside glob patterns', () => {
    const policy = PolicyDocumentSchema.parse({
      version: 1,
      rules: [{
        id: 'literal-dot',
        match: { server: 'repo.*', tools: ['read.*'] },
        decision: 'allow',
      }],
    });

    expect(matchPolicy(policy, 'repo.github', 'read.file').decision).toBe('allow');
    expect(matchPolicy(policy, 'repoXgithub', 'readXfile').decision).toBe('ask');
  });

  it('uses Deny over Ask over Allow for otherwise tied rules', () => {
    const policy = PolicyDocumentSchema.parse({
      version: 1,
      rules: ['allow', 'ask', 'deny'].map((decision) => ({
        id: decision,
        priority: 1,
        match: { server: '*', tools: ['same'] },
        decision,
      })),
    });

    expect(matchPolicy(policy, 'repo', 'same').decision).toBe('deny');
  });

  it('is deterministic regardless of input rule order', () => {
    const rules = [
      { id: 'b-rule', priority: 1, match: { server: '*', tools: ['same'] }, decision: 'ask' },
      { id: 'a-rule', priority: 1, match: { server: '*', tools: ['same'] }, decision: 'ask' },
    ] as const;
    const forward = PolicyDocumentSchema.parse({ version: 1, rules });
    const reversed = PolicyDocumentSchema.parse({ version: 1, rules: [...rules].reverse() });

    expect(matchPolicy(forward, 'repo', 'same').rule?.id).toBe('a-rule');
    expect(matchPolicy(reversed, 'repo', 'same').rule?.id).toBe('a-rule');
  });
});

describe('policy evaluator', () => {
  it('escalates a high-risk Allow to Ask', () => {
    const policy = PolicyDocumentSchema.parse({
      version: 1,
      rules: [{
        id: 'overly-broad-allow',
        match: { server: '*', tools: ['delete_repository'] },
        decision: 'allow',
        risk_tags: ['destructive', 'external_side_effect'],
      }],
    });

    const evaluation = evaluatePolicy(policy, {
      serverId: 'github',
      toolName: 'delete_repository',
      arguments: { target: '*' },
    });

    expect(evaluation.baseDecision).toBe('allow');
    expect(evaluation.effectiveDecision).toBe('ask');
    expect(evaluation.reasonCodes).toContain('risk_escalation');
  });

  it('never lowers an explicit Deny', () => {
    const evaluation = evaluatePolicy(basePolicy, {
      serverId: 'github',
      toolName: 'push_main',
      arguments: {},
    });

    expect(evaluation.baseDecision).toBe('deny');
    expect(evaluation.effectiveDecision).toBe('deny');
  });
});

describe('live policy controller', () => {
  it('atomically saves a valid policy, applies it immediately, and rejects stale or invalid writes', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'apg-policy-'));
    const path = join(directory, 'policy.yaml');
    const initial = 'version: 1\nrules:\n  - id: allow-read\n    match: { server: repo, tools: [read_file] }\n    decision: allow\n    risk_tags: [local_read]\n';
    writeFileSync(path, initial, { mode: 0o644 });

    try {
      const controller = new LivePolicyController(path);
      const original = controller.getView();
      expect((await controller.evaluate({ serverId: 'repo', toolName: 'read_file', arguments: {} })).action).toBe('forward');

      const next = 'version: 1\ndefaults:\n  approval_ttl_seconds: 5\n  tool_timeout_seconds: 60\nrules:\n  - id: deny-read\n    match: { server: repo, tools: [read_file] }\n    decision: deny\n';
      const updated = controller.update(next, original.revision);
      expect(updated.source).toBe(next);
      expect(controller.getApprovalTtlMs()).toBe(5_000);
      expect((await controller.evaluate({ serverId: 'repo', toolName: 'read_file', arguments: {} })).action).toBe('deny');
      expect(statSync(path).mode & 0o777).toBe(0o600);
      expect(readdirSync(directory)).toEqual(['policy.yaml']);

      expect(() => controller.update('version: [1\n', updated.revision)).toThrow(PolicyLoadError);
      expect(controller.getView()).toEqual(updated);
      expect(() => controller.update(initial, original.revision)).toThrow(PolicyConflictError);

      writeFileSync(path, initial, { mode: 0o600 });
      expect(() => controller.update(initial, updated.revision)).toThrow(/outside APG/);
      expect(controller.getView()).toEqual(updated);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
