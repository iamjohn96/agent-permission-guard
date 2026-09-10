import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import {
  PortableReceiptService,
  serializePortableReceipt,
  verifyPortableReceipt,
} from '../../src/audit/portable-receipt.js';
import { canonicalReceiptJson, type ReceiptContext } from '../../src/audit/receipt.js';
import { SqliteAuditRecorder } from '../../src/audit/recorder.js';
import { parseReceiptArguments, runReceipt } from '../../src/cli/receipt.js';
import { openAuditDatabase } from '../../src/db/database.js';
import { policyIdentity } from '../../src/policy/identity.js';
import { parsePolicyYaml } from '../../src/policy/loader.js';
import { APG_VERSION } from '../../src/version.js';

const temporaryPaths: string[] = [];

afterEach(() => {
  for (const path of temporaryPaths.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe('portable unsigned receipt', () => {
  it('records Graph output overflow with detailed incomplete external-read evidence', () => {
    const database = openAuditDatabase(':memory:');
    const recorder = new SqliteAuditRecorder(database);
    const call = recorder.begin(
      { serverId: 'apg-graph-genesis', toolName: 'filesystem_metadata_graph', arguments: {} },
      { ...receiptDecision('forward'), receipt: graphReceiptContext() },
    );
    call.markAuthorized();
    call.markExecutionStarted();
    call.finalizeGraphGenesisOutcome({
      metadata: { externalReadStatus: 'incomplete', requestCount: 1, uniquePackageCount: 1, responseBytes: 128 },
      process: { status: 'output_overflow', exitCode: null, stdoutBytes: 262144, stderrBytes: 0 },
      cleanup: { status: 'quarantined', quarantineReferenceDigest: `sha256:${'c'.repeat(64)}` },
      terminalAudit: { status: 'complete' },
      errorCode: 'output_overflow',
    }, 'incomplete_external_read');
    const envelope = new PortableReceiptService(database, recorder).exportAction(call.actionId);
    expect(envelope.outcome?.receipt.execution).toMatchObject({
      terminalStatus: 'incomplete_external_read',
      observedResult: {
        kind: 'graph_genesis', executionStatus: 'output_overflow', externalReadStatus: 'incomplete',
        cleanupStatus: 'quarantined', terminalAuditStatus: 'complete', errorCode: 'output_overflow',
      },
    });
    expect(verifyPortableReceipt(serializePortableReceipt(envelope))).toMatchObject({ valid: true, status: 'incomplete' });
    database.close();
  });

  it('records a validated downstream failure atomically as execution_error and rejects the mismatched incomplete status', () => {
    const database = openAuditDatabase(':memory:');
    const recorder = new SqliteAuditRecorder(database);
    const summary = {
      metadata: { externalReadStatus: 'validated' as const, requestCount: 126, uniquePackageCount: 1, responseBytes: 6_792_802 },
      process: { status: 'completed' as const, exitCode: 0, stdoutBytes: 0, stderrBytes: 0 },
      cleanup: { status: 'quarantined' as const, quarantineReferenceDigest: `sha256:${'d'.repeat(64)}` },
      terminalAudit: { status: 'failed' as const }, errorCode: 'acceptance_incomplete',
    };
    const call = recorder.begin(
      { serverId: 'apg-graph-genesis', toolName: 'filesystem_metadata_graph', arguments: {} },
      { ...receiptDecision('forward'), receipt: graphReceiptContext() },
    );
    call.markAuthorized();
    call.markExecutionStarted();
    call.finalizeGraphGenesisOutcome(summary, 'execution_error');
    const terminalEvents = database.prepare(`
      SELECT event_type FROM audit_events WHERE tool_call_id = ?
      AND event_type IN ('graph_genesis_incomplete', 'execution_completed', 'outcome_receipt_finalized') ORDER BY sequence
    `).all(call.actionId);
    expect(terminalEvents).toEqual([
      { event_type: 'graph_genesis_incomplete' },
      { event_type: 'execution_completed' },
      { event_type: 'outcome_receipt_finalized' },
    ]);
    expect(new PortableReceiptService(database, recorder).exportAction(call.actionId).outcome?.receipt.execution)
      .toMatchObject({ terminalStatus: 'execution_error', observedResult: { externalReadStatus: 'validated' } });

    const rejected = recorder.begin(
      { serverId: 'apg-graph-genesis', toolName: 'filesystem_metadata_graph', arguments: {} },
      { ...receiptDecision('forward'), receipt: graphReceiptContext() },
    );
    rejected.markAuthorized();
    rejected.markExecutionStarted();
    expect(() => rejected.finalizeGraphGenesisOutcome(summary, 'incomplete_external_read'))
      .toThrow('Incomplete external read status lacks external-read evidence');
    expect(database.prepare(`
      SELECT event_type FROM audit_events WHERE tool_call_id = ?
      AND event_type IN ('graph_genesis_incomplete', 'execution_completed', 'outcome_receipt_finalized')
    `).all(rejected.actionId)).toEqual([]);
    database.close();
  });

  it('exports and independently verifies linked authorization and outcome evidence without sensitive output', () => {
    const database = openAuditDatabase(':memory:');
    const recorder = new SqliteAuditRecorder(database);
    const call = recorder.begin({
      serverId: 'install-guard',
      toolName: 'npm_install',
      arguments: {
        package: 'yaml@2.9.0',
        workingDirectory: '/Users/example/private-project',
        token: 'low-entropy-secret',
      },
    }, receiptDecision('ask'));
    const actionId = currentActionId(database);
    const approval = {
      id: '11111111-1111-4111-8111-111111111111',
      serverId: 'install-guard',
      toolName: 'npm install',
      arguments: {},
      risk: { score: 25, band: 'low' as const, signals: [] },
      reasonCodes: ['local_install_execution'],
      requestedAt: '2026-09-07T00:00:00.000Z',
      expiresAt: '2026-09-07T00:02:00.000Z',
    };
    call.markApprovalRequested(approval);
    call.markApprovalResolved(approval.id, 'approved');
    call.markForwarding();
    call.markExecutionResult({
      status: 'completed',
      exitCode: 0,
      durationMs: 12,
      output: {
        stdoutBytes: 120,
        stderrBytes: 0,
        stdoutPreview: 'must not enter portable evidence',
        stderrPreview: '',
        truncated: false,
      },
      verification: {
        status: 'verified',
        exactPackageVersionObserved: true,
        approvedIntegrityObserved: true,
        changedFiles: ['package-lock.json'],
        reasonCodes: [],
      },
    }, false);

    const receipts = new PortableReceiptService(database, recorder);
    const envelope = receipts.exportAction(actionId);
    const serialized = serializePortableReceipt(envelope);
    const verification = verifyPortableReceipt(serialized);

    expect(envelope.completeness).toBe('complete');
    expect(envelope.authorization?.receipt.action).toMatchObject({
      identityAssurance: 'execution_plan_exact',
      executionPlanHash: 'a'.repeat(64),
    });
    expect(envelope.authorization?.receipt.approval).toMatchObject({
      outcome: 'approved',
      principalAssurance: 'local_dashboard_session',
    });
    expect(envelope.outcome?.receipt.execution.observedResult).toMatchObject({
      kind: 'install',
      executionStatus: 'completed',
      stdoutBytes: 120,
      verificationStatus: 'verified',
    });
    expect(verification).toMatchObject({ valid: true, status: 'verified_unsigned', actionId });
    expect(serialized).not.toContain('low-entropy-secret');
    expect(serialized).not.toContain('/Users/example');
    expect(serialized).not.toContain('must not enter portable evidence');
    expect(serialized).toContain('directBypassUnprotected');
    expect(serializePortableReceipt(receipts.exportAction(actionId))).toBe(serialized);
    database.close();
  });

  it('rejects field mutation, cross-action substitution, unknown versions, and duplicate keys', () => {
    const database = openAuditDatabase(':memory:');
    const recorder = new SqliteAuditRecorder(database);
    const first = completedReceipt(database, recorder, 'yaml@2.9.0');
    const second = completedReceipt(database, recorder, 'zod@4.4.3');

    const mutated = structuredClone(first) as Record<string, any>;
    mutated.authorization.receipt.action.subject = 'other@1.0.0';
    expect(verifyPortableReceipt(`${canonicalReceiptJson(mutated)}\n`)).toMatchObject({
      valid: false,
      status: 'invalid',
    });

    const substituted = structuredClone(first) as Record<string, any>;
    substituted.outcome = second.outcome;
    substituted.localEvidence.proofs[1] = second.localEvidence.proofs[1];
    expect(verifyPortableReceipt(`${canonicalReceiptJson(substituted)}\n`)).toMatchObject({
      valid: false,
      status: 'invalid',
    });

    const unknownVersion = structuredClone(first) as Record<string, any>;
    unknownVersion.format.majorVersion = 2;
    expect(verifyPortableReceipt(`${canonicalReceiptJson(unknownVersion)}\n`).valid).toBe(false);

    const canonical = serializePortableReceipt(first);
    const duplicate = canonical.replace(
      '{"actionId":',
      `{"actionId":"${first.actionId}","actionId":`,
    );
    expect(verifyPortableReceipt(duplicate).valid).toBe(false);
    database.close();
  });

  it('reports authorized actions without terminal evidence as incomplete without rewriting the database', () => {
    const database = openAuditDatabase(':memory:');
    const recorder = new SqliteAuditRecorder(database);
    const call = recorder.begin(
      { serverId: 'fixture', toolName: 'write_file', arguments: { path: '/tmp/a' } },
      receiptDecision('forward'),
    );
    const actionId = currentActionId(database);
    call.markForwarding();

    const envelope = new PortableReceiptService(database, recorder).exportAction(actionId);
    expect(envelope.completeness).toBe('incomplete');
    expect(verifyPortableReceipt(serializePortableReceipt(envelope))).toMatchObject({
      valid: true,
      status: 'incomplete',
    });
    const row = database.prepare('SELECT status FROM tool_calls WHERE id = ?').get(actionId) as { status: string };
    expect(row.status).toBe('forwarding');
    database.close();
  });

  it('keeps a recoverable post-dispatch audit failure explicitly incomplete', () => {
    const database = openAuditDatabase(':memory:');
    const recorder = new SqliteAuditRecorder(database);
    const call = recorder.begin(
      { serverId: 'fixture', toolName: 'write_file', arguments: {} },
      receiptDecision('forward'),
    );
    const actionId = currentActionId(database);
    call.markForwarding();
    call.markFailed('audit_completion_failed');

    const envelope = new PortableReceiptService(database, recorder).exportAction(actionId);
    expect(envelope.completeness).toBe('incomplete');
    expect(envelope.outcome?.receipt.execution).toMatchObject({
      terminalStatus: 'audit_failed',
      observedResult: { isError: true, errorCode: 'audit_completion_failed' },
    });
    expect(verifyPortableReceipt(serializePortableReceipt(envelope))).toMatchObject({
      valid: true,
      status: 'incomplete',
    });
    database.close();
  });

  it('exports denied actions as authorization-only and old actions as legacy-incomplete', () => {
    const database = openAuditDatabase(':memory:');
    const recorder = new SqliteAuditRecorder(database);
    const denied = recorder.begin(
      { serverId: 'fixture', toolName: 'delete_all', arguments: {} },
      receiptDecision('deny'),
    );
    const deniedId = currentActionId(database);
    denied.markBlocked('denied');
    const deniedEnvelope = new PortableReceiptService(database, recorder).exportAction(deniedId);
    expect(deniedEnvelope.completeness).toBe('authorization_only');
    expect(verifyPortableReceipt(serializePortableReceipt(deniedEnvelope)).status).toBe('verified_unsigned');

    recorder.begin(
      { serverId: 'legacy', toolName: 'pending', arguments: {} },
      receiptDecision('ask'),
    );
    const legacyId = currentActionId(database);
    const legacyEnvelope = new PortableReceiptService(database, recorder).exportAction(legacyId);
    expect(legacyEnvelope.completeness).toBe('legacy_incomplete');
    expect(verifyPortableReceipt(serializePortableReceipt(legacyEnvelope))).toMatchObject({
      valid: true,
      status: 'legacy_incomplete',
    });
    database.close();
  });

  it('refuses to export from a locally invalid audit chain', () => {
    const database = openAuditDatabase(':memory:');
    const recorder = new SqliteAuditRecorder(database);
    completedReceipt(database, recorder, 'yaml@2.9.0');
    const actionId = currentActionId(database);
    database.prepare("UPDATE audit_events SET event_json = '{\"tampered\":true}' WHERE sequence = 1").run();

    expect(() => new PortableReceiptService(database, recorder).exportAction(actionId)).toThrow(/chain verification failed/);
    database.close();
  });

  it('writes an explicit private export without overwriting and verifies it offline', () => {
    const directory = temporaryDirectory();
    const databasePath = join(directory, 'audit.sqlite');
    const receiptPath = join(directory, 'action.apg-receipt.json');
    const database = openAuditDatabase(databasePath);
    const recorder = new SqliteAuditRecorder(database);
    completedReceipt(database, recorder, 'yaml@2.9.0');
    const actionId = currentActionId(database);
    database.close();
    const databaseDigestBeforeExport = fileDigest(databasePath);

    const output: string[] = [];
    const exportArguments = parseReceiptArguments([
      'export', actionId, '--audit-db', databasePath, '--output', receiptPath,
    ]);
    expect(runReceipt(exportArguments, { write: (text) => output.push(text) })).toEqual({ successful: true });
    expect(statSync(receiptPath).mode & 0o777).toBe(0o600);
    expect(fileDigest(databasePath)).toBe(databaseDigestBeforeExport);
    expect(output.join('')).toContain('PORTABLE_UNSIGNED');
    expect(() => runReceipt(exportArguments)).toThrow();

    const verifyOutput: string[] = [];
    expect(runReceipt(parseReceiptArguments(['verify', receiptPath]), {
      write: (text) => verifyOutput.push(text),
    })).toEqual({ successful: true });
    expect(verifyOutput.join('')).toContain('VERIFIED_UNSIGNED');
    expect(readFileSync(receiptPath, 'utf8')).toContain('issuerAuthentication');
  });
});

describe('receipt canonicalization and policy identity', () => {
  it('keeps the receipt issuer version aligned with the package version', () => {
    const packageJson = JSON.parse(readFileSync('package.json', 'utf8')) as { version: string };
    expect(APG_VERSION).toBe(packageJson.version);
  });

  it('is deterministic for JSON values and rejects unsafe values', () => {
    const fixtures = JSON.parse(readFileSync('test/fixtures/receipt-canonical-v1.json', 'utf8')) as Array<{
      name: string;
      value: unknown;
      canonical: string;
    }>;
    for (const fixture of fixtures) {
      expect(canonicalReceiptJson(fixture.value), fixture.name).toBe(fixture.canonical);
    }
    expect(canonicalReceiptJson({ negativeZero: -0 })).toBe('{"negativeZero":0}');
    expect(() => canonicalReceiptJson({ value: Number.NaN })).toThrow(/finite/);
    expect(() => canonicalReceiptJson({ value: undefined })).toThrow(/JSON data model/);
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => canonicalReceiptJson(cyclic)).toThrow(/cyclic/);
  });

  it('rejects oversized or excessively nested receipt sources before verification', () => {
    expect(verifyPortableReceipt(Buffer.alloc(1_048_577, 0x20))).toMatchObject({ valid: false, status: 'invalid' });
    const nested = `${'{"a":'.repeat(65)}null${'}'.repeat(65)}\n`;
    expect(verifyPortableReceipt(nested)).toMatchObject({ valid: false, status: 'invalid' });
  });

  it('digests the validated policy object rather than YAML formatting', () => {
    const compact = parsePolicyYaml('version: 1\nrules: []\n');
    const formatted = parsePolicyYaml('# comment\nrules: []\nversion: 1\n');
    const changed = parsePolicyYaml('version: 1\ndefaults: { approval_ttl_seconds: 5 }\nrules: []\n');

    expect(policyIdentity(compact).contentDigest).toBe(policyIdentity(formatted).contentDigest);
    expect(policyIdentity(changed).contentDigest).not.toBe(policyIdentity(compact).contentDigest);
  });
});

function receiptDecision(action: 'forward' | 'ask' | 'deny') {
  const decision = action === 'forward' ? 'allow' : action;
  return {
    action,
    ...(action === 'forward' ? {} : { reason: 'fixture' }),
    evaluation: {
      baseDecision: decision,
      effectiveDecision: decision,
      matchedRuleId: 'fixture_rule',
      reasonCodes: [action === 'ask' ? 'local_install_execution' : 'fixture_policy'],
      risk: { score: action === 'ask' ? 25 : 0, band: 'low' as const, signals: [] },
    },
    receipt: installReceiptContext('yaml@2.9.0'),
  } as const;
}

function installReceiptContext(subject: string): ReceiptContext {
  return {
    adapter: 'install_guard',
    adapterVersion: '1',
    operation: 'npm_install',
    boundary: 'install_guard_plan',
    identityAssurance: 'execution_plan_exact',
    identityMaterial: { planHash: 'a'.repeat(64) },
    subject,
    executionPlanHash: 'a'.repeat(64),
    policy: {
      schemaVersion: 1,
      contentDigest: `sha256:${'b'.repeat(64)}`,
      evaluatorName: 'fixture_evaluator',
      evaluatorVersion: '1',
    },
  };
}

function graphReceiptContext(): ReceiptContext {
  return {
    adapter: 'graph_genesis', adapterVersion: '1', operation: 'filesystem_metadata_graph',
    boundary: 'graph_genesis_plan', identityAssurance: 'execution_plan_exact',
    identityMaterial: { executionEnvelopeHash: 'd'.repeat(64) },
    subject: '@modelcontextprotocol/server-filesystem@2026.7.10', executionPlanHash: 'd'.repeat(64),
    policy: {
      schemaVersion: 1, contentDigest: `sha256:${'e'.repeat(64)}`,
      evaluatorName: 'graph_genesis_builtin_policy', evaluatorVersion: '1',
    },
  };
}

function completedReceipt(
  database: ReturnType<typeof openAuditDatabase>,
  recorder: SqliteAuditRecorder,
  subject: string,
) {
  const call = recorder.begin(
    { serverId: 'fixture', toolName: 'npm_install', arguments: { hidden: 'do-not-export' } },
    { ...receiptDecision('forward'), receipt: installReceiptContext(subject) },
  );
  const actionId = currentActionId(database);
  call.markForwarding();
  call.markExecutionResult({ status: 'completed', exitCode: 0, durationMs: 1 }, false);
  return new PortableReceiptService(database, recorder).exportAction(actionId);
}

function currentActionId(database: ReturnType<typeof openAuditDatabase>): string {
  const row = database.prepare('SELECT id FROM tool_calls ORDER BY rowid DESC LIMIT 1').get() as { id: string };
  return row.id;
}

function temporaryDirectory(): string {
  const path = mkdtempSync(join(tmpdir(), 'apg-receipt-'));
  temporaryPaths.push(path);
  return path;
}

function fileDigest(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}
