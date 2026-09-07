import { describe, expect, it } from 'vitest';

import { PortableReceiptService, serializePortableReceipt, verifyPortableReceipt } from '../../src/audit/portable-receipt.js';
import { canonicalReceiptJson, type ReceiptContext } from '../../src/audit/receipt.js';
import { SqliteAuditRecorder } from '../../src/audit/recorder.js';
import { LocalApprovalService } from '../../src/approval/service.js';
import { openAuditDatabase } from '../../src/db/database.js';
import { prepareToolCall } from '../../src/gateway/call-interceptor.js';
import {
  defineMcpIdentityProfile,
  ExactMcpIdentityRequiredError,
  McpIdentityAuthority,
  observedInputSchemaDigest,
  optionalIdentityField,
  publicBoolean,
  publicEnum,
  publicInteger,
  publicString,
  publicStringList,
  type McpIdentityField,
} from '../../src/identity/mcp-identity.js';

const inputSchema = {
  type: 'object' as const,
  properties: {
    count: { type: 'integer' },
    enabled: { type: 'boolean' },
    labels: { type: 'array', items: { type: 'string' } },
    mode: { type: 'string', enum: ['read', 'write'] },
    note: { type: 'string' },
  },
  required: ['count', 'enabled', 'labels', 'mode'],
  additionalProperties: false,
};

function exactProfile() {
  return defineMcpIdentityProfile({
    id: 'synthetic.action.v1',
    version: 1,
    serverId: 'synthetic-server',
    toolName: 'synthetic_action',
    parameterCoverage: 'complete_action_parameters',
    expectedInputSchemaDigest: observedInputSchemaDigest(inputSchema),
    fields: {
      mode: publicEnum(['read', 'write']),
      count: publicInteger({ minimum: 0, maximum: 10 }),
      enabled: publicBoolean(),
      labels: publicStringList({ maxItems: 4, itemMaxLength: 24 }),
      note: optionalIdentityField(publicString({ maxLength: 40 })),
    },
  });
}

function exactArguments() {
  return {
    mode: 'write',
    count: 2,
    enabled: true,
    labels: ['alpha', 'beta'],
  };
}

describe('trusted MCP identity profiles', () => {
  it('binds typed claims deterministically and dispatches only the frozen snapshot', () => {
    const authority = new McpIdentityAuthority([exactProfile()]);
    const original = { name: 'synthetic_action', arguments: exactArguments() };
    const prepared = prepareToolCall(
      'synthetic-server',
      original,
      undefined,
      inputSchema,
      authority,
    );
    const sameSemanticInput = prepareToolCall(
      'synthetic-server',
      {
        name: 'synthetic_action',
        arguments: { labels: ['alpha', 'beta'], enabled: true, count: 2, mode: 'write' },
      },
      undefined,
      inputSchema,
      authority,
    );

    expect(prepared.context.identity?.assurance).toBe('adapter_action_exact');
    expect(prepared.context.identity?.evidence).toMatchObject({
      profileStatus: 'projected',
      parameterCoverage: 'complete_action_parameters',
      omittedCategories: [],
      serverProvenanceAssurance: 'configured_label_only',
    });
    expect(prepared.context.identity?.approvalView.safeClaims.map((claim) => claim.name)).toEqual([
      'count', 'enabled', 'labels', 'mode',
    ]);
    expect(canonicalReceiptJson(prepared.context.identity?.identityMaterial)).toBe(
      canonicalReceiptJson(sameSemanticInput.context.identity?.identityMaterial),
    );

    original.arguments.mode = 'read';
    original.arguments.labels.push('mutated');
    expect(prepared.dispatchParams.arguments).toEqual(exactArguments());
    expect(Object.isFrozen(prepared.dispatchParams)).toBe(true);
    expect(Object.isFrozen(prepared.dispatchParams.arguments)).toBe(true);

    const changed = prepareToolCall(
      'synthetic-server',
      { name: 'synthetic_action', arguments: { ...exactArguments(), count: 3 } },
      undefined,
      inputSchema,
      authority,
    );
    const reorderedList = prepareToolCall(
      'synthetic-server',
      { name: 'synthetic_action', arguments: { ...exactArguments(), labels: ['beta', 'alpha'] } },
      undefined,
      inputSchema,
      authority,
    );
    expect(canonicalReceiptJson(changed.context.identity?.identityMaterial)).not.toBe(
      canonicalReceiptJson(prepared.context.identity?.identityMaterial),
    );
    expect(canonicalReceiptJson(reorderedList.context.identity?.identityMaterial)).not.toBe(
      canonicalReceiptJson(prepared.context.identity?.identityMaterial),
    );
  });

  it('rejects unknown fields, invalid types, request metadata, and schema drift instead of claiming exactness', () => {
    const authority = new McpIdentityAuthority([exactProfile()]);
    const cases = [
      { name: 'synthetic_action', arguments: { ...exactArguments(), extra: 'unknown' } },
      { name: 'synthetic_action', arguments: { ...exactArguments(), count: '2' } },
      { name: 'synthetic_action', arguments: exactArguments(), task: { ttl: 30 } },
    ] as const;
    for (const params of cases) {
      expect(authority.prepare('synthetic-server', params, inputSchema).result).toMatchObject({
        assurance: 'structural_only',
        evidence: { profileStatus: 'rejected', parameterCoverage: 'none' },
      });
    }

    const changedSchema = { ...inputSchema, additionalProperties: true };
    expect(authority.prepare(
      'synthetic-server',
      { name: 'synthetic_action', arguments: exactArguments() },
      changedSchema,
    ).result).toMatchObject({
      assurance: 'structural_only',
      evidence: { failureCode: 'input_schema_mismatch' },
    });
    expect(() => authority.prepare(
      'synthetic-server',
      { name: 'synthetic_action', arguments: { ...exactArguments(), extra: 'unknown' } },
      inputSchema,
      'exact',
    )).toThrow(ExactMcpIdentityRequiredError);
  });

  it('keeps a partial projection useful without binding or exposing omitted sensitive input', () => {
    const profile = defineMcpIdentityProfile({
      id: 'synthetic.partial.v1',
      version: 1,
      serverId: 'synthetic-server',
      toolName: 'partial_action',
      parameterCoverage: 'declared_subset',
      omittedCategories: ['private_payload'],
      fields: { mode: publicEnum(['read', 'write']) },
    });
    const result = new McpIdentityAuthority([profile]).prepare('synthetic-server', {
      name: 'partial_action',
      arguments: { mode: 'write', payload: 'must-not-leak' },
    }).result;

    expect(result).toMatchObject({
      assurance: 'adapter_scoped',
      evidence: {
        parameterCoverage: 'declared_subset',
        omittedCategories: ['private_payload'],
      },
    });
    expect(JSON.stringify(result)).not.toContain('must-not-leak');
    expect(() => new McpIdentityAuthority([profile]).prepare(
      'synthetic-server',
      { name: 'partial_action', arguments: { mode: 'write', payload: 'hidden' } },
      undefined,
      'exact',
    )).toThrow(ExactMcpIdentityRequiredError);
  });

  it('rejects unsafe or ambiguous profile definitions', () => {
    expect(() => defineMcpIdentityProfile({
      id: 'synthetic.secret.v1',
      version: 1,
      serverId: 'synthetic-server',
      toolName: 'unsafe_action',
      parameterCoverage: 'complete_action_parameters',
      fields: { apiToken: publicString() },
    })).toThrow(/credential-like/);

    const profile = exactProfile();
    expect(() => new McpIdentityAuthority([profile, profile])).toThrow(/Duplicate/);
    expect(() => defineMcpIdentityProfile({
      id: 'synthetic.untrusted.v1',
      version: 1,
      serverId: 'synthetic-server',
      toolName: 'unsafe_action',
      parameterCoverage: 'complete_action_parameters',
      fields: {
        value: {
          optional: false,
          manifest: {},
          parse: () => ({ type: 'string', value: 'spoofed' }),
        } as McpIdentityField,
      },
    })).toThrow(/Untrusted identity field/);
  });
});

describe('MCP identity approval and receipt integration', () => {
  it('exports exact profile evidence as receipt schema 1.1 while remaining unsigned and private', () => {
    const authority = new McpIdentityAuthority([exactProfile()]);
    const context = prepareToolCall(
      'synthetic-server',
      { name: 'synthetic_action', arguments: exactArguments() },
      undefined,
      inputSchema,
      authority,
    ).context;
    const database = openAuditDatabase(':memory:');
    const recorder = new SqliteAuditRecorder(database);
    const call = recorder.begin(context, structuralDecision());
    const actionId = currentActionId(database);
    call.markForwarding();
    call.markCompleted({ content: [{ type: 'text', text: 'private upstream body' }] });

    const envelope = new PortableReceiptService(database, recorder).exportAction(actionId);
    const serialized = serializePortableReceipt(envelope);
    expect(envelope.format.minorVersion).toBe(1);
    expect(envelope.authorization?.receipt.schema.minorVersion).toBe(1);
    expect(envelope.authorization?.receipt.action).toMatchObject({
      identityAssurance: 'adapter_action_exact',
      identityEvidence: {
        profileId: 'synthetic.action.v1',
        parameterCoverage: 'complete_action_parameters',
      },
    });
    expect(envelope.outcome?.receipt.action).toEqual(envelope.authorization?.receipt.action);
    expect(verifyPortableReceipt(serialized)).toMatchObject({ valid: true, status: 'verified_unsigned' });
    expect(serialized).not.toContain('private upstream body');

    const invalidCoverage = structuredClone(envelope) as Record<string, any>;
    invalidCoverage.authorization.receipt.action.identityEvidence.parameterCoverage = 'declared_subset';
    expect(verifyPortableReceipt(`${canonicalReceiptJson(invalidCoverage)}\n`)).toMatchObject({
      valid: false,
      status: 'invalid',
    });
    database.close();
  });

  it('prevents a generic interceptor from self-declaring exact assurance', () => {
    const database = openAuditDatabase(':memory:');
    const recorder = new SqliteAuditRecorder(database);
    const context = {
      serverId: 'untrusted-server',
      toolName: 'untrusted_action',
      arguments: { value: 'private-value' },
    };
    const receipt: ReceiptContext = {
      ...baseReceiptContext(),
      identityAssurance: 'adapter_action_exact',
      identityMaterial: { arbitrary: 'caller-controlled' },
      identityEvidence: {
        profileStatus: 'projected',
        profileId: 'spoofed.profile.v1',
        profileVersion: 1,
        profileManifestDigest: `sha256:${'c'.repeat(64)}`,
        serverProvenanceAssurance: 'configured_label_only',
        parameterCoverage: 'complete_action_parameters',
        safeClaims: [],
        omittedCategories: [],
      },
    };
    const call = recorder.begin(context, {
      ...structuralDecision(),
      receipt,
    });
    const actionId = currentActionId(database);
    call.markForwarding();
    call.markCompleted({ content: [] });

    const envelope = new PortableReceiptService(database, recorder).exportAction(actionId);
    expect(envelope.authorization?.receipt.schema.minorVersion).toBe(0);
    expect(envelope.authorization?.receipt.action).toMatchObject({ identityAssurance: 'structural_only' });
    expect(envelope.authorization?.receipt.action.identityEvidence).toBeUndefined();
    database.close();
  });

  it('shows only trusted safe identity claims as the authoritative approval view', () => {
    const authority = new McpIdentityAuthority([exactProfile()]);
    const prepared = authority.prepare(
      'synthetic-server',
      { name: 'synthetic_action', arguments: exactArguments() },
      inputSchema,
    );
    const approvals = new LocalApprovalService();
    const ticket = approvals.request({
      serverId: 'synthetic-server',
      toolName: 'synthetic_action',
      arguments: { token: 'must-not-leak', other: 'redacted-preview' },
      identity: prepared.result.approvalView,
      risk: { score: 50, band: 'medium', signals: [] },
      reasonCodes: ['synthetic_approval'],
    }, 1_000);

    expect(ticket.request.identity).toMatchObject({
      assurance: 'adapter_action_exact',
      limitation: 'all_behavior_parameters_bound',
    });
    expect(JSON.stringify(ticket.request)).not.toContain('must-not-leak');
    approvals.close();
  });
});

function structuralDecision() {
  return {
    action: 'forward' as const,
    evaluation: {
      baseDecision: 'allow' as const,
      effectiveDecision: 'allow' as const,
      matchedRuleId: 'synthetic_rule',
      reasonCodes: ['synthetic_policy'],
      risk: { score: 0, band: 'low' as const, signals: [] },
    },
    receipt: baseReceiptContext(),
  };
}

function baseReceiptContext(): ReceiptContext {
  return {
    adapter: 'mcp_proxy',
    adapterVersion: '1',
    operation: 'synthetic_action',
    boundary: 'mcp_proxy_call',
    identityAssurance: 'structural_only',
    identityMaterial: { serverId: 'synthetic-server', toolName: 'synthetic_action' },
    policy: {
      schemaVersion: 1,
      contentDigest: `sha256:${'b'.repeat(64)}`,
      evaluatorName: 'synthetic_evaluator',
      evaluatorVersion: '1',
    },
  };
}

function currentActionId(database: ReturnType<typeof openAuditDatabase>): string {
  const row = database.prepare('SELECT id FROM tool_calls ORDER BY rowid DESC LIMIT 1').get() as { id: string };
  return row.id;
}
