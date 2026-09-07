import { createHash, timingSafeEqual } from 'node:crypto';

import { z } from 'zod';

import type { AuditDatabase } from '../db/database.js';
import { canonicalJson } from './canonical-json.js';
import {
  AuthorizationReceiptSchema,
  canonicalReceiptJson,
  OutcomeReceiptSchema,
  receiptDigest,
  type AuthorizationReceipt,
  type OutcomeReceipt,
} from './receipt.js';
import type { SqliteAuditRecorder } from './recorder.js';

const MAX_RECEIPT_FILE_BYTES = 1_048_576;
const MAX_SOURCE_NESTING = 64;
const HASH = /^[0-9a-f]{64}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;

const ReceiptEventProofSchema = z.object({
  sequence: z.number().int().positive(),
  eventType: z.enum(['authorization_receipt_finalized', 'outcome_receipt_finalized']),
  eventJson: z.string().min(1).max(524_288),
  previousHash: z.string().regex(HASH),
  eventHash: z.string().regex(HASH),
}).strict();

const ReceiptRecordSchema = z.object({
  receipt: z.union([AuthorizationReceiptSchema, OutcomeReceiptSchema]),
  digest: z.string().regex(DIGEST),
}).strict();

const ReceiptAuditEventSchema = z.object({
  eventId: z.uuid(),
  toolCallId: z.uuid(),
  eventType: z.enum(['authorization_receipt_finalized', 'outcome_receipt_finalized']),
  details: z.object({
    receipt: z.unknown(),
    receiptDigest: z.string().regex(DIGEST),
  }).strict(),
  createdAt: z.iso.datetime({ offset: true }),
}).strict();

export const PortableReceiptEnvelopeSchema = z.object({
  format: z.object({
    name: z.literal('apg-portable-evidence'),
    majorVersion: z.literal(1),
    minorVersion: z.literal(0),
    canonicalization: z.literal('apg-canonical-json-v1'),
  }).strict(),
  actionId: z.uuid(),
  assuranceLevel: z.literal('portable_unsigned'),
  completeness: z.enum(['complete', 'authorization_only', 'incomplete', 'legacy_incomplete']),
  authorization: ReceiptRecordSchema.extend({ receipt: AuthorizationReceiptSchema }).strict().optional(),
  outcome: ReceiptRecordSchema.extend({ receipt: OutcomeReceiptSchema }).strict().optional(),
  legacy: z.object({
    status: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/),
    startedAt: z.iso.datetime({ offset: true }),
    reason: z.literal('receipt_evidence_unavailable'),
  }).strict().optional(),
  localEvidence: z.object({
    chainId: z.literal('apg-local-global-v1'),
    chainVerifiedAtExport: z.literal(true),
    proofs: z.array(ReceiptEventProofSchema).max(2),
    continuityToGenesisIncluded: z.literal(false),
  }).strict(),
  limitations: z.object({
    issuerAuthentication: z.literal('none'),
    localChainRecomputableByDatabaseOwner: z.literal(true),
    directBypassUnprotected: z.literal(true),
    unobservedEffects: z.literal(true),
  }).strict(),
}).strict();

export type PortableReceiptEnvelope = z.infer<typeof PortableReceiptEnvelopeSchema>;

export type PortableReceiptVerification = Readonly<{
  valid: boolean;
  status: 'verified_unsigned' | 'incomplete' | 'legacy_incomplete' | 'invalid';
  actionId?: string;
  message: string;
}>;

type ReceiptEventRow = {
  sequence: number;
  event_type: string;
  event_json: string;
  previous_hash: string;
  event_hash: string;
};

type ToolCallRow = {
  id: string;
  status: string;
  started_at: string;
};

type ParsedReceiptEvent = Readonly<{
  proof: z.infer<typeof ReceiptEventProofSchema>;
  receipt: AuthorizationReceipt | OutcomeReceipt;
  digest: string;
}>;

export class PortableReceiptService {
  constructor(
    private readonly database: AuditDatabase,
    private readonly recorder: SqliteAuditRecorder,
  ) {}

  exportAction(actionId: string): PortableReceiptEnvelope {
    if (!z.uuid().safeParse(actionId).success) throw new Error('Receipt action ID must be a UUID');
    return this.database.transaction(() => this.exportSnapshot(actionId))();
  }

  private exportSnapshot(actionId: string): PortableReceiptEnvelope {
    if (!this.recorder.verifyHashChain()) {
      throw new Error('Local audit chain verification failed; refusing to export evidence');
    }
    const toolCall = this.database.prepare(`
      SELECT id, status, started_at FROM tool_calls WHERE id = ?
    `).get(actionId) as ToolCallRow | undefined;
    if (toolCall === undefined) throw new Error('Audit action was not found');

    const rows = this.database.prepare(`
      SELECT sequence, event_type, event_json, previous_hash, event_hash
      FROM audit_events
      WHERE tool_call_id = ?
        AND event_type IN ('authorization_receipt_finalized', 'outcome_receipt_finalized')
      ORDER BY sequence ASC
    `).all(actionId) as ReceiptEventRow[];
    const events = rows.map(parseReceiptEvent);
    const authorizationEvents = events.filter(
      (event): event is ParsedReceiptEvent & { receipt: AuthorizationReceipt } =>
        event.receipt.receipt.type === 'authorization',
    );
    const outcomeEvents = events.filter(
      (event): event is ParsedReceiptEvent & { receipt: OutcomeReceipt } =>
        event.receipt.receipt.type === 'outcome',
    );
    if (authorizationEvents.length > 1 || outcomeEvents.length > 1) {
      throw new Error('Audit action contains duplicate receipt finalization events');
    }
    const authorization = authorizationEvents[0];
    const outcome = outcomeEvents[0];
    if (outcome !== undefined && authorization === undefined) {
      throw new Error('Outcome receipt is missing its Authorization Receipt');
    }

    const envelope = authorization === undefined
      ? legacyEnvelope(toolCall)
      : receiptEnvelope(toolCall, authorization, outcome);
    const parsed = PortableReceiptEnvelopeSchema.parse(envelope);
    assertEnvelopeRelationships(parsed);
    return parsed;
  }
}

export function serializePortableReceipt(envelope: PortableReceiptEnvelope): string {
  const parsed = PortableReceiptEnvelopeSchema.parse(envelope);
  assertEnvelopeRelationships(parsed);
  return `${canonicalReceiptJson(parsed)}\n`;
}

export function verifyPortableReceipt(source: string | Buffer): PortableReceiptVerification {
  try {
    const bytes = typeof source === 'string' ? Buffer.from(source, 'utf8') : source;
    if (bytes.byteLength > MAX_RECEIPT_FILE_BYTES) throw new Error('Receipt file exceeds the size limit');
    const text = bytes.toString('utf8');
    if (!Buffer.from(text, 'utf8').equals(bytes)) throw new Error('Receipt file must be valid UTF-8');
    assertSourceNesting(text);
    const parsedJson = JSON.parse(text) as unknown;
    const envelope = PortableReceiptEnvelopeSchema.parse(parsedJson);
    const canonical = `${canonicalReceiptJson(envelope)}\n`;
    if (text !== canonical) throw new Error('Receipt file is not canonical apg-canonical-json-v1');
    assertEnvelopeRelationships(envelope);

    if (envelope.completeness === 'legacy_incomplete') {
      return {
        valid: true,
        status: 'legacy_incomplete',
        actionId: envelope.actionId,
        message: 'Legacy audit data is structurally valid but lacks portable receipt evidence.',
      };
    }
    if (envelope.completeness === 'incomplete') {
      return {
        valid: true,
        status: 'incomplete',
        actionId: envelope.actionId,
        message: 'Authorization is valid, but no terminal Outcome Receipt is available.',
      };
    }
    return {
      valid: true,
      status: 'verified_unsigned',
      actionId: envelope.actionId,
      message: 'Receipt structure and digests verified; issuer identity is not authenticated.',
    };
  } catch (error) {
    return {
      valid: false,
      status: 'invalid',
      message: error instanceof Error ? error.message : 'Receipt verification failed',
    };
  }
}

function parseReceiptEvent(row: ReceiptEventRow): ParsedReceiptEvent {
  if (canonicalJson(JSON.parse(row.event_json) as unknown) !== row.event_json) {
    throw new Error('Receipt audit event is not canonical');
  }
  if (sha256(`${row.previous_hash}\n${row.event_json}`) !== row.event_hash) {
    throw new Error('Receipt audit event hash is invalid');
  }
  const wrapper = ReceiptAuditEventSchema.parse(JSON.parse(row.event_json) as unknown);
  if (wrapper.eventType !== row.event_type) throw new Error('Receipt event type does not match its database row');
  const receipt = wrapper.eventType === 'authorization_receipt_finalized'
    ? AuthorizationReceiptSchema.parse(wrapper.details.receipt)
    : OutcomeReceiptSchema.parse(wrapper.details.receipt);
  if (!digestEquals(receiptDigest(receipt), wrapper.details.receiptDigest)) {
    throw new Error('Stored receipt digest is invalid');
  }
  return {
    proof: {
      sequence: row.sequence,
      eventType: wrapper.eventType,
      eventJson: row.event_json,
      previousHash: row.previous_hash,
      eventHash: row.event_hash,
    },
    receipt,
    digest: wrapper.details.receiptDigest,
  };
}

function legacyEnvelope(toolCall: ToolCallRow): PortableReceiptEnvelope {
  return PortableReceiptEnvelopeSchema.parse({
    ...baseEnvelope(toolCall.id, 'legacy_incomplete'),
    legacy: {
      status: safeStatus(toolCall.status),
      startedAt: toolCall.started_at,
      reason: 'receipt_evidence_unavailable',
    },
    localEvidence: localEvidence([]),
  });
}

function receiptEnvelope(
  toolCall: ToolCallRow,
  authorization: ParsedReceiptEvent & { receipt: AuthorizationReceipt },
  outcome: (ParsedReceiptEvent & { receipt: OutcomeReceipt }) | undefined,
): PortableReceiptEnvelope {
  if (authorization.receipt.action.id !== toolCall.id) throw new Error('Authorization Receipt action mismatch');
  const authorized = authorization.receipt.authorization.status === 'authorized';
  const completeness = outcome === undefined
    ? authorized ? 'incomplete' : 'authorization_only'
    : isIncompleteOutcome(outcome.receipt) ? 'incomplete' : 'complete';
  return PortableReceiptEnvelopeSchema.parse({
    ...baseEnvelope(toolCall.id, completeness),
    authorization: { receipt: authorization.receipt, digest: authorization.digest },
    ...(outcome === undefined ? {} : { outcome: { receipt: outcome.receipt, digest: outcome.digest } }),
    localEvidence: localEvidence([
      authorization.proof,
      ...(outcome === undefined ? [] : [outcome.proof]),
    ]),
  });
}

function baseEnvelope(
  actionId: string,
  completeness: PortableReceiptEnvelope['completeness'],
): Omit<PortableReceiptEnvelope, 'localEvidence'> {
  return {
    format: {
      name: 'apg-portable-evidence',
      majorVersion: 1,
      minorVersion: 0,
      canonicalization: 'apg-canonical-json-v1',
    },
    actionId,
    assuranceLevel: 'portable_unsigned',
    completeness,
    limitations: {
      issuerAuthentication: 'none',
      localChainRecomputableByDatabaseOwner: true,
      directBypassUnprotected: true,
      unobservedEffects: true,
    },
  };
}

function localEvidence(
  proofs: readonly z.infer<typeof ReceiptEventProofSchema>[],
): PortableReceiptEnvelope['localEvidence'] {
  return {
    chainId: 'apg-local-global-v1',
    chainVerifiedAtExport: true,
    proofs: [...proofs],
    continuityToGenesisIncluded: false,
  };
}

function assertEnvelopeRelationships(envelope: PortableReceiptEnvelope): void {
  const authorization = envelope.authorization;
  const outcome = envelope.outcome;
  if (envelope.completeness === 'legacy_incomplete') {
    if (envelope.legacy === undefined || authorization !== undefined || outcome !== undefined) {
      throw new Error('Legacy receipt envelope has inconsistent evidence');
    }
    if (envelope.localEvidence.proofs.length !== 0) throw new Error('Legacy evidence cannot contain receipt proofs');
    return;
  }
  if (envelope.legacy !== undefined || authorization === undefined) {
    throw new Error('Portable receipt envelope is missing Authorization evidence');
  }
  if (authorization.receipt.action.id !== envelope.actionId) throw new Error('Authorization action ID mismatch');
  if (!digestEquals(receiptDigest(authorization.receipt), authorization.digest)) {
    throw new Error('Authorization Receipt digest is invalid');
  }
  if (outcome !== undefined) {
    if (authorization.receipt.authorization.status !== 'authorized') {
      throw new Error('Outcome Receipt cannot extend a blocked authorization');
    }
    if (outcome.receipt.action.id !== envelope.actionId) throw new Error('Outcome action ID mismatch');
    if (!digestEquals(receiptDigest(outcome.receipt), outcome.digest)) throw new Error('Outcome Receipt digest is invalid');
    if (!digestEquals(outcome.receipt.authorizationReceiptDigest, authorization.digest)) {
      throw new Error('Outcome Receipt does not extend this Authorization Receipt');
    }
    if (canonicalReceiptJson(outcome.receipt.action) !== canonicalReceiptJson(authorization.receipt.action)) {
      throw new Error('Outcome Receipt action does not match authorization');
    }
  }

  const expectedCompleteness = outcome !== undefined
    ? isIncompleteOutcome(outcome.receipt) ? 'incomplete' : 'complete'
    : authorization.receipt.authorization.status === 'authorized' ? 'incomplete' : 'authorization_only';
  if (envelope.completeness !== expectedCompleteness) throw new Error('Receipt completeness is inconsistent');

  const expectedRecords = [authorization, ...(outcome === undefined ? [] : [outcome])];
  if (envelope.localEvidence.proofs.length !== expectedRecords.length) {
    throw new Error('Receipt event proof count is inconsistent');
  }
  envelope.localEvidence.proofs.forEach((proof, index) => {
    const record = expectedRecords[index];
    if (record === undefined) throw new Error('Unexpected receipt event proof');
    verifyProof(proof, record);
    if (index > 0 && proof.sequence <= envelope.localEvidence.proofs[index - 1]!.sequence) {
      throw new Error('Receipt event proof sequence is not increasing');
    }
  });
}

function verifyProof(
  proof: z.infer<typeof ReceiptEventProofSchema>,
  record: z.infer<typeof ReceiptRecordSchema>,
): void {
  if (sha256(`${proof.previousHash}\n${proof.eventJson}`) !== proof.eventHash) {
    throw new Error('Receipt event proof hash is invalid');
  }
  const event = ReceiptAuditEventSchema.parse(JSON.parse(proof.eventJson) as unknown);
  if (canonicalJson(event) !== proof.eventJson) throw new Error('Receipt event proof is not canonical');
  if (
    event.eventType !== proof.eventType
    || event.toolCallId !== record.receipt.action.id
    || event.details.receiptDigest !== record.digest
    || canonicalReceiptJson(event.details.receipt) !== canonicalReceiptJson(record.receipt)
  ) {
    throw new Error('Receipt event proof does not match its receipt');
  }
}

function digestEquals(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

function isIncompleteOutcome(receipt: OutcomeReceipt): boolean {
  return receipt.execution.terminalStatus === 'audit_failed'
    || receipt.execution.terminalStatus === 'outcome_unknown_after_interruption';
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function safeStatus(status: string): string {
  return /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(status)
    ? status
    : `opaque_status_${sha256(status).slice(0, 32)}`;
}

function assertSourceNesting(source: string): void {
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (const character of source) {
    if (inString) {
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === '"') inString = false;
      continue;
    }
    if (character === '"') inString = true;
    else if (character === '{' || character === '[') {
      depth += 1;
      if (depth > MAX_SOURCE_NESTING) throw new Error('Receipt source exceeds the nesting limit');
    } else if (character === '}' || character === ']') {
      depth -= 1;
      if (depth < 0) throw new Error('Receipt source has invalid nesting');
    }
  }
  if (inString || depth !== 0) throw new Error('Receipt source has invalid nesting');
}
