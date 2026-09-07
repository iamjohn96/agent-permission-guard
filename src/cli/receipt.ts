import {
  closeSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { resolve } from 'node:path';

import { PortableReceiptService, serializePortableReceipt, verifyPortableReceipt } from '../audit/portable-receipt.js';
import { SqliteAuditRecorder } from '../audit/recorder.js';
import { openAuditDatabaseReadOnly } from '../db/database.js';

const MAX_RECEIPT_FILE_BYTES = 1_048_576;

type TextOutput = Readonly<{ write(text: string): unknown }>;

export type ReceiptArguments =
  | Readonly<{
    operation: 'export';
    actionId: string;
    auditDbPath: string;
    outputPath: string;
  }>
  | Readonly<{
    operation: 'verify';
    receiptPath: string;
  }>;

export function parseReceiptArguments(argv: readonly string[]): ReceiptArguments {
  if (argv[0] === 'verify' && argv.length === 2 && argv[1] !== undefined) {
    return { operation: 'verify', receiptPath: argv[1] };
  }
  if (argv[0] !== 'export' || argv[1] === undefined) throw receiptUsageError();
  const actionId = argv[1];
  let auditDbPath = '.apg/audit.sqlite';
  let outputPath: string | undefined;
  const seen = new Set<string>();
  for (let index = 2; index < argv.length; index += 2) {
    const option = argv[index];
    const value = argv[index + 1];
    if (
      option === undefined
      || value === undefined
      || seen.has(option)
      || (option !== '--audit-db' && option !== '--output')
    ) {
      throw receiptUsageError();
    }
    seen.add(option);
    if (option === '--audit-db') auditDbPath = value;
    else outputPath = value;
  }
  if (outputPath === undefined) throw receiptUsageError();
  return { operation: 'export', actionId, auditDbPath, outputPath };
}

export function runReceipt(
  arguments_: ReceiptArguments,
  output: TextOutput = process.stdout,
): Readonly<{ successful: boolean }> {
  if (arguments_.operation === 'verify') {
    const path = resolve(arguments_.receiptPath);
    const metadata = lstatSync(path);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new Error('Receipt path must be a regular file, not a symbolic link');
    }
    if (metadata.size > MAX_RECEIPT_FILE_BYTES) throw new Error('Receipt file exceeds the size limit');
    const verification = verifyPortableReceipt(readFileSync(path));
    output.write([
      `Receipt: ${verification.status.toUpperCase()}`,
      `Assurance: PORTABLE_UNSIGNED`,
      verification.message,
      'Coverage: direct bypasses and unobserved downstream effects remain outside APG coverage.',
      '',
    ].join('\n'));
    return { successful: verification.status === 'verified_unsigned' };
  }

  const databasePath = resolve(arguments_.auditDbPath);
  const metadata = lstatSync(databasePath);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error('Audit database path must be a regular file, not a symbolic link');
  }
  const database = openAuditDatabaseReadOnly(databasePath);
  try {
    const recorder = new SqliteAuditRecorder(database);
    const envelope = new PortableReceiptService(database, recorder).exportAction(arguments_.actionId);
    const outputPath = resolve(arguments_.outputPath);
    writeExclusivePrivateFile(outputPath, serializePortableReceipt(envelope));
    output.write([
      'Receipt exported',
      `Action: ${arguments_.actionId}`,
      `Assurance: PORTABLE_UNSIGNED`,
      `Completeness: ${envelope.completeness.toUpperCase()}`,
      'Issuer identity is not authenticated; direct bypasses remain outside APG coverage.',
      '',
    ].join('\n'));
    return {
      successful: envelope.completeness === 'complete' || envelope.completeness === 'authorization_only',
    };
  } finally {
    database.close();
  }
}

function writeExclusivePrivateFile(path: string, contents: string): void {
  let descriptor: number | undefined;
  let created = false;
  try {
    descriptor = openSync(path, 'wx', 0o600);
    created = true;
    writeFileSync(descriptor, contents, 'utf8');
    fsyncSync(descriptor);
  } catch (error) {
    if (created) {
      try { unlinkSync(path); } catch { /* best-effort cleanup of an incomplete export */ }
    }
    throw error;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function receiptUsageError(): Error {
  return new Error([
    'Usage:',
    'apg receipt export <action-id> [--audit-db <audit.sqlite>] --output <receipt.json>',
    'apg receipt verify <receipt.json>',
  ].join(' '));
}
