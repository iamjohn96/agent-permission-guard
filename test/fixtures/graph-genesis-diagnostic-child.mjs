import { emitGraphGenesisDiagnostic } from '../../dist/src/stage/graph-genesis-diagnostics.js';
import { closeSync, writeSync } from 'node:fs';

const mode = process.argv[2] ?? 'normal';
const failure = Object.freeze({
  failureVersion: 2,
  planHash: 'a'.repeat(64),
  causeCode: 'graph_metadata_invalid',
  diagnosticVersion: 1,
  predicate: 'http_status_rejected',
  requestOrdinal: 7,
  reservedRequestCount: 10,
  activeRequestCount: 4,
  committedResponseCount: 6,
  committedResponseBytes: 644145,
  failureDigest: 'b'.repeat(64),
});
if (mode === 'closed-fd') closeSync(2);
if (mode === 'broken-pipe') await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
const emitted = emitGraphGenesisDiagnostic(failure, (line) => writeSync(2, line, null, 'utf8'));
process.exitCode = emitted === (mode === 'normal') ? 0 : 1;
