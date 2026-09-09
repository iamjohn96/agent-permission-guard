import { canonicalJson } from '../audit/canonical-json.js';
import type { AuthenticatedHardenedBrokerFailure } from './graph-genesis-network.js';

export const GRAPH_GENESIS_DIAGNOSTIC_PREFIX = '[apg] graph-genesis-diagnostic ';
const MAX_DIAGNOSTIC_BYTES = 1024;

type DiagnosticWriter = (line: string) => unknown;

/**
 * Formats only owner-authenticated broker evidence. A write failure is deliberately
 * ignored so diagnostics cannot alter terminal classification or process liveness.
 */
export function emitGraphGenesisDiagnostic(
  failure: AuthenticatedHardenedBrokerFailure,
  write: DiagnosticWriter,
): boolean {
  const projection = Object.freeze({
    diagnosticVersion: failure.diagnosticVersion,
    predicate: failure.predicate,
    requestOrdinal: failure.requestOrdinal,
    reservedRequestCount: failure.reservedRequestCount,
    activeRequestCount: failure.activeRequestCount,
    committedResponseCount: failure.committedResponseCount,
    committedResponseBytes: failure.committedResponseBytes,
    planHash: failure.planHash,
    failureDigest: failure.failureDigest,
  });
  const line = `${GRAPH_GENESIS_DIAGNOSTIC_PREFIX}${canonicalJson(projection)}\n`;
  if (Buffer.byteLength(line, 'utf8') > MAX_DIAGNOSTIC_BYTES) return false;
  try {
    write(line);
    return true;
  } catch {
    return false;
  }
}
