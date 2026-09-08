import type { PackageStageLimits } from './types.js';

export const ARCHIVE_WORKER_PROTOCOL_VERSION = 1 as const;
export const ARCHIVE_WORKER_ACK = 0x06;
export const ARCHIVE_WORKER_MAX_BODY_CHUNK_BYTES = 64 * 1024;
export const ARCHIVE_WORKER_MAX_REQUEST_BYTES = 32 * 1024;

export type ArchiveWorkerPass = 'pass_a' | 'pass_b';

export type ArchiveWorkerRequest = Readonly<{
  protocolVersion: typeof ARCHIVE_WORKER_PROTOCOL_VERSION;
  pass: ArchiveWorkerPass;
  artifactBytes: number;
  artifactSha512: string;
  bodyChunkBytes: number;
  expectedTranscriptDigest: string | null;
  limits: PackageStageLimits;
}>;

export type ArchiveWorkerCapabilities = Readonly<{
  nodeMajor: number;
  permissionModel: boolean;
  fileSystemWriteDenied: boolean;
  childProcessDenied: boolean;
  workerThreadDenied: boolean;
  nativeAddonDenied: boolean;
  networkDenied: boolean | null;
}>;

export function encodeArchiveWorkerFrame(value: unknown): Buffer {
  const body = Buffer.from(JSON.stringify(value), 'utf8');
  const header = Buffer.alloc(4);
  header.writeUInt32BE(body.length, 0);
  return Buffer.concat([header, body]);
}

export function encodeArchiveWorkerRequestHeader(request: ArchiveWorkerRequest): Buffer {
  const body = Buffer.from(JSON.stringify(request), 'utf8');
  if (body.length > ARCHIVE_WORKER_MAX_REQUEST_BYTES) throw new Error('archive_protocol_invalid');
  const header = Buffer.alloc(8);
  header.writeUInt32BE(body.length, 0);
  header.writeUInt32BE(request.artifactBytes, 4);
  return Buffer.concat([header, body]);
}
