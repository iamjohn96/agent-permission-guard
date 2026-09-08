import process from 'node:process';

import { PackageStageError, type PackageStageErrorCode } from './profile.js';
import {
  ARCHIVE_WORKER_ACK,
  ARCHIVE_WORKER_MAX_BODY_CHUNK_BYTES,
  ARCHIVE_WORKER_MAX_REQUEST_BYTES,
  ARCHIVE_WORKER_PROTOCOL_VERSION,
  encodeArchiveWorkerFrame,
  type ArchiveWorkerCapabilities,
  type ArchiveWorkerRequest,
} from './archive-worker-protocol.js';
import { inspectTarArchiveForWorker } from './tar-archive-parser.js';
import type { PackageStageLimits } from './types.js';

const ERROR_CODES = new Set<PackageStageErrorCode>([
  'artifact_cancelled',
  'archive_invalid',
  'archive_limit_exceeded',
]);

class InputReader {
  readonly #iterator = process.stdin[Symbol.asyncIterator]();
  readonly #chunks: Buffer[] = [];
  #bufferedBytes = 0;

  async readExact(length: number): Promise<Buffer> {
    while (this.#bufferedBytes < length) {
      const next = await this.#iterator.next();
      if (next.done === true) throw new PackageStageError('archive_protocol_invalid');
      const chunk = Buffer.from(next.value);
      this.#chunks.push(chunk);
      this.#bufferedBytes += chunk.length;
    }
    const output = Buffer.allocUnsafe(length);
    let written = 0;
    while (written < length) {
      const chunk = this.#chunks[0]!;
      const copyBytes = Math.min(chunk.length, length - written);
      chunk.copy(output, written, 0, copyBytes);
      written += copyBytes;
      this.#bufferedBytes -= copyBytes;
      if (copyBytes === chunk.length) this.#chunks.shift();
      else this.#chunks[0] = chunk.subarray(copyBytes);
    }
    return output;
  }
}

async function main(): Promise<void> {
  const input = new InputReader();
  const header = await input.readExact(8);
  const requestBytes = header.readUInt32BE(0);
  const artifactBytes = header.readUInt32BE(4);
  if (requestBytes === 0 || requestBytes > ARCHIVE_WORKER_MAX_REQUEST_BYTES) {
    throw new PackageStageError('archive_protocol_invalid');
  }
  const request = parseRequest(JSON.parse((await input.readExact(requestBytes)).toString('utf8')));
  if (request.artifactBytes !== artifactBytes) throw new PackageStageError('archive_protocol_invalid');
  const artifact = await input.readExact(artifactBytes);
  const inspection = inspectTarArchiveForWorker(artifact, request.limits);
  if (inspection.transcript.artifactSha512 !== request.artifactSha512) {
    throw new PackageStageError('archive_invalid');
  }

  if (request.pass === 'pass_a') {
    await sendFrame(input, { type: 'transcript', transcript: inspection.transcript });
  } else {
    if (inspection.transcript.transcriptDigest !== request.expectedTranscriptDigest) {
      throw new PackageStageError('archive_invalid');
    }
    for (let index = 0; index < inspection.entries.length; index += 1) {
      const entry = inspection.entries[index]!;
      await sendFrame(input, {
        type: 'entry_start',
        index,
        archivePath: entry.transcript.archivePath,
        relativePath: entry.transcript.relativePath,
        entryType: entry.transcript.type,
        declaredSize: entry.transcript.declaredSize,
        normalizedMode: entry.transcript.normalizedMode,
      });
      for (let offset = 0; offset < entry.body.length; offset += request.bodyChunkBytes) {
        const chunk = entry.body.subarray(offset, Math.min(entry.body.length, offset + request.bodyChunkBytes));
        await sendFrame(input, {
          type: 'body_chunk',
          index,
          offset,
          bytes: chunk.toString('base64'),
        });
      }
      await sendFrame(input, {
        type: 'entry_end',
        index,
        observedSize: entry.transcript.observedSize,
        bodySha256: entry.transcript.bodySha256,
      });
    }
  }

  await sendFrame(input, {
    type: 'complete',
    pass: request.pass,
    entryCount: inspection.transcript.entryCount,
    transcriptDigest: inspection.transcript.transcriptDigest,
    capabilities: workerCapabilities(),
  });
  process.stdin.destroy();
}

async function sendFrame(input: InputReader, value: unknown): Promise<void> {
  const frame = encodeArchiveWorkerFrame(value);
  await new Promise<void>((resolve, reject) => {
    process.stdout.write(frame, (error) => error === undefined || error === null
      ? resolve()
      : reject(error));
  });
  const ack = await input.readExact(1);
  if (ack[0] !== ARCHIVE_WORKER_ACK) throw new PackageStageError('archive_protocol_invalid');
}

function parseRequest(input: unknown): ArchiveWorkerRequest {
  assertRecord(input);
  assertExactKeys(input, [
    'protocolVersion',
    'pass',
    'artifactBytes',
    'artifactSha512',
    'bodyChunkBytes',
    'expectedTranscriptDigest',
    'limits',
  ]);
  if (
    input.protocolVersion !== ARCHIVE_WORKER_PROTOCOL_VERSION
    || !['pass_a', 'pass_b'].includes(String(input.pass))
    || !isPositiveInteger(input.artifactBytes)
    || !isSha512(input.artifactSha512)
    || !isPositiveInteger(input.bodyChunkBytes)
    || input.bodyChunkBytes > ARCHIVE_WORKER_MAX_BODY_CHUNK_BYTES
    || (input.pass === 'pass_a' && input.expectedTranscriptDigest !== null)
    || (input.pass === 'pass_b' && !isSha256(input.expectedTranscriptDigest))
  ) {
    throw new PackageStageError('archive_protocol_invalid');
  }
  const limits = parseLimits(input.limits);
  if (input.artifactBytes > limits.compressedArtifactBytes) {
    throw new PackageStageError('archive_limit_exceeded');
  }
  return Object.freeze({
    protocolVersion: ARCHIVE_WORKER_PROTOCOL_VERSION,
    pass: input.pass as 'pass_a' | 'pass_b',
    artifactBytes: input.artifactBytes,
    artifactSha512: input.artifactSha512,
    bodyChunkBytes: input.bodyChunkBytes,
    expectedTranscriptDigest: input.expectedTranscriptDigest as string | null,
    limits,
  });
}

function parseLimits(input: unknown): PackageStageLimits {
  assertRecord(input);
  const keys = [
    'graphNodes',
    'compressedArtifactBytes',
    'totalCompressedBytes',
    'uncompressedArtifactBytes',
    'totalUncompressedBytes',
    'regularFileBytes',
    'archiveEntries',
    'relativePathBytes',
    'pathDepth',
  ] as const;
  assertExactKeys(input, keys);
  for (const key of keys) {
    if (!isPositiveInteger(input[key])) throw new PackageStageError('archive_protocol_invalid');
  }
  return Object.freeze({ ...input }) as PackageStageLimits;
}

function workerCapabilities(): ArchiveWorkerCapabilities {
  const permission = process.permission;
  const nodeMajor = Number.parseInt(process.versions.node.split('.')[0]!, 10);
  return Object.freeze({
    nodeMajor,
    permissionModel: permission !== undefined,
    fileSystemWriteDenied: permission !== undefined && !permission.has('fs.write'),
    childProcessDenied: permission !== undefined && !permission.has('child'),
    workerThreadDenied: permission !== undefined && !permission.has('worker'),
    nativeAddonDenied: permission !== undefined && !permission.has('addon'),
    networkDenied: nodeMajor >= 25 && permission !== undefined ? !permission.has('net') : null,
  });
}

function assertRecord(input: unknown): asserts input is Record<string, unknown> {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw new PackageStageError('archive_protocol_invalid');
  }
}

function assertExactKeys(input: Record<string, unknown>, expected: readonly string[]): void {
  const actual = Object.keys(input).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new PackageStageError('archive_protocol_invalid');
  }
}

function isPositiveInteger(input: unknown): input is number {
  return typeof input === 'number' && Number.isSafeInteger(input) && input > 0;
}

function isSha256(input: unknown): input is string {
  return typeof input === 'string' && /^[a-f0-9]{64}$/u.test(input);
}

function isSha512(input: unknown): input is string {
  return typeof input === 'string' && /^sha512-[A-Za-z0-9+/]+={0,2}$/u.test(input);
}

main().catch(async (error: unknown) => {
  const code = error instanceof PackageStageError && ERROR_CODES.has(error.code)
    ? error.code
    : 'archive_worker_failed';
  try {
    const frame = encodeArchiveWorkerFrame({ type: 'error', code });
    await new Promise<void>((resolve) => process.stdout.write(frame, () => resolve()));
  } finally {
    process.stdin.destroy();
    process.exitCode = 1;
  }
});
