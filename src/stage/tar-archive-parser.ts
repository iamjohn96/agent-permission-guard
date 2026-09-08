import { createHash } from 'node:crypto';
import { inflateRawSync } from 'node:zlib';

import { Parser } from 'tar/parse';

import { canonicalJson } from '../audit/canonical-json.js';
import { PortableArchivePolicy } from './archive-policy.js';
import { PACKAGE_STAGE_HARD_CEILINGS, PackageStageError } from './profile.js';
import type { ArchiveEntryDescription, PackageStageLimits } from './types.js';

const TAR_BLOCK_BYTES = 512;
const TAR_END_BYTES = TAR_BLOCK_BYTES * 2;
const GZIP_HEADER_BYTES = 10;
const GZIP_TRAILER_BYTES = 8;
const MAX_COMPRESSION_RATIO = 20;
const MAX_META_ENTRY_BYTES = 64 * 1024;
const UTF8 = new TextDecoder('utf-8', { fatal: true });

export const TAR_PARSER_PACKAGE = 'tar' as const;
export const TAR_PARSER_VERSION = '7.5.22' as const;
export const TAR_PARSER_ENTRYPOINT = 'tar/parse' as const;

export type TarArchiveTranscriptEntry = Readonly<{
  archivePath: string;
  relativePath: string;
  type: 'file' | 'directory';
  declaredSize: number;
  observedSize: number;
  normalizedMode: number;
  bodySha256: string | null;
}>;

export type TarArchiveTranscript = Readonly<{
  adapterContractVersion: 1;
  candidatePackage: typeof TAR_PARSER_PACKAGE;
  candidateVersion: typeof TAR_PARSER_VERSION;
  candidateEntrypoint: typeof TAR_PARSER_ENTRYPOINT;
  archiveRulesVersion: 1;
  format: 'gzip_ustar_v0';
  artifactSha512: string;
  compressedBytes: number;
  expandedBytes: number;
  entries: readonly TarArchiveTranscriptEntry[];
  entryCount: number;
  transcriptDigest: string;
}>;

export type TarArchiveWorkerEntry = Readonly<{
  transcript: TarArchiveTranscriptEntry;
  body: Buffer;
}>;

export type TarArchiveWorkerInspection = Readonly<{
  transcript: TarArchiveTranscript;
  entries: readonly TarArchiveWorkerEntry[];
}>;

type RawUstarEntry = Readonly<{
  archivePath: string;
  type: 'file' | 'directory';
  size: number;
  mode: number;
  body: Buffer;
}>;

type CandidateEntry = Readonly<{
  archivePath: string;
  type: 'file' | 'directory';
  size: number;
  mode: number;
  observedSize: number;
  bodySha256: string | null;
}>;

export class TarArchiveTranscriptAuthority {
  readonly #authenticated = new WeakSet<object>();

  inspect(
    encodedBytes: Uint8Array,
    limits: PackageStageLimits,
    signal?: AbortSignal,
  ): TarArchiveTranscript {
    const { transcript } = inspectArchive(encodedBytes, limits, signal);
    this.#authenticated.add(transcript);
    return transcript;
  }

  authenticates(candidate: unknown): candidate is TarArchiveTranscript {
    return typeof candidate === 'object'
      && candidate !== null
      && this.#authenticated.has(candidate);
  }

  assertMatching(first: TarArchiveTranscript, second: TarArchiveTranscript): void {
    if (!this.authenticates(first) || !this.authenticates(second)) {
      throw new PackageStageError('archive_invalid');
    }
    if (
      first.transcriptDigest !== second.transcriptDigest
      || canonicalJson(first) !== canonicalJson(second)
    ) {
      throw new PackageStageError('archive_invalid');
    }
  }
}

/** Child-worker-only parser result. It performs no filesystem or network access. */
export function inspectTarArchiveForWorker(
  encodedBytes: Uint8Array,
  limits: PackageStageLimits,
  signal?: AbortSignal,
): TarArchiveWorkerInspection {
  const { transcript, rawEntries } = inspectArchive(encodedBytes, limits, signal);
  return Object.freeze({
    transcript,
    entries: Object.freeze(rawEntries.map((entry, index) => Object.freeze({
      transcript: transcript.entries[index]!,
      body: Buffer.from(entry.body),
    }))),
  });
}

function inspectArchive(
  encodedBytes: Uint8Array,
  limits: PackageStageLimits,
  signal?: AbortSignal,
): Readonly<{ transcript: TarArchiveTranscript; rawEntries: readonly RawUstarEntry[] }> {
  assertArchiveLimits(limits);
  assertNotAborted(signal);
  const compressed = Buffer.from(encodedBytes);
  const expanded = decodeExactGzipMember(compressed, limits);
  assertNotAborted(signal);

  const rawEntries = inspectExactUstar(expanded, limits);
  const candidateEntries = parseWithCandidate(expanded, limits);
  assertNotAborted(signal);
  assertCandidateMatchesRaw(rawEntries, candidateEntries);

  const policyInput = rawEntries.map((entry): ArchiveEntryDescription => Object.freeze({
    path: entry.archivePath,
    type: entry.type,
    size: entry.size,
    mode: entry.mode,
  }));
  const preflight = new PortableArchivePolicy(limits).preflight(policyInput);
  const normalizedByPath = new Map(preflight.entries.map((entry) => [entry.relativePath, entry]));
  const entries = candidateEntries.map((entry): TarArchiveTranscriptEntry => {
    const relativePath = stripPackageRoot(entry.archivePath);
    const normalized = normalizedByPath.get(relativePath);
    if (
      normalized === undefined
      || normalized.type !== entry.type
      || normalized.size !== entry.size
    ) {
      throw new PackageStageError('archive_invalid');
    }
    return Object.freeze({
      archivePath: entry.archivePath,
      relativePath,
      type: entry.type,
      declaredSize: entry.size,
      observedSize: entry.observedSize,
      normalizedMode: normalized.normalizedMode,
      bodySha256: entry.bodySha256,
    });
  });

  const unsigned = Object.freeze({
    adapterContractVersion: 1 as const,
    candidatePackage: TAR_PARSER_PACKAGE,
    candidateVersion: TAR_PARSER_VERSION,
    candidateEntrypoint: TAR_PARSER_ENTRYPOINT,
    archiveRulesVersion: 1 as const,
    format: 'gzip_ustar_v0' as const,
    artifactSha512: `sha512-${createHash('sha512').update(compressed).digest('base64')}`,
    compressedBytes: compressed.length,
    expandedBytes: preflight.expandedBytes,
    entries: Object.freeze(entries),
    entryCount: entries.length,
  });
  const transcript = Object.freeze({
    ...unsigned,
    transcriptDigest: sha256(canonicalJson(unsigned)),
  });
  return Object.freeze({ transcript, rawEntries });
}

function decodeExactGzipMember(compressed: Buffer, limits: PackageStageLimits): Buffer {
  if (compressed.length > limits.compressedArtifactBytes) {
    throw new PackageStageError('archive_limit_exceeded');
  }
  if (
    compressed.length < GZIP_HEADER_BYTES + GZIP_TRAILER_BYTES
    || compressed[0] !== 0x1f
    || compressed[1] !== 0x8b
    || compressed[2] !== 0x08
    || compressed[3] !== 0x00
  ) {
    throw new PackageStageError('archive_invalid');
  }

  const maximumTarBytes = limits.uncompressedArtifactBytes
    + limits.archiveEntries * (TAR_BLOCK_BYTES * 2 - 1)
    + TAR_END_BYTES;
  if (!Number.isSafeInteger(maximumTarBytes)) {
    throw new PackageStageError('archive_limit_exceeded');
  }
  let inflated: Readonly<{ buffer: Buffer; engine: Readonly<{ bytesWritten: number }> }>;
  try {
    inflated = inflateRawSync(compressed.subarray(GZIP_HEADER_BYTES), {
      info: true,
      maxOutputLength: maximumTarBytes + 1,
    }) as unknown as typeof inflated;
  } catch (error) {
    if (isErrorCode(error, 'ERR_BUFFER_TOO_LARGE')) {
      throw new PackageStageError('archive_limit_exceeded');
    }
    throw new PackageStageError('archive_invalid');
  }

  const deflateBytes = inflated.engine.bytesWritten;
  const trailerOffset = GZIP_HEADER_BYTES + deflateBytes;
  if (
    !Number.isSafeInteger(deflateBytes)
    || deflateBytes <= 0
    || trailerOffset + GZIP_TRAILER_BYTES !== compressed.length
  ) {
    throw new PackageStageError('archive_invalid');
  }
  const expanded = Buffer.from(inflated.buffer);
  if (
    expanded.length > maximumTarBytes
    || expanded.length / compressed.length > MAX_COMPRESSION_RATIO
  ) {
    throw new PackageStageError('archive_limit_exceeded');
  }
  if (
    compressed.readUInt32LE(trailerOffset) !== crc32(expanded)
    || compressed.readUInt32LE(trailerOffset + 4) !== (expanded.length >>> 0)
  ) {
    throw new PackageStageError('archive_invalid');
  }
  return expanded;
}

function inspectExactUstar(expanded: Buffer, limits: PackageStageLimits): readonly RawUstarEntry[] {
  if (expanded.length < TAR_END_BYTES || expanded.length % TAR_BLOCK_BYTES !== 0) {
    throw new PackageStageError('archive_invalid');
  }
  const entries: RawUstarEntry[] = [];
  let fileBytes = 0;
  let offset = 0;

  while (offset + TAR_BLOCK_BYTES <= expanded.length) {
    const header = expanded.subarray(offset, offset + TAR_BLOCK_BYTES);
    if (isZeroBlock(header)) {
      if (
        offset + TAR_END_BYTES !== expanded.length
        || !isZeroBlock(expanded.subarray(offset + TAR_BLOCK_BYTES, offset + TAR_END_BYTES))
      ) {
        throw new PackageStageError('archive_invalid');
      }
      if (entries.length === 0) throw new PackageStageError('archive_invalid');
      return Object.freeze(entries);
    }

    if (
      !header.subarray(257, 263).equals(Buffer.from('ustar\0', 'ascii'))
      || !header.subarray(263, 265).equals(Buffer.from('00', 'ascii'))
      || !checksumIsValid(header)
      || !isZeroFilledField(header.subarray(157, 257))
    ) {
      throw new PackageStageError('archive_invalid');
    }

    const typeFlag = header[156];
    const type = typeFlag === 0 || typeFlag === 0x30
      ? 'file' as const
      : typeFlag === 0x35
        ? 'directory' as const
        : undefined;
    if (type === undefined) throw new PackageStageError('archive_invalid');

    const name = decodeCanonicalTextField(header.subarray(0, 100));
    const prefix = decodeCanonicalTextField(header.subarray(345, 500));
    const archivePath = prefix.length === 0 ? name : `${prefix}/${name}`;
    const size = parseCanonicalOctal(header.subarray(124, 136));
    const mode = parseCanonicalOctal(header.subarray(100, 108));
    if (archivePath.length === 0 || (type === 'directory' && size !== 0)) {
      throw new PackageStageError('archive_invalid');
    }

    const bodyOffset = offset + TAR_BLOCK_BYTES;
    const paddedBodyBytes = Math.ceil(size / TAR_BLOCK_BYTES) * TAR_BLOCK_BYTES;
    const nextOffset = bodyOffset + paddedBodyBytes;
    if (!Number.isSafeInteger(nextOffset) || nextOffset > expanded.length - TAR_END_BYTES) {
      throw new PackageStageError('archive_invalid');
    }
    const body = Buffer.from(expanded.subarray(bodyOffset, bodyOffset + size));
    const padding = expanded.subarray(bodyOffset + size, nextOffset);
    if (!isZeroBlock(padding)) throw new PackageStageError('archive_invalid');

    if (type === 'file') fileBytes += size;
    if (
      size > limits.regularFileBytes
      || fileBytes > limits.uncompressedArtifactBytes
      || entries.length + 1 > limits.archiveEntries
    ) {
      throw new PackageStageError('archive_limit_exceeded');
    }
    entries.push(Object.freeze({ archivePath, type, size, mode, body }));
    offset = nextOffset;
  }

  throw new PackageStageError('archive_invalid');
}

function parseWithCandidate(expanded: Buffer, limits: PackageStageLimits): readonly CandidateEntry[] {
  const entries: CandidateEntry[] = [];
  let parserFailed = false;
  let parserEnded = false;
  let nullBlocks = 0;
  let eofEvents = 0;

  const parser = new Parser({
    sync: true,
    strict: true,
    gzip: false,
    brotli: false,
    zstd: false,
    noResume: true,
    maxMetaEntrySize: MAX_META_ENTRY_BYTES,
    onReadEntry: (entry) => {
      let observedSize = 0;
      const bodyHash = createHash('sha256');
      entry.on('data', (chunk: Buffer) => {
        observedSize += chunk.length;
        bodyHash.update(chunk);
      });
      entry.on('error', () => {
        parserFailed = true;
      });
      entry.on('end', () => {
        const type = entry.type === 'File' || entry.type === 'OldFile'
          ? 'file' as const
          : entry.type === 'Directory'
            ? 'directory' as const
            : undefined;
        if (
          type === undefined
          || entry.meta
          || entry.ignore
          || entry.unsupported
          || entry.extended !== undefined
          || entry.globalExtended !== undefined
          || entry.linkpath !== undefined
          || observedSize > limits.regularFileBytes
        ) {
          parserFailed = true;
          return;
        }
        entries.push(Object.freeze({
          archivePath: entry.path,
          type,
          size: entry.size,
          mode: entry.mode ?? 0,
          observedSize,
          bodySha256: type === 'directory' ? null : bodyHash.digest('hex'),
        }));
      });
      entry.resume();
    },
  });
  parser.on('warn', () => {
    parserFailed = true;
  });
  parser.on('error', () => {
    parserFailed = true;
  });
  parser.on('ignoredEntry', () => {
    parserFailed = true;
  });
  parser.on('meta', () => {
    parserFailed = true;
  });
  parser.on('nullBlock', () => {
    nullBlocks += 1;
  });
  parser.on('eof', () => {
    eofEvents += 1;
  });
  parser.on('end', () => {
    parserEnded = true;
  });

  try {
    parser.end(expanded);
  } catch {
    parserFailed = true;
  }
  if (parserFailed || !parserEnded || nullBlocks !== 1 || eofEvents !== 1) {
    throw new PackageStageError('archive_invalid');
  }
  return Object.freeze(entries);
}

function assertCandidateMatchesRaw(
  rawEntries: readonly RawUstarEntry[],
  candidateEntries: readonly CandidateEntry[],
): void {
  if (rawEntries.length !== candidateEntries.length) {
    throw new PackageStageError('archive_invalid');
  }
  for (let index = 0; index < rawEntries.length; index += 1) {
    const raw = rawEntries[index]!;
    const candidate = candidateEntries[index]!;
    const bodySha256 = raw.type === 'directory' ? null : sha256(raw.body);
    if (
      candidate.archivePath !== raw.archivePath
      || candidate.type !== raw.type
      || candidate.size !== raw.size
      || candidate.mode !== raw.mode
      || candidate.observedSize !== raw.size
      || candidate.bodySha256 !== bodySha256
    ) {
      throw new PackageStageError('archive_invalid');
    }
  }
}

function decodeCanonicalTextField(field: Buffer): string {
  const nul = field.indexOf(0);
  const end = nul === -1 ? field.length : nul;
  if (nul !== -1 && !isZeroFilledField(field.subarray(nul))) {
    throw new PackageStageError('archive_invalid');
  }
  try {
    return UTF8.decode(field.subarray(0, end));
  } catch {
    throw new PackageStageError('archive_invalid');
  }
}

function parseCanonicalOctal(field: Buffer): number {
  let end = field.length;
  while (end > 0 && (field[end - 1] === 0 || field[end - 1] === 0x20)) end -= 1;
  const digits = field.subarray(0, end);
  if (
    digits.length === 0
    || [...digits].some((byte) => byte < 0x30 || byte > 0x37)
    || [...field.subarray(end)].some((byte) => byte !== 0 && byte !== 0x20)
  ) {
    throw new PackageStageError('archive_invalid');
  }
  const value = Number.parseInt(digits.toString('ascii'), 8);
  if (!Number.isSafeInteger(value) || value < 0) throw new PackageStageError('archive_invalid');
  return value;
}

function checksumIsValid(header: Buffer): boolean {
  let stored: number;
  try {
    stored = parseCanonicalOctal(header.subarray(148, 156));
  } catch {
    return false;
  }
  const copy = Buffer.from(header);
  copy.fill(0x20, 148, 156);
  return copy.reduce((sum, byte) => sum + byte, 0) === stored;
}

function stripPackageRoot(path: string): string {
  if (!path.startsWith('package/')) throw new PackageStageError('archive_invalid');
  return path.slice('package/'.length);
}

function isZeroBlock(bytes: Buffer): boolean {
  return bytes.every((byte) => byte === 0);
}

function isZeroFilledField(bytes: Buffer): boolean {
  return bytes.every((byte) => byte === 0);
}

function assertNotAborted(signal?: AbortSignal): void {
  if (signal?.aborted === true) throw new PackageStageError('artifact_cancelled');
}

function assertArchiveLimits(limits: PackageStageLimits): void {
  const keys = Object.keys(PACKAGE_STAGE_HARD_CEILINGS) as (keyof PackageStageLimits)[];
  if (keys.some((key) => {
    const value = limits[key];
    return !Number.isSafeInteger(value) || value <= 0 || value > PACKAGE_STAGE_HARD_CEILINGS[key];
  })) {
    throw new PackageStageError('archive_limit_exceeded');
  }
  if (
    limits.compressedArtifactBytes > limits.totalCompressedBytes
    || limits.uncompressedArtifactBytes > limits.totalUncompressedBytes
    || limits.regularFileBytes > limits.uncompressedArtifactBytes
  ) {
    throw new PackageStageError('archive_limit_exceeded');
  }
}

function isErrorCode(error: unknown, code: string): boolean {
  return typeof error === 'object'
    && error !== null
    && 'code' in error
    && (error as { code?: unknown }).code === code;
}

function sha256(input: string | Uint8Array): string {
  return createHash('sha256').update(input).digest('hex');
}

function crc32(bytes: Uint8Array): number {
  let value = 0xffffffff;
  for (const byte of bytes) {
    value = CRC32_TABLE[(value ^ byte) & 0xff]! ^ (value >>> 8);
  }
  return (value ^ 0xffffffff) >>> 0;
}

const CRC32_TABLE = Object.freeze(Array.from({ length: 256 }, (_, index) => {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) {
    value = (value & 1) === 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  }
  return value >>> 0;
}));
