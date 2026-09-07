import { createHash } from 'node:crypto';
import { deflateRawSync } from 'node:zlib';

import type { ArchiveEntryDescription } from '../../src/stage/types.js';

const TAR_BLOCK_BYTES = 512;
const GZIP_HEADER = Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff]);

export type ExpectedArchiveTranscriptEntry = Readonly<{
  archivePath: string;
  relativePath: string;
  type: 'file' | 'directory';
  declaredSize: number;
  normalizedMode: number;
  bodySha256: string | null;
}>;

export type ExpectedArchiveTranscript = Readonly<{
  archiveRulesVersion: 1;
  format: 'gzip_ustar_v0';
  entries: readonly ExpectedArchiveTranscriptEntry[];
  entryCount: number;
  expandedBytes: number;
}>;

export type ArchiveFixtureExpectation =
  | Readonly<{
      kind: 'accept';
      transcript: ExpectedArchiveTranscript;
    }>
  | Readonly<{
      kind: 'reject';
      layer: 'gzip' | 'tar' | 'policy' | 'limit';
      reason: string;
      expectedCode: 'archive_invalid' | 'archive_limit_exceeded';
    }>;

export type ArchiveAdversarialFixture = Readonly<{
  id: string;
  encodedBytes: Buffer;
  uncompressedBytes: Buffer;
  contentEncoding: 'gzip' | 'identity' | 'unknown';
  expectation: ArchiveFixtureExpectation;
  policyEntries: readonly ArchiveEntryDescription[];
}>;

export type CrossPassArchiveFixture = Readonly<{
  id: string;
  passABytes: Buffer;
  passBBytes: Buffer;
  expectedReason: 'artifact_changed' | 'entry_order_changed' | 'entry_body_changed';
}>;

export type UstarFixtureEntry = Readonly<{
  path: string | Uint8Array;
  body?: string | Uint8Array;
  typeFlag?: string;
  mode?: number;
  linkName?: string | Uint8Array;
  declaredSize?: number;
  rawSizeField?: Uint8Array;
  corruptChecksum?: boolean;
}>;

export type UstarArchiveOptions = Readonly<{
  terminalZeroBlocks?: number;
  trailingBytes?: Uint8Array;
}>;

export const fixturePolicyLimits = Object.freeze({
  graphNodes: 8,
  compressedArtifactBytes: 128 * 1024,
  totalCompressedBytes: 256 * 1024,
  uncompressedArtifactBytes: 4 * 1024,
  totalUncompressedBytes: 8 * 1024,
  regularFileBytes: 2 * 1024,
  archiveEntries: 8,
  relativePathBytes: 128,
  pathDepth: 8,
});

export function buildUstarArchive(
  entries: readonly UstarFixtureEntry[],
  options: UstarArchiveOptions = {},
): Buffer {
  const chunks: Buffer[] = [];
  for (const entry of entries) {
    const body = toBuffer(entry.body ?? Buffer.alloc(0));
    const declaredSize = entry.declaredSize ?? body.length;
    chunks.push(buildUstarHeader(entry, declaredSize));
    chunks.push(body);
    const padding = (TAR_BLOCK_BYTES - (body.length % TAR_BLOCK_BYTES)) % TAR_BLOCK_BYTES;
    if (padding > 0) chunks.push(Buffer.alloc(padding));
  }
  chunks.push(Buffer.alloc((options.terminalZeroBlocks ?? 2) * TAR_BLOCK_BYTES));
  if (options.trailingBytes !== undefined) chunks.push(Buffer.from(options.trailingBytes));
  return Buffer.concat(chunks);
}

export function buildDeterministicGzip(input: Uint8Array): Buffer {
  const body = Buffer.from(input);
  const deflateBlocks: Buffer[] = [];
  if (body.length === 0) {
    deflateBlocks.push(Buffer.from([0x01, 0x00, 0x00, 0xff, 0xff]));
  } else {
    for (let offset = 0; offset < body.length; offset += 0xffff) {
      const length = Math.min(0xffff, body.length - offset);
      const isFinal = offset + length === body.length;
      const blockHeader = Buffer.alloc(5);
      blockHeader[0] = isFinal ? 0x01 : 0x00;
      blockHeader.writeUInt16LE(length, 1);
      blockHeader.writeUInt16LE((~length) & 0xffff, 3);
      deflateBlocks.push(blockHeader, body.subarray(offset, offset + length));
    }
  }
  const trailer = Buffer.alloc(8);
  trailer.writeUInt32LE(crc32(body), 0);
  trailer.writeUInt32LE(body.length >>> 0, 4);
  return Buffer.concat([GZIP_HEADER, ...deflateBlocks, trailer]);
}

export function createArchiveAdversarialFixtureCorpus(): readonly ArchiveAdversarialFixture[] {
  const packageJson = Buffer.from('{"name":"fixture","version":"1.0.0"}\n');
  const indexJs = Buffer.from('export default 1;\n');
  const minimalEntries: readonly UstarFixtureEntry[] = [
    { path: 'package/package.json', body: packageJson, mode: 0o644 },
    { path: 'package/index.js', body: indexJs, mode: 0o644 },
  ];
  const minimalPolicy: readonly ArchiveEntryDescription[] = [
    policyEntry('package/package.json', 'file', packageJson.length, 0o644),
    policyEntry('package/index.js', 'file', indexJs.length, 0o644),
  ];
  const minimalTar = buildUstarArchive(minimalEntries);
  const fixtures: ArchiveAdversarialFixture[] = [
    acceptedFixture('valid_minimal', minimalTar, minimalPolicy, transcriptFor([
      transcriptEntry('package/package.json', 'file', packageJson, 0o644),
      transcriptEntry('package/index.js', 'file', indexJs, 0o644),
    ])),
  ];

  const emptyEntries: readonly UstarFixtureEntry[] = [
    { path: 'package/lib', typeFlag: '5', mode: 0o755 },
    { path: 'package/lib/empty.js', body: Buffer.alloc(0), mode: 0o755 },
  ];
  const emptyPolicy: readonly ArchiveEntryDescription[] = [
    policyEntry('package/lib', 'directory', 0, 0o755),
    policyEntry('package/lib/empty.js', 'file', 0, 0o755),
  ];
  fixtures.push(acceptedFixture(
    'valid_directory_and_empty_executable',
    buildUstarArchive(emptyEntries),
    emptyPolicy,
    transcriptFor([
      transcriptEntry('package/lib', 'directory', Buffer.alloc(0), 0o755),
      transcriptEntry('package/lib/empty.js', 'file', Buffer.alloc(0), 0o755),
    ]),
  ));

  const checksumTar = Buffer.from(minimalTar);
  checksumTar[0] = checksumTar[0]! ^ 0x01;
  fixtures.push(rejectedFixture('tar_bad_checksum', checksumTar, 'tar', 'header_checksum'));
  fixtures.push(rejectedFixture(
    'tar_truncated_header',
    minimalTar.subarray(0, 300),
    'tar',
    'truncated_header',
  ));
  fixtures.push(rejectedFixture(
    'tar_truncated_body',
    buildUstarArchive([{ path: 'package/body.bin', body: Buffer.alloc(32, 0x41) }]).subarray(0, 520),
    'tar',
    'truncated_body',
  ));
  fixtures.push(rejectedFixture(
    'tar_missing_end_blocks',
    buildUstarArchive(minimalEntries, { terminalZeroBlocks: 0 }),
    'tar',
    'missing_end_blocks',
  ));
  fixtures.push(rejectedFixture(
    'tar_one_end_block',
    buildUstarArchive(minimalEntries, { terminalZeroBlocks: 1 }),
    'tar',
    'one_end_block',
  ));
  fixtures.push(rejectedFixture(
    'tar_trailing_nonzero',
    buildUstarArchive(minimalEntries, { trailingBytes: Buffer.from('unexpected') }),
    'tar',
    'trailing_nonzero',
  ));

  const corruptCrc = buildDeterministicGzip(minimalTar);
  corruptCrc[corruptCrc.length - 8] = corruptCrc[corruptCrc.length - 8]! ^ 0xff;
  fixtures.push(rejectedEncodedFixture('gzip_bad_crc', corruptCrc, minimalTar, 'gzip', 'crc_mismatch'));
  const gzip = buildDeterministicGzip(minimalTar);
  fixtures.push(rejectedEncodedFixture(
    'gzip_truncated_trailer',
    gzip.subarray(0, gzip.length - 4),
    minimalTar,
    'gzip',
    'truncated_trailer',
  ));
  fixtures.push(rejectedEncodedFixture(
    'gzip_concatenated_members',
    Buffer.concat([gzip, gzip]),
    Buffer.concat([minimalTar, minimalTar]),
    'gzip',
    'multiple_members',
  ));
  fixtures.push(rejectedEncodedFixture(
    'gzip_trailing_garbage',
    Buffer.concat([gzip, Buffer.from('garbage')]),
    minimalTar,
    'gzip',
    'trailing_garbage',
  ));
  const highRatioTar = buildUstarArchive([{
    path: 'package/high-ratio.bin',
    body: Buffer.alloc(fixturePolicyLimits.uncompressedArtifactBytes, 0),
  }]);
  fixtures.push(Object.freeze({
    id: 'limit_gzip_compression_ratio',
    encodedBytes: buildCompressedGzip(highRatioTar),
    uncompressedBytes: highRatioTar,
    contentEncoding: 'gzip' as const,
    expectation: reject('limit', 'compression_ratio'),
    policyEntries: Object.freeze([
      policyEntry('package/high-ratio.bin', 'file', fixturePolicyLimits.uncompressedArtifactBytes),
    ]),
  }));
  fixtures.push(Object.freeze({
    id: 'plain_tar_rejected',
    encodedBytes: Buffer.from(minimalTar),
    uncompressedBytes: Buffer.from(minimalTar),
    contentEncoding: 'identity' as const,
    expectation: reject('gzip', 'gzip_required'),
    policyEntries: Object.freeze([]),
  }));
  fixtures.push(Object.freeze({
    id: 'zip_magic_rejected',
    encodedBytes: Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x00]),
    uncompressedBytes: Buffer.alloc(0),
    contentEncoding: 'unknown' as const,
    expectation: reject('gzip', 'unsupported_compression'),
    policyEntries: Object.freeze([]),
  }));

  const paxPath = paxRecord('path', 'package/hidden.js');
  const paxSize = paxRecord('size', '2048');
  fixtures.push(extensionFixture('pax_local_header', [
    { path: 'PaxHeaders/x', typeFlag: 'x', body: paxPath },
    { path: 'package/visible.js', body: 'safe' },
  ]));
  fixtures.push(extensionFixture('pax_global_header', [
    { path: 'GlobalHead/x', typeFlag: 'g', body: paxPath },
    { path: 'package/visible.js', body: 'safe' },
  ]));
  fixtures.push(extensionFixture('gnu_long_name_header', [
    { path: '././@LongLink', typeFlag: 'L', body: 'package/long-name.js\0' },
    { path: 'package/short.js', body: 'safe' },
  ]));
  fixtures.push(extensionFixture('gnu_long_link_header', [
    { path: '././@LongLink', typeFlag: 'K', body: 'package/target.js\0' },
    { path: 'package/link', typeFlag: '2', linkName: 'package/short.js' },
  ]));
  fixtures.push(extensionFixture('pax_gnu_parser_smuggling', [
    { path: 'PaxHeaders/x', typeFlag: 'x', body: paxSize },
    { path: '././@LongLink', typeFlag: 'L', body: 'package/long.js\0' },
    { path: 'package/a.js', body: 'A'.repeat(16) },
    { path: 'package/b.js', body: 'B'.repeat(16) },
  ]));
  fixtures.push(extensionFixture('pax_malformed_length', [
    { path: 'PaxHeaders/x', typeFlag: 'x', body: '99 path=package/a.js\n' },
    { path: 'package/visible.js', body: 'safe' },
  ]));
  fixtures.push(extensionFixture('pax_duplicate_path_keys', [
    {
      path: 'PaxHeaders/x',
      typeFlag: 'x',
      body: Buffer.concat([
        paxRecord('path', 'package/first.js'),
        paxRecord('path', 'package/second.js'),
      ]),
    },
    { path: 'package/visible.js', body: 'safe' },
  ]));
  fixtures.push(extensionFixture('pax_numeric_path', [
    { path: 'PaxHeaders/x', typeFlag: 'x', body: paxRecord('path', '12345') },
    { path: 'package/visible.js', body: 'safe' },
  ]));
  fixtures.push(extensionFixture('pax_nul_path', [
    { path: 'PaxHeaders/x', typeFlag: 'x', body: paxRecord('path', 'package/a\0b') },
    { path: 'package/visible.js', body: 'safe' },
  ]));

  fixtures.push(rawSizeFixture('tar_negative_base256_size', 0xff));
  fixtures.push(rawSizeFixture('tar_oversized_base256_size', 0x80));
  fixtures.push(rejectedFixture(
    'tar_invalid_utf8_path',
    buildUstarArchive([{ path: Buffer.from([0x70, 0x61, 0x63, 0x6b, 0x61, 0x67, 0x65, 0x2f, 0xff]), body: 'x' }]),
    'tar',
    'invalid_utf8_path',
  ));
  fixtures.push(rejectedFixture(
    'tar_nul_path',
    buildUstarArchive([{ path: Buffer.from('package/a\0b', 'utf8'), body: 'x' }]),
    'tar',
    'nul_path',
  ));

  for (const [id, entries] of policyRejectionCases()) {
    fixtures.push(Object.freeze({
      id,
      encodedBytes: buildDeterministicGzip(buildPolicyTar(entries)),
      uncompressedBytes: buildPolicyTar(entries),
      contentEncoding: 'gzip' as const,
      expectation: reject(id.startsWith('limit_') ? 'limit' : 'policy', id),
      policyEntries: Object.freeze(entries.map((entry) => Object.freeze({ ...entry }))),
    }));
  }

  return Object.freeze(fixtures);
}

export function createCrossPassArchiveFixtures(): readonly CrossPassArchiveFixture[] {
  const first = buildDeterministicGzip(buildUstarArchive([
    { path: 'package/a.js', body: 'AAAA' },
    { path: 'package/b.js', body: 'BBBB' },
  ]));
  return Object.freeze([
    Object.freeze({
      id: 'body_changed_same_length',
      passABytes: first,
      passBBytes: buildDeterministicGzip(buildUstarArchive([
        { path: 'package/a.js', body: 'AAAB' },
        { path: 'package/b.js', body: 'BBBB' },
      ])),
      expectedReason: 'entry_body_changed' as const,
    }),
    Object.freeze({
      id: 'entry_order_changed',
      passABytes: first,
      passBBytes: buildDeterministicGzip(buildUstarArchive([
        { path: 'package/b.js', body: 'BBBB' },
        { path: 'package/a.js', body: 'AAAA' },
      ])),
      expectedReason: 'entry_order_changed' as const,
    }),
    Object.freeze({
      id: 'header_path_changed_same_length',
      passABytes: first,
      passBBytes: buildDeterministicGzip(buildUstarArchive([
        { path: 'package/c.js', body: 'AAAA' },
        { path: 'package/b.js', body: 'BBBB' },
      ])),
      expectedReason: 'artifact_changed' as const,
    }),
  ]);
}

export function fixtureSha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function buildUstarHeader(entry: UstarFixtureEntry, declaredSize: number): Buffer {
  const header = Buffer.alloc(TAR_BLOCK_BYTES);
  writeUstarPath(header, entry.path);
  writeOctal(header, 100, 8, entry.mode ?? 0o644);
  writeOctal(header, 108, 8, 0);
  writeOctal(header, 116, 8, 0);
  if (entry.rawSizeField === undefined) {
    writeOctal(header, 124, 12, declaredSize);
  } else {
    if (entry.rawSizeField.length !== 12) throw new Error('fixture_raw_size_invalid');
    Buffer.from(entry.rawSizeField).copy(header, 124);
  }
  writeOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  writeBytes(header, 156, 1, Buffer.from(entry.typeFlag ?? '0', 'ascii'));
  if (entry.linkName !== undefined) writeBytes(header, 157, 100, toBuffer(entry.linkName));
  Buffer.from('ustar\0', 'ascii').copy(header, 257);
  Buffer.from('00', 'ascii').copy(header, 263);
  Buffer.from('apg', 'ascii').copy(header, 265);
  Buffer.from('apg', 'ascii').copy(header, 297);
  writeOctal(header, 329, 8, 0);
  writeOctal(header, 337, 8, 0);
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  const checksumText = `${checksum.toString(8).padStart(6, '0')}\0 `;
  Buffer.from(checksumText, 'ascii').copy(header, 148);
  if (entry.corruptChecksum === true) header[148] = header[148]! ^ 0x01;
  return header;
}

function writeUstarPath(target: Buffer, path: string | Uint8Array): void {
  const pathBytes = toBuffer(path);
  if (pathBytes.length <= 100) {
    writeBytes(target, 0, 100, pathBytes);
    return;
  }
  for (let index = pathBytes.length - 1; index >= 0; index -= 1) {
    if (pathBytes[index] !== 0x2f) continue;
    const prefix = pathBytes.subarray(0, index);
    const name = pathBytes.subarray(index + 1);
    if (prefix.length <= 155 && name.length > 0 && name.length <= 100) {
      writeBytes(target, 0, 100, name);
      writeBytes(target, 345, 155, prefix);
      return;
    }
  }
  throw new Error('fixture_field_too_long');
}

function writeOctal(target: Buffer, offset: number, length: number, value: number): void {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error('fixture_octal_invalid');
  const text = value.toString(8).padStart(length - 1, '0');
  if (text.length > length - 1) throw new Error('fixture_octal_overflow');
  Buffer.from(`${text}\0`, 'ascii').copy(target, offset);
}

function writeBytes(target: Buffer, offset: number, length: number, value: Buffer): void {
  if (value.length > length) throw new Error('fixture_field_too_long');
  value.copy(target, offset);
}

function toBuffer(value: string | Uint8Array): Buffer {
  return typeof value === 'string' ? Buffer.from(value, 'utf8') : Buffer.from(value);
}

function crc32(bytes: Uint8Array): number {
  let value = 0xffffffff;
  for (const byte of bytes) {
    value = CRC32_TABLE[(value ^ byte) & 0xff]! ^ (value >>> 8);
  }
  return (value ^ 0xffffffff) >>> 0;
}

function buildCompressedGzip(input: Buffer): Buffer {
  const trailer = Buffer.alloc(8);
  trailer.writeUInt32LE(crc32(input), 0);
  trailer.writeUInt32LE(input.length >>> 0, 4);
  return Buffer.concat([GZIP_HEADER, deflateRawSync(input, { level: 9 }), trailer]);
}

const CRC32_TABLE = Object.freeze(Array.from({ length: 256 }, (_, index) => {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) {
    value = (value & 1) === 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  }
  return value >>> 0;
}));

function policyEntry(
  path: string,
  type: ArchiveEntryDescription['type'] = 'file',
  size = 1,
  mode = 0o644,
): ArchiveEntryDescription {
  return Object.freeze({ path, type, size, mode });
}

function transcriptEntry(
  archivePath: string,
  type: 'file' | 'directory',
  body: Buffer,
  mode: number,
): ExpectedArchiveTranscriptEntry {
  return Object.freeze({
    archivePath,
    relativePath: archivePath.slice('package/'.length),
    type,
    declaredSize: body.length,
    normalizedMode: type === 'directory' ? 0o755 : (mode & 0o111) === 0 ? 0o644 : 0o755,
    bodySha256: type === 'directory' ? null : fixtureSha256(body),
  });
}

function transcriptFor(entries: readonly ExpectedArchiveTranscriptEntry[]): ExpectedArchiveTranscript {
  return Object.freeze({
    archiveRulesVersion: 1 as const,
    format: 'gzip_ustar_v0' as const,
    entries: Object.freeze([...entries]),
    entryCount: entries.length,
    expandedBytes: entries.reduce((sum, entry) => sum + entry.declaredSize, 0),
  });
}

function acceptedFixture(
  id: string,
  tar: Buffer,
  policyEntries: readonly ArchiveEntryDescription[],
  transcript: ExpectedArchiveTranscript,
): ArchiveAdversarialFixture {
  return Object.freeze({
    id,
    encodedBytes: buildDeterministicGzip(tar),
    uncompressedBytes: Buffer.from(tar),
    contentEncoding: 'gzip' as const,
    expectation: Object.freeze({ kind: 'accept' as const, transcript }),
    policyEntries: Object.freeze([...policyEntries]),
  });
}

function rejectedFixture(
  id: string,
  tar: Buffer,
  layer: 'tar' | 'policy' | 'limit',
  reason: string,
): ArchiveAdversarialFixture {
  return Object.freeze({
    id,
    encodedBytes: buildDeterministicGzip(tar),
    uncompressedBytes: Buffer.from(tar),
    contentEncoding: 'gzip' as const,
    expectation: reject(layer, reason),
    policyEntries: Object.freeze([]),
  });
}

function rejectedEncodedFixture(
  id: string,
  encodedBytes: Buffer,
  uncompressedBytes: Buffer,
  layer: 'gzip',
  reason: string,
): ArchiveAdversarialFixture {
  return Object.freeze({
    id,
    encodedBytes: Buffer.from(encodedBytes),
    uncompressedBytes: Buffer.from(uncompressedBytes),
    contentEncoding: 'gzip' as const,
    expectation: reject(layer, reason),
    policyEntries: Object.freeze([]),
  });
}

function reject(
  layer: 'gzip' | 'tar' | 'policy' | 'limit',
  reason: string,
): ArchiveFixtureExpectation {
  return Object.freeze({
    kind: 'reject' as const,
    layer,
    reason,
    expectedCode: layer === 'limit' ? 'archive_limit_exceeded' as const : 'archive_invalid' as const,
  });
}

function extensionFixture(id: string, entries: readonly UstarFixtureEntry[]): ArchiveAdversarialFixture {
  return rejectedFixture(id, buildUstarArchive(entries), 'tar', 'extension_metadata');
}

function rawSizeFixture(id: string, firstByte: number): ArchiveAdversarialFixture {
  const rawSizeField = Buffer.alloc(12, firstByte === 0xff ? 0xff : 0x00);
  rawSizeField[0] = firstByte;
  return rejectedFixture(id, buildUstarArchive([{
    path: 'package/size.bin',
    body: Buffer.alloc(0),
    rawSizeField,
  }]), 'tar', 'invalid_numeric_size');
}

function paxRecord(key: string, value: string): Buffer {
  const suffix = ` ${key}=${value}\n`;
  let length = Buffer.byteLength(suffix, 'utf8') + 1;
  while (true) {
    const record = `${length}${suffix}`;
    const actual = Buffer.byteLength(record, 'utf8');
    if (actual === length) return Buffer.from(record, 'utf8');
    length = actual;
  }
}

function policyRejectionCases(): readonly (readonly [string, readonly ArchiveEntryDescription[]])[] {
  const manyEntries = Array.from({ length: fixturePolicyLimits.archiveEntries + 1 }, (_, index) =>
    policyEntry(`package/empty-${index}.js`, 'file', 0));
  return [
    ['policy_parent_traversal', [policyEntry('package/../escape')]],
    ['policy_absolute_path', [policyEntry('/package/escape')]],
    ['policy_windows_separator', [policyEntry('package\\escape')]],
    ['policy_dot_segment', [policyEntry('package/./escape')]],
    ['policy_empty_segment', [policyEntry('package//escape')]],
    ['policy_control_path', [policyEntry('package/a\nb')]],
    ['policy_unicode_nfd', [policyEntry('package/e\u0301.js')]],
    ['policy_case_collision', [policyEntry('package/A.js'), policyEntry('package/a.js')]],
    ['policy_duplicate_path', [policyEntry('package/a.js'), policyEntry('package/a.js')]],
    ['policy_nested_node_modules', [policyEntry('package/node_modules/a.js')]],
    ['policy_npmrc', [policyEntry('package/.npmrc')]],
    ['policy_symlink', [{ ...policyEntry('package/link', 'symlink'), linkTarget: '../escape' }]],
    ['policy_hardlink', [{ ...policyEntry('package/link', 'hardlink'), linkTarget: 'package/a.js' }]],
    ['policy_block_device', [policyEntry('package/device', 'block_device')]],
    ['policy_character_device', [policyEntry('package/device', 'character_device')]],
    ['policy_fifo', [policyEntry('package/fifo', 'fifo')]],
    ['policy_socket', [policyEntry('package/socket', 'socket')]],
    ['policy_sparse', [{ ...policyEntry('package/sparse'), sparse: true }]],
    ['policy_setuid', [policyEntry('package/setuid', 'file', 1, 0o4755)]],
    ['limit_regular_file', [policyEntry('package/large', 'file', fixturePolicyLimits.regularFileBytes + 1)]],
    ['limit_entry_count', manyEntries],
    ['limit_uncompressed_artifact', [
      policyEntry('package/first.bin', 'file', fixturePolicyLimits.regularFileBytes),
      policyEntry('package/second.bin', 'file', fixturePolicyLimits.regularFileBytes),
      policyEntry('package/last.bin', 'file', 1),
    ]],
    ['policy_path_bytes_ceiling', [policyEntry(`package/${'a'.repeat(64)}/${'b'.repeat(64)}`)]],
    ['policy_path_depth_ceiling', [policyEntry(`package/${Array.from({ length: 9 }, () => 'a').join('/')}`)]],
  ];
}

function buildPolicyTar(entries: readonly ArchiveEntryDescription[]): Buffer {
  return buildUstarArchive(entries.map((entry) => ({
    path: entry.path,
    body: entry.type === 'file' ? Buffer.alloc(Math.min(entry.size, 4096), 0x41) : Buffer.alloc(0),
    typeFlag: entry.sparse === true ? 'S' : typeFlagFor(entry.type),
    mode: entry.mode,
    linkName: entry.linkTarget ?? '',
  })));
}

function typeFlagFor(type: ArchiveEntryDescription['type']): string {
  switch (type) {
    case 'file': return '0';
    case 'directory': return '5';
    case 'symlink': return '2';
    case 'hardlink': return '1';
    case 'block_device': return '4';
    case 'character_device': return '3';
    case 'fifo': return '6';
    case 'socket': return 's';
  }
}
