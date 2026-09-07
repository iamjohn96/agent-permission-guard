import { gunzipSync } from 'node:zlib';
import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { PortableArchivePolicy } from '../../src/stage/archive-policy.js';
import {
  createArchiveAdversarialFixtureCorpus,
  createCrossPassArchiveFixtures,
  fixturePolicyLimits,
  fixtureSha256,
} from '../fixtures/archive-adversarial-fixtures.js';

describe('library-independent archive adversarial fixtures', () => {
  it('builds deterministic valid gzip-wrapped USTAR controls with explicit transcripts', () => {
    const first = createArchiveAdversarialFixtureCorpus();
    const second = createArchiveAdversarialFixtureCorpus();
    const valid = first.filter((fixture) => fixture.expectation.kind === 'accept');

    expect(valid.map((fixture) => fixture.id)).toEqual([
      'valid_minimal',
      'valid_directory_and_empty_executable',
    ]);
    expect(first.map((fixture) => fixtureSha256(fixture.encodedBytes)))
      .toEqual(second.map((fixture) => fixtureSha256(fixture.encodedBytes)));

    const minimal = valid[0]!;
    expect(gunzipSync(minimal.encodedBytes)).toEqual(minimal.uncompressedBytes);
    expect(minimal.uncompressedBytes.subarray(257, 263).toString('ascii')).toBe('ustar\0');
    expect(minimal.uncompressedBytes.subarray(-1024)).toEqual(Buffer.alloc(1024));
    expect(validUstarChecksum(minimal.uncompressedBytes.subarray(0, 512))).toBe(true);
    expect(validUstarChecksum(minimal.uncompressedBytes.subarray(1024, 1536))).toBe(true);
    expect(minimal.expectation).toEqual({
      kind: 'accept',
      transcript: {
        archiveRulesVersion: 1,
        format: 'gzip_ustar_v0',
        entries: [
          {
            archivePath: 'package/package.json',
            relativePath: 'package.json',
            type: 'file',
            declaredSize: 37,
            normalizedMode: 0o644,
            bodySha256: '8812280c0ddd054048a24ca505da8848a0c0dd053d4fd858a536a7917a648a36',
          },
          {
            archivePath: 'package/index.js',
            relativePath: 'index.js',
            type: 'file',
            declaredSize: 18,
            normalizedMode: 0o644,
            bodySha256: '96909e1dce85ca534fd8881f6c8369a8a87e06df5a4bf81ef44a72db195b0704',
          },
        ],
        entryCount: 2,
        expandedBytes: 55,
      },
    });
  });

  it('keeps fixture IDs unique, bounded, and split by enforcement layer', () => {
    const fixtures = createArchiveAdversarialFixtureCorpus();
    const ids = fixtures.map((fixture) => fixture.id);
    const layers = fixtures.flatMap((fixture) =>
      fixture.expectation.kind === 'reject' ? [fixture.expectation.layer] : []);

    expect(new Set(ids).size).toBe(ids.length);
    expect(fixtures.length).toBe(52);
    expect({
      accept: fixtures.filter((fixture) => fixture.expectation.kind === 'accept').length,
      gzip: layers.filter((layer) => layer === 'gzip').length,
      tar: layers.filter((layer) => layer === 'tar').length,
      policy: layers.filter((layer) => layer === 'policy').length,
      limit: layers.filter((layer) => layer === 'limit').length,
    }).toEqual({ accept: 2, gzip: 6, tar: 19, policy: 21, limit: 4 });
    expect(fixtures.reduce((sum, fixture) => sum + fixture.encodedBytes.length, 0)).toBeLessThan(512 * 1024);
  });

  it('maps every semantic accept/reject fixture through the existing portable archive policy', () => {
    const fixtures = createArchiveAdversarialFixtureCorpus();
    for (const fixture of fixtures) {
      if (fixture.expectation.kind === 'accept') {
        const result = new PortableArchivePolicy(fixturePolicyLimits).preflight(fixture.policyEntries);
        expect(result.entryCount, fixture.id).toBe(fixture.expectation.transcript.entryCount);
        expect(result.expandedBytes, fixture.id).toBe(fixture.expectation.transcript.expandedBytes);
        continue;
      }
      if (fixture.expectation.layer !== 'policy' && fixture.expectation.layer !== 'limit') continue;
      expect(
        () => new PortableArchivePolicy(fixturePolicyLimits).preflight(fixture.policyEntries),
        fixture.id,
      ).toThrowError(expect.objectContaining({ code: fixture.expectation.expectedCode }));
    }
  });

  it('preserves format attacks as bytes that cannot be normalized away by policy descriptions', () => {
    const fixtures = createArchiveAdversarialFixtureCorpus();
    const byId = new Map(fixtures.map((fixture) => [fixture.id, fixture]));
    const extensionFlags = ['x', 'g', 'L', 'K'];

    expect(validUstarChecksum(byId.get('tar_bad_checksum')!.uncompressedBytes.subarray(0, 512))).toBe(false);
    expect(byId.get('tar_missing_end_blocks')!.uncompressedBytes.subarray(-1024))
      .not.toEqual(Buffer.alloc(1024));
    expect(byId.get('tar_trailing_nonzero')!.uncompressedBytes.subarray(-10).toString())
      .toBe('unexpected');
    expect(byId.get('tar_invalid_utf8_path')!.uncompressedBytes.includes(0xff)).toBe(true);

    const observedFlags = [
      byId.get('pax_local_header')!.uncompressedBytes[156],
      byId.get('pax_global_header')!.uncompressedBytes[156],
      byId.get('gnu_long_name_header')!.uncompressedBytes[156],
      byId.get('gnu_long_link_header')!.uncompressedBytes[156],
    ].map((value) => String.fromCharCode(value!));
    expect(observedFlags).toEqual(extensionFlags);
  });

  it('captures gzip ambiguity and corruption without treating Node gunzip as the policy oracle', () => {
    const fixtures = createArchiveAdversarialFixtureCorpus();
    const byId = new Map(fixtures.map((fixture) => [fixture.id, fixture]));

    expect(() => gunzipSync(byId.get('gzip_bad_crc')!.encodedBytes)).toThrow();
    expect(() => gunzipSync(byId.get('gzip_truncated_trailer')!.encodedBytes)).toThrow();

    const concatenated = byId.get('gzip_concatenated_members')!;
    expect(gunzipSync(concatenated.encodedBytes)).toEqual(concatenated.uncompressedBytes);
    expect(concatenated.expectation).toMatchObject({
      kind: 'reject',
      layer: 'gzip',
      reason: 'multiple_members',
    });

    const highRatio = byId.get('limit_gzip_compression_ratio')!;
    expect(gunzipSync(highRatio.encodedBytes)).toEqual(highRatio.uncompressedBytes);
    expect(highRatio.uncompressedBytes.length / highRatio.encodedBytes.length).toBeGreaterThan(20);
  });

  it('provides equal-length cross-pass substitutions with different authenticated bytes', () => {
    const fixtures = createCrossPassArchiveFixtures();
    expect(fixtures.map((fixture) => fixture.id)).toEqual([
      'body_changed_same_length',
      'entry_order_changed',
      'header_path_changed_same_length',
    ]);
    for (const fixture of fixtures) {
      expect(fixture.passABytes.length, fixture.id).toBe(fixture.passBBytes.length);
      expect(fixtureSha256(fixture.passABytes), fixture.id).not.toBe(fixtureSha256(fixture.passBBytes));
      expect(() => gunzipSync(fixture.passABytes), fixture.id).not.toThrow();
      expect(() => gunzipSync(fixture.passBBytes), fixture.id).not.toThrow();
    }
  });

  it('imports neither archive candidate and leaves dependency manifests unchanged', () => {
    const fixtureSource = readFileSync('test/fixtures/archive-adversarial-fixtures.ts', 'utf8');
    const packageJson = readFileSync('package.json', 'utf8');
    const packageLock = readFileSync('package-lock.json', 'utf8');

    expect(fixtureSource).not.toMatch(/from ['"](?:tar|tar-stream)(?:\/[^'"]*)?['"]/u);
    expect(JSON.parse(packageJson).dependencies).not.toHaveProperty('tar');
    expect(JSON.parse(packageJson).dependencies).not.toHaveProperty('tar-stream');
    expect(JSON.parse(packageLock).packages[''].dependencies).not.toHaveProperty('tar');
    expect(JSON.parse(packageLock).packages[''].dependencies).not.toHaveProperty('tar-stream');
  });
});

function validUstarChecksum(header: Buffer): boolean {
  const stored = Number.parseInt(header.subarray(148, 154).toString('ascii'), 8);
  const copy = Buffer.from(header);
  copy.fill(0x20, 148, 156);
  const computed = copy.reduce((sum, byte) => sum + byte, 0);
  return Number.isSafeInteger(stored) && stored === computed;
}
