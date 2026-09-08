import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';

import { describe, expect, it } from 'vitest';

import { PackageStageError } from '../../src/stage/profile.js';
import {
  TAR_PARSER_ENTRYPOINT,
  TAR_PARSER_PACKAGE,
  TAR_PARSER_VERSION,
  TarArchiveTranscriptAuthority,
} from '../../src/stage/tar-archive-parser.js';
import {
  createArchiveAdversarialFixtureCorpus,
  createCrossPassArchiveFixtures,
  fixturePolicyLimits,
} from '../fixtures/archive-adversarial-fixtures.js';

describe('exact tar/parse archive fixture adapter', () => {
  it('binds accepted fixture bytes to an authenticated parser transcript', () => {
    const authority = new TarArchiveTranscriptAuthority();
    const fixtures = createArchiveAdversarialFixtureCorpus()
      .filter((fixture) => fixture.expectation.kind === 'accept');

    for (const fixture of fixtures) {
      if (fixture.expectation.kind !== 'accept') throw new Error('fixture_expectation_invalid');
      const transcript = authority.inspect(fixture.encodedBytes, fixturePolicyLimits);
      expect(authority.authenticates(transcript), fixture.id).toBe(true);
      expect(Object.isFrozen(transcript), fixture.id).toBe(true);
      expect(Object.isFrozen(transcript.entries), fixture.id).toBe(true);
      expect(transcript).toMatchObject({
        adapterContractVersion: 1,
        candidatePackage: TAR_PARSER_PACKAGE,
        candidateVersion: TAR_PARSER_VERSION,
        candidateEntrypoint: TAR_PARSER_ENTRYPOINT,
        archiveRulesVersion: 1,
        format: 'gzip_ustar_v0',
        entryCount: fixture.expectation.transcript.entryCount,
        expandedBytes: fixture.expectation.transcript.expandedBytes,
      });
      expect(transcript.entries).toEqual(fixture.expectation.transcript.entries.map((entry) => ({
        ...entry,
        observedSize: entry.declaredSize,
      })));
      expect(transcript.artifactSha512).toMatch(/^sha512-[A-Za-z0-9+/]+={0,2}$/u);
      expect(transcript.transcriptDigest).toMatch(/^[a-f0-9]{64}$/u);
    }
  });

  it('fails closed across every independent negative fixture', () => {
    const authority = new TarArchiveTranscriptAuthority();
    const fixtures = createArchiveAdversarialFixtureCorpus()
      .filter((fixture) => fixture.expectation.kind === 'reject');

    expect(fixtures).toHaveLength(50);
    for (const fixture of fixtures) {
      if (fixture.expectation.kind !== 'reject') throw new Error('fixture_expectation_invalid');
      expect(
        () => authority.inspect(fixture.encodedBytes, fixturePolicyLimits),
        fixture.id,
      ).toThrowError(expect.objectContaining({ code: fixture.expectation.expectedCode }));
    }
  });

  it('requires complete authenticated equality across parser passes', () => {
    const authority = new TarArchiveTranscriptAuthority();
    const valid = createArchiveAdversarialFixtureCorpus()
      .find((fixture) => fixture.id === 'valid_minimal')!;
    const first = authority.inspect(valid.encodedBytes, fixturePolicyLimits);
    const second = authority.inspect(valid.encodedBytes, fixturePolicyLimits);
    expect(() => authority.assertMatching(first, second)).not.toThrow();

    for (const fixture of createCrossPassArchiveFixtures()) {
      const passA = authority.inspect(fixture.passABytes, fixturePolicyLimits);
      const passB = authority.inspect(fixture.passBBytes, fixturePolicyLimits);
      expect(() => authority.assertMatching(passA, passB), fixture.id)
        .toThrowError(expect.objectContaining({ code: 'archive_invalid' }));
    }
  });

  it('rejects forged transcripts and already-aborted work', () => {
    const authority = new TarArchiveTranscriptAuthority();
    const valid = createArchiveAdversarialFixtureCorpus()
      .find((fixture) => fixture.id === 'valid_minimal')!;
    const transcript = authority.inspect(valid.encodedBytes, fixturePolicyLimits);
    const forged = { ...transcript };
    expect(authority.authenticates(forged)).toBe(false);
    expect(() => authority.assertMatching(transcript, forged))
      .toThrowError(expect.objectContaining({ code: 'archive_invalid' }));

    const controller = new AbortController();
    controller.abort();
    expect(() => authority.inspect(valid.encodedBytes, fixturePolicyLimits, controller.signal))
      .toThrowError(expect.objectContaining({ code: 'artifact_cancelled' }));
    expect(() => authority.inspect(valid.encodedBytes, {
      ...fixturePolicyLimits,
      compressedArtifactBytes: 0,
    })).toThrowError(expect.objectContaining({ code: 'archive_limit_exceeded' }));
  });

  it('permits only the exact parser import and reviewed lock graph', () => {
    const sourceFiles = collectTypeScriptFiles('src');
    const tarImports = sourceFiles.flatMap((file) => {
      const source = readFileSync(file, 'utf8');
      return [...source.matchAll(/(?:from\s+|import\s*\()['"](tar(?:\/[^'"]*)?)['"]/gu)]
        .map((match) => ({ file: relative('.', file), specifier: match[1] }));
    });
    expect(tarImports).toEqual([{
      file: 'src/stage/tar-archive-parser.ts',
      specifier: 'tar/parse',
    }]);

    const adapterSource = readFileSync('src/stage/tar-archive-parser.ts', 'utf8');
    expect(adapterSource).not.toMatch(/node:(?:fs|child_process|net|http|https)/u);
    expect(adapterSource).not.toMatch(/tar\/(?:x|extract|unpack|list|t|create|c|pack|replace|r|update|u)/u);

    const packageJson = JSON.parse(readFileSync('package.json', 'utf8')) as {
      dependencies: Record<string, string>;
    };
    const packageLock = JSON.parse(readFileSync('package-lock.json', 'utf8')) as {
      packages: Record<string, Readonly<{
        version?: string;
        resolved?: string;
        integrity?: string;
        dev?: boolean;
        optional?: boolean;
        hasInstallScript?: boolean;
      }>>;
    };
    expect(packageJson.dependencies.tar).toBe('7.5.22');
    expect(packageLock.packages['']?.version).toBe('0.2.0');
    expect(packageLock.packages[''] && (packageLock.packages[''] as unknown as {
      dependencies: Record<string, string>;
    }).dependencies.tar).toBe('7.5.22');

    const graph = [
      [
        'node_modules/tar',
        '7.5.22',
        'https://registry.npmjs.org/tar/-/tar-7.5.22.tgz',
        'sha512-MFO/QzvtAOmJbkhOaCTvbGcFN9L9b+JunIsDwaKljSOdcLMea3NJ1k9Usz/rjdfSXTq4dfzfeS7W4p4YOAAHeA==',
      ],
      [
        'node_modules/@isaacs/fs-minipass',
        '4.0.1',
        'https://registry.npmjs.org/@isaacs/fs-minipass/-/fs-minipass-4.0.1.tgz',
        'sha512-wgm9Ehl2jpeqP3zw/7mo3kRHFp5MEDhqAdwy1fTGkHAwnkGOVsgpvQhL8B5n1qlb01jV3n/bI0ZfZp5lWA1k4w==',
      ],
      [
        'node_modules/chownr',
        '3.0.0',
        'https://registry.npmjs.org/chownr/-/chownr-3.0.0.tgz',
        'sha512-+IxzY9BZOQd/XuYPRmrvEVjF/nqj5kgT4kEq7VofrDoM1MxoRjEWkrCC3EtLi59TVawxTAn+orJwFQcrqEN1+g==',
      ],
      [
        'node_modules/minipass',
        '7.1.3',
        'https://registry.npmjs.org/minipass/-/minipass-7.1.3.tgz',
        'sha512-tEBHqDnIoM/1rXME1zgka9g6Q2lcoCkxHLuc7ODJ5BxbP5d4c2Z5cGgtXAku59200Cx7diuHTOYfSBD8n6mm8A==',
      ],
      [
        'node_modules/minizlib',
        '3.1.0',
        'https://registry.npmjs.org/minizlib/-/minizlib-3.1.0.tgz',
        'sha512-KZxYo1BUkWD2TVFLr0MQoM8vUUigWD3LlD83a/75BqC+4qE0Hb1Vo5v1FgcfaNXvfXzr+5EhQ6ing/CaBijTlw==',
      ],
      [
        'node_modules/yallist',
        '5.0.0',
        'https://registry.npmjs.org/yallist/-/yallist-5.0.0.tgz',
        'sha512-YgvUTfwqyc7UXVMrB+SImsVYSmTS8X/tSrtdNZMImM+n7+QTriRXyXim0mBrTXNeqzVF0KWGgHPeiyViFFrNDw==',
      ],
    ] as const;
    for (const [installPath, version, resolved, integrity] of graph) {
      const node = packageLock.packages[installPath];
      expect(node?.version, installPath).toBe(version);
      expect(node?.resolved, installPath).toBe(resolved);
      expect(node?.integrity, installPath).toBe(integrity);
      expect(node?.dev, installPath).not.toBe(true);
      expect(node?.optional, installPath).not.toBe(true);
      expect(node?.hasInstallScript, installPath).not.toBe(true);
    }
  });
});

function collectTypeScriptFiles(directory: string): readonly string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return collectTypeScriptFiles(path);
    return entry.isFile() && entry.name.endsWith('.ts') ? [path] : [];
  });
}
