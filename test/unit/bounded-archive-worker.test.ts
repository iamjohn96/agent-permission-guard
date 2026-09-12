import { chmodSync, copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import {
  BoundedArchiveWorker,
  repositoryArchiveWorkerOptions,
  supportsArchiveWorkerNetworkDenial,
  type ArchiveWorkerMaterializationSink,
} from '../../src/stage/bounded-archive-worker.js';
import type { TarArchiveTranscriptEntry } from '../../src/stage/tar-archive-parser.js';
import {
  createArchiveAdversarialFixtureCorpus,
  createCrossPassArchiveFixtures,
  fixturePolicyLimits,
} from '../fixtures/archive-adversarial-fixtures.js';

const temporaryPaths: string[] = [];

afterEach(() => {
  for (const path of temporaryPaths.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe('bounded archive child worker', () => {
  it('runs the complete independent corpus in fresh permission-gated child processes', async () => {
    const worker = await createRepositoryWorker();
    const fixtures = createArchiveAdversarialFixtureCorpus();
    let accepted = 0;
    let rejected = 0;

    for (const fixture of fixtures) {
      if (fixture.expectation.kind === 'accept') {
        const result = await worker.inspect(fixture.encodedBytes, fixturePolicyLimits);
        expect(worker.authenticates(result), fixture.id).toBe(true);
        expect(Object.isFrozen(result), fixture.id).toBe(true);
        expect(result.transcript.entries, fixture.id).toEqual(
          fixture.expectation.transcript.entries.map((entry) => ({
            ...entry,
            observedSize: entry.declaredSize,
          })),
        );
        accepted += 1;
      } else {
        await expect(worker.inspect(fixture.encodedBytes, fixturePolicyLimits), fixture.id)
          .rejects.toMatchObject({ code: fixture.expectation.expectedCode });
        rejected += 1;
      }
    }
    expect({ accepted, rejected }).toEqual({ accepted: 2, rejected: 50 });
  }, 60_000);

  it('streams pass B in exact order with bounded chunks and rejects cross-pass substitutions', async () => {
    const worker = await createRepositoryWorker({ bodyChunkBytes: 7 });
    const valid = createArchiveAdversarialFixtureCorpus()
      .find((fixture) => fixture.id === 'valid_minimal')!;
    const first = await worker.inspect(valid.encodedBytes, fixturePolicyLimits);
    const sink = collectingSink();
    await worker.materialize(valid.encodedBytes, first, fixturePolicyLimits, sink);

    expect(sink.events.map((event) => event.kind)).toEqual([
      'start', 'body', 'body', 'body', 'body', 'body', 'body', 'end',
      'start', 'body', 'body', 'body', 'end',
    ]);
    expect(Buffer.concat(sink.bodies.get('package.json') ?? []).toString('utf8'))
      .toBe('{"name":"fixture","version":"1.0.0"}\n');

    for (const fixture of createCrossPassArchiveFixtures()) {
      const passA = await worker.inspect(fixture.passABytes, fixturePolicyLimits);
      await expect(worker.materialize(
        fixture.passBBytes,
        passA,
        fixturePolicyLimits,
        collectingSink(),
      ), fixture.id).rejects.toMatchObject({ code: 'archive_invalid' });
    }
  });

  it('rejects forged authority objects, pre-cancelled work, runtime drift, and unsafe cwd mode', async () => {
    const valid = createArchiveAdversarialFixtureCorpus()
      .find((fixture) => fixture.id === 'valid_minimal')!;
    const worker = await createRepositoryWorker();
    const first = await worker.inspect(valid.encodedBytes, fixturePolicyLimits);
    await expect(worker.materialize(
      valid.encodedBytes,
      { ...first },
      fixturePolicyLimits,
      collectingSink(),
    )).rejects.toMatchObject({ code: 'archive_invalid' });

    const controller = new AbortController();
    controller.abort();
    await expect(worker.inspect(valid.encodedBytes, fixturePolicyLimits, controller.signal))
      .rejects.toMatchObject({ code: 'artifact_cancelled' });

    const driftRoot = temporaryDirectory('apg-worker-drift-');
    const driftEntry = join(driftRoot, 'worker.js');
    copyFileSync(resolve('dist/test/fixtures/archive-worker-hang.js'), driftEntry);
    const driftWorker = await BoundedArchiveWorker.create(faultWorkerOptions(driftRoot, driftEntry));
    writeFileSync(driftEntry, '\n', { flag: 'a' });
    await expect(driftWorker.inspect(valid.encodedBytes, fixturePolicyLimits))
      .rejects.toMatchObject({ code: 'archive_worker_failed' });

    const unsafe = temporaryDirectory('apg-worker-unsafe-');
    chmodSync(unsafe, 0o755);
    await expect(BoundedArchiveWorker.create(repositoryArchiveWorkerOptions(process.cwd(), unsafe)))
      .rejects.toMatchObject({ code: 'archive_worker_failed' });
  });

  it('bounds timeout, malformed stdout, and stderr overflow without trusting child errors', async () => {
    const valid = createArchiveAdversarialFixtureCorpus()
      .find((fixture) => fixture.id === 'valid_minimal')!;
    const cases = [
      ['archive-worker-hang.js', 'archive_worker_timeout', 150],
      ['archive-worker-invalid-frame.js', 'archive_protocol_invalid', 1_000],
      ['archive-worker-stderr-overflow.js', 'archive_protocol_invalid', 1_000],
    ] as const;
    for (const [name, code, timeoutMs] of cases) {
      const root = temporaryDirectory(`apg-${name}-`);
      const entry = resolve('dist/test/fixtures', name);
      const worker = await BoundedArchiveWorker.create(faultWorkerOptions(root, entry, timeoutMs));
      await expect(worker.inspect(valid.encodedBytes, fixturePolicyLimits), name)
        .rejects.toMatchObject({ code });
    }
  }, 10_000);

  it('makes the Node 24 network-denial limitation explicit', () => {
    expect(supportsArchiveWorkerNetworkDenial(24)).toBe(false);
    expect(supportsArchiveWorkerNetworkDenial(25)).toBe(true);
    expect(supportsArchiveWorkerNetworkDenial(26)).toBe(true);
    expect(supportsArchiveWorkerNetworkDenial(27)).toBe(false);

    const childSource = readFileSync('src/stage/archive-worker-entry.ts', 'utf8');
    expect(childSource).not.toMatch(/node:(?:fs|child_process|worker_threads|net|http|https)/u);
    expect(childSource).not.toContain('process.env');
  });
});

async function createRepositoryWorker(
  override: Parameters<typeof repositoryArchiveWorkerOptions>[2] = {},
): Promise<BoundedArchiveWorker> {
  const cwd = temporaryDirectory('apg-archive-worker-');
  return BoundedArchiveWorker.create(repositoryArchiveWorkerOptions(process.cwd(), cwd, override));
}

function faultWorkerOptions(root: string, entrypoint: string, timeoutMs = 150) {
  return {
    nodeExecutable: process.execPath,
    expectedNodeMajor: Number.parseInt(process.versions.node.split('.')[0]!, 10) as 24 | 25 | 26,
    workerEntrypoint: entrypoint,
    workingDirectory: root,
    readOnlyRuntimeFiles: Object.freeze([resolve('package.json'), entrypoint]),
    timeoutMs,
    maxFrameBytes: 4 * 1024,
    maxStdoutBytes: 8 * 1024,
    maxStderrBytes: 512,
    bodyChunkBytes: 1024,
    maxOldSpaceMb: 32,
    maxSemiSpaceMb: 4,
  } as const;
}

function temporaryDirectory(prefix: string): string {
  const path = mkdtempSync(join(tmpdir(), prefix));
  chmodSync(path, 0o700);
  temporaryPaths.push(path);
  return path;
}

function collectingSink(): ArchiveWorkerMaterializationSink & Readonly<{
  events: Array<Readonly<{ kind: 'start' | 'body' | 'end'; path: string }>>;
  bodies: Map<string, Buffer[]>;
}> {
  const events: Array<Readonly<{ kind: 'start' | 'body' | 'end'; path: string }>> = [];
  const bodies = new Map<string, Buffer[]>();
  return {
    events,
    bodies,
    async start(entry) {
      events.push({ kind: 'start', path: entry.relativePath });
      bodies.set(entry.relativePath, []);
    },
    async write(entry, _index, _offset, bytes) {
      events.push({ kind: 'body', path: entry.relativePath });
      bodies.get(entry.relativePath)!.push(Buffer.from(bytes));
    },
    async end(entry) {
      events.push({ kind: 'end', path: entry.relativePath });
    },
    async abort() {},
  };
}
