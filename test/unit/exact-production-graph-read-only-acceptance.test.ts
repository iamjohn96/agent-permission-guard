import { createHash } from 'node:crypto';
import { chmodSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { ARCHIVE_WORKER_PROTOCOL_VERSION } from '../../src/stage/archive-worker-protocol.js';
import {
  BoundedArchiveWorker,
  repositoryArchiveWorkerOptions,
} from '../../src/stage/bounded-archive-worker.js';
import {
  ExactGraphCandidateAuthority,
  ExactGraphMetadataAuthority,
  ReadOnlyArtifactAcceptancePlanAuthority,
  SyntheticProductionProfileReviewAuthority,
  SyntheticReadOnlyArtifactApprovalAuthority,
  type ExactGraphCandidate,
  type ExactGraphCandidateInput,
  type ExactGraphMetadataTransport,
  type GraphMetadataResponse,
} from '../../src/stage/exact-production-graph.js';
import {
  CompleteReadOnlyAcceptanceAuthority,
  SyntheticReadOnlyAcceptanceAuditAuthority,
} from '../../src/stage/read-only-artifact-acceptance.js';
import {
  PrivateArtifactRootAuthority,
  VerifiedArtifactFileAuthority,
  type ReadOnlyArtifactTransport,
} from '../../src/stage/read-only-artifact-file.js';
import {
  projectAndValidatePackageManifest,
} from '../../src/stage/package-manifest-projection.js';
import {
  buildDeterministicGzip,
  buildUstarArchive,
  fixturePolicyLimits,
} from '../fixtures/archive-adversarial-fixtures.js';

const temporaryPaths: string[] = [];
const NOW = new Date('2026-09-08T00:00:00.000Z');

afterEach(() => {
  for (const path of temporaryPaths.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe('exact production graph and read-only artifact acceptance foundation', () => {
  it('compiles a closed exact lock graph and rejects unsupported, unreachable, cyclic, and forged authority objects', () => {
    const archive = packageArchive('fixture', '1.0.0');
    const authority = new ExactGraphCandidateAuthority();
    const candidate = authority.compile(candidateInput(archive));
    expect(authority.authenticates(candidate)).toBe(true);
    expect(candidate.graphNodes).toHaveLength(1);
    expect(candidate.graphNodes[0]).toMatchObject({
      installPath: 'node_modules/fixture',
      packageName: 'fixture',
      exactVersion: '1.0.0',
    });
    expect(authority.authenticates({ ...candidate })).toBe(false);

    const unsupported = candidateInput(archive);
    (unsupported.packageLock as LockFixture).packages['node_modules/fixture']!.hasInstallScript = true;
    expect(() => authority.compile(unsupported)).toThrowError(expect.objectContaining({ code: 'graph_lock_invalid' }));

    const unreachable = candidateInput(archive);
    unreachable.packageLock = withPackage(unreachable.packageLock as LockFixture, 'node_modules/unused', {
      version: '2.0.0',
      resolved: 'https://registry.npmjs.org/unused/-/unused-2.0.0.tgz',
      integrity: sha512(Buffer.from('unused')),
    });
    expect(() => authority.compile(unreachable)).toThrowError(expect.objectContaining({ code: 'graph_lock_invalid' }));

    const cyclic = candidateInput(archive);
    (cyclic.packageLock as LockFixture).packages['node_modules/fixture']!.dependencies = { fixture: '1.0.0' };
    expect(() => authority.compile(cyclic)).toThrowError(expect.objectContaining({ code: 'graph_lock_invalid' }));
  });

  it('issues one opaque, authority-authenticated closed predicate for every candidate compiler rejection class', () => {
    const archive = packageArchive('fixture', '1.0.0');
    const cases: ReadonlyArray<readonly [string, (input: ExactGraphCandidateInput & { packageLock: LockFixture }) => void]> = [
      ['candidate_input_rejected', (input) => { (input as { profileId: string }).profileId = '!'; }],
      ['lock_document_shape_rejected', (input) => { input.packageLock = [] as unknown as LockFixture; }],
      ['root_package_shape_rejected', (input) => { delete input.packageLock.packages['']; }],
      ['root_dependency_identity_rejected', (input) => { (input.packageLock.packages[''] as LockPackage).dependencies = { fixture: '2.0.0' }; }],
      ['graph_size_rejected', (input) => { delete input.packageLock.packages['node_modules/fixture']; }],
      ['install_path_rejected', (input) => {
        const record = input.packageLock.packages['node_modules/fixture']!;
        delete input.packageLock.packages['node_modules/fixture'];
        input.packageLock.packages.bad = record;
      }],
      ['package_record_shape_rejected', (input) => { (input.packageLock.packages['node_modules/fixture'] as LockPackage).unexpected = true; }],
      ['package_role_rejected', (input) => { (input.packageLock.packages['node_modules/fixture'] as LockPackage).hasInstallScript = true; }],
      ['package_artifact_identity_rejected', (input) => { (input.packageLock.packages['node_modules/fixture'] as LockPackage).integrity = 'sha512-not-base64'; }],
      ['dependency_specifier_rejected', (input) => { (input.packageLock.packages['node_modules/fixture'] as LockPackage).dependencies = { dep: 'file:private' }; }],
      ['dependency_resolution_rejected', (input) => { (input.packageLock.packages['node_modules/fixture'] as LockPackage).dependencies = { dep: '1.0.0' }; }],
      ['target_identity_rejected', (input) => { (input.packageLock.packages['node_modules/fixture'] as LockPackage).version = '2.0.0'; }],
      ['graph_connectivity_rejected', (input) => {
        input.packageLock = withPackage(input.packageLock, 'node_modules/unused', {
          version: '2.0.0', resolved: 'https://registry.npmjs.org/unused/-/unused-2.0.0.tgz', integrity: sha512(Buffer.from('unused')),
        });
      }],
    ];
    for (const [predicate, mutate] of cases) {
      const authority = new ExactGraphCandidateAuthority();
      const input = candidateInput(archive);
      mutate(input);
      let error: unknown;
      try { authority.compile(input); } catch (thrown) { error = thrown; }
      expect(error).toMatchObject({ code: 'graph_lock_invalid' });
      const failure = authority.claimFailure(error);
      expect(failure).toEqual({ diagnosticVersion: 1, predicate });
      expect(Object.isFrozen(failure)).toBe(true);
      expect(JSON.stringify(failure)).not.toContain('registry.npmjs.org');
      expect(authority.authenticatesFailure(failure)).toBe(true);
      const copied = { ...failure! };
      const forgedPredicate = { ...failure!, predicate: 'forged_predicate' };
      const forgedExtra = { ...failure!, rawLockBytes: 'private-lock-bytes' };
      expect(authority.authenticatesFailure(copied)).toBe(false);
      expect(authority.authenticatesFailure(forgedPredicate)).toBe(false);
      expect(authority.authenticatesFailure(forgedExtra)).toBe(false);
      expect('emitFailureDiagnostic' in authority).toBe(false);
      expect(authority.claimFailure(error)).toBeUndefined();
      expect(authority.claimFailure(new Error('graph_lock_invalid'))).toBeUndefined();
      expect(new ExactGraphCandidateAuthority().authenticatesFailure(failure)).toBe(false);
    }
  });

  it('models Node ancestor lookup rather than accepting an arbitrary same-name dependency', () => {
    const topArchive = packageArchive('fixture', '1.0.0', { dep: '^2.0.0' });
    const authority = new ExactGraphCandidateAuthority();
    const input = candidateInput(topArchive);
    (input.packageLock as LockFixture).packages['node_modules/fixture']!.dependencies = { dep: '^2.0.0' };
    input.packageLock = withPackage(input.packageLock as LockFixture, 'node_modules/dep', {
      version: '2.0.0',
      resolved: 'https://registry.npmjs.org/dep/-/dep-2.0.0.tgz',
      integrity: sha512(Buffer.from('dep')),
    });
    const candidate = authority.compile(input);
    expect(candidate.graphNodes.find((node) => node.packageName === 'fixture')!.dependencyEdges)
      .toEqual([{ packageName: 'dep', declaredSpecifier: '^2.0.0', installPath: 'node_modules/dep' }]);
  });

  it('requires complete exact metadata, binds a fresh one-time plan, and rejects replay', async () => {
    const fixture = await acceptanceFixture();
    expect(fixture.metadata.observations).toHaveLength(1);
    expect(fixture.plan.candidateDigest).toBe(fixture.candidate.candidateDigest);
    fixture.approvalAuthority.consume(fixture.approval, fixture.plan, NOW);
    expect(() => fixture.approvalAuthority.consume(fixture.approval, fixture.plan, NOW))
      .toThrowError(expect.objectContaining({ code: 'approval_consumed' }));

    const metadataAuthority = new ExactGraphMetadataAuthority(fixture.candidateAuthority);
    await expect(metadataAuthority.confirm(
      fixture.candidate,
      metadataTransportFor(fixture.candidate, { sha512Integrity: sha512(Buffer.from('wrong')) }),
      metadataLimits(),
      NOW,
    )).rejects.toMatchObject({ code: 'graph_metadata_invalid' });
    await expect(metadataAuthority.confirm(
      fixture.candidate,
      { async fetch() { return new Promise<never>(() => undefined); } },
      { ...metadataLimits(), requestTimeoutMs: 5, totalTimeoutMs: 10 },
      NOW,
    )).rejects.toMatchObject({ code: 'graph_metadata_incomplete' });
  });

  it('streams fixture bytes through private files, performs two fresh Pass-A inspections, cleans up, and only then permits synthetic review', async () => {
    const fixture = await acceptanceFixture();
    const acceptance = new CompleteReadOnlyAcceptanceAuthority(
      fixture.candidateAuthority,
      fixture.planAuthority,
      fixture.fileAuthority,
      new SyntheticReadOnlyAcceptanceAuditAuthority(),
    );
    const evidence = await acceptance.acceptForTest(
      fixture.candidate,
      fixture.plan,
      fixture.approval,
      fixture.root,
      artifactTransportFor(fixture.archive),
      fixture.worker,
      NOW,
    );
    expect(acceptance.authenticates(evidence)).toBe(true);
    expect(evidence.cleanupComplete).toBe(true);
    expect(evidence.artifacts).toHaveLength(1);
    expect(readdirSync(fixture.root.path)).toEqual([]);
    expect(acceptance.lastReport).toMatchObject({
      terminalState: 'ACCEPTANCE_COMPLETE',
      cleanupComplete: true,
      acceptedArtifactCount: 1,
    });
    expect(acceptance.lastReport!.events.filter((event) => event === 'artifact_pass_a_verified')).toHaveLength(1);
    expect(acceptance.lastReport!.events.filter((event) => event === 'artifact_second_pass_a_verified')).toHaveLength(1);

    const review = new SyntheticProductionProfileReviewAuthority(fixture.candidateAuthority);
    const profile = review.acceptForTest(fixture.candidate, evidence, acceptance);
    expect(review.authenticates(profile)).toBe(true);
    expect(review.authenticates({ ...profile })).toBe(false);
    expect(() => review.acceptForTest(fixture.candidate, { ...evidence }, acceptance))
      .toThrowError(expect.objectContaining({ code: 'acceptance_incomplete' }));
  }, 30_000);

  it('rejects duplicate manifest keys and cleans verified files without materializing archive contents', async () => {
    const archive = packageArchiveRaw('{"name":"fixture","name":"substitute","version":"1.0.0"}\n');
    const fixture = await acceptanceFixture(archive);
    const first = await fixture.worker.inspectSourceWithManifest(
      memorySource(archive),
      fixture.candidate.limits,
    );
    expect(() => projectAndValidatePackageManifest(
      first.packageManifestBase64,
      first.transcript,
      fixture.candidate,
      fixture.candidate.graphNodes,
    )).toThrowError(expect.objectContaining({ code: 'manifest_invalid' }));

    const acceptance = new CompleteReadOnlyAcceptanceAuthority(
      fixture.candidateAuthority,
      fixture.planAuthority,
      fixture.fileAuthority,
      new SyntheticReadOnlyAcceptanceAuditAuthority(),
    );
    await expect(acceptance.acceptForTest(
      fixture.candidate,
      fixture.plan,
      fixture.approval,
      fixture.root,
      artifactTransportFor(archive),
      fixture.worker,
      NOW,
    )).rejects.toMatchObject({ code: 'manifest_invalid' });
    expect(readdirSync(fixture.root.path)).toEqual([]);
    expect(acceptance.lastReport).toMatchObject({
      terminalState: 'ACCEPTANCE_INCOMPLETE_QUARANTINE',
      cleanupComplete: true,
    });
  }, 30_000);

  it('rejects integrity substitution before worker access and removes the exact partial artifact', async () => {
    const fixture = await acceptanceFixture();
    const acceptance = new CompleteReadOnlyAcceptanceAuthority(
      fixture.candidateAuthority,
      fixture.planAuthority,
      fixture.fileAuthority,
      new SyntheticReadOnlyAcceptanceAuditAuthority(),
    );
    await expect(acceptance.acceptForTest(
      fixture.candidate,
      fixture.plan,
      fixture.approval,
      fixture.root,
      artifactTransportFor(Buffer.from('not the approved artifact')),
      fixture.worker,
      NOW,
    )).rejects.toMatchObject({ code: 'integrity_mismatch' });
    expect(readdirSync(fixture.root.path)).toEqual([]);
    expect(acceptance.lastReport!.events).not.toContain('artifact_pass_a_verified');

    const timeoutFixture = await acceptanceFixture(packageArchive('fixture', '1.0.0'), {
      artifactRequestTimeoutMs: 100,
      totalArtifactTimeoutMs: 100,
    });
    const timeoutAcceptance = new CompleteReadOnlyAcceptanceAuthority(
      timeoutFixture.candidateAuthority,
      timeoutFixture.planAuthority,
      timeoutFixture.fileAuthority,
      new SyntheticReadOnlyAcceptanceAuditAuthority(),
    );
    await expect(timeoutAcceptance.acceptForTest(
      timeoutFixture.candidate,
      timeoutFixture.plan,
      timeoutFixture.approval,
      timeoutFixture.root,
      { async fetch() { return new Promise<never>(() => undefined); } },
      timeoutFixture.worker,
      NOW,
    )).rejects.toMatchObject({ code: 'artifact_file_invalid' });
    expect(readdirSync(timeoutFixture.root.path)).toEqual([]);
    expect(timeoutAcceptance.lastReport!.events).not.toContain('artifact_pass_a_verified');
  });
});

async function acceptanceFixture(
  archive = packageArchive('fixture', '1.0.0'),
  artifactTimeouts = { artifactRequestTimeoutMs: 5000, totalArtifactTimeoutMs: 10_000 },
) {
  const candidateAuthority = new ExactGraphCandidateAuthority();
  const candidate = candidateAuthority.compile(candidateInput(archive));
  const metadataAuthority = new ExactGraphMetadataAuthority(candidateAuthority);
  const metadata = await metadataAuthority.confirm(
    candidate,
    metadataTransportFor(candidate),
    metadataLimits(),
    NOW,
  );
  const rootAuthority = new PrivateArtifactRootAuthority();
  const root = await rootAuthority.capture(temporaryDirectory('apg-artifact-acceptance-'));
  const worker = await BoundedArchiveWorker.create(repositoryArchiveWorkerOptions(
    process.cwd(),
    temporaryDirectory('apg-artifact-worker-'),
  ));
  const planAuthority = new ReadOnlyArtifactAcceptancePlanAuthority(candidateAuthority, metadataAuthority);
  const plan = planAuthority.create(candidate, metadata, {
    acceptanceSessionId: 'a'.repeat(32),
    runtimeDigest: worker.runtimeDigest,
    quarantineRootBinding: root.binding,
    artifactRequestTimeoutMs: artifactTimeouts.artifactRequestTimeoutMs,
    totalArtifactTimeoutMs: artifactTimeouts.totalArtifactTimeoutMs,
    now: NOW,
  });
  const approvalAuthority = new SyntheticReadOnlyArtifactApprovalAuthority(planAuthority);
  const approval = approvalAuthority.issueForTest(plan, {
    approvalId: 'b'.repeat(32),
    expiresAt: '2026-09-08T00:05:00.000Z',
  });
  const fileAuthority = new VerifiedArtifactFileAuthority(rootAuthority, planAuthority, approvalAuthority);
  return {
    archive, candidateAuthority, candidate, metadata, root, worker, planAuthority, plan,
    approvalAuthority, approval, fileAuthority,
  };
}

function candidateInput(archive: Buffer): ExactGraphCandidateInput & { packageLock: LockFixture } {
  const tarballUrl = 'https://registry.npmjs.org/fixture/-/fixture-1.0.0.tgz';
  return {
    profileId: 'fixture-darwin-arm64-node26',
    profileVersion: 1,
    topPackage: {
      name: 'fixture',
      exactVersion: '1.0.0',
      exactEntrypointRelativePath: 'index.js',
    },
    registryOrigin: 'https://registry.npmjs.org/',
    runtimeConstraint: {
      os: 'darwin',
      architecture: 'arm64',
      nodeMajor: 26,
      nodeVersion: '26.3.1',
      npmGraphGeneratorVersion: '11.16.0',
      lockfileVersion: 3,
    },
    materializationRulesVersion: 1,
    archiveRulesVersion: 1,
    workerProtocolVersion: ARCHIVE_WORKER_PROTOCOL_VERSION,
    limits: fixturePolicyLimits,
    packageLock: {
      name: 'apg-graph-genesis',
      version: '1.0.0',
      lockfileVersion: 3,
      requires: true,
      packages: {
        '': { name: 'apg-graph-genesis', version: '1.0.0', dependencies: { fixture: '1.0.0' } },
        'node_modules/fixture': { version: '1.0.0', resolved: tarballUrl, integrity: sha512(archive) },
      },
    },
  };
}

type LockPackage = Record<string, unknown> & {
  version: string;
  resolved: string;
  integrity: string;
  dependencies?: Record<string, string>;
  hasInstallScript?: boolean;
};

type LockFixture = {
  name: string;
  version: string;
  lockfileVersion: number;
  requires: boolean;
  packages: Record<string, LockPackage | Record<string, unknown>>;
};

function withPackage(lock: LockFixture, path: string, value: LockPackage): LockFixture {
  return { ...lock, packages: { ...lock.packages, [path]: value } };
}

function metadataTransportFor(
  candidate: ExactGraphCandidate,
  override: Partial<GraphMetadataResponse> = {},
): ExactGraphMetadataTransport {
  const node = candidate.graphNodes[0]!;
  return {
    async fetch(request) {
      expect(request.headers).toEqual({ accept: 'application/json' });
      return {
        status: 200,
        contentType: 'application/json',
        responseBytes: 256,
        redirected: false,
        finalUrl: 'https://registry.npmjs.org/fixture/1.0.0',
        packageName: node.packageName,
        exactVersion: node.exactVersion,
        tarballUrl: node.tarballUrl,
        sha512Integrity: node.sha512Integrity,
        ...override,
      };
    },
  };
}

function artifactTransportFor(bytes: Buffer): ReadOnlyArtifactTransport {
  return {
    async fetch(request) {
      expect(request.headers).toEqual({ accept: 'application/octet-stream', acceptEncoding: 'identity' });
      return {
        status: 200,
        redirected: false,
        finalUrl: request.url,
        contentType: 'application/octet-stream',
        contentEncoding: 'identity',
        contentLength: bytes.length,
        body: (async function* () {
          for (let offset = 0; offset < bytes.length; offset += 17) yield bytes.subarray(offset, offset + 17);
        })(),
      };
    },
  };
}

function memorySource(bytes: Buffer) {
  return Object.freeze({
    artifactBytes: bytes.length,
    artifactSha512: sha512(bytes),
    async *chunks() { yield bytes; },
    async validateAfterRead() {},
  });
}

function packageArchive(name: string, version: string, dependencies: Record<string, string> = {}): Buffer {
  return packageArchiveRaw(`${JSON.stringify({ name, version, dependencies })}\n`);
}

function packageArchiveRaw(packageJson: string): Buffer {
  return buildDeterministicGzip(buildUstarArchive([
    { path: 'package/package.json', body: packageJson, mode: 0o644 },
    { path: 'package/index.js', body: 'export default 1;\n', mode: 0o644 },
  ]));
}

function metadataLimits() {
  return {
    responseBytes: 1024,
    aggregateBytes: 8 * 1024,
    freshnessMs: 10 * 60 * 1000,
    requestTimeoutMs: 1000,
    totalTimeoutMs: 5000,
  } as const;
}

function temporaryDirectory(prefix: string): string {
  const path = mkdtempSync(join(tmpdir(), prefix));
  chmodSync(path, 0o700);
  temporaryPaths.push(path);
  return path;
}

function sha512(input: Uint8Array): string {
  return `sha512-${createHash('sha512').update(input).digest('base64')}`;
}
