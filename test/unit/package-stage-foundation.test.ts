import { createHash } from 'node:crypto';
import {
  chmodSync,
  linkSync,
  mkdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { PortableArchivePolicy } from '../../src/stage/archive-policy.js';
import {
  SyntheticSealedPackageStageAuthority,
  SyntheticStageAuditAuthority,
} from '../../src/stage/authority.js';
import { runSyntheticArtifactPreflight } from '../../src/stage/foundation.js';
import { PackageArtifactIntegrityAuthority } from '../../src/stage/integrity.js';
import {
  PackageStagePlanAuthority,
  SyntheticPackageStageApprovalAuthority,
} from '../../src/stage/plan.js';
import {
  computeGraphProfileDigest,
  PackageStageError,
  VerifiedMcpGraphProfileAuthority,
} from '../../src/stage/profile.js';
import { PackageStageStateMachine } from '../../src/stage/state-machine.js';
import {
  createMaterializedTreeManifest,
  revalidateMaterializedTree,
  validateMaterializedPackageGraph,
} from '../../src/stage/tree-manifest.js';
import type {
  ArchiveEntryDescription,
  PackageStageLimits,
  UnsignedVerifiedMcpGraphProfile,
  VerifiedMcpGraphProfileDefinition,
} from '../../src/stage/types.js';

const temporaryPaths: string[] = [];
const artifactBytes = Buffer.from('synthetic reviewed package bytes');

afterEach(() => {
  for (const path of temporaryPaths.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe('verified MCP graph profile and stage-plan authorities', () => {
  it('canonicalizes graph data, binds mutations, and authenticates only owning-authority objects', () => {
    const definition = profileDefinition();
    const authority = new VerifiedMcpGraphProfileAuthority([definition]);
    const profile = authority.select(definition.profileId);
    const other = new VerifiedMcpGraphProfileAuthority([]);

    expect(profile.manifestDigest).toBe(definition.manifestDigest);
    expect(authority.authenticates(profile)).toBe(true);
    expect(other.authenticates(profile)).toBe(false);
    expect(authority.authenticates({ ...profile })).toBe(false);
    expect(Object.isFrozen(profile)).toBe(true);
    expect(Object.isFrozen(profile.graphNodes)).toBe(true);

    const changed = unsignedProfile({ archiveRulesVersion: 2 });
    expect(computeGraphProfileDigest(changed)).not.toBe(profile.manifestDigest);
  });

  it('rejects digest drift, unknown fields, dynamic sources, invalid integrity, and unreachable graph nodes', () => {
    expect(() => new VerifiedMcpGraphProfileAuthority([{
      ...profileDefinition(),
      manifestDigest: '0'.repeat(64),
    }])).toThrowError(expect.objectContaining({ code: 'profile_digest_mismatch' }));

    const unknown = { ...profileDefinition(), unexpected: true } as unknown as VerifiedMcpGraphProfileDefinition;
    expect(() => new VerifiedMcpGraphProfileAuthority([unknown])).toThrowError(expect.objectContaining({ code: 'profile_invalid' }));

    const invalidUrl = unsignedProfile({
      graphNodes: [{ ...unsignedProfile().graphNodes[0]!, tarballUrl: 'http://registry.npmjs.org/package.tgz' }],
    });
    expect(() => authorityForUnsigned(invalidUrl)).toThrowError(expect.objectContaining({ code: 'profile_invalid' }));

    const invalidIntegrity = unsignedProfile({
      graphNodes: [{ ...unsignedProfile().graphNodes[0]!, sha512Integrity: 'sha512-not-base64' }],
    });
    expect(() => authorityForUnsigned(invalidIntegrity)).toThrowError(expect.objectContaining({ code: 'integrity_invalid' }));

    const orphan = unsignedProfile({
      graphNodes: [
        ...unsignedProfile().graphNodes,
        {
          ...unsignedProfile().graphNodes[0]!,
          installPath: 'node_modules/orphan',
          packageName: 'orphan',
          tarballUrl: 'https://registry.npmjs.org/orphan/-/orphan-1.0.0.tgz',
        },
      ],
    });
    expect(() => authorityForUnsigned(orphan)).toThrowError(expect.objectContaining({ code: 'profile_invalid' }));
  });

  it('binds one exact plan and rejects approval replay or cross-plan substitution', () => {
    const { profileAuthority, profile, planAuthority, plan } = stageFixture();
    const approvals = new SyntheticPackageStageApprovalAuthority(planAuthority);
    const approval = approvals.issueForTest(plan);
    approvals.consume(approval, plan);
    expect(() => approvals.consume(approval, plan)).toThrowError(expect.objectContaining({ code: 'approval_consumed' }));

    const second = planAuthority.create(profile, planInput({ stageId: 'b'.repeat(32) }));
    const secondApproval = approvals.issueForTest(second);
    expect(() => approvals.consume(secondApproval, plan)).toThrowError(expect.objectContaining({ code: 'approval_invalid' }));
    expect(planAuthority.authenticates({ ...plan })).toBe(false);
    expect(profileAuthority.authenticates({ ...profile })).toBe(false);
    expect(Object.isFrozen(plan.graphNodes)).toBe(true);

    expect(() => planAuthority.create(profile, planInput({
      metadataExpiresAt: '2026-09-06T23:59:59.000Z',
    }))).toThrowError(expect.objectContaining({ code: 'plan_invalid' }));
  });
});

describe('artifact integrity and injected preflight ordering', () => {
  it('allows archive inspection only after exact SHA-512 verification', async () => {
    const { planAuthority, plan } = stageFixture();
    const approvals = new SyntheticPackageStageApprovalAuthority(planAuthority);
    const approval = approvals.issueForTest(plan);
    let inspected = 0;

    const result = await runSyntheticArtifactPreflight(plan, approval, {
      planAuthority,
      approvalAuthority: approvals,
      downloader: {
        async download(_plan, node) {
          return { finalUrl: node.tarballUrl, redirected: false, body: chunks(artifactBytes, 7) };
        },
      },
      archiveInspector: {
        async preflight(artifact) {
          inspected += 1;
          expect(artifact.sha512Integrity).toBe(plan.graphNodes[0]!.sha512Integrity);
          return new PortableArchivePolicy(plan.limits).preflight(validArchive());
        },
      },
    });

    expect(inspected).toBe(1);
    expect(result.compressedBytes).toBe(artifactBytes.length);
    expect(result.archivePreflights[0]?.entries.map((entry) => entry.relativePath)).toEqual([
      'index.js',
      'package.json',
    ]);
  });

  it('rejects mismatch, oversize, cancellation, and redirects before archive inspection', async () => {
    const fixture = stageFixture();
    const node = fixture.plan.graphNodes[0]!;
    const mismatch = new PackageArtifactIntegrityAuthority(fixture.plan.limits);
    await expect(mismatch.verify(node, chunks(Buffer.from('wrong'), 2))).rejects.toMatchObject({
      code: 'integrity_mismatch',
    });

    const tinyLimits = { ...fixture.plan.limits, compressedArtifactBytes: 2, totalCompressedBytes: 2 };
    const oversized = new PackageArtifactIntegrityAuthority(tinyLimits);
    await expect(oversized.verify(node, chunks(artifactBytes, 4))).rejects.toMatchObject({
      code: 'artifact_too_large',
    });

    const controller = new AbortController();
    controller.abort();
    const cancelled = new PackageArtifactIntegrityAuthority(fixture.plan.limits);
    await expect(cancelled.verify(node, chunks(artifactBytes, 4), controller.signal)).rejects.toMatchObject({
      code: 'artifact_cancelled',
    });

    const approvals = new SyntheticPackageStageApprovalAuthority(fixture.planAuthority);
    let inspected = 0;
    await expect(runSyntheticArtifactPreflight(
      fixture.plan,
      approvals.issueForTest(fixture.plan),
      {
        planAuthority: fixture.planAuthority,
        approvalAuthority: approvals,
        downloader: {
          async download(_plan, current) {
            return { finalUrl: current.tarballUrl, redirected: true, body: chunks(artifactBytes, 5) };
          },
        },
        archiveInspector: {
          async preflight() {
            inspected += 1;
            return new PortableArchivePolicy(fixture.plan.limits).preflight(validArchive());
          },
        },
      },
    )).rejects.toMatchObject({ code: 'integrity_invalid' });
    expect(inspected).toBe(0);
  });
});

describe('portable archive policy', () => {
  it('normalizes safe entries and rejects traversal, links, special files, ambiguity, and nested package state', () => {
    const limits = stageLimits();
    const valid = new PortableArchivePolicy(limits).preflight(validArchive());
    expect(valid.entries).toEqual([
      { relativePath: 'index.js', type: 'file', size: 20, normalizedMode: 0o644 },
      { relativePath: 'package.json', type: 'file', size: 40, normalizedMode: 0o644 },
    ]);

    const invalidSets: ArchiveEntryDescription[][] = [
      [entry('package/../escape')],
      [entry('/package/escape')],
      [entry('package\\escape')],
      [entry('package/e\u0301.js')],
      [{ ...entry('package/link'), type: 'symlink', linkTarget: '../escape' }],
      [{ ...entry('package/link'), type: 'hardlink', linkTarget: 'package/index.js' }],
      [{ ...entry('package/fifo'), type: 'fifo' }],
      [entry('package/A.js'), entry('package/a.js')],
      [entry('package/node_modules/hidden.js')],
      [entry('package/.npmrc')],
      [{ ...entry('package/setuid'), mode: 0o4755 }],
      [{ ...entry('package/sparse'), sparse: true }],
      [{ ...entry('package/xattr'), hasExtendedAttributes: true }],
    ];
    for (const entries of invalidSets) {
      expect(() => new PortableArchivePolicy(limits).preflight(entries)).toThrowError(PackageStageError);
    }
  });

  it('enforces per-file, expanded-byte, entry-count, path-byte, and depth ceilings', () => {
    const limits = { ...stageLimits(), regularFileBytes: 10, uncompressedArtifactBytes: 15, archiveEntries: 1, relativePathBytes: 30, pathDepth: 2 };
    expect(() => new PortableArchivePolicy(limits).preflight([{ ...entry('package/large'), size: 11 }]))
      .toThrowError(expect.objectContaining({ code: 'archive_limit_exceeded' }));
    expect(() => new PortableArchivePolicy(limits).preflight([entry('package/a'), entry('package/b')]))
      .toThrowError(expect.objectContaining({ code: 'archive_limit_exceeded' }));
    expect(() => new PortableArchivePolicy(limits).preflight([entry(`package/${'a'.repeat(31)}`)]))
      .toThrowError(PackageStageError);
    expect(() => new PortableArchivePolicy(limits).preflight([entry('package/a/b/c')]))
      .toThrowError(PackageStageError);
  });
});

describe('materialized tree, state, and synthetic seal authority', () => {
  it('creates a deterministic exact graph manifest and detects byte or file-type changes', async () => {
    const root = materializedFixture();
    const { profileAuthority, profile } = stageFixture();
    const first = await createMaterializedTreeManifest(root, profile.limits);
    const second = await createMaterializedTreeManifest(root, profile.limits);
    const validated = await validateMaterializedPackageGraph(root, profile, profileAuthority);

    expect(first).toEqual(second);
    expect(validated.entrypointRelativePath).toBe('node_modules/synthetic-server/index.js');
    expect(validated.entrypointSha256).toMatch(/^[0-9a-f]{64}$/u);

    writeFileSync(join(root, 'node_modules', 'synthetic-server', 'index.js'), 'changed\n');
    await expect(revalidateMaterializedTree(root, first, profile.limits)).rejects.toMatchObject({
      code: 'tree_changed',
    });

    const secondRoot = materializedFixture();
    symlinkSync('/private/tmp', join(secondRoot, 'node_modules', 'synthetic-server', 'escape'));
    await expect(createMaterializedTreeManifest(secondRoot, profile.limits)).rejects.toMatchObject({
      code: 'tree_invalid',
    });

    const thirdRoot = materializedFixture();
    linkSync(
      join(thirdRoot, 'node_modules', 'synthetic-server', 'index.js'),
      join(thirdRoot, 'node_modules', 'synthetic-server', 'second.js'),
    );
    await expect(createMaterializedTreeManifest(thirdRoot, profile.limits)).rejects.toMatchObject({
      code: 'tree_invalid',
    });

    const fourthRoot = materializedFixture();
    chmodSync(join(fourthRoot, 'node_modules', 'synthetic-server', 'index.js'), 0o666);
    await expect(createMaterializedTreeManifest(fourthRoot, profile.limits)).rejects.toMatchObject({
      code: 'tree_invalid',
    });

    const fifthRoot = materializedFixture();
    mkdirSync(join(fifthRoot, 'node_modules', 'surprise'), { mode: 0o755 });
    await expect(validateMaterializedPackageGraph(fifthRoot, profile, profileAuthority)).rejects.toMatchObject({
      code: 'tree_invalid',
    });
  });

  it('rejects package identity, dependency, lifecycle, and entrypoint drift', async () => {
    const { profileAuthority, profile } = stageFixture();
    const cases = [
      { name: 'other', version: '1.0.0', dependencies: {}, scripts: {} },
      { name: 'synthetic-server', version: '2.0.0', dependencies: {}, scripts: {} },
      { name: 'synthetic-server', version: '1.0.0', dependencies: { surprise: '^1' }, scripts: {} },
      { name: 'synthetic-server', version: '1.0.0', dependencies: {}, scripts: { prepare: 'private command' } },
    ];
    for (const packageJson of cases) {
      const root = materializedFixture(packageJson);
      await expect(validateMaterializedPackageGraph(root, profile, profileAuthority)).rejects.toMatchObject({
        code: 'tree_invalid',
      });
    }
    const missingEntrypoint = materializedFixture();
    rmSync(join(missingEntrypoint, 'node_modules', 'synthetic-server', 'index.js'));
    await expect(validateMaterializedPackageGraph(missingEntrypoint, profile, profileAuthority)).rejects.toMatchObject({
      code: 'tree_invalid',
    });
  });

  it('permits only monotonic transitions and cannot recover failed or invalid stages', () => {
    const state = new PackageStageStateMachine();
    expect(state.transition('METADATA_CONFIRMING')).toBe('METADATA_CONFIRMING');
    expect(() => state.transition('READY')).toThrowError(expect.objectContaining({ code: 'state_transition_invalid' }));
    expect(state.transition('FAILED_QUARANTINE')).toBe('FAILED_QUARANTINE');
    expect(() => state.transition('READY')).toThrowError(expect.objectContaining({ code: 'state_transition_invalid' }));

    const ready = new PackageStageStateMachine('READY');
    expect(ready.transition('INVALID')).toBe('INVALID');
    expect(() => ready.transition('READY')).toThrowError(expect.objectContaining({ code: 'state_transition_invalid' }));
  });

  it('requires matching authenticated audit evidence and rejects forged sealed stages', async () => {
    const fixture = stageFixture();
    const tree = await createMaterializedTreeManifest(materializedFixture(), fixture.profile.limits);
    const audit = new SyntheticStageAuditAuthority();
    const stageAuthority = new SyntheticSealedPackageStageAuthority(
      fixture.profileAuthority,
      fixture.planAuthority,
      audit,
    );
    const evidence = audit.recordCommittedForTest(fixture.plan, fixture.planAuthority, tree);
    const stage = stageAuthority.sealForTest(fixture.profile, fixture.plan, tree, evidence);

    expect(stageAuthority.authenticates(stage)).toBe(true);
    expect(stageAuthority.authenticates({ ...stage })).toBe(false);
    expect(stage.assurance).toMatchObject({
      publisherIdentity: 'unverified',
      buildReproducibility: 'unverified',
      runtimeContainment: 'none',
    });

    const otherAudit = new SyntheticStageAuditAuthority();
    const forgedEvidence = otherAudit.recordCommittedForTest(fixture.plan, fixture.planAuthority, tree);
    expect(() => stageAuthority.sealForTest(fixture.profile, fixture.plan, tree, forgedEvidence))
      .toThrowError(expect.objectContaining({ code: 'stage_audit_incomplete' }));
  });

  it('uses bounded errors that omit private paths, package bytes, and approval material', async () => {
    const privatePath = join(tmpdir(), 'private-stage-secret');
    let error: unknown;
    try {
      await createMaterializedTreeManifest(privatePath, stageLimits());
    } catch (caught) {
      error = caught;
    }
    expect(String(error)).toContain('tree_invalid');
    expect(String(error)).not.toContain(privatePath);
    expect(String(error)).not.toContain(artifactBytes.toString('utf8'));
  });
});

function stageFixture() {
  const definition = profileDefinition();
  const profileAuthority = new VerifiedMcpGraphProfileAuthority([definition]);
  const profile = profileAuthority.select(definition.profileId);
  const planAuthority = new PackageStagePlanAuthority(
    profileAuthority,
    () => new Date('2026-09-07T00:00:00.000Z'),
  );
  const plan = planAuthority.create(profile, planInput());
  return { profileAuthority, profile, planAuthority, plan };
}

function unsignedProfile(
  override: Partial<UnsignedVerifiedMcpGraphProfile> = {},
): UnsignedVerifiedMcpGraphProfile {
  return {
    profileId: 'synthetic.mcp-stage.v0',
    profileVersion: 1,
    topPackage: {
      name: 'synthetic-server',
      exactVersion: '1.0.0',
      exactEntrypointRelativePath: 'index.js',
    },
    registryOrigin: 'https://registry.npmjs.org/',
    runtimeConstraint: {
      os: 'darwin',
      architecture: 'arm64',
      nodeMajor: 26,
      npmGraphGeneratorVersion: '11.16.0',
    },
    graphNodes: [{
      installPath: 'node_modules/synthetic-server',
      packageName: 'synthetic-server',
      exactVersion: '1.0.0',
      tarballUrl: 'https://registry.npmjs.org/synthetic-server/-/synthetic-server-1.0.0.tgz',
      sha512Integrity: `sha512-${createHash('sha512').update(artifactBytes).digest('base64')}`,
      dependencyEdges: [],
      expectedLifecycleScriptNames: [],
    }],
    materializationRulesVersion: 1,
    archiveRulesVersion: 1,
    limits: stageLimits(),
    ...override,
  };
}

function profileDefinition(): VerifiedMcpGraphProfileDefinition {
  const unsigned = unsignedProfile();
  return { ...unsigned, manifestDigest: computeGraphProfileDigest(unsigned) };
}

function authorityForUnsigned(unsigned: UnsignedVerifiedMcpGraphProfile): VerifiedMcpGraphProfileAuthority {
  return new VerifiedMcpGraphProfileAuthority([{
    ...unsigned,
    manifestDigest: computeGraphProfileDigest(unsigned),
  }]);
}

function stageLimits(): PackageStageLimits {
  return {
    graphNodes: 8,
    compressedArtifactBytes: 1024,
    totalCompressedBytes: 4096,
    uncompressedArtifactBytes: 2048,
    totalUncompressedBytes: 8192,
    regularFileBytes: 1024,
    archiveEntries: 100,
    relativePathBytes: 512,
    pathDepth: 32,
  };
}

function planInput(override: Record<string, string> = {}) {
  return {
    stageId: 'a'.repeat(32),
    metadataObservationDigest: 'b'.repeat(64),
    metadataExpiresAt: '2026-09-07T12:00:00.000Z',
    stageRootBinding: 'c'.repeat(64),
    ...override,
  };
}

function validArchive(): ArchiveEntryDescription[] {
  return [
    entry('package/package.json', 40),
    entry('package/index.js', 20),
  ];
}

function entry(path: string, size = 1): ArchiveEntryDescription {
  return { path, type: 'file', size, mode: 0o644 };
}

async function* chunks(bytes: Uint8Array, size: number): AsyncIterable<Uint8Array> {
  for (let index = 0; index < bytes.length; index += size) {
    yield bytes.subarray(index, Math.min(bytes.length, index + size));
  }
}

function materializedFixture(
  packageJson: Record<string, unknown> = {
    name: 'synthetic-server',
    version: '1.0.0',
    dependencies: {},
    scripts: {},
  },
): string {
  const root = join(tmpdir(), `apg-stage-${crypto.randomUUID()}`);
  const packageRoot = join(root, 'node_modules', 'synthetic-server');
  mkdirSync(packageRoot, { recursive: true, mode: 0o755 });
  writeFileSync(join(packageRoot, 'package.json'), `${JSON.stringify(packageJson)}\n`, { mode: 0o644 });
  writeFileSync(join(packageRoot, 'index.js'), 'export {};\n', { mode: 0o644 });
  temporaryPaths.push(root);
  return root;
}
