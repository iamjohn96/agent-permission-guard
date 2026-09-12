import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { canonicalJson } from '../../src/audit/canonical-json.js';
import { ARCHIVE_WORKER_PROTOCOL_VERSION } from '../../src/stage/archive-worker-protocol.js';
import {
  ExactGraphCandidateV2Authority,
  PEER_SEMANTICS_V2_CONTRACT,
  type ExactGraphCandidateV2Input,
} from '../../src/stage/exact-production-graph-v2.js';
import {
  COMPILATION_CONTRACT_DIGEST,
  EXACT_COMPILATION_CONTRACT_V1,
  GRAPH_GENESIS_V2_POLICY,
  GRAPH_GENESIS_V2_POLICY_DIGEST,
  GraphGenesisV2BindingAuthority,
  SEMANTIC_CONTRACT_DIGEST,
  type GraphGenesisEnvelopeV2Input,
  type GraphGenesisPlanV3Input,
} from '../../src/stage/graph-genesis-v2-binding.js';
import { encodeExactGraphCandidateV2, decodeExactGraphCandidateV2 } from '../../src/stage/graph-genesis-candidate-codec-v2.js';
import { GRAPH_GENESIS_POLICY as CURRENT_GRAPH_GENESIS_POLICY } from '../../src/stage/graph-genesis-composition.js';
import { PACKAGE_STAGE_HARD_CEILINGS } from '../../src/stage/profile.js';

const MiB = 1024 * 1024;
const digest = (character: string): string => character.repeat(64);
const sha256 = (value: unknown): string => createHash('sha256').update(canonicalJson(value)).digest('hex');
const runtimeSnapshots = () => ({
  node: digest('1'),
  npmCli: digest('2'),
  sandboxExec: digest('3'),
  brokerRuntime: digest('4'),
  probeRuntime: digest('5'),
  npmTree: digest('6'),
  brokerTree: digest('7'),
});

const planInput = (): GraphGenesisPlanV3Input => ({
  planVersion: 3,
  candidateSchemaVersion: 2,
  peerSemanticsVersion: 1,
  compilationContractVersion: 1,
  semanticContract: PEER_SEMANTICS_V2_CONTRACT,
  semanticContractDigest: SEMANTIC_CONTRACT_DIGEST,
  compilationContract: EXACT_COMPILATION_CONTRACT_V1,
  compilationContractDigest: COMPILATION_CONTRACT_DIGEST,
  planId: 'a'.repeat(32),
  targetName: '@modelcontextprotocol/server-filesystem',
  exactTargetVersion: '2026.7.10',
  registryOrigin: 'https://registry.npmjs.org/',
  platform: 'darwin',
  architecture: 'arm64',
  osBuild: '25A1',
  nodeVersion: '26.3.1',
  npmVersion: '11.16.0',
  hostEvidenceDigest: digest('8'),
  runtimeVersionEvidenceDigest: digest('9'),
  runtimeSnapshots: runtimeSnapshots(),
  runtimeManifestDigest: digest('a'),
  containmentEvidenceDigest: digest('b'),
  containmentProfileDigest: digest('c'),
  containmentProviderId: 'macos-seatbelt-loopback-development-v0',
  workspaceBinding: digest('d'),
  brokerAddress: '127.0.0.1',
  brokerPort: 43121,
  routeTokenDigest: digest('e'),
  privatePathSetDigest: digest('f'),
  launchDigest: digest('0'),
  environmentDigest: digest('1'),
  executionCapsuleDigest: digest('2'),
  limits: {
    broker: {
      uniquePackageNames: 128,
      totalRequests: 256,
      concurrentRequests: 4,
      responseBytes: 4 * MiB,
      aggregateResponseBytes: 64 * MiB,
      requestTimeoutMs: 10_000,
    },
    completeTimeoutMs: 120_000,
    stdoutBytes: 256 * 1024,
    stderrBytes: 256 * 1024,
    packageJsonBytes: 64 * 1024,
    packageLockBytes: 4 * MiB,
  },
  maxCandidateOutputs: 1,
  consequence: 'bounded_public_metadata_graph_genesis',
});

const envelopeInput = (): GraphGenesisEnvelopeV2Input => ({
  envelopeVersion: 2,
  sessionId: 'b'.repeat(32),
  bootSessionDigest: digest('3'),
  auditSchemaDigest: digest('4'),
  auditFileIdentityDigest: digest('5'),
  auditDatabaseInstanceId: '12345678-1234-4123-8123-123456789abc',
  initialAuditChainTail: digest('6'),
  auditDurabilityProfileDigest: digest('7'),
  outputCanonicalPathDigest: digest('8'),
  outputParentIdentityDigest: digest('9'),
  outputRule: 'exclusive_new_private_file',
  dashboardInstanceId: 'abcdefab-cdef-4abc-8def-abcdefabcdef',
  dashboardPort: 43122,
  requestedAt: '2026-09-12T00:00:00.000Z',
  planDeadlineMonotonicMs: 180_000,
});

const candidateInput = (overrides: Record<string, unknown> = {}): ExactGraphCandidateV2Input => ({
  profileId: 'filesystem-2026-7-10-candidate',
  profileVersion: 1,
  topPackage: {
    name: '@modelcontextprotocol/server-filesystem',
    exactVersion: '2026.7.10',
    exactEntrypointRelativePath: 'dist/index.js',
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
  limits: { ...PACKAGE_STAGE_HARD_CEILINGS },
  packageLock: {
    name: 'fixture',
    version: '1.0.0',
    lockfileVersion: 3,
    requires: true,
    packages: {
      '': {
        name: 'fixture',
        version: '1.0.0',
        dependencies: { '@modelcontextprotocol/server-filesystem': '2026.7.10' },
      },
      'node_modules/@modelcontextprotocol/server-filesystem': {
        version: '2026.7.10',
        resolved: 'https://registry.npmjs.org/@modelcontextprotocol/server-filesystem/-/server-filesystem-2026.7.10.tgz',
        integrity: `sha512-${Buffer.alloc(64, 3).toString('base64')}`,
      },
    },
  },
  ...overrides,
});

const prepare = (candidateAuthority = new ExactGraphCandidateV2Authority()) => {
  const authority = new GraphGenesisV2BindingAuthority(candidateAuthority);
  return { authority, prepared: authority.prepare({ plan: planInput(), envelope: envelopeInput() }) };
};

const exactMaximumLimits = (): GraphGenesisPlanV3Input['limits'] => ({
  broker: {
    uniquePackageNames: 128,
    totalRequests: 256,
    concurrentRequests: 4,
    responseBytes: 4 * MiB,
    aggregateResponseBytes: 64 * MiB,
    requestTimeoutMs: 10_000,
  },
  completeTimeoutMs: 120_000,
  stdoutBytes: 256 * 1024,
  stderrBytes: 256 * 1024,
  packageJsonBytes: 64 * 1024,
  packageLockBytes: 4 * MiB,
});

describe('memory-only Graph Genesis v2 binding authority', () => {
  it('derives a deterministic closed contract, Plan3, Projection3, and Envelope2 hash DAG', () => {
    const first = prepare().prepared;
    const second = prepare().prepared;
    expect(first.plan).toEqual(second.plan);
    expect(first.projection).toEqual(second.projection);
    expect(first.envelope).toEqual(second.envelope);
    expect(first.plan.planHash).toMatch(/^[a-f0-9]{64}$/u);
    expect(first.envelope.executionEnvelopeHash).toMatch(/^[a-f0-9]{64}$/u);
    expect(first.envelope.projectionDigest).toMatch(/^[a-f0-9]{64}$/u);
    const { planHash, ...unsignedPlan } = first.plan;
    const { executionEnvelopeHash, ...unsignedEnvelope } = first.envelope;
    expect(planHash).toBe(sha256(unsignedPlan));
    expect(first.envelope.projectionDigest).toBe(sha256(first.projection));
    expect(executionEnvelopeHash).toBe(sha256(unsignedEnvelope));
    expect(first.projection).toMatchObject({
      projectionVersion: 3,
      planVersion: 3,
      planHash: first.plan.planHash,
      candidateSchemaVersion: 2,
      peerSemanticsVersion: 1,
    });
    expect(Object.isFrozen(first.envelope)).toBe(true);
    expect(Object.keys(first.plan)).not.toContain('candidateDigest');
    expect(Object.keys(first.envelope)).not.toContain('candidateDigest');
    expect(Object.keys(first.plan).sort()).toEqual([
      'architecture', 'brokerAddress', 'brokerPort', 'candidateSchemaVersion',
      'compilationContract', 'compilationContractDigest', 'compilationContractVersion',
      'consequence', 'containmentEvidenceDigest', 'containmentProfileDigest',
      'containmentProviderId', 'environmentDigest', 'exactTargetVersion',
      'executionCapsuleDigest', 'hostEvidenceDigest', 'launchDigest', 'limits',
      'maxCandidateOutputs', 'nodeVersion', 'npmVersion', 'osBuild', 'peerSemanticsVersion',
      'planHash', 'planId', 'planVersion', 'platform', 'privatePathSetDigest',
      'registryOrigin', 'routeTokenDigest', 'runtimeManifestDigest',
      'runtimeSnapshots', 'runtimeVersionEvidenceDigest', 'semanticContract',
      'semanticContractDigest', 'targetName', 'workspaceBinding',
    ].sort());
    expect(Object.keys(first.projection).sort()).toEqual([
      'candidateSchemaVersion', 'compilationContractDigest', 'compilationContractVersion',
      'consequence', 'host', 'limits', 'maxCandidateOutputs', 'peerSemanticsVersion',
      'planHash', 'planId', 'planVersion', 'projectionVersion', 'registryOrigin', 'runtime',
      'runtimeManifestDigest', 'semanticContractDigest', 'statements', 'target',
    ].sort());
    expect(Object.keys(first.envelope).sort()).toEqual([
      'approvalTtlMs', 'auditDatabaseInstanceId', 'auditDurabilityProfileDigest',
      'auditFileIdentityDigest', 'auditSchemaDigest', 'bootSessionDigest',
      'candidateSchemaVersion', 'compilationContractDigest', 'compilationContractVersion',
      'consequence', 'containmentEvidenceDigest', 'containmentProfileDigest',
      'dashboardInstanceId', 'dashboardPort', 'envelopeVersion', 'environmentDigest',
      'executionCapsuleDigest', 'executionEnvelopeHash', 'hostEvidenceDigest',
      'initialAuditChainTail', 'launchDigest', 'limitsDigest', 'outputCanonicalPathDigest',
      'outputParentIdentityDigest', 'outputRule', 'peerSemanticsVersion', 'planHash',
      'planId', 'planVersion', 'policy', 'policyDigest', 'projectionDigest',
      'projectionVersion', 'requestedAt', 'routeTokenDigest', 'runtimeManifestDigest',
      'semanticContractDigest', 'sessionId', 'workspaceBinding', 'planDeadlineMonotonicMs',
    ].sort());
  });

  it('binds every flexible Plan3 and Envelope2 input field into identity', () => {
    const baseline = prepare().prepared;
    const planMutations: readonly Partial<GraphGenesisPlanV3Input>[] = [
      { planId: 'c'.repeat(32) }, { osBuild: '25A2' }, { hostEvidenceDigest: digest('a') },
      { runtimeVersionEvidenceDigest: digest('b') },
      { runtimeSnapshots: { ...runtimeSnapshots(), node: digest('c') } },
      { runtimeSnapshots: { ...runtimeSnapshots(), npmCli: digest('c') } },
      { runtimeSnapshots: { ...runtimeSnapshots(), sandboxExec: digest('c') } },
      { runtimeSnapshots: { ...runtimeSnapshots(), brokerRuntime: digest('c') } },
      { runtimeSnapshots: { ...runtimeSnapshots(), probeRuntime: digest('c') } },
      { runtimeSnapshots: { ...runtimeSnapshots(), npmTree: digest('c') } },
      { runtimeSnapshots: { ...runtimeSnapshots(), brokerTree: digest('c') } },
      { runtimeManifestDigest: digest('4') }, { containmentEvidenceDigest: digest('5') },
      { containmentProfileDigest: digest('6') }, { workspaceBinding: digest('7') },
      { brokerPort: 43123 }, { routeTokenDigest: digest('8') },
      { privatePathSetDigest: digest('9') }, { launchDigest: digest('a') },
      { environmentDigest: digest('b') }, { executionCapsuleDigest: digest('c') },
      { limits: { ...planInput().limits, stdoutBytes: 255 * 1024 } },
    ];
    for (const mutation of planMutations) {
      const changed = new GraphGenesisV2BindingAuthority(new ExactGraphCandidateV2Authority())
        .prepare({ plan: { ...planInput(), ...mutation }, envelope: envelopeInput() });
      expect(changed.plan.planHash).not.toBe(baseline.plan.planHash);
      expect(changed.envelope.executionEnvelopeHash).not.toBe(baseline.envelope.executionEnvelopeHash);
    }

    const envelopeMutations: readonly Partial<GraphGenesisEnvelopeV2Input>[] = [
      { sessionId: 'c'.repeat(32) }, { bootSessionDigest: digest('a') },
      { auditSchemaDigest: digest('b') }, { auditFileIdentityDigest: digest('c') },
      { auditDatabaseInstanceId: '22345678-1234-4123-8123-123456789abc' },
      { initialAuditChainTail: digest('d') }, { auditDurabilityProfileDigest: digest('e') },
      { outputCanonicalPathDigest: digest('f') }, { outputParentIdentityDigest: digest('a') },
      { dashboardInstanceId: 'bbcdefab-cdef-4abc-8def-abcdefabcdef' },
      { dashboardPort: 43124 }, { requestedAt: '2026-09-12T00:00:01.000Z' },
      { planDeadlineMonotonicMs: 180_000.25 },
    ];
    for (const mutation of envelopeMutations) {
      const changed = new GraphGenesisV2BindingAuthority(new ExactGraphCandidateV2Authority())
        .prepare({ plan: planInput(), envelope: { ...envelopeInput(), ...mutation } });
      expect(changed.plan.planHash).toBe(baseline.plan.planHash);
      expect(changed.envelope.executionEnvelopeHash).not.toBe(baseline.envelope.executionEnvelopeHash);
    }
  });

  it('rejects exact-plus-one budgets and accepts the exact boundaries', () => {
    expect(() => new GraphGenesisV2BindingAuthority(new ExactGraphCandidateV2Authority())
      .prepare({ plan: { ...planInput(), limits: exactMaximumLimits() }, envelope: envelopeInput() }))
      .not.toThrow();
    const lower = exactMaximumLimits();
    expect(() => new GraphGenesisV2BindingAuthority(new ExactGraphCandidateV2Authority())
      .prepare({
        plan: {
          ...planInput(),
          limits: {
            broker: {
              uniquePackageNames: 1, totalRequests: 1, concurrentRequests: 1,
              responseBytes: 1, aggregateResponseBytes: 1, requestTimeoutMs: 1,
            },
            completeTimeoutMs: 1, stdoutBytes: 1, stderrBytes: 1,
            packageJsonBytes: 1, packageLockBytes: 1,
          },
        },
        envelope: envelopeInput(),
      })).not.toThrow();
    expect(lower).toEqual(planInput().limits);
    const cases = [
      ['uniquePackageNames', 129], ['totalRequests', 257], ['concurrentRequests', 5],
      ['responseBytes', 4 * MiB + 1], ['aggregateResponseBytes', 64 * MiB + 1],
      ['requestTimeoutMs', 10_001],
    ] as const;
    for (const [key, value] of cases) {
      const baseline = planInput();
      const plan = {
        ...baseline,
        limits: { ...baseline.limits, broker: { ...baseline.limits.broker, [key]: value } },
      } as GraphGenesisPlanV3Input;
      expect(() => new GraphGenesisV2BindingAuthority(new ExactGraphCandidateV2Authority())
        .prepare({ plan, envelope: envelopeInput() })).toThrow('graph_genesis_v2_binding_invalid');
    }
    for (const [key, value] of [
      ['completeTimeoutMs', 120_001], ['stdoutBytes', 256 * 1024 + 1],
      ['stderrBytes', 256 * 1024 + 1], ['packageJsonBytes', 64 * 1024 + 1],
      ['packageLockBytes', 4 * MiB + 1],
    ] as const) {
      const baseline = planInput();
      const plan = {
        ...baseline,
        limits: { ...baseline.limits, [key]: value },
      } as GraphGenesisPlanV3Input;
      expect(() => new GraphGenesisV2BindingAuthority(new ExactGraphCandidateV2Authority())
        .prepare({ plan, envelope: envelopeInput() })).toThrow('graph_genesis_v2_binding_invalid');
    }
  });

  it('preserves finite safe-range fractional monotonic deadlines and rejects invalid numbers', () => {
    const authority = new GraphGenesisV2BindingAuthority(new ExactGraphCandidateV2Authority());
    const baseline = authority.prepare({ plan: planInput(), envelope: envelopeInput() });
    const fractional = authority.prepare({
      plan: planInput(),
      envelope: { ...envelopeInput(), planDeadlineMonotonicMs: 180_000.25 },
    });
    expect(fractional.envelope.planDeadlineMonotonicMs).toBe(180_000.25);
    expect(fractional.envelope.executionEnvelopeHash).not.toBe(baseline.envelope.executionEnvelopeHash);
    for (const planDeadlineMonotonicMs of [
      0, -1, Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY,
      -0, Number.MAX_SAFE_INTEGER + 1,
    ]) {
      expect(() => authority.prepare({
        plan: planInput(),
        envelope: { ...envelopeInput(), planDeadlineMonotonicMs },
      })).toThrow('graph_genesis_v2_binding_invalid');
    }
  });

  it('rejects drift in every peer semantic contract literal', () => {
    const semanticMutations: unknown[] = [
      { ...PEER_SEMANTICS_V2_CONTRACT, candidateSchemaVersion: 3 },
      { ...PEER_SEMANTICS_V2_CONTRACT, peerSemanticsVersion: 2 },
      { ...PEER_SEMANTICS_V2_CONTRACT, grammar: 'other' },
      { ...PEER_SEMANTICS_V2_CONTRACT, resolver: 'other' },
      { ...PEER_SEMANTICS_V2_CONTRACT, closure: 'other' },
    ];
    for (const key of Object.keys(PEER_SEMANTICS_V2_CONTRACT.limits) as
      (keyof typeof PEER_SEMANTICS_V2_CONTRACT.limits)[]) {
      semanticMutations.push({
        ...PEER_SEMANTICS_V2_CONTRACT,
        limits: {
          ...PEER_SEMANTICS_V2_CONTRACT.limits,
          [key]: PEER_SEMANTICS_V2_CONTRACT.limits[key] + 1,
        },
      });
    }
    for (const semanticContract of semanticMutations) {
      expect(() => new GraphGenesisV2BindingAuthority(new ExactGraphCandidateV2Authority())
        .prepare({
          plan: { ...planInput(), semanticContract } as never,
          envelope: envelopeInput(),
        })).toThrow('graph_genesis_v2_binding_invalid');
    }
  });

  it('rejects drift in every compilation contract literal group and nested fixed field', () => {
    const contractMutations: unknown[] = [
      { ...EXACT_COMPILATION_CONTRACT_V1, compilationContractVersion: 2 },
      {
        ...EXACT_COMPILATION_CONTRACT_V1,
        semanticContract: { ...PEER_SEMANTICS_V2_CONTRACT, grammar: 'other' },
      },
      { ...EXACT_COMPILATION_CONTRACT_V1, semanticContractDigest: digest('f') },
      { ...EXACT_COMPILATION_CONTRACT_V1, profileId: 'other-profile' },
      { ...EXACT_COMPILATION_CONTRACT_V1, profileVersion: 2 },
      {
        ...EXACT_COMPILATION_CONTRACT_V1,
        topPackage: { ...EXACT_COMPILATION_CONTRACT_V1.topPackage, name: 'other' },
      },
      {
        ...EXACT_COMPILATION_CONTRACT_V1,
        topPackage: { ...EXACT_COMPILATION_CONTRACT_V1.topPackage, exactVersion: '2026.7.11' },
      },
      {
        ...EXACT_COMPILATION_CONTRACT_V1,
        topPackage: { ...EXACT_COMPILATION_CONTRACT_V1.topPackage, exactEntrypointRelativePath: 'other.js' },
      },
      { ...EXACT_COMPILATION_CONTRACT_V1, registryOrigin: 'https://registry.example.com/' },
      { ...EXACT_COMPILATION_CONTRACT_V1, materializationRulesVersion: 2 },
      { ...EXACT_COMPILATION_CONTRACT_V1, archiveRulesVersion: 2 },
      { ...EXACT_COMPILATION_CONTRACT_V1, workerProtocolVersion: ARCHIVE_WORKER_PROTOCOL_VERSION + 1 },
      { ...EXACT_COMPILATION_CONTRACT_V1, effectiveLockBytes: EXACT_COMPILATION_CONTRACT_V1.effectiveLockBytes + 1 },
      { ...EXACT_COMPILATION_CONTRACT_V1, effectiveCandidateBytes: EXACT_COMPILATION_CONTRACT_V1.effectiveCandidateBytes + 1 },
      { ...EXACT_COMPILATION_CONTRACT_V1, maxCandidateOutputs: 2 },
      { ...EXACT_COMPILATION_CONTRACT_V1, candidateOutputRule: 'other' },
    ];
    for (const key of Object.keys(EXACT_COMPILATION_CONTRACT_V1.runtimeConstraint) as
      (keyof typeof EXACT_COMPILATION_CONTRACT_V1.runtimeConstraint)[]) {
      const value = EXACT_COMPILATION_CONTRACT_V1.runtimeConstraint[key];
      contractMutations.push({
        ...EXACT_COMPILATION_CONTRACT_V1,
        runtimeConstraint: {
          ...EXACT_COMPILATION_CONTRACT_V1.runtimeConstraint,
          [key]: typeof value === 'number' ? value + 1 : `${value}-other`,
        },
      });
    }
    for (const key of Object.keys(PACKAGE_STAGE_HARD_CEILINGS) as
      (keyof typeof PACKAGE_STAGE_HARD_CEILINGS)[]) {
      contractMutations.push({
        ...EXACT_COMPILATION_CONTRACT_V1,
        limits: {
          ...EXACT_COMPILATION_CONTRACT_V1.limits,
          [key]: EXACT_COMPILATION_CONTRACT_V1.limits[key] + 1,
        },
      });
    }
    for (const compilationContract of contractMutations) {
      expect(() => new GraphGenesisV2BindingAuthority(new ExactGraphCandidateV2Authority())
        .prepare({
          plan: { ...planInput(), compilationContract } as never,
          envelope: envelopeInput(),
        })).toThrow('graph_genesis_v2_binding_invalid');
    }
  });

  it('rejects old, mixed, unknown, missing, wildcard, and extra tuple fields', () => {
    for (const mutation of [
      { planVersion: 2 }, { planVersion: 4 }, { candidateSchemaVersion: 1 },
      { peerSemanticsVersion: 2 }, { compilationContractVersion: 2 },
      { targetName: '*' }, { exactTargetVersion: 'latest' }, { maxCandidateOutputs: 2 },
      { registryOrigin: 'https://registry.example.com/' }, { platform: 'linux' },
      { architecture: 'x64' }, { nodeVersion: '26.3.2' }, { npmVersion: '11.16.1' },
      { containmentProviderId: 'other-provider' }, { brokerAddress: '0.0.0.0' },
      { consequence: 'other' },
      { semanticContract: { ...PEER_SEMANTICS_V2_CONTRACT, grammar: 'other' } },
      { semanticContractDigest: digest('e') },
      { compilationContract: { ...EXACT_COMPILATION_CONTRACT_V1, profileVersion: 2 } },
      { compilationContractDigest: digest('d') },
    ]) {
      expect(() => new GraphGenesisV2BindingAuthority(new ExactGraphCandidateV2Authority())
        .prepare({ plan: { ...planInput(), ...mutation } as GraphGenesisPlanV3Input, envelope: envelopeInput() }))
        .toThrow('graph_genesis_v2_binding_invalid');
    }
    const missing = planInput() as unknown as Record<string, unknown>;
    delete missing.planId;
    expect(() => new GraphGenesisV2BindingAuthority(new ExactGraphCandidateV2Authority())
      .prepare({ plan: missing as GraphGenesisPlanV3Input, envelope: envelopeInput() }))
      .toThrow('graph_genesis_v2_binding_invalid');
    expect(() => new GraphGenesisV2BindingAuthority(new ExactGraphCandidateV2Authority())
      .prepare({ plan: { ...planInput(), candidateDigest: undefined } as never, envelope: envelopeInput() }))
      .toThrow('graph_genesis_v2_binding_invalid');
    expect(() => new GraphGenesisV2BindingAuthority(new ExactGraphCandidateV2Authority())
      .prepare({ plan: planInput(), envelope: { ...envelopeInput(), envelopeVersion: 1 } as never }))
      .toThrow('graph_genesis_v2_binding_invalid');
    expect(() => new GraphGenesisV2BindingAuthority(new ExactGraphCandidateV2Authority())
      .prepare({ plan: planInput(), envelope: { ...envelopeInput(), outputRule: '*' } as never }))
      .toThrow('graph_genesis_v2_binding_invalid');
    const missingEnvelope = envelopeInput() as unknown as Record<string, unknown>;
    delete missingEnvelope.sessionId;
    expect(() => new GraphGenesisV2BindingAuthority(new ExactGraphCandidateV2Authority())
      .prepare({ plan: planInput(), envelope: missingEnvelope as GraphGenesisEnvelopeV2Input }))
      .toThrow('graph_genesis_v2_binding_invalid');
    expect(() => new GraphGenesisV2BindingAuthority(new ExactGraphCandidateV2Authority())
      .prepare({ plan: planInput(), envelope: { ...envelopeInput(), extra: true } as never }))
      .toThrow('graph_genesis_v2_binding_invalid');
  });

  it('rejects closed-data hazards without invoking getters', () => {
    let calls = 0;
    const accessor = planInput() as unknown as Record<string, unknown>;
    Object.defineProperty(accessor, 'planId', {
      enumerable: true,
      get: () => { calls += 1; return 'a'.repeat(32); },
    });
    const hazards: unknown[] = [
      accessor,
      { ...planInput(), extra: true },
      { ...planInput(), osBuild: Number.NaN },
      { ...planInput(), brokerPort: -0 },
      { ...planInput(), osBuild: () => '25A1' },
      { ...planInput(), osBuild: 1n },
      { ...planInput(), osBuild: 'x'.repeat(257) },
      { ...planInput(), planId: 'a'.repeat(33) },
    ];
    const symbol = planInput() as unknown as Record<PropertyKey, unknown>;
    symbol[Symbol('hidden')] = true;
    hazards.push(symbol);
    const cycle = planInput() as unknown as Record<string, unknown>;
    cycle.osBuild = cycle;
    hazards.push(cycle);
    let tooDeep: Record<string, unknown> = {};
    for (let index = 0; index < 26; index += 1) tooDeep = { child: tooDeep };
    hazards.push({ ...planInput(), extra: tooDeep });
    const nestedAccessor = planInput() as unknown as Record<string, unknown>;
    const snapshots = runtimeSnapshots() as Record<string, unknown>;
    Object.defineProperty(snapshots, 'node', {
      enumerable: true,
      get: () => { calls += 1; return digest('1'); },
    });
    nestedAccessor.runtimeSnapshots = snapshots;
    hazards.push(nestedAccessor);
    for (const plan of hazards) {
      expect(() => new GraphGenesisV2BindingAuthority(new ExactGraphCandidateV2Authority())
        .prepare({ plan: plan as GraphGenesisPlanV3Input, envelope: envelopeInput() }))
        .toThrow('graph_genesis_v2_binding_invalid');
    }
    expect(calls).toBe(0);
  });

  it('keeps plan, projection, envelope, and private pairing authority-local', () => {
    const { authority, prepared } = prepare();
    const other = authority.prepare({
      plan: { ...planInput(), planId: 'c'.repeat(32) },
      envelope: { ...envelopeInput(), sessionId: 'd'.repeat(32) },
    });
    expect(authority.authenticatesPair(prepared.plan, prepared.projection, prepared.envelope, prepared.privateBinding)).toBe(true);
    expect(authority.authenticatesPair(
      prepared.plan, other.projection, prepared.envelope, prepared.privateBinding,
    )).toBe(false);
    expect(authority.authenticatesPair(
      other.plan, other.projection, other.envelope, prepared.privateBinding,
    )).toBe(false);
    expect(authority.authenticatesPair({ ...prepared.plan }, prepared.projection, prepared.envelope, prepared.privateBinding)).toBe(false);
    expect(authority.authenticatesPair(prepared.plan, { ...prepared.projection }, prepared.envelope, prepared.privateBinding)).toBe(false);
    expect(authority.authenticatesPair(prepared.plan, prepared.projection, { ...prepared.envelope }, prepared.privateBinding)).toBe(false);
    expect(new GraphGenesisV2BindingAuthority(new ExactGraphCandidateV2Authority())
      .authenticatesPair(prepared.plan, prepared.projection, prepared.envelope, prepared.privateBinding)).toBe(false);
    const editedProjection = { ...prepared.projection, target: prepared.projection.target };
    expect(authority.authenticatesPair(prepared.plan, editedProjection, prepared.envelope, prepared.privateBinding)).toBe(false);

    const { planHash: _oldPlanHash, ...unsignedPlan } = prepared.plan;
    const forgedPlan = { ...unsignedPlan, osBuild: '25A2' } as typeof unsignedPlan;
    const rehashedPlan = { ...forgedPlan, planHash: sha256(forgedPlan) };
    const forgedProjection = { ...prepared.projection, planHash: rehashedPlan.planHash };
    const { executionEnvelopeHash: _oldEnvelopeHash, ...unsignedEnvelope } = prepared.envelope;
    const reboundEnvelope = {
      ...unsignedEnvelope,
      planHash: rehashedPlan.planHash,
      projectionDigest: sha256(forgedProjection),
    };
    const rehashedEnvelope = { ...reboundEnvelope, executionEnvelopeHash: sha256(reboundEnvelope) };
    expect(authority.authenticatesPair(
      rehashedPlan, forgedProjection, rehashedEnvelope, prepared.privateBinding,
    )).toBe(false);
  });

  it('matches only a candidate from the paired candidate authority and exact compilation contract', () => {
    const candidates = new ExactGraphCandidateV2Authority();
    const { authority, prepared } = prepare(candidates);
    const candidate = candidates.compile(candidateInput());
    expect(authority.authenticatesCandidate(
      prepared.plan, prepared.projection, prepared.envelope, prepared.privateBinding, candidate,
    )).toBe(true);

    const mismatched = candidates.compile(candidateInput({ profileId: 'other-profile' }));
    expect(authority.authenticatesCandidate(
      prepared.plan, prepared.projection, prepared.envelope, prepared.privateBinding, mismatched,
    )).toBe(false);
    const foreignCandidate = new ExactGraphCandidateV2Authority().compile(candidateInput());
    expect(authority.authenticatesCandidate(
      prepared.plan, prepared.projection, prepared.envelope, prepared.privateBinding, foreignCandidate,
    )).toBe(false);
    const decoded = decodeExactGraphCandidateV2(encodeExactGraphCandidateV2(candidate));
    expect(authority.authenticatesCandidate(
      prepared.plan, prepared.projection, prepared.envelope, prepared.privateBinding, decoded,
    )).toBe(false);

    for (const input of [
      candidateInput({ profileVersion: 2 }),
      candidateInput({
        runtimeConstraint: { ...candidateInput().runtimeConstraint, npmGraphGeneratorVersion: '11.16.1' },
      }),
      candidateInput({ materializationRulesVersion: 2 }),
      candidateInput({ archiveRulesVersion: 2 }),
      candidateInput({ limits: { ...PACKAGE_STAGE_HARD_CEILINGS, graphNodes: 255 } }),
    ]) {
      const altered = candidates.compile(input);
      expect(authority.authenticatesCandidate(
        prepared.plan, prepared.projection, prepared.envelope, prepared.privateBinding, altered,
      )).toBe(false);
    }
  });

  it('exposes the exact frozen policy and compilation descriptors without execution capability', () => {
    expect(EXACT_COMPILATION_CONTRACT_V1).toMatchObject({
      compilationContractVersion: 1,
      semanticContract: PEER_SEMANTICS_V2_CONTRACT,
      effectiveLockBytes: 4 * MiB,
      effectiveCandidateBytes: 4 * MiB,
      maxCandidateOutputs: 1,
    });
    expect(GRAPH_GENESIS_V2_POLICY).toEqual({
      schemaVersion: 1,
      evaluatorName: 'graph_genesis_builtin_policy',
      evaluatorVersion: '1',
      decision: 'ask',
      score: 70,
      band: 'high',
      reasonCodes: [
        'public_registry_metadata_disclosure',
        'local_npm_process',
        'persistent_audit_write',
        'candidate_artifact_write',
        'development_only_containment',
      ],
    });
    expect(GRAPH_GENESIS_V2_POLICY).toEqual(CURRENT_GRAPH_GENESIS_POLICY);
    expect(EXACT_COMPILATION_CONTRACT_V1.limits).toEqual(PACKAGE_STAGE_HARD_CEILINGS);
    expect(Object.keys(PEER_SEMANTICS_V2_CONTRACT).sort()).toEqual([
      'candidateSchemaVersion', 'closure', 'grammar', 'limits', 'peerSemanticsVersion', 'resolver',
    ].sort());
    expect(Object.keys(PEER_SEMANTICS_V2_CONTRACT.limits).sort()).toEqual([
      'atoms', 'branches', 'candidateBytes', 'combinedRequirements', 'comparisons', 'nodes',
      'pathBytes', 'pathSegments', 'peers', 'peersPerNode', 'rangeBytes',
    ].sort());
    expect(Object.keys(EXACT_COMPILATION_CONTRACT_V1).sort()).toEqual([
      'archiveRulesVersion', 'candidateOutputRule', 'compilationContractVersion',
      'effectiveCandidateBytes', 'effectiveLockBytes', 'limits', 'materializationRulesVersion',
      'maxCandidateOutputs', 'profileId', 'profileVersion', 'registryOrigin', 'runtimeConstraint',
      'semanticContract', 'semanticContractDigest', 'topPackage', 'workerProtocolVersion',
    ].sort());
    expect(Object.keys(EXACT_COMPILATION_CONTRACT_V1.topPackage).sort()).toEqual([
      'exactEntrypointRelativePath', 'exactVersion', 'name',
    ].sort());
    expect(Object.keys(EXACT_COMPILATION_CONTRACT_V1.runtimeConstraint).sort()).toEqual([
      'architecture', 'lockfileVersion', 'nodeMajor', 'nodeVersion',
      'npmGraphGeneratorVersion', 'os',
    ].sort());
    expect(Object.keys(EXACT_COMPILATION_CONTRACT_V1.limits).sort())
      .toEqual(Object.keys(PACKAGE_STAGE_HARD_CEILINGS).sort());
    for (const value of [
      SEMANTIC_CONTRACT_DIGEST, COMPILATION_CONTRACT_DIGEST, GRAPH_GENESIS_V2_POLICY_DIGEST,
    ]) expect(value).toMatch(/^[a-f0-9]{64}$/u);
    expect(SEMANTIC_CONTRACT_DIGEST)
      .toBe('2f550766120d1417fd6d0713342a31c95b68b1e50c3a13d99bc87431a6d9106b');
    expect(COMPILATION_CONTRACT_DIGEST)
      .toBe('d4863636e623c0113d7185f841947db06e1a56d13e25bf268b04a2fdc7adc743');
    expect(GRAPH_GENESIS_V2_POLICY_DIGEST)
      .toBe('d1a301000a976c5c5bb0ce4a0b222e7678b78859dfd52b5bb00bdcf532d022d7');
    expect(GRAPH_GENESIS_V2_POLICY_DIGEST).toBe(sha256(CURRENT_GRAPH_GENESIS_POLICY));
    expect(Object.isFrozen(EXACT_COMPILATION_CONTRACT_V1)).toBe(true);
    expect(Object.isFrozen(GRAPH_GENESIS_V2_POLICY.reasonCodes)).toBe(true);
  });
});
