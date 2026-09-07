import { createHash } from 'node:crypto';

import { canonicalJson } from '../audit/canonical-json.js';
import { PackageStageError, VerifiedMcpGraphProfileAuthority } from './profile.js';
import type {
  AuthenticatedVerifiedMcpGraphProfile,
  PackageStagePlan,
} from './types.js';

export type PackageStagePlanInput = Readonly<{
  stageId: string;
  metadataObservationDigest: string;
  metadataExpiresAt: string;
  stageRootBinding: string;
}>;

export type PackageStageApproval = Readonly<{
  approvalVersion: 1;
  stageId: string;
  stagePlanHash: string;
  consequence: 'package_download_and_private_stage';
}>;

export class PackageStagePlanAuthority {
  readonly #authenticatedPlans = new WeakSet<object>();

  constructor(
    private readonly profileAuthority: VerifiedMcpGraphProfileAuthority,
    private readonly now: () => Date = () => new Date(),
  ) {}

  create(
    profile: AuthenticatedVerifiedMcpGraphProfile,
    input: PackageStagePlanInput,
  ): PackageStagePlan {
    this.profileAuthority.assertAuthenticates(profile);
    validateInput(input, this.now());
    const approvedNetworkHosts = Object.freeze([new URL(profile.registryOrigin).host]);
    const unsigned = {
      planVersion: 1 as const,
      stageId: input.stageId,
      graphProfileId: profile.profileId,
      graphProfileDigest: profile.manifestDigest,
      registryOrigin: profile.registryOrigin,
      metadataObservationDigest: input.metadataObservationDigest,
      metadataExpiresAt: input.metadataExpiresAt,
      graphNodes: profile.graphNodes,
      approvedNetworkHosts,
      limits: profile.limits,
      packageScripts: 'disabled' as const,
      stageRootBinding: input.stageRootBinding,
    };
    const stagePlanHash = createHash('sha256').update(canonicalJson(unsigned)).digest('hex');
    const plan = deepFreeze({ ...unsigned, stagePlanHash });
    this.#authenticatedPlans.add(plan);
    return plan;
  }

  authenticates(candidate: unknown): candidate is PackageStagePlan {
    return typeof candidate === 'object'
      && candidate !== null
      && this.#authenticatedPlans.has(candidate);
  }

  assertAuthenticates(candidate: unknown): asserts candidate is PackageStagePlan {
    if (!this.authenticates(candidate)) throw new PackageStageError('plan_not_authenticated');
  }
}

/**
 * Network-free foundation authority. It models one-time binding and replay
 * rejection only; production human approval is intentionally not connected.
 */
export class SyntheticPackageStageApprovalAuthority {
  readonly #issued = new WeakSet<object>();
  readonly #consumed = new WeakSet<object>();

  constructor(private readonly planAuthority: PackageStagePlanAuthority) {}

  issueForTest(plan: PackageStagePlan): PackageStageApproval {
    this.planAuthority.assertAuthenticates(plan);
    const approval = Object.freeze({
      approvalVersion: 1 as const,
      stageId: plan.stageId,
      stagePlanHash: plan.stagePlanHash,
      consequence: 'package_download_and_private_stage' as const,
    });
    this.#issued.add(approval);
    return approval;
  }

  consume(approval: PackageStageApproval, plan: PackageStagePlan): void {
    this.planAuthority.assertAuthenticates(plan);
    if (!this.#issued.has(approval) || approval.stageId !== plan.stageId || approval.stagePlanHash !== plan.stagePlanHash) {
      throw new PackageStageError('approval_invalid');
    }
    if (this.#consumed.has(approval)) throw new PackageStageError('approval_consumed');
    this.#consumed.add(approval);
  }
}

function validateInput(input: PackageStagePlanInput, now: Date): void {
  if (
    typeof input !== 'object'
    || input === null
    || Object.keys(input).sort().join(',') !== [
      'metadataExpiresAt',
      'metadataObservationDigest',
      'stageId',
      'stageRootBinding',
    ].join(',')
    || !/^[0-9a-f]{32}$/u.test(input.stageId)
    || !/^[0-9a-f]{64}$/u.test(input.metadataObservationDigest)
    || !/^[0-9a-f]{64}$/u.test(input.stageRootBinding)
    || !isCanonicalTimestamp(input.metadataExpiresAt)
    || Date.parse(input.metadataExpiresAt) <= now.getTime()
  ) {
    throw new PackageStageError('plan_invalid');
  }
}

function isCanonicalTimestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString() === value;
}

function deepFreeze<T>(input: T): T {
  if (typeof input !== 'object' || input === null || Object.isFrozen(input)) return input;
  for (const value of Object.values(input)) deepFreeze(value);
  return Object.freeze(input);
}
