import { createHash } from 'node:crypto';

import { canonicalJson } from '../audit/canonical-json.js';
import { PackageStageError } from './profile.js';

const SHA256 = /^[a-f0-9]{64}$/u;

export type SeatbeltLoopbackProfile = Readonly<{
  profileVersion: 1;
  providerId: 'macos-seatbelt-loopback-development-v0';
  osBuild: string;
  sandboxExecSha256: string;
  loopbackAddress: '127.0.0.1';
  allowedPort: number;
  profileText: string;
  profileDigest: string;
}>;

export type SeatbeltSelfTestObservations = Readonly<{
  approvedLoopbackPortConnected: boolean;
  alternateLoopbackPortDenied: boolean;
  nonLoopbackLocalAddressDenied: boolean;
  ipv6LoopbackDenied: boolean;
  outsideWorkspaceWriteDenied: boolean;
  childProcessDenied: boolean;
  workerThreadDenied: boolean;
  addonGrantAbsent: boolean;
  publicNetworkAttempted: false;
}>;

export type AuthenticatedContainmentSelfTest = Readonly<{
  evidenceVersion: 1;
  providerId: SeatbeltLoopbackProfile['providerId'];
  osBuild: string;
  profileDigest: string;
  testedPort: number;
  observations: SeatbeltSelfTestObservations;
  evidenceDigest: string;
}>;

export class SeatbeltLoopbackContainmentAuthority {
  readonly #profiles = new WeakSet<object>();
  readonly #evidence = new WeakSet<object>();

  prepare(input: Readonly<{
    osBuild: string;
    sandboxExecSha256: string;
    allowedPort: number;
  }>): SeatbeltLoopbackProfile {
    if (
      process.platform !== 'darwin'
      || !isSafeText(input.osBuild, 128)
      || !SHA256.test(input.sandboxExecSha256)
      || !isPort(input.allowedPort)
    ) throw new PackageStageError('artifact_plan_invalid');
    const profileText = seatbeltProfileText(input.allowedPort);
    const unsigned = deepFreeze({
      profileVersion: 1 as const,
      providerId: 'macos-seatbelt-loopback-development-v0' as const,
      osBuild: input.osBuild,
      sandboxExecSha256: input.sandboxExecSha256,
      loopbackAddress: '127.0.0.1' as const,
      allowedPort: input.allowedPort,
      profileText,
    });
    const profile = deepFreeze({ ...unsigned, profileDigest: sha256(canonicalJson(unsigned)) });
    this.#profiles.add(profile);
    return profile;
  }

  /** Records results observed by the repo-owned local-only probe; it does not run npm or public I/O. */
  authenticateObservedSelfTest(
    profile: SeatbeltLoopbackProfile,
    observations: SeatbeltSelfTestObservations,
  ): AuthenticatedContainmentSelfTest {
    this.assertProfile(profile);
    assertExactKeys(observations, [
      'approvedLoopbackPortConnected',
      'alternateLoopbackPortDenied',
      'nonLoopbackLocalAddressDenied',
      'ipv6LoopbackDenied',
      'outsideWorkspaceWriteDenied',
      'childProcessDenied',
      'workerThreadDenied',
      'addonGrantAbsent',
      'publicNetworkAttempted',
    ]);
    if (
      !observations.approvedLoopbackPortConnected
      || !observations.alternateLoopbackPortDenied
      || !observations.nonLoopbackLocalAddressDenied
      || !observations.ipv6LoopbackDenied
      || !observations.outsideWorkspaceWriteDenied
      || !observations.childProcessDenied
      || !observations.workerThreadDenied
      || !observations.addonGrantAbsent
      || observations.publicNetworkAttempted !== false
    ) throw new PackageStageError('artifact_plan_invalid');
    const unsigned = deepFreeze({
      evidenceVersion: 1 as const,
      providerId: profile.providerId,
      osBuild: profile.osBuild,
      profileDigest: profile.profileDigest,
      testedPort: profile.allowedPort,
      observations: { ...observations },
    });
    const evidence = deepFreeze({ ...unsigned, evidenceDigest: sha256(canonicalJson(unsigned)) });
    this.#evidence.add(evidence);
    return evidence;
  }

  authenticatesProfile(candidate: unknown): candidate is SeatbeltLoopbackProfile {
    return typeof candidate === 'object' && candidate !== null && this.#profiles.has(candidate);
  }

  authenticatesSelfTest(candidate: unknown): candidate is AuthenticatedContainmentSelfTest {
    return typeof candidate === 'object' && candidate !== null && this.#evidence.has(candidate);
  }

  assertProfile(candidate: unknown): asserts candidate is SeatbeltLoopbackProfile {
    if (!this.authenticatesProfile(candidate)) throw new PackageStageError('artifact_plan_invalid');
  }

  assertSelfTest(candidate: unknown): asserts candidate is AuthenticatedContainmentSelfTest {
    if (!this.authenticatesSelfTest(candidate)) throw new PackageStageError('artifact_plan_invalid');
  }
}

export function seatbeltProfileText(allowedPort: number): string {
  if (!isPort(allowedPort)) throw new PackageStageError('artifact_plan_invalid');
  return [
    '(version 1)',
    '(allow default)',
    '(deny network-inbound)',
    `(deny network-outbound (require-not (remote tcp \"localhost:${allowedPort}\")))`,
    '',
  ].join('\n');
}

function assertExactKeys(input: object, expected: readonly string[]): void {
  const actual = Object.keys(input).sort();
  const wanted = [...expected].sort();
  if (canonicalJson(actual) !== canonicalJson(wanted)) throw new PackageStageError('artifact_plan_invalid');
}

function isPort(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 1024 && value <= 65535;
}

function isSafeText(value: unknown, max: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max
    && !/[\u0000-\u001f\u007f]/u.test(value);
}

function sha256(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

function deepFreeze<T>(input: T): T {
  if (typeof input !== 'object' || input === null || Object.isFrozen(input)) return input;
  for (const value of Object.values(input)) deepFreeze(value);
  return Object.freeze(input);
}
