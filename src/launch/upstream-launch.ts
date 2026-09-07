import { createHash } from 'node:crypto';
import { constants, type BigIntStats } from 'node:fs';
import { access, open, realpath, stat } from 'node:fs/promises';
import { delimiter, isAbsolute, resolve } from 'node:path';

import type { StdioUpstreamConfig } from '../transport/types.js';

export const MAX_UPSTREAM_EXECUTABLE_BYTES = 512 * 1024 * 1024;

export type UpstreamLaunchErrorCode =
  | 'unsupported_platform'
  | 'invalid_configuration'
  | 'cwd_unavailable'
  | 'working_directory_changed'
  | 'command_not_found'
  | 'executable_unavailable'
  | 'executable_not_regular'
  | 'executable_not_executable'
  | 'executable_too_large'
  | 'executable_snapshot_failed'
  | 'prepared_launch_invalid'
  | 'executable_changed'
  | 'launch_profile_unknown'
  | 'launch_profile_invalid';

export class UpstreamLaunchError extends Error {
  readonly code: UpstreamLaunchErrorCode;

  constructor(code: UpstreamLaunchErrorCode) {
    super(`Upstream launch failed: ${code}`);
    this.name = 'UpstreamLaunchError';
    this.code = code;
  }
}

export type UpstreamExecutableSnapshot = Readonly<{
  resolvedPath: string;
  device: string;
  inode: string;
  size: number;
  mode: number;
  modifiedTimeNs: string;
  changeTimeNs: string;
  sha256: string;
}>;

export type WorkingDirectorySnapshot = Readonly<{
  resolvedPath: string;
  device: string;
  inode: string;
  mode: number;
}>;

export type PreparedUpstreamLaunch = Readonly<{
  snapshotFormat: 1;
  serverId: string;
  executable: UpstreamExecutableSnapshot;
  arguments: readonly string[];
  cwd: string;
  workingDirectory: WorkingDirectorySnapshot;
  environment: Readonly<Record<string, string>>;
  launchDigest: string;
  launchConfigurationAssurance: 'prepared_snapshot';
  serverProvenanceAssurance: 'configured_label_only';
}>;

export type LaunchProfileInput = Readonly<{
  executablePath: string;
  arguments: readonly string[];
  cwd: string;
  environment: Readonly<Record<string, string>>;
}>;

export type LaunchProfileDefinition = Readonly<{
  id: string;
  inspect(input: LaunchProfileInput): Readonly<{ codeSelectors: readonly string[] }>;
}>;

export type AuthenticatedLaunchProfileResult = Readonly<{
  profileId: string;
  assurance: 'profile_scoped';
  codeSelectors: readonly string[];
}>;

const preparedLaunches = new WeakSet<object>();

/**
 * An authority authenticates only results it created. Constructing another
 * authority cannot forge a result for the production authority that owns a
 * future launch-profile selection.
 */
export class LaunchProfileAuthority {
  readonly #profiles: ReadonlyMap<string, LaunchProfileDefinition>;
  readonly #authenticatedResults = new WeakSet<object>();

  constructor(profiles: readonly LaunchProfileDefinition[]) {
    const entries = new Map<string, LaunchProfileDefinition>();
    for (const profile of profiles) {
      if (profile.id.length === 0 || entries.has(profile.id)) {
        throw new UpstreamLaunchError('launch_profile_invalid');
      }
      entries.set(profile.id, profile);
    }
    this.#profiles = entries;
  }

  inspect(profileId: string, input: LaunchProfileInput): AuthenticatedLaunchProfileResult {
    const profile = this.#profiles.get(profileId);
    if (profile === undefined) throw new UpstreamLaunchError('launch_profile_unknown');

    let inspected: Readonly<{ codeSelectors: readonly string[] }>;
    try {
      inspected = profile.inspect(input);
    } catch {
      throw new UpstreamLaunchError('launch_profile_invalid');
    }
    if (!Array.isArray(inspected.codeSelectors) || inspected.codeSelectors.some(
      (selector) => typeof selector !== 'string' || selector.length === 0 || selector.includes('\0'),
    )) {
      throw new UpstreamLaunchError('launch_profile_invalid');
    }

    const result = Object.freeze({
      profileId,
      assurance: 'profile_scoped' as const,
      codeSelectors: Object.freeze([...inspected.codeSelectors]),
    });
    this.#authenticatedResults.add(result);
    return result;
  }

  authenticates(result: unknown): result is AuthenticatedLaunchProfileResult {
    return typeof result === 'object'
      && result !== null
      && this.#authenticatedResults.has(result);
  }
}

export async function prepareUpstreamLaunch(
  config: StdioUpstreamConfig,
): Promise<PreparedUpstreamLaunch> {
  if (process.platform === 'win32') throw new UpstreamLaunchError('unsupported_platform');
  validateConfiguration(config);

  const workingDirectory = await snapshotWorkingDirectory(config.cwd);
  const cwd = workingDirectory.resolvedPath;
  const environment = freezeEnvironment(config.env);
  const executable = await resolveExecutable(config.command, cwd, environment);
  const args = Object.freeze([...config.args]);
  const launchDigest = digestLaunch({
    serverId: config.serverId,
    executable,
    arguments: args,
    cwd,
    workingDirectory,
    environment,
  });
  const prepared = Object.freeze({
    snapshotFormat: 1 as const,
    serverId: config.serverId,
    executable,
    arguments: args,
    cwd,
    workingDirectory,
    environment,
    launchDigest,
    launchConfigurationAssurance: 'prepared_snapshot' as const,
    serverProvenanceAssurance: 'configured_label_only' as const,
  });
  preparedLaunches.add(prepared);
  return prepared;
}

export async function revalidatePreparedUpstreamLaunch(
  prepared: PreparedUpstreamLaunch,
): Promise<void> {
  assertPreparedUpstreamLaunch(prepared);

  let currentWorkingDirectory: WorkingDirectorySnapshot;
  try {
    currentWorkingDirectory = await snapshotWorkingDirectory(prepared.cwd);
  } catch {
    throw new UpstreamLaunchError('working_directory_changed');
  }
  if (!sameWorkingDirectorySnapshot(prepared.workingDirectory, currentWorkingDirectory)) {
    throw new UpstreamLaunchError('working_directory_changed');
  }

  let currentPath: string;
  try {
    currentPath = await realpath(prepared.executable.resolvedPath);
  } catch {
    throw new UpstreamLaunchError('executable_changed');
  }
  if (currentPath !== prepared.executable.resolvedPath) {
    throw new UpstreamLaunchError('executable_changed');
  }

  let current: UpstreamExecutableSnapshot;
  try {
    current = await snapshotExecutable(currentPath);
  } catch {
    throw new UpstreamLaunchError('executable_changed');
  }
  if (!sameExecutableSnapshot(prepared.executable, current)) {
    throw new UpstreamLaunchError('executable_changed');
  }

  const currentDigest = digestLaunch({
    serverId: prepared.serverId,
    executable: current,
    arguments: prepared.arguments,
    cwd: prepared.cwd,
    workingDirectory: currentWorkingDirectory,
    environment: prepared.environment,
  });
  if (currentDigest !== prepared.launchDigest) {
    throw new UpstreamLaunchError('executable_changed');
  }
}

export function assertPreparedUpstreamLaunch(
  candidate: unknown,
): asserts candidate is PreparedUpstreamLaunch {
  if (typeof candidate !== 'object' || candidate === null || !preparedLaunches.has(candidate)) {
    throw new UpstreamLaunchError('prepared_launch_invalid');
  }
}

function validateConfiguration(config: StdioUpstreamConfig): void {
  if (
    config.serverId.length === 0
    || config.serverId.includes('\0')
    || config.command.length === 0
    || config.command.includes('\0')
    || (config.cwd !== undefined && (config.cwd.length === 0 || config.cwd.includes('\0')))
    || config.args.some((argument) => argument.includes('\0'))
  ) {
    throw new UpstreamLaunchError('invalid_configuration');
  }
  for (const [name, value] of Object.entries(config.env)) {
    if (name.length === 0 || name.includes('=') || name.includes('\0') || value.includes('\0')) {
      throw new UpstreamLaunchError('invalid_configuration');
    }
  }
}

async function snapshotWorkingDirectory(
  configuredCwd: string | undefined,
): Promise<WorkingDirectorySnapshot> {
  try {
    const resolvedPath = await realpath(resolve(configuredCwd ?? process.cwd()));
    const observed = await stat(resolvedPath, { bigint: true });
    if (!observed.isDirectory()) throw new UpstreamLaunchError('cwd_unavailable');
    return Object.freeze({
      resolvedPath,
      device: observed.dev.toString(),
      inode: observed.ino.toString(),
      mode: Number(observed.mode),
    });
  } catch {
    throw new UpstreamLaunchError('cwd_unavailable');
  }
}

function freezeEnvironment(environment: Readonly<Record<string, string>>): Readonly<Record<string, string>> {
  return Object.freeze(Object.fromEntries(
    Object.entries(environment).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0),
  ));
}

async function resolveExecutable(
  command: string,
  cwd: string,
  environment: Readonly<Record<string, string>>,
): Promise<UpstreamExecutableSnapshot> {
  if (command.includes('/')) {
    const candidate = isAbsolute(command) ? command : resolve(cwd, command);
    let resolvedPath: string;
    try {
      resolvedPath = await realpath(candidate);
    } catch {
      throw new UpstreamLaunchError('executable_unavailable');
    }
    return snapshotExecutable(resolvedPath);
  }

  for (const entry of (environment.PATH ?? '').split(delimiter)) {
    if (entry.length === 0) continue;
    const searchDirectory = isAbsolute(entry) ? entry : resolve(cwd, entry);
    const candidate = resolve(searchDirectory, command);
    let resolvedPath: string;
    try {
      resolvedPath = await realpath(candidate);
    } catch {
      continue;
    }
    return snapshotExecutable(resolvedPath);
  }
  throw new UpstreamLaunchError('command_not_found');
}

async function snapshotExecutable(resolvedPath: string): Promise<UpstreamExecutableSnapshot> {
  const handle = await openExecutable(resolvedPath);
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile()) throw new UpstreamLaunchError('executable_not_regular');
    if ((before.mode & 0o111n) === 0n) throw new UpstreamLaunchError('executable_not_executable');
    if (before.size > BigInt(MAX_UPSTREAM_EXECUTABLE_BYTES)) {
      throw new UpstreamLaunchError('executable_too_large');
    }
    try {
      await access(resolvedPath, constants.X_OK);
    } catch {
      throw new UpstreamLaunchError('executable_not_executable');
    }

    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let position = 0;
    const size = Number(before.size);
    while (position < size) {
      const length = Math.min(buffer.length, size - position);
      const { bytesRead } = await handle.read(buffer, 0, length, position);
      if (bytesRead === 0) throw new UpstreamLaunchError('executable_snapshot_failed');
      hash.update(buffer.subarray(0, bytesRead));
      position += bytesRead;
    }

    const after = await handle.stat({ bigint: true });
    const pathAfter = await stat(resolvedPath, { bigint: true });
    if (!sameOpenFileIdentity(before, after) || !sameOpenFileIdentity(after, pathAfter)) {
      throw new UpstreamLaunchError('executable_snapshot_failed');
    }

    return Object.freeze({
      resolvedPath,
      device: after.dev.toString(),
      inode: after.ino.toString(),
      size,
      mode: Number(after.mode),
      modifiedTimeNs: after.mtimeNs.toString(),
      changeTimeNs: after.ctimeNs.toString(),
      sha256: hash.digest('hex'),
    });
  } finally {
    await handle.close();
  }
}

async function openExecutable(resolvedPath: string) {
  try {
    return await open(resolvedPath, 'r');
  } catch {
    throw new UpstreamLaunchError('executable_unavailable');
  }
}

function sameOpenFileIdentity(
  left: BigIntStats,
  right: BigIntStats,
): boolean {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mode === right.mode
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function sameExecutableSnapshot(
  left: UpstreamExecutableSnapshot,
  right: UpstreamExecutableSnapshot,
): boolean {
  return left.resolvedPath === right.resolvedPath
    && left.device === right.device
    && left.inode === right.inode
    && left.size === right.size
    && left.mode === right.mode
    && left.modifiedTimeNs === right.modifiedTimeNs
    && left.changeTimeNs === right.changeTimeNs
    && left.sha256 === right.sha256;
}

function sameWorkingDirectorySnapshot(
  left: WorkingDirectorySnapshot,
  right: WorkingDirectorySnapshot,
): boolean {
  return left.resolvedPath === right.resolvedPath
    && left.device === right.device
    && left.inode === right.inode
    && left.mode === right.mode;
}

function digestLaunch(input: Readonly<{
  serverId: string;
  executable: UpstreamExecutableSnapshot;
  arguments: readonly string[];
  cwd: string;
  workingDirectory: WorkingDirectorySnapshot;
  environment: Readonly<Record<string, string>>;
}>): string {
  return createHash('sha256').update(JSON.stringify({
    snapshotFormat: 1,
    serverId: input.serverId,
    executable: input.executable,
    arguments: input.arguments,
    cwd: input.cwd,
    workingDirectory: input.workingDirectory,
    environment: input.environment,
  })).digest('hex');
}
