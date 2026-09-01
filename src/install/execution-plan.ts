import { createHash } from 'node:crypto';
import { access, readFile, realpath, stat } from 'node:fs/promises';
import { constants } from 'node:fs';
import { delimiter, join } from 'node:path';

import { canonicalJson } from '../audit/canonical-json.js';
import { snapshotKnownInstallFiles } from './verifier.js';
import type {
  InstallExecutionPlan,
  InstallExecutionPlanner,
  InstallExecutableIdentity,
  InstallRequest,
  ResolvedPackageMetadata,
} from './types.js';

const MAX_EXECUTABLE_BYTES = 20_000_000;
const MAX_METADATA_AGE_MS = 300_000;
const PACKAGE_NAME = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
const NPM_OPTIONS = new Set(['--save-dev', '--save-exact', '--ignore-scripts']);
const NPX_OPTIONS = new Set(['--yes']);

export class InstallExecutionPlanError extends Error {}

export class LocalInstallExecutionPlanner implements InstallExecutionPlanner {
  constructor(private readonly options: Readonly<{
    environment?: NodeJS.ProcessEnv;
    now?: () => Date;
  }> = {}) {}

  async create(
    request: InstallRequest,
    metadata: ResolvedPackageMetadata,
    timeoutMs: number,
  ): Promise<InstallExecutionPlan> {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1_000 || timeoutMs > 900_000) {
      throw new InstallExecutionPlanError('Install timeout must be between 1 and 900 seconds');
    }
    if (
      !PACKAGE_NAME.test(request.packageName)
      || request.packageName !== metadata.packageName
      || !isExactVersion(metadata.version)
    ) {
      throw new InstallExecutionPlanError('Execution requires matching exact package metadata');
    }
    validateOptions(request);
    const now = (this.options.now ?? (() => new Date()))().getTime();
    const observedAt = Date.parse(metadata.observedAt);
    if (!Number.isFinite(now) || !Number.isFinite(observedAt) || observedAt > now || now - observedAt > MAX_METADATA_AGE_MS) {
      throw new InstallExecutionPlanError('Registry evidence expired before execution approval');
    }
    const registry = validateHttpsUrl(metadata.registry, 'Registry');
    const tarballUrl = validateHttpsUrl(metadata.tarballUrl, 'Package tarball');
    if (!isValidSha512Integrity(metadata.integrity)) {
      throw new InstallExecutionPlanError('Execution requires a valid SHA-512 package integrity value');
    }

    const workingDirectory = await realpath(request.workingDirectory);
    const directoryStats = await stat(workingDirectory);
    if (!directoryStats.isDirectory()) throw new InstallExecutionPlanError('Install working directory is not a directory');
    await rejectProjectNpmrc(workingDirectory);
    if (request.runner === 'npm') {
      const packageJson = await stat(join(workingDirectory, 'package.json')).catch(() => undefined);
      if (packageJson?.isFile() !== true) {
        throw new InstallExecutionPlanError('npm installation requires an existing package.json');
      }
    }

    const environment = this.options.environment ?? process.env;
    const environmentPath = environment.PATH;
    if (environmentPath === undefined) throw new InstallExecutionPlanError('PATH is required for execution planning');
    const executable = await resolveExecutableIdentity(request.runner, environment);
    const runtimeExecutable = await resolveExecutableIdentity('node', environment);
    const executableBin = request.runner === 'npx'
      ? selectExecutableBin(request.packageName, metadata.executableBins)
      : undefined;
    const arguments_ = buildArguments(request, metadata, registry, executableBin);
    const beforeFiles = await snapshotKnownInstallFiles(workingDirectory);
    const body = {
      runner: request.runner,
      executable,
      runtimeExecutable,
      environmentPath,
      arguments: arguments_,
      packageName: request.packageName,
      originalSpecifier: request.requestedSpecifier,
      resolvedVersion: metadata.version,
      tarballUrl,
      integrity: metadata.integrity,
      ...(executableBin === undefined ? {} : { executableBin }),
      options: [...request.options],
      workingDirectory,
      workingDirectoryDevice: directoryStats.dev,
      workingDirectoryInode: directoryStats.ino,
      registry,
      metadataObservedAt: metadata.observedAt,
      lifecycleScripts: [...metadata.lifecycleScripts],
      timeoutMs,
      beforeFiles,
    };
    return deepFreeze({
      planHash: createHash('sha256').update(canonicalJson(body)).digest('hex'),
      ...body,
    });
  }
}

function buildArguments(
  request: InstallRequest,
  metadata: ResolvedPackageMetadata,
  registry: string,
  executableBin: string | undefined,
): readonly string[] {
  const exactPackage = `${request.packageName}@${metadata.version}`;
  if (request.runner === 'npm') {
    return Object.freeze([
      'install',
      '--no-audit',
      '--no-fund',
      `--registry=${registry}`,
      ...request.options,
      exactPackage,
    ]);
  }
  if (executableBin === undefined) throw new InstallExecutionPlanError('npx requires one exact executable binary');
  return Object.freeze([
    '--yes',
    `--registry=${registry}`,
    `--package=${exactPackage}`,
    '--',
    executableBin,
  ]);
}

function selectExecutableBin(
  packageName: string,
  bins: Readonly<Record<string, string>> | undefined,
): string {
  if (bins === undefined) throw new InstallExecutionPlanError('npx package metadata did not declare an executable');
  const names = Object.keys(bins).sort();
  const preferred = packageName.includes('/') ? packageName.slice(packageName.lastIndexOf('/') + 1) : packageName;
  if (names.includes(preferred)) return preferred;
  if (names.length === 1 && names[0] !== undefined) return names[0];
  throw new InstallExecutionPlanError('npx package exposes multiple ambiguous executables');
}

async function resolveExecutableIdentity(
  name: 'npm' | 'npx' | 'node',
  environment: NodeJS.ProcessEnv,
): Promise<InstallExecutableIdentity> {
  const pathValue = environment.PATH;
  if (pathValue === undefined) throw new InstallExecutionPlanError('PATH is required to locate the package runner');
  const suffixes = process.platform === 'win32'
    ? (environment.PATHEXT ?? '.EXE;.CMD;.BAT').split(';')
    : [''];
  for (const directory of pathValue.split(delimiter)) {
    if (directory.length === 0) continue;
    for (const suffix of suffixes) {
      const candidate = join(directory, `${name}${suffix.toLowerCase()}`);
      try {
        await access(candidate, constants.X_OK);
        const path = await realpath(candidate);
        const fileStats = await stat(path);
        if (!fileStats.isFile() || fileStats.size > MAX_EXECUTABLE_BYTES) continue;
        const bytes = await readFile(path);
        return Object.freeze({
          path,
          sha256: createHash('sha256').update(bytes).digest('hex'),
        });
      } catch {
        // Try the next PATH candidate without exposing local path details.
      }
    }
  }
  throw new InstallExecutionPlanError(`Could not resolve a trusted ${name} executable`);
}

async function rejectProjectNpmrc(workingDirectory: string): Promise<void> {
  const npmrc = await stat(join(workingDirectory, '.npmrc')).catch(() => undefined);
  if (npmrc !== undefined) {
    throw new InstallExecutionPlanError('Project .npmrc is not supported by the credential-free execution preview');
  }
}

function validateHttpsUrl(input: string | undefined, label: string): string {
  if (input === undefined) throw new InstallExecutionPlanError(`${label} evidence is required for execution`);
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new InstallExecutionPlanError(`${label} must be a valid HTTPS URL`);
  }
  if (
    url.protocol !== 'https:'
    || url.username.length > 0
    || url.password.length > 0
    || url.search.length > 0
    || url.hash.length > 0
  ) {
    throw new InstallExecutionPlanError(`${label} must be an HTTPS URL without credentials, query, or fragment`);
  }
  return url.toString();
}

function validateOptions(request: InstallRequest): void {
  const allowed = request.runner === 'npm' ? NPM_OPTIONS : NPX_OPTIONS;
  const options = [...request.options];
  if (
    options.some((option) => !allowed.has(option))
    || new Set(options).size !== options.length
    || JSON.stringify(options) !== JSON.stringify([...options].sort())
  ) {
    throw new InstallExecutionPlanError('Install options are unsupported or not canonical');
  }
}

function isValidSha512Integrity(value: string | undefined): value is string {
  if (value === undefined || !value.startsWith('sha512-')) return false;
  const encoded = value.slice('sha512-'.length);
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) return false;
  try {
    const bytes = Buffer.from(encoded, 'base64');
    return bytes.byteLength === 64 && bytes.toString('base64') === encoded;
  } catch {
    return false;
  }
}

function isExactVersion(value: string): boolean {
  return /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(value);
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== 'object' || value === null || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const nested of Object.values(value as Record<string, unknown>)) deepFreeze(nested);
  return value;
}
