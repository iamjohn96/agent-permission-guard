import { createHash } from 'node:crypto';
import { readFile, realpath, stat } from 'node:fs/promises';
import { join } from 'node:path';

import { canonicalJson } from '../audit/canonical-json.js';
import type {
  InstallExecutionPlan,
  InstallFileSnapshot,
  InstallVerificationResult,
} from './types.js';

const KNOWN_FILES = ['package.json', 'package-lock.json', 'npm-shrinkwrap.json'] as const;
const MAX_PROJECT_FILE_BYTES = 5_000_000;

export async function snapshotKnownInstallFiles(
  workingDirectory: string,
): Promise<readonly InstallFileSnapshot[]> {
  return Object.freeze(await Promise.all(KNOWN_FILES.map(async (relativePath) => {
    const path = join(workingDirectory, relativePath);
    const fileStats = await stat(path).catch(() => undefined);
    if (fileStats === undefined) return Object.freeze({ relativePath, exists: false });
    if (!fileStats.isFile() || fileStats.size > MAX_PROJECT_FILE_BYTES) {
      throw new Error(`Install verification cannot safely snapshot ${relativePath}`);
    }
    const bytes = await readFile(path);
    return Object.freeze({
      relativePath,
      exists: true,
      sha256: createHash('sha256').update(bytes).digest('hex'),
    });
  })));
}

export async function validateInstallPlanPreconditions(plan: InstallExecutionPlan): Promise<void> {
  const { planHash, ...body } = plan;
  const currentPlanHash = createHash('sha256').update(canonicalJson(body)).digest('hex');
  if (currentPlanHash !== planHash) throw new Error('Install execution plan identity is invalid');
  const canonicalDirectory = await realpath(plan.workingDirectory);
  const directoryStats = await stat(canonicalDirectory);
  if (
    canonicalDirectory !== plan.workingDirectory
    || directoryStats.dev !== plan.workingDirectoryDevice
    || directoryStats.ino !== plan.workingDirectoryInode
  ) {
    throw new Error('Install working directory identity changed after approval');
  }
  await validateExecutableIdentity(plan.executable.path, plan.executable.sha256, 'Package runner');
  await validateExecutableIdentity(plan.runtimeExecutable.path, plan.runtimeExecutable.sha256, 'Node runtime');
  const currentFiles = await snapshotKnownInstallFiles(plan.workingDirectory);
  if (JSON.stringify(currentFiles) !== JSON.stringify(plan.beforeFiles)) {
    throw new Error('Project manifest or lockfile changed after approval');
  }
  const npmrc = await stat(join(plan.workingDirectory, '.npmrc')).catch(() => undefined);
  if (npmrc !== undefined) throw new Error('Project .npmrc appeared after approval');
}

async function validateExecutableIdentity(path: string, expectedHash: string, label: string): Promise<void> {
  const bytes = await readFile(path);
  const hash = createHash('sha256').update(bytes).digest('hex');
  if (hash !== expectedHash) throw new Error(`${label} executable changed after approval`);
}

export async function verifyInstallExecution(
  plan: InstallExecutionPlan,
  processCompleted: boolean,
): Promise<InstallVerificationResult> {
  const afterFiles = await snapshotKnownInstallFiles(plan.workingDirectory);
  const changedFiles = afterFiles
    .filter((item, index) => JSON.stringify(item) !== JSON.stringify(plan.beforeFiles[index]))
    .map((item) => item.relativePath);
  if (!processCompleted) {
    return Object.freeze({
      status: 'limited',
      exactPackageVersionObserved: false,
      approvedIntegrityObserved: false,
      changedFiles: Object.freeze(changedFiles),
      reasonCodes: Object.freeze(['process_not_completed']),
    });
  }
  if (plan.runner === 'npx') {
    return Object.freeze({
      status: 'limited',
      exactPackageVersionObserved: false,
      approvedIntegrityObserved: false,
      changedFiles: Object.freeze(changedFiles),
      reasonCodes: Object.freeze(['npx_effects_not_contained']),
    });
  }
  const observed = await inspectLockfileIdentity(plan);
  const verified = observed.exactPackageVersionObserved && observed.approvedIntegrityObserved;
  const reasonCodes = [
    ...(observed.exactPackageVersionObserved ? [] : ['exact_version_not_observed']),
    ...(observed.approvedIntegrityObserved ? [] : ['approved_integrity_not_observed']),
  ];
  return Object.freeze({
    status: verified ? 'verified' : 'failed',
    ...observed,
    changedFiles: Object.freeze(changedFiles),
    reasonCodes: Object.freeze(reasonCodes),
  });
}

async function inspectLockfileIdentity(plan: InstallExecutionPlan): Promise<Readonly<{
  exactPackageVersionObserved: boolean;
  approvedIntegrityObserved: boolean;
}>> {
  for (const relativePath of ['npm-shrinkwrap.json', 'package-lock.json'] as const) {
    try {
      const value = JSON.parse(await readFile(join(plan.workingDirectory, relativePath), 'utf8')) as unknown;
      const record = asRecord(value);
      const packages = asRecord(record?.packages);
      const packageEntry = asRecord(packages?.[`node_modules/${plan.packageName}`]);
      if (packageEntry?.version === plan.resolvedVersion) {
        return {
          exactPackageVersionObserved: true,
          approvedIntegrityObserved: packageEntry.integrity === plan.integrity,
        };
      }
      const dependencies = asRecord(record?.dependencies);
      const dependency = asRecord(dependencies?.[plan.packageName]);
      if (dependency?.version === plan.resolvedVersion) {
        return {
          exactPackageVersionObserved: true,
          approvedIntegrityObserved: dependency.integrity === plan.integrity,
        };
      }
    } catch {
      // Try the other npm lockfile form.
    }
  }
  return { exactPackageVersionObserved: false, approvedIntegrityObserved: false };
}

function asRecord(value: unknown): Readonly<Record<string, unknown>> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Readonly<Record<string, unknown>>
    : undefined;
}
