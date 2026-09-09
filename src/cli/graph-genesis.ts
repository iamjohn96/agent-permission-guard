import { existsSync, lstatSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, normalize, resolve } from 'node:path';

import type { ProductionGraphGenesisLiveResult } from '../stage/graph-genesis-live.js';

const USAGE = 'Usage: apg graph genesis filesystem --audit-db <existing-private-apg-audit.sqlite> --output <absent-candidate.json> [--dashboard-port <0-or-port>] [--dashboard-state <absent-private-dashboard.json>]';
const FORBIDDEN_ENVIRONMENT_KEYS = /^(?:NODE_OPTIONS|NODE_EXTRA_CA_CERTS|NODE_TLS_REJECT_UNAUTHORIZED|SSL_CERT_FILE|SSL_CERT_DIR|HTTPS?_PROXY|ALL_PROXY|NO_PROXY|NPM_CONFIG_.+)$/iu;

export type ExactGraphGenesisArguments = Readonly<{
  kind: 'run';
  auditDbPath: string;
  outputPath: string;
  dashboardPort: number;
  dashboardStatePath?: string;
}>;

export type GraphGenesisHelpArguments = Readonly<{ kind: 'help' }>;

export function parseGraphGenesisArguments(
  argv: readonly string[],
): ExactGraphGenesisArguments | GraphGenesisHelpArguments {
  if (argv.length === 4 && argv[0] === 'graph' && argv[1] === 'genesis'
    && argv[2] === 'filesystem' && (argv[3] === '--help' || argv[3] === '-h')) return Object.freeze({ kind: 'help' });
  if (argv[0] !== 'graph' || argv[1] !== 'genesis' || argv[2] !== 'filesystem') throw usageError();
  let auditDbPath: string | undefined;
  let outputPath: string | undefined;
  let dashboardStatePath: string | undefined;
  let dashboardPort = 0;
  const seen = new Set<string>();
  for (let index = 3; index < argv.length; index += 2) {
    const option = argv[index];
    const value = argv[index + 1];
    if (value === undefined || value.startsWith('--') || option === undefined || seen.has(option)) throw usageError();
    seen.add(option);
    if (option === '--audit-db' && auditDbPath === undefined) auditDbPath = parseAbsoluteNormalizedPath(value);
    else if (option === '--output' && outputPath === undefined) outputPath = parseAbsoluteNormalizedPath(value);
    else if (option === '--dashboard-state' && dashboardStatePath === undefined) dashboardStatePath = parseAbsoluteNormalizedPath(value);
    else if (option === '--dashboard-port' && dashboardPort === 0) dashboardPort = parseDashboardPort(value);
    else throw usageError();
  }
  if (auditDbPath === undefined || outputPath === undefined) throw usageError();
  const paths = [auditDbPath, outputPath, ...(dashboardStatePath === undefined ? [] : [dashboardStatePath])];
  if (new Set(paths).size !== paths.length) throw usageError();
  return Object.freeze({
    kind: 'run' as const,
    auditDbPath,
    outputPath,
    dashboardPort,
    ...(dashboardStatePath === undefined ? {} : { dashboardStatePath }),
  });
}

/** Closed CLI handoff. Dynamic loading keeps parsing and --help effect-free. */
export async function runGraphGenesisReadiness(
  input: ExactGraphGenesisArguments,
  signal?: AbortSignal,
): Promise<ProductionGraphGenesisLiveResult> {
  const { runExactProductionGraphGenesisLive } = await import('../stage/graph-genesis-live.js');
  return runExactProductionGraphGenesisLive(input, signal);
}

/** Read-only input validation used by the sole production owner before any local effect. */
export function assertGraphGenesisLocalInputs(input: ExactGraphGenesisArguments, signal?: AbortSignal): void {
  if (signal?.aborted === true) throw new Error('cancelled');
  assertNoForbiddenEnvironmentKeys();
  assertGraphGenesisPathInputs(input);
}

/** Path-only half of local validation; exposed for network-free tests without environment-value access. */
export function assertGraphGenesisPathInputs(input: ExactGraphGenesisArguments): void {
  assertPrivateExistingAuditFile(input.auditDbPath);
  assertAbsentPrivateOutput(input.outputPath);
  if (input.dashboardStatePath !== undefined) assertAbsentPrivateOutput(input.dashboardStatePath);
}

export function graphGenesisUsage(): string { return USAGE; }

export function isGraphGenesisUsageError(value: unknown): value is Error & { exitCode: 64 } {
  return value instanceof GraphGenesisUsageError;
}

function parseAbsoluteNormalizedPath(value: string): string {
  if (value.length < 1 || value.length > 4096 || /[\u0000-\u001f\u007f]/u.test(value)
    || !isAbsolute(value) || normalize(value) !== value || resolve(value) !== value) throw usageError();
  return value;
}

function parseDashboardPort(value: string): number {
  if (!/^(?:0|[1-9]\d{3,4})$/u.test(value)) throw usageError();
  const port = Number(value);
  if (!Number.isSafeInteger(port) || port > 65_535 || (port !== 0 && port < 1024)) throw usageError();
  return port;
}

function assertNoForbiddenEnvironmentKeys(): void {
  if (Object.keys(process.env).some((key) => FORBIDDEN_ENVIRONMENT_KEYS.test(key))) {
    throw new Error('Runtime-affecting environment key is present');
  }
}

function assertPrivateExistingAuditFile(path: string): void {
  if (realpathSync(path) !== path) throw new Error('Audit path is not canonical');
  const parent = lstatSync(dirname(path));
  const file = lstatSync(path);
  const currentUser = typeof process.geteuid === 'function' ? process.geteuid() : file.uid;
  if (!parent.isDirectory() || parent.isSymbolicLink() || parent.uid !== currentUser || (parent.mode & 0o777) !== 0o700
    || !file.isFile() || file.isSymbolicLink() || file.nlink !== 1 || file.uid !== currentUser
    || (file.mode & 0o777) !== 0o600) throw new Error('Audit path is not an exact private file');
}

function assertAbsentPrivateOutput(path: string): void {
  if (existsSync(path)) throw new Error('Output path already exists');
  const parentPath = dirname(path);
  if (realpathSync(parentPath) !== parentPath) throw new Error('Output parent is not canonical');
  const parent = lstatSync(parentPath);
  const currentUser = typeof process.geteuid === 'function' ? process.geteuid() : parent.uid;
  if (!parent.isDirectory() || parent.isSymbolicLink() || parent.uid !== currentUser
    || (parent.mode & 0o777) !== 0o700) throw new Error('Output parent is not private');
}

class GraphGenesisUsageError extends Error {
  readonly exitCode = 64 as const;
  constructor() { super(USAGE); }
}

function usageError(): GraphGenesisUsageError { return new GraphGenesisUsageError(); }
