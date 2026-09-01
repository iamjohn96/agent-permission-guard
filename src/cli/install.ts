import { randomBytes } from 'node:crypto';

import { LocalApprovalService } from '../approval/service.js';
import { AuditQueryService } from '../audit/query-service.js';
import { SqliteAuditRecorder } from '../audit/recorder.js';
import { startDashboard } from '../dashboard/server.js';
import { openAuditDatabase } from '../db/database.js';
import { InstallAuditAdapter } from '../install/audit.js';
import { LocalInstallExecutionPlanner } from '../install/execution-plan.js';
import {
  FetchNpmRegistryTransport,
  NpmRegistryMetadataProvider,
  type NpmRegistryTransport,
} from '../install/npm-registry.js';
import { parseInstallRequest } from '../install/parser.js';
import { ControlledLocalInstallRunner } from '../install/runner.js';
import { InstallGuardService } from '../install/service.js';
import type {
  InstallExecutionPlanner,
  InstallGuardResult,
  InstallRequest,
  InstallRunnerAdapter,
} from '../install/types.js';
import { LivePolicyController } from '../policy/live-controller.js';

const DEFAULT_REGISTRY = 'https://registry.npmjs.org/';

export type InstallArguments = Readonly<{
  request: InstallRequest;
  registry: string;
  timeoutMs: number;
  approvalTtlMs: number;
  policyPath: string;
  auditDbPath: string;
  dashboardPort: number;
}>;

type TextOutput = Readonly<{ write(text: string): unknown }>;

export function parseInstallArguments(
  argv: readonly string[],
  workingDirectory: string = process.cwd(),
): InstallArguments {
  const runner = argv[0];
  if (runner !== 'npm' && runner !== 'npx') throw installUsageError();

  let registry = DEFAULT_REGISTRY;
  let timeoutMs = 300_000;
  let approvalTtlMs = 120_000;
  let policyPath = '.apg/policy.yaml';
  let auditDbPath = '.apg/audit.sqlite';
  let dashboardPort = 47_831;
  const packageArguments: string[] = [];
  const seen = new Set<string>();

  for (let index = 1; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === undefined) throw installUsageError();
    if (!INSTALL_OPTIONS.has(token)) {
      packageArguments.push(token);
      continue;
    }
    if (seen.has(token)) throw installUsageError();
    const value = argv[index + 1];
    if (value === undefined) throw installUsageError();
    seen.add(token);
    index += 1;
    if (token === '--registry') registry = validateRegistry(value);
    else if (token === '--timeout-seconds') timeoutMs = parseSeconds(value, 1, 900) * 1_000;
    else if (token === '--approval-ttl-seconds') approvalTtlMs = parseSeconds(value, 1, 3_600) * 1_000;
    else if (token === '--policy') policyPath = value;
    else if (token === '--audit-db') auditDbPath = value;
    else dashboardPort = parsePort(value);
  }

  let request: InstallRequest;
  try {
    request = parseInstallRequest(runner, packageArguments, workingDirectory);
  } catch {
    throw installUsageError();
  }
  return {
    request,
    registry,
    timeoutMs,
    approvalTtlMs,
    policyPath,
    auditDbPath,
    dashboardPort,
  };
}

const INSTALL_OPTIONS = new Set([
  '--registry',
  '--timeout-seconds',
  '--approval-ttl-seconds',
  '--policy',
  '--audit-db',
  '--dashboard-port',
]);

export async function runInstall(
  arguments_: InstallArguments,
  dependencies: Readonly<{
    transport?: NpmRegistryTransport;
    planner?: InstallExecutionPlanner;
    runner?: InstallRunnerAdapter;
    output?: TextOutput;
    errorOutput?: TextOutput;
  }> = {},
): Promise<InstallGuardResult> {
  const output = dependencies.output ?? process.stdout;
  const errorOutput = dependencies.errorOutput ?? process.stderr;
  errorOutput.write([
    '[apg] Install Guard protects only this explicitly routed command.',
    '[apg] Direct npm/npx commands bypass APG and are not approved, verified, or audited.',
    `[apg] Registry metadata read will disclose ${arguments_.request.packageName} to ${arguments_.registry}`,
    '',
  ].join('\n'));

  const policies = new LivePolicyController(arguments_.policyPath);
  const database = openAuditDatabase(arguments_.auditDbPath);
  const auditRecorder = new SqliteAuditRecorder(database);
  const approvals = new LocalApprovalService();
  let dashboard;
  try {
    dashboard = await startDashboard({
      approvals,
      audit: new AuditQueryService(database, auditRecorder),
      auditRecorder,
      policies,
      token: randomBytes(32).toString('base64url'),
      port: arguments_.dashboardPort,
    });
  } catch (error) {
    approvals.close();
    database.close();
    throw error;
  }

  errorOutput.write(`[apg] install approval dashboard: ${dashboard.url}\n`);
  const controller = new AbortController();
  const cancel = () => controller.abort();
  process.once('SIGINT', cancel);
  process.once('SIGTERM', cancel);
  try {
    const metadata = new NpmRegistryMetadataProvider({
      registry: arguments_.registry,
      transport: dependencies.transport ?? new FetchNpmRegistryTransport(),
    });
    const service = new InstallGuardService({
      metadata,
      approvals,
      audit: new InstallAuditAdapter(auditRecorder),
      planner: dependencies.planner ?? new LocalInstallExecutionPlanner(),
      runner: dependencies.runner ?? new ControlledLocalInstallRunner(),
    });
    const result = await service.run(arguments_.request, arguments_.approvalTtlMs, {
      timeoutMs: arguments_.timeoutMs,
      signal: controller.signal,
    });
    output.write(formatInstallResult(result));
    return result;
  } finally {
    process.removeListener('SIGINT', cancel);
    process.removeListener('SIGTERM', cancel);
    approvals.close();
    try {
      await dashboard.close();
    } finally {
      database.close();
    }
  }
}

function formatInstallResult(result: InstallGuardResult): string {
  const lines = [
    'Install Guard result',
    `Status: ${result.status.toUpperCase()}`,
    `Decision: ${result.evaluation.effectiveDecision.toUpperCase()}`,
    `Reasons: ${result.evaluation.reasonCodes.join(', ')}`,
  ];
  if (result.plan !== undefined) {
    lines.push(`Package: ${result.plan.packageName}@${result.plan.resolvedVersion}`);
    lines.push(`Plan: ${result.plan.planHash}`);
  }
  if (result.execution !== undefined) {
    lines.push(`Exit code: ${result.execution.exitCode ?? 'none'}`);
    lines.push(`Duration: ${result.execution.durationMs}ms`);
    lines.push(`Verification: ${result.execution.verification?.status ?? 'unavailable'}`);
  }
  lines.push('Coverage: only this APG-routed request was protected; direct npm/npx remains outside coverage.');
  lines.push('');
  return lines.join('\n');
}

function validateRegistry(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw installUsageError();
  }
  if (
    url.protocol !== 'https:'
    || url.username.length > 0
    || url.password.length > 0
    || url.search.length > 0
    || url.hash.length > 0
  ) {
    throw installUsageError();
  }
  url.pathname = `${url.pathname.replace(/\/+$/, '')}/`;
  return url.toString();
}

function parseSeconds(value: string, minimum: number, maximum: number): number {
  const seconds = Number(value);
  if (!Number.isSafeInteger(seconds) || seconds < minimum || seconds > maximum) throw installUsageError();
  return seconds;
}

function parsePort(value: string): number {
  const port = Number(value);
  if (!Number.isSafeInteger(port) || port < 0 || port > 65_535) throw installUsageError();
  return port;
}

function installUsageError(): Error {
  return new Error([
    'Usage: apg install <npm|npx> <package-spec> [supported package options]',
    '  [--registry <https-url>] [--timeout-seconds <1..900>] [--approval-ttl-seconds <1..3600>]',
    '  [--policy <policy.yaml>] [--audit-db <audit.sqlite>] [--dashboard-port <port>]',
  ].join(' '));
}
