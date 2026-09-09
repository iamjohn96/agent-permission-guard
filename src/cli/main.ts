#!/usr/bin/env node

import { randomBytes } from 'node:crypto';
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { AuditQueryService } from '../audit/query-service.js';
import { SqliteAuditRecorder } from '../audit/recorder.js';
import { LocalApprovalService } from '../approval/service.js';
import { startDashboard } from '../dashboard/server.js';
import { type DashboardStateFile, writeDashboardStateFile } from '../dashboard/state-file.js';
import { openAuditDatabase } from '../db/database.js';
import { createGateway } from '../gateway/gateway.js';
import { selectBuiltInMcpIdentityProfile } from '../identity/builtin-profiles.js';
import { prepareUpstreamLaunch } from '../launch/upstream-launch.js';
import { LivePolicyController } from '../policy/live-controller.js';
import { serveStdioGateway } from '../transport/stdio-downstream.js';
import { parseDoctorArguments, runDoctor } from './doctor.js';
import { parseInitArguments, runInit } from './init.js';
import { parseInspectArguments, runInspect } from './inspect.js';
import { parseInstallArguments, runInstall } from './install.js';
import { parseReceiptArguments, runReceipt } from './receipt.js';
import {
  graphGenesisUsage,
  isGraphGenesisUsageError,
  parseGraphGenesisArguments,
  runGraphGenesisReadiness,
} from './graph-genesis.js';

export type ProxyArguments = Readonly<{
  policyPath: string;
  auditDbPath: string;
  dashboardPort: number;
  dashboardStatePath?: string;
  identityProfileId?: string;
  command: string;
  args: readonly string[];
}>;

export function parseProxyArguments(argv: readonly string[]): ProxyArguments {
  if (argv[0] !== 'proxy') throw usageError();
  let policyPath: string | undefined;
  let auditDbPath: string | undefined;
  let dashboardPort = 47_831;
  let dashboardStatePath: string | undefined;
  let identityProfileId: string | undefined;
  let index = 1;

  while (index < argv.length && argv[index] !== '--') {
    const option = argv[index];
    const value = argv[index + 1];
    if (value === undefined || value === '--') throw usageError();
    if (option === '--policy' && policyPath === undefined) policyPath = value;
    else if (option === '--audit-db' && auditDbPath === undefined) auditDbPath = value;
    else if (option === '--dashboard-port') dashboardPort = parsePort(value);
    else if (option === '--dashboard-state' && dashboardStatePath === undefined) dashboardStatePath = value;
    else if (option === '--identity-profile' && identityProfileId === undefined) identityProfileId = value;
    else throw usageError();
    index += 2;
  }
  const command = argv[index + 1];
  if (argv[index] !== '--' || command === undefined || policyPath === undefined || auditDbPath === undefined) {
    throw usageError();
  }

  return {
    policyPath,
    auditDbPath,
    dashboardPort,
    ...(dashboardStatePath === undefined ? {} : { dashboardStatePath }),
    ...(identityProfileId === undefined ? {} : { identityProfileId }),
    command,
    args: argv.slice(index + 2),
  };
}

function parsePort(value: string): number {
  const port = Number(value);
  if (!Number.isSafeInteger(port) || port < 0 || port > 65_535) throw usageError();
  return port;
}

function usageError(): Error {
  return new Error('Usage: apg proxy --policy <policy.yaml> --audit-db <audit.sqlite> [--dashboard-port <port>] [--dashboard-state <dashboard.json>] [--identity-profile <profile-id>] -- <upstream-command> [args...]');
}

export async function main(argv: readonly string[] = process.argv.slice(2)): Promise<void> {
  if (argv[0] === 'init') {
    runInit(parseInitArguments(argv.slice(1)));
    return;
  }
  if (argv[0] === 'doctor') {
    const healthy = await runDoctor(parseDoctorArguments(argv.slice(1)));
    if (!healthy) process.exitCode = 1;
    return;
  }
  if (argv[0] === 'inspect') {
    await runInspect(parseInspectArguments(argv.slice(1)));
    return;
  }
  if (argv[0] === 'install') {
    const result = await runInstall(parseInstallArguments(argv.slice(1)));
    if (result.status !== 'completed') process.exitCode = 1;
    return;
  }
  if (argv[0] === 'receipt') {
    const result = runReceipt(parseReceiptArguments(argv.slice(1)));
    if (!result.successful) process.exitCode = 1;
    return;
  }
  if (argv[0] === 'graph') {
    let parsed;
    try { parsed = parseGraphGenesisArguments(argv); } catch (error) {
      if (!isGraphGenesisUsageError(error)) throw error;
      process.stderr.write(`${error.message}\n`);
      process.exitCode = error.exitCode;
      return;
    }
    if (parsed.kind === 'help') {
      process.stdout.write(`${graphGenesisUsage()}\n`);
      return;
    }
    const result = await runGraphGenesisReadiness(parsed);
    process.stderr.write('[apg] Graph Genesis live execution remains fail-closed at this readiness checkpoint.\n');
    process.stderr.write(`[apg] protection boundary: ${result.bypassWarning}\n`);
    process.exitCode = result.exitCode;
    return;
  }
  if (argv[0] === '--help' || argv[0] === '-h' || argv.length === 0) {
    process.stdout.write(`${generalUsage()}\n`);
    return;
  }

  const parsed = parseProxyArguments(argv);
  const identitySelection = parsed.identityProfileId === undefined
    ? undefined
    : selectBuiltInMcpIdentityProfile(parsed.identityProfileId);
  const preparedLaunch = await prepareUpstreamLaunch({
    serverId: 'local-upstream',
    command: parsed.command,
    args: parsed.args,
    env: createMinimalEnvironment(),
  });
  const policies = new LivePolicyController(parsed.policyPath);
  const database = openAuditDatabase(parsed.auditDbPath);
  const audit = new SqliteAuditRecorder(database);
  const auditQuery = new AuditQueryService(database, audit);
  const approvals = new LocalApprovalService();
  let gateway;
  try {
    gateway = await createGateway(
      preparedLaunch,
      policies,
      audit,
      {
        coordinator: approvals,
        getTtlMs: () => policies.getApprovalTtlMs(),
      },
      identitySelection?.authority,
    );
  } catch (error) {
    approvals.close();
    database.close();
    throw error;
  }

  let dashboard;
  try {
    dashboard = await startDashboard({
      approvals,
      audit: auditQuery,
      auditRecorder: audit,
      policies,
      token: randomBytes(32).toString('base64url'),
      port: parsed.dashboardPort,
    });
  } catch (error) {
    approvals.close();
    await gateway.close();
    database.close();
    throw error;
  }
  if (identitySelection !== undefined) {
    process.stderr.write(
      `[apg] identity profile: ${identitySelection.profileId} (required for ${identitySelection.toolName})\n`,
    );
  }
  process.stderr.write('[apg] server provenance: configured label only\n');
  process.stderr.write('[apg] upstream launch: local pre-spawn checks applied; package, publisher, dependencies, and runtime are not verified\n');
  process.stderr.write('[apg] protection boundary: only MCP calls routed through APG are protected; direct MCP, node, npm, and npx commands are outside coverage\n');
  process.stderr.write(`[apg] approval dashboard: ${dashboard.url}\n`);

  let dashboardState: DashboardStateFile | undefined;
  if (parsed.dashboardStatePath !== undefined) {
    try {
      dashboardState = writeDashboardStateFile(
        parsed.dashboardStatePath,
        dashboard.url,
        dashboard.instanceId,
        process.pid,
        new Date(),
      );
      process.stderr.write(`[apg] dashboard state: ${dashboardState.path}\n`);
    } catch (error) {
      approvals.close();
      await dashboard.close();
      await gateway.close();
      database.close();
      throw error;
    }
  }

  const downstream = serveStdioGateway(gateway);
  let closing = false;
  const close = async () => {
    if (closing) return;
    closing = true;
    approvals.close();
    await downstream.close();
    try {
      await dashboard.close();
    } finally {
      dashboardState?.remove();
    }
    await gateway.close();
    database.close();
  };

  process.once('SIGINT', () => void close());
  process.once('SIGTERM', () => void close());
  process.stdin.once('end', () => void close());
}

function generalUsage(): string {
  return [
    'Agent Permission Guard',
    '',
    'Usage:',
    '  apg init [--directory <path>]',
    '  apg doctor [--policy <policy.yaml>] [--audit-db <audit.sqlite>] [--dashboard-port <port>] [--dashboard-state <dashboard.json>] [-- <upstream-command> [args...]]',
    '  apg inspect <npm|npx> <package-spec> [--registry <https-url>]',
    '  apg install <npm|npx> <package-spec> [supported package options] [--registry <https-url>] [--timeout-seconds <1..900>] [--approval-ttl-seconds <1..3600>] [--policy <policy.yaml>] [--audit-db <audit.sqlite>] [--dashboard-port <port>]',
    '  apg receipt export <action-id> [--audit-db <audit.sqlite>] --output <receipt.json>',
    '  apg receipt verify <receipt.json>',
    '  apg graph genesis filesystem --audit-db <existing-private-apg-audit.sqlite> --output <absent-candidate.json> [--dashboard-port <0-or-port>] [--dashboard-state <absent-private-dashboard.json>]',
    '  apg proxy --policy <policy.yaml> --audit-db <audit.sqlite> [--dashboard-port <port>] [--dashboard-state <dashboard.json>] [--identity-profile <profile-id>] -- <upstream-command> [args...]',
  ].join('\n');
}

function createMinimalEnvironment(): Record<string, string> {
  return process.env.PATH === undefined ? {} : { PATH: process.env.PATH };
}

export function isEntryPointPath(entryPath: string | undefined, moduleUrl: string): boolean {
  if (entryPath === undefined) return false;
  try {
    return realpathSync(entryPath) === realpathSync(fileURLToPath(moduleUrl));
  } catch {
    return false;
  }
}

const isEntryPoint = isEntryPointPath(process.argv[1], import.meta.url);

if (isEntryPoint) {
  main().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`[apg] fatal: ${message}\n`);
    process.exitCode = 1;
  });
}
