#!/usr/bin/env node

import { randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';

import { AuditQueryService } from '../audit/query-service.js';
import { SqliteAuditRecorder } from '../audit/recorder.js';
import { LocalApprovalService } from '../approval/service.js';
import { startDashboard } from '../dashboard/server.js';
import { openAuditDatabase } from '../db/database.js';
import { createGateway } from '../gateway/gateway.js';
import { LivePolicyController } from '../policy/live-controller.js';
import { serveStdioGateway } from '../transport/stdio-downstream.js';

export type ProxyArguments = Readonly<{
  policyPath: string;
  auditDbPath: string;
  dashboardPort: number;
  command: string;
  args: readonly string[];
}>;

export function parseProxyArguments(argv: readonly string[]): ProxyArguments {
  if (argv[0] !== 'proxy') throw usageError();
  let policyPath: string | undefined;
  let auditDbPath: string | undefined;
  let dashboardPort = 47_831;
  let index = 1;

  while (index < argv.length && argv[index] !== '--') {
    const option = argv[index];
    const value = argv[index + 1];
    if (value === undefined || value === '--') throw usageError();
    if (option === '--policy' && policyPath === undefined) policyPath = value;
    else if (option === '--audit-db' && auditDbPath === undefined) auditDbPath = value;
    else if (option === '--dashboard-port') dashboardPort = parsePort(value);
    else throw usageError();
    index += 2;
  }
  const command = argv[index + 1];
  if (argv[index] !== '--' || command === undefined || policyPath === undefined || auditDbPath === undefined) {
    throw usageError();
  }

  return { policyPath, auditDbPath, dashboardPort, command, args: argv.slice(index + 2) };
}

function parsePort(value: string): number {
  const port = Number(value);
  if (!Number.isSafeInteger(port) || port < 0 || port > 65_535) throw usageError();
  return port;
}

function usageError(): Error {
  return new Error('Usage: apg proxy --policy <policy.yaml> --audit-db <audit.sqlite> [--dashboard-port <port>] -- <upstream-command> [args...]');
}

export async function main(argv: readonly string[] = process.argv.slice(2)): Promise<void> {
  const parsed = parseProxyArguments(argv);
  const policies = new LivePolicyController(parsed.policyPath);
  const database = openAuditDatabase(parsed.auditDbPath);
  const audit = new SqliteAuditRecorder(database);
  const auditQuery = new AuditQueryService(database, audit);
  const approvals = new LocalApprovalService();
  const environment = createMinimalEnvironment();
  let gateway;
  try {
    gateway = await createGateway(
      {
        serverId: 'local-upstream',
        command: parsed.command,
        args: parsed.args,
        env: environment,
      },
      policies,
      audit,
      {
        coordinator: approvals,
        getTtlMs: () => policies.getApprovalTtlMs(),
      },
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
  process.stderr.write(`[apg] approval dashboard: ${dashboard.url}\n`);

  const downstream = serveStdioGateway(gateway);
  let closing = false;
  const close = async () => {
    if (closing) return;
    closing = true;
    approvals.close();
    await downstream.close();
    await dashboard.close();
    await gateway.close();
    database.close();
  };

  process.once('SIGINT', () => void close());
  process.once('SIGTERM', () => void close());
  process.stdin.once('end', () => void close());
}

function createMinimalEnvironment(): Record<string, string> {
  return process.env.PATH === undefined ? {} : { PATH: process.env.PATH };
}

const isEntryPoint = process.argv[1] !== undefined
  && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isEntryPoint) {
  main().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`[apg] fatal: ${message}\n`);
    process.exitCode = 1;
  });
}
