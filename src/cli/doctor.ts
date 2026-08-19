import { accessSync, constants, existsSync, readFileSync, statSync } from 'node:fs';
import { createServer } from 'node:net';
import { delimiter, dirname, isAbsolute, resolve } from 'node:path';

import { parsePolicyYaml } from '../policy/loader.js';

export type DoctorArguments = Readonly<{
  policyPath: string;
  auditDbPath: string;
  dashboardPort: number;
  command?: string;
}>;

export type DoctorCheck = Readonly<{
  name: string;
  status: 'pass' | 'fail' | 'skip';
  detail: string;
}>;

export function parseDoctorArguments(argv: readonly string[]): DoctorArguments {
  let policyPath = '.apg/policy.yaml';
  let auditDbPath = '.apg/audit.sqlite';
  let dashboardPort = 47_831;
  let command: string | undefined;
  let index = 0;

  while (index < argv.length && argv[index] !== '--') {
    const option = argv[index];
    const value = argv[index + 1];
    if (value === undefined || value === '--') throw doctorUsageError();
    if (option === '--policy') policyPath = value;
    else if (option === '--audit-db') auditDbPath = value;
    else if (option === '--dashboard-port') dashboardPort = parseDoctorPort(value);
    else throw doctorUsageError();
    index += 2;
  }

  if (argv[index] === '--') {
    command = argv[index + 1];
    if (command === undefined) throw doctorUsageError();
  }

  return command === undefined
    ? { policyPath, auditDbPath, dashboardPort }
    : { policyPath, auditDbPath, dashboardPort, command };
}

export async function collectDoctorChecks(
  arguments_: DoctorArguments,
  environment: NodeJS.ProcessEnv = process.env,
): Promise<DoctorCheck[]> {
  const checks: DoctorCheck[] = [];
  checks.push(checkNodeVersion());
  checks.push(checkPolicy(arguments_.policyPath));
  checks.push(checkAuditPath(arguments_.auditDbPath));
  checks.push(await checkDashboardPort(arguments_.dashboardPort));
  checks.push(checkCommand(arguments_.command, environment.PATH));
  return checks;
}

export async function runDoctor(arguments_: DoctorArguments): Promise<boolean> {
  const checks = await collectDoctorChecks(arguments_);
  for (const check of checks) {
    const marker = check.status === 'pass' ? 'PASS' : check.status === 'fail' ? 'FAIL' : 'SKIP';
    process.stdout.write(`[${marker}] ${check.name}: ${check.detail}\n`);
  }
  const healthy = checks.every((check) => check.status !== 'fail');
  process.stdout.write(healthy ? '[apg] doctor passed\n' : '[apg] doctor found problems\n');
  return healthy;
}

function checkNodeVersion(): DoctorCheck {
  const major = Number(process.versions.node.split('.')[0]);
  const supported = Number.isInteger(major) && major >= 24 && major < 27;
  return {
    name: 'Node.js',
    status: supported ? 'pass' : 'fail',
    detail: supported
      ? `${process.versions.node} is supported`
      : `${process.versions.node} is unsupported; use Node.js 24-26`,
  };
}

function checkPolicy(path: string): DoctorCheck {
  const absolutePath = resolve(path);
  try {
    const policy = parsePolicyYaml(readFileSync(absolutePath, 'utf8'));
    return {
      name: 'Policy',
      status: 'pass',
      detail: `${absolutePath} is valid (version ${policy.version}, ${policy.rules.length} rules)`,
    };
  } catch (error) {
    return { name: 'Policy', status: 'fail', detail: errorMessage(error, absolutePath) };
  }
}

function checkAuditPath(path: string): DoctorCheck {
  const absolutePath = resolve(path);
  try {
    if (existsSync(absolutePath)) {
      if (!statSync(absolutePath).isFile()) throw new Error(`${absolutePath} is not a file`);
      accessSync(absolutePath, constants.R_OK | constants.W_OK);
      return { name: 'Audit database', status: 'pass', detail: `${absolutePath} is readable and writable` };
    }
    const parent = dirname(absolutePath);
    accessSync(parent, constants.W_OK);
    return { name: 'Audit database', status: 'pass', detail: `${absolutePath} can be created` };
  } catch (error) {
    return { name: 'Audit database', status: 'fail', detail: errorMessage(error, absolutePath) };
  }
}

async function checkDashboardPort(port: number): Promise<DoctorCheck> {
  return await new Promise((resolveCheck) => {
    const server = createServer();
    server.unref();
    server.once('error', (error) => {
      resolveCheck({ name: 'Dashboard port', status: 'fail', detail: error.message });
    });
    server.listen(port, '127.0.0.1', () => {
      const address = server.address();
      const selectedPort = typeof address === 'object' && address !== null ? address.port : port;
      server.close(() => {
        resolveCheck({
          name: 'Dashboard port',
          status: 'pass',
          detail: `127.0.0.1:${selectedPort} is available`,
        });
      });
    });
  });
}

function checkCommand(command: string | undefined, path: string | undefined): DoctorCheck {
  if (command === undefined) {
    return {
      name: 'Upstream command',
      status: 'skip',
      detail: 'not provided; pass -- <command> to check it without executing it',
    };
  }

  const executable = findExecutable(command, path);
  return executable === undefined
    ? { name: 'Upstream command', status: 'fail', detail: `${command} was not found or is not executable` }
    : { name: 'Upstream command', status: 'pass', detail: `${executable} is executable (not run)` };
}

function findExecutable(command: string, path: string | undefined): string | undefined {
  const candidates = command.includes('/') || isAbsolute(command)
    ? [resolve(command)]
    : (path ?? '').split(delimiter).filter(Boolean).map((directory) => resolve(directory, command));

  return candidates.find((candidate) => {
    try {
      accessSync(candidate, constants.X_OK);
      return statSync(candidate).isFile();
    } catch {
      return false;
    }
  });
}

function parseDoctorPort(value: string): number {
  const port = Number(value);
  if (!Number.isSafeInteger(port) || port < 0 || port > 65_535) throw doctorUsageError();
  return port;
}

function doctorUsageError(): Error {
  return new Error('Usage: apg doctor [--policy <policy.yaml>] [--audit-db <audit.sqlite>] [--dashboard-port <port>] [-- <upstream-command> [args...]]');
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}
