import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export type InitArguments = Readonly<{
  directory: string;
}>;

export function parseInitArguments(argv: readonly string[]): InitArguments {
  let directory = '.apg';

  if (argv.length === 0) return { directory };
  if (argv.length === 2 && argv[0] === '--directory' && argv[1]?.trim()) {
    directory = argv[1];
    return { directory };
  }

  throw new Error('Usage: apg init [--directory <path>]');
}

export function runInit(arguments_: InitArguments): void {
  const directory = resolve(arguments_.directory);
  const policyPath = resolve(directory, 'policy.yaml');
  const auditDbPath = resolve(directory, 'audit.sqlite');
  const moduleDirectory = dirname(fileURLToPath(import.meta.url));
  const examplePolicyPath = [
    resolve(moduleDirectory, '../../apg.example.yaml'),
    resolve(moduleDirectory, '../../../apg.example.yaml'),
  ].find((candidate) => existsSync(candidate));
  if (examplePolicyPath === undefined) {
    throw new Error('Packaged starter policy apg.example.yaml was not found');
  }

  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const policy = readFileSync(examplePolicyPath, 'utf8');

  try {
    writeFileSync(policyPath, policy, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
  } catch (error) {
    if (isAlreadyExistsError(error)) {
      throw new Error(`Refusing to overwrite existing policy: ${policyPath}`);
    }
    throw error;
  }

  process.stdout.write([
    `[apg] initialized ${directory}`,
    `[apg] policy: ${policyPath}`,
    `[apg] audit database: ${auditDbPath} (created on first proxy start)`,
    `[apg] next: apg doctor --policy ${quoteForDisplay(policyPath)} --audit-db ${quoteForDisplay(auditDbPath)}`,
    '',
  ].join('\n'));
}

function isAlreadyExistsError(error: unknown): boolean {
  return error instanceof Error && 'code' in error && error.code === 'EEXIST';
}

function quoteForDisplay(value: string): string {
  return JSON.stringify(value);
}
