import {
  FetchNpmRegistryTransport,
  NpmRegistryMetadataProvider,
  type NpmRegistryTransport,
} from '../install/npm-registry.js';
import { parseInstallRequest } from '../install/parser.js';
import { evaluateInstallPolicy } from '../install/policy.js';
import { validateInstallResolution } from '../install/service.js';
import type { InstallRunner } from '../install/types.js';

const DEFAULT_REGISTRY = 'https://registry.npmjs.org/';

export type InspectArguments = Readonly<{
  runner: InstallRunner;
  packageSpec: string;
  registry: string;
  workingDirectory: string;
}>;

type TextOutput = Readonly<{ write(text: string): unknown }>;

export function parseInspectArguments(
  argv: readonly string[],
  workingDirectory: string = process.cwd(),
): InspectArguments {
  const runner = argv[0];
  const packageSpec = argv[1];
  if (runner !== 'npm' && runner !== 'npx') throw inspectUsageError();
  if (packageSpec === undefined) throw inspectUsageError();

  let registry = DEFAULT_REGISTRY;
  if (argv.length === 4 && argv[2] === '--registry' && argv[3]?.trim()) {
    registry = argv[3];
  } else if (argv.length !== 2) {
    throw inspectUsageError();
  }

  return { runner, packageSpec, registry, workingDirectory };
}

export async function runInspect(
  arguments_: InspectArguments,
  dependencies: Readonly<{
    transport?: NpmRegistryTransport;
    output?: TextOutput;
  }> = {},
): Promise<void> {
  const request = parseInstallRequest(
    arguments_.runner,
    [arguments_.packageSpec],
    arguments_.workingDirectory,
  );
  const provider = new NpmRegistryMetadataProvider({
    registry: arguments_.registry,
    transport: dependencies.transport ?? new FetchNpmRegistryTransport(),
  });
  const resolution = validateInstallResolution(request, await provider.resolve(request));
  const evaluation = evaluateInstallPolicy(resolution);
  const output = dependencies.output ?? process.stdout;
  const resolved = resolution.status === 'resolved' ? resolution.metadata : undefined;

  output.write([
    'Install Guard inspection',
    `Package: ${request.packageName}@${request.requestedSpecifier}`,
    `Resolved version: ${resolved?.version ?? 'not resolved'}`,
    `Install lifecycle script: ${resolved === undefined ? 'unknown' : resolved.lifecycleScripts.length > 0 ? 'present' : 'not declared'}`,
    `Decision: ${evaluation.effectiveDecision.toUpperCase()}`,
    `Risk: ${evaluation.risk.score} (${evaluation.risk.band})`,
    `Reasons: ${evaluation.reasonCodes.join(', ')}`,
    'Result: inspection only; no package was downloaded or installed.',
    '',
  ].join('\n'));
}

function inspectUsageError(): Error {
  return new Error('Usage: apg inspect <npm|npx> <package-spec> [--registry <https-url>]');
}
