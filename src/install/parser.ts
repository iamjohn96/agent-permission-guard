import { isAbsolute } from 'node:path';

import type { InstallRequest, InstallRunner } from './types.js';

const NPM_OPTIONS = new Set(['--save-dev', '--save-exact', '--ignore-scripts']);
const NPX_OPTIONS = new Set(['--yes']);
const UNSAFE_TOKEN = /[;&|`$<>\n\r\0]/;
const PACKAGE_NAME = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
const SPECIFIER = /^[a-zA-Z0-9*^~<>=|.+-]+$/;

export class InstallParseError extends Error {}

export function parseInstallRequest(
  runner: InstallRunner,
  argv: readonly string[],
  workingDirectory: string,
): InstallRequest {
  if (!isAbsolute(workingDirectory)) {
    throw new InstallParseError('Install working directory must be an absolute path');
  }

  const supportedOptions = runner === 'npm' ? NPM_OPTIONS : NPX_OPTIONS;
  const options: string[] = [];
  const targets: string[] = [];

  for (const token of argv) {
    if (token.length === 0 || UNSAFE_TOKEN.test(token)) {
      throw new InstallParseError('Install arguments contain an unsafe token');
    }
    if (token === '--' || token.startsWith('-')) {
      if (!supportedOptions.has(token)) {
        throw new InstallParseError(`Unsupported ${runner} option: ${token}`);
      }
      if (!options.includes(token)) options.push(token);
      continue;
    }
    targets.push(token);
  }

  if (targets.length !== 1) {
    throw new InstallParseError('Install Guard v0 requires exactly one package target');
  }

  const target = targets[0];
  if (target === undefined) {
    throw new InstallParseError('Install Guard v0 requires exactly one package target');
  }
  const parsed = parseRegistryPackageSpec(target);

  return {
    runner,
    packageName: parsed.packageName,
    requestedSpecifier: parsed.requestedSpecifier,
    options: options.sort(),
    workingDirectory,
  };
}

function parseRegistryPackageSpec(target: string): Readonly<{
  packageName: string;
  requestedSpecifier: string;
}> {
  if (target.length > 343 || (target.includes('/') && !target.startsWith('@'))) {
    throw new InstallParseError('Only npm registry package names are supported');
  }
  if (/^(?:file|git|https?|github):/i.test(target) || target.startsWith('.') || target.startsWith('/')) {
    throw new InstallParseError('Local paths, URLs, and git sources are not supported');
  }

  const separator = target.startsWith('@')
    ? target.lastIndexOf('@')
    : target.indexOf('@');
  const hasSpecifier = target.startsWith('@')
    ? separator > target.indexOf('/')
    : separator > 0;
  const packageName = hasSpecifier ? target.slice(0, separator) : target;
  const requestedSpecifier = hasSpecifier ? target.slice(separator + 1) : 'latest';

  if (packageName.length > 214 || !PACKAGE_NAME.test(packageName)) {
    throw new InstallParseError(`Invalid npm package name: ${packageName}`);
  }
  if (requestedSpecifier.length === 0 || requestedSpecifier.length > 128 || !SPECIFIER.test(requestedSpecifier)) {
    throw new InstallParseError('Invalid npm package version or tag');
  }

  return { packageName, requestedSpecifier };
}
