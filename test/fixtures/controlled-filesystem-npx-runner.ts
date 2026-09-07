import { spawn } from 'node:child_process';
import { existsSync, realpathSync, statSync } from 'node:fs';
import { isAbsolute, join, relative, sep } from 'node:path';

const PINNED_PACKAGE = '@modelcontextprotocol/server-filesystem@2026.7.10';

const [workspaceRootArgument, npxExecutableArgument, packageArgument, allowedDirectoryArgument] =
  process.argv.slice(2);

if (
  workspaceRootArgument === undefined
  || npxExecutableArgument === undefined
  || packageArgument === undefined
  || allowedDirectoryArgument === undefined
  || process.argv.length !== 6
) {
  fail('Controlled Filesystem runner received an invalid invocation');
}

if (packageArgument !== PINNED_PACKAGE) {
  fail('Controlled Filesystem runner rejected an unpinned package');
}
if (!isAbsolute(npxExecutableArgument)) {
  fail('Controlled Filesystem runner requires an absolute npx executable path');
}

const workspaceRoot = existingPrivateDirectory(workspaceRootArgument, 'workspace');
const npxExecutable = existingRealPath(npxExecutableArgument, 'npx executable');
if (!statSync(npxExecutable).isFile()) fail('Controlled Filesystem runner requires a regular npx executable');
const allowedDirectory = existingPrivateDirectory(allowedDirectoryArgument, 'allowed directory');
assertWithin(workspaceRoot, allowedDirectory, 'allowed directory');

const home = existingPrivateChild(workspaceRoot, 'home', 'directory');
const cache = existingPrivateChild(workspaceRoot, 'npm-cache', 'directory');
const temporaryDirectory = existingPrivateChild(workspaceRoot, 'tmp', 'directory');
const prefix = existingPrivateChild(workspaceRoot, 'npm-prefix', 'directory');
const userConfig = existingPrivateChild(workspaceRoot, 'empty-user.npmrc', 'file');
const globalConfig = existingPrivateChild(workspaceRoot, 'empty-global.npmrc', 'file');

const environment: NodeJS.ProcessEnv = {
  PATH: process.env.PATH ?? '',
  HOME: home,
  TMPDIR: temporaryDirectory,
  npm_config_userconfig: userConfig,
  npm_config_globalconfig: globalConfig,
  npm_config_cache: cache,
  npm_config_prefix: prefix,
  npm_config_registry: 'https://registry.npmjs.org/',
  npm_config_ignore_scripts: 'true',
  npm_config_audit: 'false',
  npm_config_fund: 'false',
  npm_config_update_notifier: 'false',
  npm_config_yes: 'true',
};

const child = spawn(npxExecutable, ['--yes', PINNED_PACKAGE, allowedDirectory], {
  cwd: workspaceRoot,
  env: environment,
  shell: false,
  stdio: 'inherit',
});

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => {
    child.kill(signal);
  });
}

child.once('error', () => {
  fail('Controlled Filesystem runner could not start npx');
});
child.once('exit', (code, signal) => {
  if (signal !== null) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 1);
});

function existingRealPath(path: string, label: string): string {
  if (!isAbsolute(path) || !existsSync(path)) fail(`Controlled Filesystem runner requires an existing ${label}`);
  return realpathSync(path);
}

function existingPrivateChild(workspaceRoot: string, name: string, kind: 'directory' | 'file'): string {
  const path = kind === 'directory'
    ? existingPrivateDirectory(join(workspaceRoot, name), name)
    : existingPrivateFile(join(workspaceRoot, name), name);
  assertWithin(workspaceRoot, path, name);
  return path;
}

function existingPrivateDirectory(path: string, label: string): string {
  const resolved = existingRealPath(path, label);
  const stats = statSync(resolved);
  if (!stats.isDirectory() || (stats.mode & 0o077) !== 0) {
    fail(`Controlled Filesystem runner requires a private ${label} directory`);
  }
  return resolved;
}

function existingPrivateFile(path: string, label: string): string {
  const resolved = existingRealPath(path, label);
  const stats = statSync(resolved);
  if (!stats.isFile() || (stats.mode & 0o077) !== 0) {
    fail(`Controlled Filesystem runner requires a private ${label} file`);
  }
  return resolved;
}

function assertWithin(parent: string, candidate: string, label: string): void {
  const pathFromParent = relative(parent, candidate);
  if (pathFromParent === '' || pathFromParent === '..' || pathFromParent.startsWith(`..${sep}`) || isAbsolute(pathFromParent)) {
    fail(`Controlled Filesystem runner rejected the ${label} boundary`);
  }
}

function fail(message: string): never {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
