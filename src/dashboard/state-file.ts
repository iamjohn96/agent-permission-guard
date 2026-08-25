import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { basename, dirname, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';

export type DashboardState = Readonly<{
  version: 1;
  url: string;
  pid: number;
  started_at: string;
}>;

export type DashboardStateFile = Readonly<{
  path: string;
  remove: () => void;
}>;

export function writeDashboardStateFile(
  path: string,
  url: string,
  pid: number = process.pid,
  startedAt: Date = new Date(),
): DashboardStateFile {
  if (path.trim().length === 0) throw new Error('Dashboard state path must not be empty');
  validateDashboardUrl(url);
  if (!Number.isSafeInteger(pid) || pid <= 0) throw new Error('Dashboard state PID must be a positive integer');

  const absolutePath = resolve(path);
  const parent = dirname(absolutePath);
  ensurePrivateDirectory(parent);

  const state: DashboardState = {
    version: 1,
    url,
    pid,
    started_at: startedAt.toISOString(),
  };
  const source = `${JSON.stringify(state, null, 2)}\n`;
  const temporaryPath = resolve(parent, `.${basename(absolutePath)}.${pid}.${randomUUID()}.tmp`);

  try {
    writeFileSync(temporaryPath, source, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    chmodSync(temporaryPath, 0o600);
    renameSync(temporaryPath, absolutePath);
    chmodSync(absolutePath, 0o600);
  } catch (error) {
    removeIfPresent(temporaryPath);
    throw new Error(`Could not write private dashboard state file: ${absolutePath}`, { cause: error });
  }

  return {
    path: absolutePath,
    remove: () => removeOwnedStateFile(absolutePath, state),
  };
}

function ensurePrivateDirectory(path: string): void {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  const status = lstatSync(path);
  if (!status.isDirectory() || status.isSymbolicLink()) {
    throw new Error(`Dashboard state parent must be a real directory: ${path}`);
  }
  if (process.platform !== 'win32' && (status.mode & 0o077) !== 0) {
    throw new Error(`Dashboard state parent must not allow group or other access: ${path}`);
  }
  chmodSync(path, 0o700);
}

function validateDashboardUrl(value: string): void {
  let url: URL;
  try {
    url = new URL(value);
  } catch (error) {
    throw new Error('Dashboard state URL must be valid', { cause: error });
  }
  const token = new URLSearchParams(url.hash.slice(1)).get('token');
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || token === null || token.length < 32) {
    throw new Error('Dashboard state URL must be a tokenized 127.0.0.1 HTTP URL');
  }
}

function removeOwnedStateFile(path: string, expected: DashboardState): void {
  try {
    const status = lstatSync(path);
    if (!status.isFile() || status.isSymbolicLink()) return;
    const current = JSON.parse(readFileSync(path, 'utf8')) as Partial<DashboardState>;
    if (current.version !== expected.version || current.url !== expected.url || current.pid !== expected.pid) return;
    unlinkSync(path);
  } catch (error) {
    if (!isMissingFileError(error)) {
      process.stderr.write(`[apg] could not remove dashboard state file: ${path}\n`);
    }
  }
}

function removeIfPresent(path: string): void {
  if (!existsSync(path)) return;
  try {
    unlinkSync(path);
  } catch {
    // Preserve the original write error. The randomly named file contains only this process's state.
  }
}

function isMissingFileError(error: unknown): boolean {
  return error instanceof Error && 'code' in error && error.code === 'ENOENT';
}
