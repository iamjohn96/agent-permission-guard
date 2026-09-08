import { constants } from 'node:fs';
import { lstat, mkdir, mkdtemp, open, readdir, realpath, rmdir, unlink } from 'node:fs/promises';
import { join } from 'node:path';

const owned = new WeakSet<object>();
type Identity = Readonly<{ dev: number; ino: number; mode: number; uid: number }>;

/** Internal disposable-root capability; never accepts a caller-selected parent. */
export class PreflightRoot {
  #closed = false;
  private constructor(readonly path: string, private readonly identity: Identity) { owned.add(this); Object.freeze(this); }

  static async create(): Promise<PreflightRoot> {
    const parent = await realpath('/private/tmp');
    if (parent !== '/private/tmp') throw new Error('preflight_root_invalid');
    const path = await mkdtemp(join(parent, 'apg-genesis-preflight-'));
    const info = await lstat(path);
    if ((info.mode & 0o777) !== 0o700 || !info.isDirectory()) throw new Error('preflight_root_invalid');
    return new PreflightRoot(path, info);
  }

  static authenticates(value: unknown): value is PreflightRoot {
    return typeof value === 'object' && value !== null && owned.has(value) && !(value as PreflightRoot).#closed;
  }

  async revalidate(): Promise<void> {
    if (!PreflightRoot.authenticates(this)) throw new Error('preflight_root_invalid');
    assertIdentity(await lstat(this.path), this.identity);
  }

  async createAuditDirectory(): Promise<string> {
    await this.revalidate();
    if ((await readdir(this.path)).some((name) => name !== 'workspace' && name !== 'audit')) throw new Error('preflight_cleanup_ambiguous');
    const path = join(this.path, 'audit');
    await mkdir(path, { mode: 0o700 });
    return path;
  }

  /** No recursive deletion. Capture the complete bounded inventory, then recheck each entry and ancestor. */
  async cleanup(): Promise<number> {
    await this.revalidate();
    if ((await readdir(this.path)).some((name) => name !== 'workspace' && name !== 'audit')) throw new Error('preflight_cleanup_ambiguous');
    const entries: Array<{ path: string; identity: Identity; directory: boolean; ancestors: Array<{ path: string; identity: Identity }> }> = [];
    const visit = async (path: string, ancestors: Array<{ path: string; identity: Identity }>, depth: number): Promise<void> => {
      if (depth > 8 || entries.length > 256) throw new Error('preflight_cleanup_ambiguous');
      const info = await lstat(path);
      if (info.isSymbolicLink() || (!info.isDirectory() && !info.isFile())
        || info.uid !== this.identity.uid || (info.mode & 0o077) !== 0
        || info.isFile() && (info.nlink !== 1 || info.size > 8 * 1024 * 1024)) throw new Error('preflight_cleanup_ambiguous');
      const entry = { path, identity: info, directory: info.isDirectory(), ancestors };
      if (info.isDirectory()) {
        for (const name of await readdir(path)) await visit(join(path, name), [...ancestors, { path, identity: info }], depth + 1);
      }
      entries.push(entry);
    };
    await visit(this.path, [], 0);
    for (const entry of entries) {
      for (const ancestor of entry.ancestors) assertIdentity(await lstat(ancestor.path), ancestor.identity);
      assertIdentity(await lstat(entry.path), entry.identity);
      if (entry.directory) await rmdir(entry.path);
      else {
        const file = await open(entry.path, constants.O_RDONLY | constants.O_NOFOLLOW);
        try { assertIdentity(await file.stat(), entry.identity); } finally { await file.close(); }
        await unlink(entry.path);
      }
    }
    this.#closed = true;
    return entries.length;
  }
}

function assertIdentity(actual: Identity & { isSymbolicLink(): boolean }, expected: Identity): void {
  if (actual.isSymbolicLink() || actual.dev !== expected.dev || actual.ino !== expected.ino
    || actual.mode !== expected.mode || actual.uid !== expected.uid) throw new Error('preflight_cleanup_ambiguous');
}
