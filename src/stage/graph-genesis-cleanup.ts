import { createHash } from 'node:crypto';
import { lstat, opendir, rmdir, unlink } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';

import { canonicalJson } from '../audit/canonical-json.js';
import type { GraphGenesisWorkspace } from './graph-genesis.js';
import type {
  AuthenticatedHardenedGraphGenesisPostState,
  HardenedGraphGenesisPostStateAuthority,
} from './graph-genesis-workspace.js';
import { computeWorkspaceBinding } from './graph-genesis-hardening.js';
import { PackageStageError } from './profile.js';

type CleanupEntry = Readonly<{
  relativePath: string;
  type: 'file' | 'directory';
  device: number;
  inode: number;
  mode: number;
  size: number;
}>;

export type AuthenticatedGraphGenesisCleanupInventory = Readonly<{
  inventoryVersion: 1;
  planHash: string;
  workspaceBinding: string;
  postStateDigest: string;
  entries: readonly CleanupEntry[];
  inventoryDigest: string;
}>;

export type AuthenticatedPostStateCleanup = Readonly<{
  cleanupVersion: 2;
  planHash: string;
  inventoryDigest: string;
  removedEntryCount: number;
  status: 'complete';
  cleanupDigest: string;
}>;

export class PostStateBoundGraphGenesisCleanupAuthority {
  readonly #inventories = new WeakSet<object>();
  readonly #cleanups = new WeakSet<object>();

  constructor(private readonly postStates: HardenedGraphGenesisPostStateAuthority) {}

  async capture(
    workspace: GraphGenesisWorkspace,
    postState: AuthenticatedHardenedGraphGenesisPostState,
  ): Promise<AuthenticatedGraphGenesisCleanupInventory> {
    if (!this.postStates.authenticates(postState)
      || postState.workspaceBinding !== computeWorkspaceBinding(workspace)) fail();
    const root = await lstat(workspace.rootRealpath);
    if (!root.isDirectory() || root.isSymbolicLink() || root.dev !== workspace.device || root.ino !== workspace.inode
      || root.uid !== workspace.owner || (root.mode & 0o777) !== 0o700) fail();
    const entries = await inspect(workspace.rootRealpath);
    const unsigned = deepFreeze({
      inventoryVersion: 1 as const,
      planHash: postState.planHash,
      workspaceBinding: postState.workspaceBinding,
      postStateDigest: postState.evidenceDigest,
      entries,
    });
    const inventory = deepFreeze({ ...unsigned, inventoryDigest: sha256(canonicalJson(unsigned)) });
    this.#inventories.add(inventory);
    return inventory;
  }

  async cleanup(
    workspace: GraphGenesisWorkspace,
    inventory: AuthenticatedGraphGenesisCleanupInventory,
  ): Promise<AuthenticatedPostStateCleanup> {
    if (!this.#inventories.has(inventory)) fail();
    const current = await inspect(workspace.rootRealpath);
    if (canonicalJson(current) !== canonicalJson(inventory.entries)) fail();
    const files = inventory.entries.filter((entry) => entry.type === 'file');
    const directories = inventory.entries.filter((entry) => entry.type === 'directory')
      .sort((left, right) => right.relativePath.split('/').length - left.relativePath.split('/').length);
    for (const entry of files) {
      await assertIdentity(join(workspace.rootRealpath, entry.relativePath), entry);
      await unlink(join(workspace.rootRealpath, entry.relativePath));
    }
    for (const entry of directories) {
      await assertIdentity(join(workspace.rootRealpath, entry.relativePath), entry);
      await rmdir(join(workspace.rootRealpath, entry.relativePath));
    }
    const root = await lstat(workspace.rootRealpath);
    if (root.dev !== workspace.device || root.ino !== workspace.inode) fail();
    await rmdir(workspace.rootRealpath);
    const unsigned = Object.freeze({
      cleanupVersion: 2 as const,
      planHash: inventory.planHash,
      inventoryDigest: inventory.inventoryDigest,
      removedEntryCount: inventory.entries.length + 1,
      status: 'complete' as const,
    });
    const result = Object.freeze({ ...unsigned, cleanupDigest: sha256(canonicalJson(unsigned)) });
    this.#cleanups.add(result);
    return result;
  }

  authenticates(value: unknown): value is AuthenticatedPostStateCleanup {
    return typeof value === 'object' && value !== null && this.#cleanups.has(value);
  }
}

async function inspect(root: string): Promise<readonly CleanupEntry[]> {
  const entries: CleanupEntry[] = [];
  const visit = async (directory: string): Promise<void> => {
    const handle = await opendir(directory);
    const names: string[] = [];
    for await (const item of handle) names.push(item.name);
    names.sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
    for (const name of names) {
      const path = join(directory, name);
      const rel = relative(root, path).split(sep).join('/');
      const info = await lstat(path);
      if (rel.startsWith('../') || rel === '..' || info.isSymbolicLink()
        || (!info.isFile() && !info.isDirectory()) || (info.isFile() && info.nlink !== 1)
        || (info.mode & 0o002) !== 0 || ++entries.length > 100_000) fail();
      const entry = Object.freeze({
        relativePath: rel,
        type: info.isDirectory() ? 'directory' as const : 'file' as const,
        device: info.dev,
        inode: info.ino,
        mode: info.mode & 0o7777,
        size: info.size,
      });
      entries[entries.length - 1] = entry;
      if (info.isDirectory()) await visit(path);
    }
  };
  await visit(root);
  return Object.freeze(entries);
}

async function assertIdentity(path: string, expected: CleanupEntry): Promise<void> {
  const info = await lstat(path);
  if (info.dev !== expected.device || info.ino !== expected.inode || (info.mode & 0o7777) !== expected.mode
    || (expected.type === 'file' && info.size !== expected.size) || info.isDirectory() !== (expected.type === 'directory')
    || info.isSymbolicLink() || (info.isFile() && info.nlink !== 1)) fail();
}

function sha256(value: string): string { return createHash('sha256').update(value).digest('hex'); }

function deepFreeze<T>(input: T): T {
  if (typeof input !== 'object' || input === null || Object.isFrozen(input)) return input;
  for (const value of Object.values(input)) deepFreeze(value);
  return Object.freeze(input);
}

function fail(): never { throw new PackageStageError('artifact_cleanup_incomplete'); }
