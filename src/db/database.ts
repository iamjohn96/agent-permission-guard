import { chmodSync, lstatSync, mkdirSync, realpathSync } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { dirname, resolve } from 'node:path';

import BetterSqlite3, { type Database } from 'better-sqlite3';

import { migrateDatabase } from './migrate.js';
import { canonicalJson } from '../audit/canonical-json.js';

export type AuditDatabase = Database;

export function openAuditDatabase(path: string): AuditDatabase {
  if (path.trim().length === 0) throw new Error('Audit database path must not be empty');
  const isMemory = path === ':memory:';
  const databasePath = isMemory ? path : resolve(path);

  if (!isMemory) mkdirSync(dirname(databasePath), { recursive: true, mode: 0o700 });
  const database = new BetterSqlite3(databasePath);

  try {
    database.pragma('foreign_keys = ON');
    database.pragma('busy_timeout = 5000');
    if (!isMemory) database.pragma('journal_mode = WAL');
    migrateDatabase(database);
    if (!isMemory) chmodSync(databasePath, 0o600);
    return database;
  } catch (error) {
    database.close();
    throw error;
  }
}

export function openAuditDatabaseReadOnly(path: string): AuditDatabase {
  if (path.trim().length === 0 || path === ':memory:') {
    throw new Error('Read-only audit database path must identify an existing file');
  }
  const database = new BetterSqlite3(resolve(path), { readonly: true, fileMustExist: true });
  try {
    database.pragma('foreign_keys = ON');
    database.pragma('busy_timeout = 5000');
    database.pragma('query_only = ON');
    const tables = database.prepare(`
      SELECT name FROM sqlite_schema
      WHERE type = 'table' AND name IN ('tool_calls', 'audit_events')
    `).all() as Array<{ name: string }>;
    if (new Set(tables.map((table) => table.name)).size !== 2) {
      throw new Error('Audit database does not contain the required receipt source tables');
    }
    return database;
  } catch (error) {
    database.close();
    throw error;
  }
}

export type ExistingGraphGenesisAuditDatabase = Readonly<{
  database: AuditDatabase;
  canonicalPath: string;
  schemaDigest: string;
  fileIdentityDigest: string;
  databaseInstanceId: string;
  initialChainTail: string;
}>;

const existingGraphGenesisAuditDatabases = new WeakSet<object>();

export function authenticatesExistingGraphGenesisAuditDatabase(
  value: unknown,
): value is ExistingGraphGenesisAuditDatabase {
  return typeof value === 'object' && value !== null && existingGraphGenesisAuditDatabases.has(value);
}

/** Rechecks the path, schema, and chain tail captured when the production session source was opened. */
export function revalidatesExistingGraphGenesisAuditDatabase(
  source: ExistingGraphGenesisAuditDatabase,
): boolean {
  if (!authenticatesExistingGraphGenesisAuditDatabase(source)) return false;
  try {
    if (realpathSync(source.canonicalPath) !== source.canonicalPath) return false;
    const parent = lstatSync(dirname(source.canonicalPath));
    const file = lstatSync(source.canonicalPath);
    const currentUser = typeof process.geteuid === 'function' ? process.geteuid() : file.uid;
    if (!parent.isDirectory() || parent.isSymbolicLink() || parent.uid !== currentUser || (parent.mode & 0o077) !== 0
      || !file.isFile() || file.isSymbolicLink() || file.nlink !== 1 || file.uid !== currentUser
      || (file.mode & 0o777) !== 0o600) return false;
    const fileIdentityDigest = sha256(canonicalJson({
      device: file.dev, inode: file.ino, owner: file.uid, mode: file.mode & 0o7777,
    }));
    if (fileIdentityDigest !== source.fileIdentityDigest) return false;
    const migrations = source.database.prepare('SELECT version FROM schema_migrations ORDER BY version')
      .all() as Array<{ version: number }>;
    if (canonicalJson(migrations.map((row) => row.version)) !== '[1,2]') return false;
    const requiredTables = ['approvals', 'audit_events', 'schema_migrations', 'tool_calls'];
    const tables = source.database.prepare(`
      SELECT name, sql FROM sqlite_schema
      WHERE type = 'table' AND name IN ('approvals', 'audit_events', 'schema_migrations', 'tool_calls')
      ORDER BY name
    `).all() as Array<{ name: string; sql: string }>;
    if (canonicalJson(tables.map((row) => row.name)) !== canonicalJson(requiredTables)
      || sha256(canonicalJson({ migrations: [1, 2], tables })) !== source.schemaDigest) return false;
    const events = source.database.prepare(`
      SELECT event_json, previous_hash, event_hash FROM audit_events ORDER BY sequence
    `).all() as Array<{ event_json: string; previous_hash: string; event_hash: string }>;
    let tail = '0'.repeat(64);
    for (const event of events) {
      if (event.previous_hash !== tail || sha256(`${event.previous_hash}\n${event.event_json}`) !== event.event_hash) return false;
      tail = event.event_hash;
    }
    return tail === source.initialChainTail;
  } catch {
    return false;
  }
}

/** Opens an already-migrated private APG audit DB without creating or migrating it. */
export function openExistingGraphGenesisAuditDatabase(path: string): ExistingGraphGenesisAuditDatabase {
  if (path.trim().length === 0 || path === ':memory:') throw new Error('Graph Genesis audit DB must be an existing file');
  const requested = resolve(path);
  const canonicalPath = realpathSync(requested);
  if (canonicalPath !== requested) throw new Error('Graph Genesis audit DB path must be canonical');
  const parent = lstatSync(dirname(canonicalPath));
  const file = lstatSync(canonicalPath);
  const currentUser = typeof process.geteuid === 'function' ? process.geteuid() : file.uid;
  if (!parent.isDirectory() || parent.isSymbolicLink() || parent.uid !== currentUser || (parent.mode & 0o077) !== 0) {
    throw new Error('Graph Genesis audit DB parent must be private and current-user owned');
  }
  if (!file.isFile() || file.isSymbolicLink() || file.nlink !== 1 || file.uid !== currentUser || (file.mode & 0o777) !== 0o600) {
    throw new Error('Graph Genesis audit DB must be a private current-user regular file');
  }
  const database = new BetterSqlite3(canonicalPath, { fileMustExist: true });
  try {
    database.pragma('foreign_keys = ON');
    database.pragma('busy_timeout = 5000');
    const migrations = database.prepare('SELECT version FROM schema_migrations ORDER BY version').all() as Array<{ version: number }>;
    if (canonicalJson(migrations.map((row) => row.version)) !== '[1,2]') throw new Error('Unsupported audit database schema');
    const requiredTables = ['approvals', 'audit_events', 'schema_migrations', 'tool_calls'];
    const tables = database.prepare(`
      SELECT name, sql FROM sqlite_schema
      WHERE type = 'table' AND name IN ('approvals', 'audit_events', 'schema_migrations', 'tool_calls')
      ORDER BY name
    `).all() as Array<{ name: string; sql: string }>;
    if (canonicalJson(tables.map((row) => row.name)) !== canonicalJson(requiredTables)) {
      throw new Error('Audit database is missing the exact supported tables');
    }
    const events = database.prepare(`
      SELECT event_json, previous_hash, event_hash FROM audit_events ORDER BY sequence
    `).all() as Array<{ event_json: string; previous_hash: string; event_hash: string }>;
    let tail = '0'.repeat(64);
    for (const event of events) {
      if (event.previous_hash !== tail || sha256(`${event.previous_hash}\n${event.event_json}`) !== event.event_hash) {
        throw new Error('Audit database hash chain verification failed');
      }
      tail = event.event_hash;
    }
    const schemaDigest = sha256(canonicalJson({ migrations: [1, 2], tables }));
    const fileIdentityDigest = sha256(canonicalJson({
      device: file.dev, inode: file.ino, owner: file.uid, mode: file.mode & 0o7777,
    }));
    const opened = Object.freeze({
      database,
      canonicalPath,
      schemaDigest,
      fileIdentityDigest,
      databaseInstanceId: randomUUID(),
      initialChainTail: tail,
    });
    existingGraphGenesisAuditDatabases.add(opened);
    return opened;
  } catch (error) {
    database.close();
    throw error;
  }
}

function sha256(value: string): string { return createHash('sha256').update(value).digest('hex'); }
