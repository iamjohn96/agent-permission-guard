import { chmodSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

import BetterSqlite3, { type Database } from 'better-sqlite3';

import { migrateDatabase } from './migrate.js';

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
