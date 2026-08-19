import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type Database from 'better-sqlite3';

const MIGRATIONS = [
  { version: 1, file: '001_initial.sql' },
  { version: 2, file: '002_approvals.sql' },
] as const;

export function migrateDatabase(database: Database.Database): void {
  database.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      applied_at TEXT NOT NULL
    )
  `);

  const apply = database.transaction((version: number, sql: string) => {
    database.exec(sql);
    database.prepare('INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)')
      .run(version, new Date().toISOString());
  });

  for (const migration of MIGRATIONS) {
    const applied = database.prepare('SELECT 1 FROM schema_migrations WHERE version = ?')
      .get(migration.version);
    if (applied !== undefined) continue;
    apply(migration.version, readMigration(migration.file));
  }
  database.pragma('optimize');
}

function readMigration(fileName: string): string {
  let directory = dirname(fileURLToPath(import.meta.url));
  for (let level = 0; level < 5; level += 1) {
    const candidate = join(directory, 'migrations', fileName);
    if (existsSync(candidate)) return readFileSync(candidate, 'utf8');
    directory = dirname(directory);
  }
  throw new Error(`Required database migration is missing: ${fileName}`);
}
