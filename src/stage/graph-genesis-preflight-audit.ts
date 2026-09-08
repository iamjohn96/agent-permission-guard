import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import BetterSqlite3 from 'better-sqlite3';

import { canonicalJson } from '../audit/canonical-json.js';
import { PreflightRoot } from './graph-genesis-preflight-root.js';

const ZERO = '0'.repeat(64);
const HASH = /^[a-f0-9]{64}$/u;
const EVENTS = ['plan_captured', 'audit_checked', 'session_closing'] as const;
type Event = typeof EVENTS[number];
type Row = { event_json: string; event_type: string; previous_hash: string; event_hash: string; tool_call_id: string };
export type PreflightAuditResult = Readonly<{ status: 'passed'; eventCount: number; chainDigest: string; reopened: true }>;

/** No product path, injected sink, general payload or execution authorization API. */
export class PreflightSqliteAudit {
  #database: BetterSqlite3.Database | undefined;
  #records: Row[] = [];
  #terminal = false;
  #failed = false;
  readonly #id = randomUUID();
  #identity: Awaited<ReturnType<typeof lstat>> | undefined;
  #directoryIdentity: Awaited<ReturnType<typeof lstat>> | undefined;
  #schemaDigest: string | undefined;

  private constructor(
    private readonly root: PreflightRoot,
    private readonly path: string,
    private readonly planHash: string,
    private readonly runtimeDigest: string,
    private readonly nativeBinding: string,
  ) {}

  static async create(root: PreflightRoot, planHash: string, runtimeDigest: string): Promise<PreflightSqliteAudit> {
    if (!PreflightRoot.authenticates(root) || !HASH.test(planHash) || !HASH.test(runtimeDigest)) fail();
    const directory = await root.createAuditDirectory();
    const path = join(directory, 'preflight.sqlite');
    const file = await open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    await file.close();
    const instance = new PreflightSqliteAudit(root, path, planHash, runtimeDigest, sqliteNativePath());
    try {
      instance.#identity = await lstat(path);
      instance.#directoryIdentity = await lstat(directory);
      const database = new BetterSqlite3(path, { nativeBinding: instance.nativeBinding, fileMustExist: true, timeout: 1000 });
      instance.#database = database;
      database.pragma('foreign_keys = ON');
      database.pragma('journal_mode = WAL');
      database.pragma('synchronous = FULL');
      if (database.pragma('synchronous', { simple: true }) !== 2) fail();
      const schemaRoot = repositoryRoot();
      const schemas = await Promise.all(['001_initial.sql', '002_approvals.sql'].map((name) => readFile(join(schemaRoot, 'migrations', name), 'utf8')));
      database.transaction(() => {
        database.exec('CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)');
        for (let i = 0; i < schemas.length; i += 1) {
          database.exec(schemas[i]!);
          database.prepare('INSERT INTO schema_migrations VALUES (?, ?)').run(i + 1, new Date().toISOString());
        }
        database.prepare(`INSERT INTO tool_calls (id, server_id, tool_name, arguments_json, request_hash,
          base_decision, effective_decision, reason_codes_json, risk_score, risk_band, risk_signals_json, status, started_at)
          VALUES (?, 'apg.graph-genesis', 'metadata_graph_genesis_preflight', '{}', ?, 'ask', 'ask',
          '["preflight_only_risk_not_evaluated"]', 0, 'low', '[]', 'preflight_only', ?)`)
          .run(instance.#id, planHash, new Date().toISOString());
      }).immediate();
      instance.#schemaDigest = schemaDigest(database);
      return instance;
    } catch { instance.close(); fail(); }
  }

  /** Synchronous transactions serialize appenders; only three exact events, with no caller payload. */
  append(event: Event): void {
    try {
      if (this.#terminal || this.#failed || this.#database === undefined || EVENTS[this.#records.length] !== event) fail();
      const eventType = `graph_genesis.preflight.${event}`;
      const eventId = randomUUID();
      const createdAt = new Date().toISOString();
      const eventJson = canonicalJson({ eventId, toolCallId: this.#id, eventType,
        details: { planHash: this.planHash, runtimeDigest: this.runtimeDigest }, createdAt });
      if (Buffer.byteLength(eventJson) > 4096 || this.#records.length >= 64
        || this.#records.reduce((sum, row) => sum + Buffer.byteLength(row.event_json), 0) + Buffer.byteLength(eventJson) > 256 * 1024) fail();
      const database = this.#database;
      const row = database.transaction(() => {
        const previous = database.prepare('SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1').get() as { event_hash: string } | undefined;
        const previousHash = previous?.event_hash ?? ZERO;
        if (previousHash !== (this.#records.at(-1)?.event_hash ?? ZERO)) fail();
        const eventHash = hash(`${previousHash}\n${eventJson}`);
        database.prepare(`INSERT INTO audit_events (event_id, tool_call_id, event_type, event_json, previous_hash, event_hash, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?)`).run(eventId, this.#id, eventType, eventJson, previousHash, eventHash, createdAt);
        return { event_json: eventJson, event_type: eventType, previous_hash: previousHash, event_hash: eventHash, tool_call_id: this.#id };
      }).immediate();
      this.#records.push(row);
      if (event === 'session_closing') this.#terminal = true;
    } catch { this.#failed = true; fail(); }
  }

  async verifyReopened(): Promise<PreflightAuditResult> {
    try {
      if (this.#failed || !this.#terminal || this.#records.length !== EVENTS.length) fail();
      this.close();
      await this.root.revalidate();
      const directory = await lstat(dirname(this.path));
      if (!directory.isDirectory() || directory.isSymbolicLink() || (directory.mode & 0o777) !== 0o700
        || directory.dev !== this.#directoryIdentity?.dev || directory.ino !== this.#directoryIdentity?.ino) fail();
      const info = await lstat(this.path);
      if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || (info.mode & 0o777) !== 0o600
        || info.dev !== this.#identity?.dev || info.ino !== this.#identity?.ino) fail();
      const database = new BetterSqlite3(this.path, { readonly: true, fileMustExist: true, nativeBinding: this.nativeBinding, timeout: 1000 });
      try {
        database.pragma('query_only = ON');
        if (schemaDigest(database) !== this.#schemaDigest) fail();
        const versions = database.prepare('SELECT version FROM schema_migrations ORDER BY version').all();
        if (canonicalJson(versions) !== '[{"version":1},{"version":2}]') fail();
        if ((database.prepare('SELECT COUNT(*) AS count FROM approvals').get() as { count: number }).count !== 0) fail();
        const parents = database.prepare('SELECT id, request_hash, status, tool_name, base_decision, effective_decision FROM tool_calls').all();
        if (canonicalJson(parents) !== canonicalJson([{ id: this.#id, request_hash: this.planHash, status: 'preflight_only',
          tool_name: 'metadata_graph_genesis_preflight', base_decision: 'ask', effective_decision: 'ask' }])) fail();
        const rows = database.prepare('SELECT event_json, event_type, previous_hash, event_hash, tool_call_id FROM audit_events ORDER BY sequence LIMIT 65').all() as Row[];
        if (canonicalJson(rows) !== canonicalJson(this.#records)) fail();
        let previous = ZERO;
        for (const row of rows) {
          if (row.previous_hash !== previous || hash(`${previous}\n${row.event_json}`) !== row.event_hash) fail();
          previous = row.event_hash;
        }
        return Object.freeze({ status: 'passed', eventCount: rows.length, chainDigest: previous, reopened: true });
      } finally { database.close(); }
    } catch { this.#failed = true; fail(); }
  }

  close(): void { this.#database?.close(); this.#database = undefined; }
}

/** Fixed repository layout; works for source tests and the compiled internal entry point. */
export function repositoryRoot(): string {
  const stage = dirname(fileURLToPath(import.meta.url));
  const base = dirname(dirname(stage));
  return base.endsWith('/dist') ? dirname(base) : base;
}

export function sqliteNativePath(): string {
  const require = createRequire(import.meta.url);
  return join(dirname(require.resolve('better-sqlite3/package.json')), 'prebuilds', `${process.platform}-${process.arch}.node`);
}

function hash(value: string): string { return createHash('sha256').update(value).digest('hex'); }
function schemaDigest(database: BetterSqlite3.Database): string {
  return hash(canonicalJson(database.prepare('SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name').all()));
}
function fail(): never { throw new Error('preflight_audit_failed'); }
