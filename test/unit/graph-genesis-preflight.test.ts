import { chmod, link, mkdir, readFile, readdir, rename, rm, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import BetterSqlite3 from 'better-sqlite3';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { PreflightRoot } from '../../src/stage/graph-genesis-preflight-root.js';
import { PreflightSqliteAudit, sqliteNativePath } from '../../src/stage/graph-genesis-preflight-audit.js';
import { captureLocalGraphGenesisPreflight } from '../../src/stage/graph-genesis-preflight.js';

const roots: string[] = [];
const audits: PreflightSqliteAudit[] = [];
const connections: BetterSqlite3.Database[] = [];
const planHash = 'a'.repeat(64);
const runtimeDigest = 'b'.repeat(64);

afterEach(async () => {
  vi.restoreAllMocks();
  for (const connection of connections.splice(0)) if (connection.open) connection.close();
  for (const audit of audits.splice(0)) audit.close();
  // Only fresh test-owned roots, including deliberately quarantined adversarial fixtures.
  for (const path of roots.splice(0)) await rm(path, { recursive: true, force: true });
});

async function rootFixture() {
  const root = await PreflightRoot.create(); roots.push(root.path); return root;
}

async function fixture() {
  const root = await rootFixture();
  const audit = await PreflightSqliteAudit.create(root, planHash, runtimeDigest); audits.push(audit);
  return { root, audit, path: join(root.path, 'audit/preflight.sqlite') };
}

function inspect(path: string) {
  const db = new BetterSqlite3(path, { nativeBinding: sqliteNativePath(), fileMustExist: true, timeout: 100 });
  connections.push(db); return db;
}

function appendAll(audit: PreflightSqliteAudit) {
  audit.append('plan_captured'); audit.append('audit_checked'); audit.append('session_closing');
}

describe('local graph genesis preparation and disposable SQLite', () => {
  it('commits, closes and reopens three exact preflight events without authorization or receipt rows', async () => {
    const { root, audit, path } = await fixture();
    appendAll(audit);
    const evidence = await audit.verifyReopened();
    expect(evidence).toMatchObject({ status: 'passed', eventCount: 3, reopened: true });
    const database = inspect(path);
    const rows = database.prepare('SELECT event_json FROM audit_events ORDER BY sequence').all();
    const text = JSON.stringify(rows);
    expect(text).toContain('graph_genesis.preflight.session_closing');
    expect(text).not.toMatch(/authorization_finalized|genesis_complete|receipt|npm_spawn/);
    expect(text).not.toContain(root.path);
    expect(database.prepare('SELECT COUNT(*) AS count FROM approvals').get()).toEqual({ count: 0 });
    expect(database.prepare('SELECT effective_decision, status FROM tool_calls').get()).toEqual({ effective_decision: 'ask', status: 'preflight_only' });
    database.close();
    await expect(root.cleanup()).resolves.toBeGreaterThan(0);
    expect(PreflightRoot.authenticates(root)).toBe(false);
  });

  it('serializes simultaneously scheduled appends without a fork in the committed chain', async () => {
    const { audit } = await fixture();
    await Promise.all(['plan_captured', 'audit_checked', 'session_closing'].map((name) => Promise.resolve().then(() => audit.append(name as 'plan_captured'))));
    await expect(audit.verifyReopened()).resolves.toMatchObject({ eventCount: 3 });
  });

  it.each(['authorization_finalized', 'x'.repeat(4097), 'session_closing', { event: 'plan_captured' }])(
    'rejects unknown, oversized or unordered events and latches failure', async (event) => {
      const { audit, path } = await fixture();
      expect(() => audit.append(event as 'plan_captured')).toThrow('preflight_audit_failed');
      expect(() => audit.append('plan_captured')).toThrow('preflight_audit_failed');
      expect(inspect(path).prepare('SELECT COUNT(*) AS count FROM audit_events').get()).toEqual({ count: 0 });
      await expect(audit.verifyReopened()).rejects.toThrow('preflight_audit_failed');
    },
  );

  it('rejects root forgeries and foreign/malformed plan identities before creating a database', async () => {
    const root = await rootFixture();
    await expect(PreflightSqliteAudit.create({ ...root } as PreflightRoot, planHash, runtimeDigest)).rejects.toThrow('preflight_audit_failed');
    await expect(PreflightSqliteAudit.create(root, 'private-path-canary', runtimeDigest)).rejects.toThrow('preflight_audit_failed');
    expect(await readdir(root.path)).toEqual([]);
  });

  it('fails closed on a bounded SQLite lock and never retries the failed append', async () => {
    const { audit, path } = await fixture();
    const blocker = inspect(path); blocker.exec('BEGIN IMMEDIATE');
    const start = performance.now();
    expect(() => audit.append('plan_captured')).toThrow('preflight_audit_failed');
    expect(performance.now() - start).toBeLessThan(2000);
    blocker.exec('ROLLBACK');
    expect(() => audit.append('plan_captured')).toThrow('preflight_audit_failed');
    expect(blocker.prepare('SELECT COUNT(*) AS count FROM audit_events').get()).toEqual({ count: 0 });
  });

  it('rejects modified, truncated and owner-recomputed history on reopen', async () => {
    const { audit, path } = await fixture();
    appendAll(audit); audit.close();
    const database = inspect(path);
    database.prepare("UPDATE audit_events SET event_json = '{}' WHERE sequence = 2").run();
    database.close();
    await expect(audit.verifyReopened()).rejects.toThrow('preflight_audit_failed');
  });

  it('rejects changed schema and cross-plan parent state', async () => {
    const { audit, path } = await fixture();
    appendAll(audit); audit.close();
    const database = inspect(path);
    database.prepare('UPDATE tool_calls SET request_hash = ?').run('c'.repeat(64));
    database.exec("INSERT INTO schema_migrations VALUES (99, 'unexpected')");
    database.close();
    await expect(audit.verifyReopened()).rejects.toThrow('preflight_audit_failed');
  });

  it('rejects unversioned schema drift and a symlinked audit parent', async () => {
    const first = await fixture();
    appendAll(first.audit); first.audit.close();
    const database = inspect(first.path); database.exec('CREATE TABLE unexpected (value TEXT)'); database.close();
    await expect(first.audit.verifyReopened()).rejects.toThrow('preflight_audit_failed');
    const second = await fixture();
    appendAll(second.audit); second.audit.close();
    await rename(join(second.root.path, 'audit'), join(second.root.path, 'audit-original'));
    await symlink(join(second.root.path, 'audit-original'), join(second.root.path, 'audit'));
    await expect(second.audit.verifyReopened()).rejects.toThrow('preflight_audit_failed');
  });

  it('does not acknowledge an insertion failure or retain raw database errors', async () => {
    const { audit } = await fixture();
    const original = BetterSqlite3.prototype.prepare;
    vi.spyOn(BetterSqlite3.prototype, 'prepare').mockImplementation(function (this: BetterSqlite3.Database, sql: string) {
      if (sql.includes('INSERT INTO audit_events')) throw new Error('SQLITE_FULL private-path-canary');
      return original.call(this, sql);
    });
    expect(() => audit.append('plan_captured')).toThrow(/^preflight_audit_failed$/);
    await expect(audit.verifyReopened()).rejects.toThrow(/^preflight_audit_failed$/);
  });

  it('rejects replacement of the closed audit file even with a valid copied database', async () => {
    const { audit, path } = await fixture();
    appendAll(audit); audit.close();
    const bytes = await readFile(path);
    await rename(path, `${path}.old`);
    await writeFile(path, bytes, { mode: 0o600 });
    await expect(audit.verifyReopened()).rejects.toThrow('preflight_audit_failed');
  });

  it.each(['symlink', 'hardlink', 'mode', 'unknown-root'])('quarantines ambiguous cleanup: %s', async (kind) => {
    const root = await rootFixture();
    await mkdir(join(root.path, 'workspace'), { mode: 0o700 });
    const target = join(root.path, 'workspace/owned');
    await writeFile(target, 'private fixture', { mode: 0o600 });
    if (kind === 'symlink') await symlink(target, join(root.path, 'workspace/link'));
    if (kind === 'hardlink') await link(target, join(root.path, 'workspace/link'));
    if (kind === 'mode') await chmod(target, 0o644);
    if (kind === 'unknown-root') await writeFile(join(root.path, 'foreign'), 'do not remove', { mode: 0o600 });
    await expect(root.cleanup()).rejects.toThrow('preflight_cleanup_ambiguous');
    expect(await readFile(target, 'utf8')).toBe('private fixture');
  });

  it('rejects a replaced root without deleting the replacement', async () => {
    const root = await rootFixture();
    const original = `${root.path}-original`; roots.push(original);
    await rename(root.path, original); await mkdir(root.path, { mode: 0o700 });
    await expect(root.cleanup()).rejects.toThrow('preflight_cleanup_ambiguous');
    expect(await readdir(root.path)).toEqual([]);
  });

  it('pre-cancel returns a closed, non-authorized report with no private data or capture', async () => {
    const controller = new AbortController(); controller.abort();
    const report = await captureLocalGraphGenesisPreflight({ signal: controller.signal });
    expect(report).toMatchObject({ status: 'local_preflight_failed', sessionClosed: true, executionAuthorized: false,
      planReusable: false, cleanup: 'not_needed', registry: 'not_attempted', npmCli: 'not_attempted' });
    expect(report.projection).toBeUndefined();
    expect(JSON.stringify(report)).not.toMatch(/\/Users\/|\/private\/|routeToken|capsule|argv/);
  });

  it('rejects injected collaborators and running through a source/test loader', async () => {
    expect(await captureLocalGraphGenesisPreflight({ transport: 'private-canary' } as never))
      .toMatchObject({ failureCode: 'preflight_input_failed', cleanup: 'not_needed' });
    expect(await captureLocalGraphGenesisPreflight()).toMatchObject({ failureCode: 'preflight_input_failed', cleanup: 'not_needed' });
    expect(await captureLocalGraphGenesisPreflight(null as never)).toMatchObject({ failureCode: 'preflight_input_failed' });
    let getterCalled = false;
    expect(await captureLocalGraphGenesisPreflight({ get signal() { getterCalled = true; return undefined; } } as never))
      .toMatchObject({ failureCode: 'preflight_input_failed' });
    expect(getterCalled).toBe(false);
  });

  it('keeps the preparation call graph away from execution entry points and inherited configuration', async () => {
    const source = await readFile(join(process.cwd(), 'src/stage/graph-genesis-preflight.ts'), 'utf8');
    expect(source).not.toMatch(/\.arm\(|\.prepareSession\(|NodeGraphGenesisSpawnAdapter|GraphGenesisProcessSupervisor|BoundedNpmPublicMetadataTransport|openAuditDatabase/);
    expect(source).not.toMatch(/process\.env\.(?:HOME|PATH|npm_config|NPM_CONFIG)/);
  });
});
