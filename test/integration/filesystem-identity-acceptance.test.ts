import { spawnSync } from 'node:child_process';
import {
  accessSync,
  chmodSync,
  constants,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { delimiter, isAbsolute, join, resolve } from 'node:path';

import { Client, type CallToolResult, type Tool } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { describe, expect, it } from 'vitest';

import {
  PortableReceiptService,
  serializePortableReceipt,
  verifyPortableReceipt,
} from '../../src/audit/portable-receipt.js';
import { SqliteAuditRecorder } from '../../src/audit/recorder.js';
import { openAuditDatabaseReadOnly } from '../../src/db/database.js';
import {
  FILESYSTEM_LIST_ALLOWED_DIRECTORIES_PROFILE_ID,
  FILESYSTEM_LIST_ALLOWED_DIRECTORIES_SCHEMA_DIGEST,
  FILESYSTEM_LIST_ALLOWED_DIRECTORIES_TOOL,
} from '../../src/identity/builtin-profiles.js';
import { observedInputSchemaDigest } from '../../src/identity/mcp-identity.js';

const runAcceptance = process.env.APG_REAL_FILESYSTEM_IDENTITY_E2E === '1';
const describeAcceptance = runAcceptance && process.platform !== 'win32' ? describe : describe.skip;
const pinnedPackage = '@modelcontextprotocol/server-filesystem@2026.7.10';
const gatewayCli = resolve('dist/src/cli/main.js');
const controlledRunner = resolve('dist/test/fixtures/controlled-filesystem-npx-runner.js');
const allowPolicy = resolve('test/fixtures/allow-all-policy.yaml');

describe('controlled Filesystem acceptance runner', () => {
  it('constructs a credential-free private npm environment without network access', () => {
    const acceptanceRoot = mkdtempSync(join(process.env.TMPDIR ?? '/tmp', 'apg-filesystem-runner-'));
    try {
      const allowedDirectory = privateDirectory(acceptanceRoot, 'allowed-directory');
      for (const directory of ['home', 'npm-cache', 'tmp', 'npm-prefix']) {
        privateDirectory(acceptanceRoot, directory);
      }
      for (const filename of ['empty-user.npmrc', 'empty-global.npmrc']) {
        writeFileSync(join(acceptanceRoot, filename), '', { encoding: 'utf8', flag: 'wx', mode: 0o600 });
      }

      const capturePath = join(acceptanceRoot, 'captured-invocation.json');
      const fakeNpx = join(acceptanceRoot, 'fake-npx.cjs');
      writeFileSync(fakeNpx, [
        `#!${process.execPath}`,
        "const { writeFileSync } = require('node:fs');",
        `writeFileSync(${JSON.stringify(capturePath)}, JSON.stringify({ args: process.argv.slice(2), cwd: process.cwd(), env: process.env }));`,
      ].join('\n'), { encoding: 'utf8', flag: 'wx', mode: 0o700 });
      chmodSync(fakeNpx, 0o700);

      const result = spawnSync(process.execPath, [
        controlledRunner,
        acceptanceRoot,
        fakeNpx,
        pinnedPackage,
        allowedDirectory,
      ], {
        encoding: 'utf8',
        env: { PATH: '/controlled/test-path', APG_SECRET_MARKER: 'must-not-forward' },
      });
      expect(result.status, result.stderr).toBe(0);

      const captured = JSON.parse(readFileSync(capturePath, 'utf8')) as {
        args: string[];
        cwd: string;
        env: Record<string, string>;
      };
      expect(captured.args).toEqual(['--yes', pinnedPackage, realpathSync(allowedDirectory)]);
      expect(captured.cwd).toBe(realpathSync(acceptanceRoot));
      expect(captured.env).not.toHaveProperty('APG_SECRET_MARKER');
      expect(captured.env).toMatchObject({
        PATH: '/controlled/test-path',
        HOME: realpathSync(join(acceptanceRoot, 'home')),
        TMPDIR: realpathSync(join(acceptanceRoot, 'tmp')),
        npm_config_userconfig: realpathSync(join(acceptanceRoot, 'empty-user.npmrc')),
        npm_config_globalconfig: realpathSync(join(acceptanceRoot, 'empty-global.npmrc')),
        npm_config_cache: realpathSync(join(acceptanceRoot, 'npm-cache')),
        npm_config_prefix: realpathSync(join(acceptanceRoot, 'npm-prefix')),
        npm_config_registry: 'https://registry.npmjs.org/',
        npm_config_ignore_scripts: 'true',
        npm_config_audit: 'false',
        npm_config_fund: 'false',
        npm_config_update_notifier: 'false',
        npm_config_yes: 'true',
      });
    } finally {
      rmSync(acceptanceRoot, { recursive: true, force: true });
    }
  });

  it('rejects an unpinned package before starting the configured executable', () => {
    const result = spawnSync(process.execPath, [
      controlledRunner,
      '/does-not-need-to-exist',
      '/does-not-need-to-exist/npx',
      '@modelcontextprotocol/server-filesystem@latest',
      '/does-not-need-to-exist/allowed',
    ], { encoding: 'utf8' });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain('rejected an unpinned package');
  });
});

describeAcceptance('pinned Filesystem exact identity acceptance', () => {
  it('calls only list_allowed_directories and verifies private receipt evidence', async () => {
    const acceptanceRoot = mkdtempSync(join(process.env.TMPDIR ?? '/tmp', 'apg-filesystem-identity-'));
    const auditPath = join(acceptanceRoot, 'audit.sqlite');
    const allowedDirectory = privateDirectory(acceptanceRoot, 'allowed-directory');
    for (const directory of ['home', 'npm-cache', 'tmp', 'npm-prefix']) {
      privateDirectory(acceptanceRoot, directory);
    }
    for (const filename of ['empty-user.npmrc', 'empty-global.npmrc']) {
      writeFileSync(join(acceptanceRoot, filename), '', { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    }

    let client: Client | undefined;
    try {
      const npxExecutable = findExecutable('npx');
      client = await connectThroughGateway(
        auditPath,
        acceptanceRoot,
        npxExecutable,
        allowedDirectory,
      );

      const listed = await client.listTools();
      const targets = listed.tools.filter((tool) => tool.name === FILESYSTEM_LIST_ALLOWED_DIRECTORIES_TOOL);
      expect(targets).toHaveLength(1);
      expect(observedInputSchemaDigest(targetSchema(targets[0]!))).toBe(
        FILESYSTEM_LIST_ALLOWED_DIRECTORIES_SCHEMA_DIGEST,
      );

      const result = await client.callTool({
        name: FILESYSTEM_LIST_ALLOWED_DIRECTORIES_TOOL,
        arguments: {},
      }) as CallToolResult;
      expect(result.isError).not.toBe(true);
      expect(textLines(result)).toEqual(['Allowed directories:', realpathSync(allowedDirectory)]);

      await client.close();
      client = undefined;

      const database = openAuditDatabaseReadOnly(auditPath);
      try {
        const recorder = new SqliteAuditRecorder(database);
        expect(recorder.verifyHashChain()).toBe(true);
        const rows = database.prepare(`
          SELECT id, arguments_json, status, result_summary_json
          FROM tool_calls
          WHERE tool_name = ?
        `).all(FILESYSTEM_LIST_ALLOWED_DIRECTORIES_TOOL) as Array<{
          id: string;
          arguments_json: string;
          status: string;
          result_summary_json: string | null;
        }>;
        expect(rows).toHaveLength(1);
        const row = rows[0]!;
        expect(row.arguments_json).toBe('{}');
        expect(row.status).toBe('completed');
        expect(JSON.parse(row.result_summary_json ?? 'null')).toEqual({
          contentCount: 1,
          contentTypes: ['text'],
          isError: false,
        });

        const envelope = new PortableReceiptService(database, recorder).exportAction(row.id);
        const serialized = serializePortableReceipt(envelope);
        expect(envelope.completeness).toBe('complete');
        expect(envelope.authorization?.receipt.action).toMatchObject({
          operation: FILESYSTEM_LIST_ALLOWED_DIRECTORIES_TOOL,
          identityAssurance: 'adapter_action_exact',
          identityEvidence: {
            profileStatus: 'projected',
            profileId: FILESYSTEM_LIST_ALLOWED_DIRECTORIES_PROFILE_ID,
            serverProvenanceAssurance: 'configured_label_only',
            parameterCoverage: 'complete_action_parameters',
            safeClaims: [],
            omittedCategories: [],
          },
        });
        expect(envelope.outcome?.receipt.action).toEqual(envelope.authorization?.receipt.action);
        expect(envelope.limitations).toMatchObject({
          issuerAuthentication: 'none',
          directBypassUnprotected: true,
          unobservedEffects: true,
        });
        expect(verifyPortableReceipt(serialized)).toMatchObject({
          valid: true,
          status: 'verified_unsigned',
          actionId: row.id,
        });

        const eventBodies = database.prepare('SELECT event_json FROM audit_events').all() as Array<{ event_json: string }>;
        const persistedEvidence = `${JSON.stringify(rows)}\n${JSON.stringify(eventBodies)}\n${serialized}`;
        expect(persistedEvidence).not.toContain(acceptanceRoot);
        expect(persistedEvidence).not.toContain(realpathSync(allowedDirectory));
      } finally {
        database.close();
      }
    } finally {
      await client?.close().catch(() => undefined);
      rmSync(acceptanceRoot, { recursive: true, force: true });
    }
  }, 90_000);
});

async function connectThroughGateway(
  auditPath: string,
  acceptanceRoot: string,
  npxExecutable: string,
  allowedDirectory: string,
): Promise<Client> {
  const client = new Client(
    { name: 'apg-filesystem-identity-acceptance', version: '0.1.0' },
    { versionNegotiation: { mode: 'auto' } },
  );
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      gatewayCli,
      'proxy',
      '--policy', allowPolicy,
      '--audit-db', auditPath,
      '--dashboard-port', '0',
      '--identity-profile', FILESYSTEM_LIST_ALLOWED_DIRECTORIES_PROFILE_ID,
      '--', process.execPath, controlledRunner, acceptanceRoot, npxExecutable, pinnedPackage, allowedDirectory,
    ],
    env: process.env.PATH === undefined ? {} : { PATH: process.env.PATH },
    stderr: 'pipe',
  });

  let stderr = '';
  transport.stderr?.on('data', (chunk) => {
    stderr = `${stderr}${String(chunk)}`.slice(-4_000);
  });
  try {
    await client.connect(transport);
    return client;
  } catch (error) {
    await client.close().catch(() => undefined);
    const message = error instanceof Error ? error.message : String(error);
    if (stderr.includes('input_schema_mismatch')) {
      const observedSchema = await capturePinnedTargetSchema(
        acceptanceRoot,
        npxExecutable,
        allowedDirectory,
      );
      throw new Error(
        `Pinned Filesystem acceptance failed: ${message}\n${stderr.trim()}\n`
        + `Observed public target schema: ${JSON.stringify(observedSchema)}`,
      );
    }
    throw new Error(`Pinned Filesystem acceptance failed: ${message}\n${stderr.trim()}`);
  }
}

async function capturePinnedTargetSchema(
  acceptanceRoot: string,
  npxExecutable: string,
  allowedDirectory: string,
): Promise<Tool['inputSchema']> {
  const client = new Client(
    { name: 'apg-filesystem-schema-capture', version: '0.1.0' },
    { versionNegotiation: { mode: 'auto' } },
  );
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [controlledRunner, acceptanceRoot, npxExecutable, pinnedPackage, allowedDirectory],
    env: process.env.PATH === undefined ? {} : { PATH: process.env.PATH },
    stderr: 'pipe',
  });
  try {
    await client.connect(transport);
    const listed = await client.listTools();
    const targets = listed.tools.filter((tool) => tool.name === FILESYSTEM_LIST_ALLOWED_DIRECTORIES_TOOL);
    if (targets.length !== 1) throw new Error('Pinned Filesystem target tool was missing or duplicated');
    return targetSchema(targets[0]!);
  } finally {
    await client.close().catch(() => undefined);
  }
}

function privateDirectory(parent: string, name: string): string {
  const path = join(parent, name);
  mkdirSync(path, { mode: 0o700 });
  return path;
}

function findExecutable(name: string): string {
  for (const directory of (process.env.PATH ?? '').split(delimiter)) {
    if (directory.length === 0) continue;
    const candidate = join(directory, name);
    try {
      accessSync(candidate, constants.X_OK);
      if (!isAbsolute(candidate)) continue;
      return realpathSync(candidate);
    } catch {
      // Keep searching the declared PATH without invoking a shell.
    }
  }
  throw new Error(`Required executable was not found: ${name}`);
}

function targetSchema(tool: Tool): Tool['inputSchema'] {
  if (tool.inputSchema === undefined) throw new Error('Target tool did not advertise an input schema');
  return tool.inputSchema;
}

function textLines(result: CallToolResult): string[] {
  const text = result.content.find((item) => item.type === 'text');
  if (text?.type !== 'text') throw new Error('Expected a text result from list_allowed_directories');
  return text.text.split(/\r?\n/u).map((line) => line.trim()).filter((line) => line.length > 0);
}
