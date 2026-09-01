import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { ApprovalCoordinator } from '../approval/types.js';
import type { AuditQueryService } from '../audit/query-service.js';
import type { SqliteAuditRecorder } from '../audit/recorder.js';
import { PolicyLoadError } from '../policy/loader.js';
import { LivePolicyController, PolicyConflictError } from '../policy/live-controller.js';

export type DashboardHandle = Readonly<{
  url: string;
  instanceId: string;
  close(): Promise<void>;
}>;

export async function startDashboard(options: Readonly<{
  approvals: ApprovalCoordinator;
  audit: AuditQueryService;
  auditRecorder: SqliteAuditRecorder;
  policies: LivePolicyController;
  token: string;
  port?: number;
}>): Promise<DashboardHandle> {
  if (options.token.length < 32) throw new Error('Dashboard token must be at least 32 characters');
  const instanceId = randomUUID();
  const assets = loadAssets();
  const server = createServer((request, response) => {
    void handleRequest(request, response, { ...options, instanceId }, assets, server.address()).catch((error: unknown) => {
      if (error instanceof DashboardHttpError) return sendJson(response, error.status, { error: error.message });
      if (error instanceof PolicyConflictError) return sendJson(response, 409, { error: error.message });
      if (error instanceof PolicyLoadError) return sendJson(response, 400, { error: error.message });
      process.stderr.write('[apg] dashboard request failed\n');
      return sendJson(response, 500, { error: 'Internal dashboard error' });
    });
  });

  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error) => reject(error);
    server.once('error', onError);
    server.listen(options.port ?? 47_831, '127.0.0.1', () => {
      server.off('error', onError);
      resolve();
    });
  });
  const address = server.address();
  if (address === null || typeof address === 'string') {
    server.close();
    throw new Error('Dashboard did not bind to a TCP port');
  }
  const origin = `http://127.0.0.1:${address.port}`;

  return {
    url: `${origin}/#token=${encodeURIComponent(options.token)}`,
    instanceId,
    close: () => new Promise<void>((resolve, reject) => {
      server.close((error) => error === undefined ? resolve() : reject(error));
    }),
  };
}

type Assets = Readonly<Record<'/' | '/app.js' | '/styles.css', Readonly<{
  body: Buffer;
  contentType: string;
}>>>;

async function handleRequest(
  request: IncomingMessage,
  response: ServerResponse,
  services: Readonly<{
    approvals: ApprovalCoordinator;
    audit: AuditQueryService;
    auditRecorder: SqliteAuditRecorder;
    policies: LivePolicyController;
    token: string;
    instanceId: string;
  }>,
  assets: Assets,
  address: ReturnType<ReturnType<typeof createServer>['address']>,
): Promise<void> {
  applySecurityHeaders(response);
  if (address === null || typeof address === 'string') return sendJson(response, 503, { error: 'Not ready' });
  const expectedHost = `127.0.0.1:${address.port}`;
  if (request.headers.host !== expectedHost) return sendJson(response, 421, { error: 'Invalid host' });

  const url = new URL(request.url ?? '/', `http://${expectedHost}`);
  if (url.pathname.startsWith('/api/')) {
    const expectedOrigin = `http://${expectedHost}`;
    if (!isAllowedOrigin(request.headers.origin, expectedOrigin)) {
      return sendJson(response, 403, { error: 'Invalid origin' });
    }
    if (!isAuthorized(request.headers.authorization, services.token)) return sendJson(response, 401, { error: 'Unauthorized' });

    if (request.method === 'GET' && url.pathname === '/api/health') {
      return sendJson(response, 200, { status: 'ok', api_version: 1, instance_id: services.instanceId });
    }
    if (request.method === 'GET' && url.pathname === '/api/approvals') {
      return sendJson(response, 200, { approvals: services.approvals.listPending() });
    }
    if (request.method === 'GET' && url.pathname === '/api/audit') {
      const rawLimit = url.searchParams.get('limit') ?? '50';
      if (!/^\d{1,3}$/.test(rawLimit)) return sendJson(response, 400, { error: 'Invalid audit limit' });
      const limit = Number(rawLimit);
      if (limit < 1 || limit > 100) return sendJson(response, 400, { error: 'Audit limit must be between 1 and 100' });
      return sendJson(response, 200, services.audit.listRecent(limit));
    }
    if (request.method === 'GET' && url.pathname === '/api/policy') {
      return sendJson(response, 200, services.policies.getView());
    }
    if (request.method === 'PUT' && url.pathname === '/api/policy') {
      const body = await readJsonBody(request);
      if (!isPolicyUpdate(body)) return sendJson(response, 400, { error: 'Expected policy source and revision' });
      const auditCall = services.auditRecorder.begin({
        serverId: 'apg-dashboard',
        toolName: 'update_policy',
        arguments: {
          expectedRevision: body.revision,
          proposedRevision: createHash('sha256').update(body.source).digest('hex'),
        },
      }, {
        action: 'forward',
        evaluation: {
          baseDecision: 'allow',
          effectiveDecision: 'allow',
          matchedRuleId: 'authenticated_local_dashboard',
          reasonCodes: ['human_policy_edit'],
          risk: {
            score: 70,
            band: 'high',
            signals: [
              { code: 'local_write', points: 20, source: 'policy_tag' },
              { code: 'privileged_target', points: 25, source: 'policy_tag' },
            ],
          },
        },
      });
      auditCall.markForwarding();
      try {
        const view = services.policies.update(body.source, body.revision);
        auditCall.markCompleted({ content: [{ type: 'text', text: 'Policy updated' }] });
        return sendJson(response, 200, view);
      } catch (error) {
        auditCall.markFailed(error instanceof PolicyConflictError ? 'policy_conflict' : 'policy_invalid');
        throw error;
      }
    }
    const match = /^\/api\/approvals\/([0-9a-f-]{36})\/(approve|deny)$/.exec(url.pathname);
    if (request.method === 'POST' && match !== null) {
      const id = match[1];
      const action = match[2];
      if (id === undefined || action === undefined) return sendJson(response, 400, { error: 'Invalid approval request' });
      const outcome = services.approvals.decide(id, action === 'approve' ? 'approved' : 'denied');
      if (outcome === undefined) return sendJson(response, 404, { error: 'Approval is no longer pending' });
      if (outcome === 'expired') return sendJson(response, 409, { error: 'Approval expired' });
      return sendJson(response, 200, { outcome });
    }
    return sendJson(response, 404, { error: 'Not found' });
  }

  if (request.method !== 'GET') return sendJson(response, 405, { error: 'Method not allowed' });
  const asset = assets[url.pathname as keyof Assets];
  if (asset === undefined) return sendJson(response, 404, { error: 'Not found' });
  response.writeHead(200, {
    'Content-Type': asset.contentType,
    'Content-Length': asset.body.length,
    'Cache-Control': 'no-store',
  });
  response.end(asset.body);
}

class DashboardHttpError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

async function readJsonBody(request: IncomingMessage): Promise<unknown> {
  const mediaType = request.headers['content-type']?.split(';', 1)[0]?.trim().toLowerCase();
  if (mediaType !== 'application/json') {
    throw new DashboardHttpError(415, 'Content-Type must be application/json');
  }
  const maximumBytes = 1_100_000;
  const declaredLength = Number(request.headers['content-length'] ?? 0);
  if (declaredLength > maximumBytes) throw new DashboardHttpError(413, 'Request body is too large');
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
    total += buffer.length;
    if (total > maximumBytes) {
      request.resume();
      throw new DashboardHttpError(413, 'Request body is too large');
    }
    chunks.push(buffer);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
  } catch {
    throw new DashboardHttpError(400, 'Request body must be valid JSON');
  }
}

function isPolicyUpdate(value: unknown): value is { source: string; revision: string } {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return Object.keys(record).length === 2
    && typeof record.source === 'string'
    && typeof record.revision === 'string'
    && /^[0-9a-f]{64}$/.test(record.revision);
}

function isAuthorized(header: string | undefined, expectedToken: string): boolean {
  if (header === undefined || !header.startsWith('Bearer ')) return false;
  const received = Buffer.from(header.slice(7));
  const expected = Buffer.from(expectedToken);
  return received.length === expected.length && timingSafeEqual(received, expected);
}

function isAllowedOrigin(header: string | undefined, expectedOrigin: string): boolean {
  return header === undefined || header === expectedOrigin;
}

function applySecurityHeaders(response: ServerResponse): void {
  response.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
  response.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  response.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  response.setHeader('Referrer-Policy', 'no-referrer');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('X-Frame-Options', 'DENY');
}

function sendJson(response: ServerResponse, status: number, payload: unknown): void {
  if (response.headersSent) {
    response.end();
    return;
  }
  const body = Buffer.from(JSON.stringify(payload));
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': body.length,
    'Cache-Control': 'no-store',
  });
  response.end(body);
}

function loadAssets(): Assets {
  const webDirectory = findWebDirectory();
  return {
    '/': { body: readFileSync(join(webDirectory, 'index.html')), contentType: 'text/html; charset=utf-8' },
    '/app.js': { body: readFileSync(join(webDirectory, 'app.js')), contentType: 'text/javascript; charset=utf-8' },
    '/styles.css': { body: readFileSync(join(webDirectory, 'styles.css')), contentType: 'text/css; charset=utf-8' },
  };
}

function findWebDirectory(): string {
  let directory = dirname(fileURLToPath(import.meta.url));
  for (let level = 0; level < 5; level += 1) {
    const candidate = join(directory, 'web');
    if (existsSync(join(candidate, 'index.html'))) return candidate;
    directory = dirname(directory);
  }
  throw new Error('Dashboard assets are missing');
}
