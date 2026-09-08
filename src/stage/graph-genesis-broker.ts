import { createHash } from 'node:crypto';

import { canonicalJson } from '../audit/canonical-json.js';
import { PackageStageError } from './profile.js';

const PACKAGE_NAME = /^(?:@[a-z0-9][a-z0-9._-]*\/[a-z0-9][a-z0-9._-]*|[a-z0-9][a-z0-9._-]*)$/u;
const SHA256 = /^[a-f0-9]{64}$/u;

export type MetadataBrokerLimits = Readonly<{
  uniquePackageNames: number;
  totalRequests: number;
  concurrentRequests: number;
  responseBytes: number;
  aggregateResponseBytes: number;
  requestTimeoutMs: number;
}>;

export type PublicPackumentRequest = Readonly<{
  url: string;
  headers: Readonly<{
    accept: 'application/vnd.npm.install-v1+json, application/json';
    acceptEncoding: 'identity';
  }>;
}>;

export type PublicPackumentResponse = Readonly<{
  status: number;
  contentType: string;
  redirected: boolean;
  finalUrl: string;
  body: Uint8Array;
}>;

export interface PublicPackumentTransport {
  fetch(request: PublicPackumentRequest, signal: AbortSignal): Promise<PublicPackumentResponse>;
}

export type BrokerAuthorization = Readonly<{
  authorizationVersion: 1;
  planHash: string;
  routeTokenDigest: string;
  registryOrigin: 'https://registry.npmjs.org/';
}>;

export type BrokerAuthorizationSource = Readonly<{
  plan: Readonly<{
    planHash: string;
    routeTokenDigest: string;
    registryOrigin: 'https://registry.npmjs.org/';
  }>;
}>;

export interface BrokerAuthorizationVerifier {
  authenticatesAuthorization(value: unknown): value is BrokerAuthorizationSource;
}

export type BrokerRequest = Readonly<{
  method: string;
  path: string;
  headers: Readonly<Record<string, string | undefined>>;
}>;

export type BrokerLedgerEntry = Readonly<{
  sequence: number;
  packageName: string;
  status: 200;
  responseBytes: number;
  bodySha256: string;
}>;

export type AuthenticatedBrokerLedger = Readonly<{
  ledgerVersion: 1;
  planHash: string;
  routeTokenDigest: string;
  requestCount: number;
  uniquePackageCount: number;
  aggregateResponseBytes: number;
  entries: readonly BrokerLedgerEntry[];
  rejectedRequestCount: 0;
  outstandingRequestCount: 0;
  terminalState: 'disarmed_complete';
  ledgerDigest: string;
}>;

type BrokerSession = {
  readonly planHash: string;
  readonly routeToken: string;
  readonly routeTokenDigest: string;
  readonly limits: MetadataBrokerLimits;
  readonly entries: BrokerLedgerEntry[];
  readonly packages: Set<string>;
  aggregateBytes: number;
  outstanding: number;
  armed: boolean;
  rejected: boolean;
};

export class MetadataBrokerAuthority {
  readonly #authorizations = new WeakSet<object>();
  readonly #consumedAuthorizations = new WeakSet<object>();
  readonly #sessions = new WeakSet<object>();
  readonly #ledgers = new WeakSet<object>();

  authorize(source: BrokerAuthorizationSource, verifier: BrokerAuthorizationVerifier): BrokerAuthorization {
    if (!verifier.authenticatesAuthorization(source)) fail();
    const input = source.plan;
    if (!SHA256.test(input.planHash) || !SHA256.test(input.routeTokenDigest)
      || input.registryOrigin !== 'https://registry.npmjs.org/') fail();
    const authorization = Object.freeze({
      authorizationVersion: 1 as const,
      planHash: input.planHash,
      routeTokenDigest: input.routeTokenDigest,
      registryOrigin: input.registryOrigin,
    });
    this.#authorizations.add(authorization);
    return authorization;
  }

  arm(
    authorization: BrokerAuthorization,
    input: Readonly<{ routeToken: string; limits: MetadataBrokerLimits }>,
  ): object {
    if (!this.#authorizations.has(authorization) || this.#consumedAuthorizations.has(authorization)) fail();
    validateMetadataBrokerLimits(input.limits);
    if (!/^[a-f0-9]{32}$/u.test(input.routeToken)
      || sha256(input.routeToken) !== authorization.routeTokenDigest) fail();
    const session: BrokerSession = {
      planHash: authorization.planHash,
      routeToken: input.routeToken,
      routeTokenDigest: authorization.routeTokenDigest,
      limits: Object.freeze({ ...input.limits }),
      entries: [],
      packages: new Set(),
      aggregateBytes: 0,
      outstanding: 0,
      armed: true,
      rejected: false,
    };
    this.#consumedAuthorizations.add(authorization);
    this.#sessions.add(session);
    return session;
  }

  async handle(
    opaqueSession: object,
    request: BrokerRequest,
    transport: PublicPackumentTransport,
    outerSignal?: AbortSignal,
  ): Promise<Uint8Array> {
    const session = this.#session(opaqueSession);
    if (!session.armed || session.rejected) fail();
    let packageName: string;
    try {
      packageName = parseBrokerPath(request, session.routeToken);
      if (session.entries.length >= session.limits.totalRequests) fail();
      if (!session.packages.has(packageName)
        && session.packages.size >= session.limits.uniquePackageNames) fail();
      if (session.outstanding >= session.limits.concurrentRequests) fail();
    } catch (error) {
      session.rejected = true;
      session.armed = false;
      throw error;
    }

    const encodedName = canonicalEncodedPackageName(packageName);
    const url = `https://registry.npmjs.org/${encodedName}`;
    const controller = new AbortController();
    const abort = () => controller.abort();
    outerSignal?.addEventListener('abort', abort, { once: true });
    const timeout = setTimeout(abort, session.limits.requestTimeoutMs);
    session.outstanding += 1;
    try {
      const fetchPromise = transport.fetch(Object.freeze({
        url,
        headers: Object.freeze({
          accept: 'application/vnd.npm.install-v1+json, application/json' as const,
          acceptEncoding: 'identity' as const,
        }),
      }), controller.signal);
      const response = await Promise.race([
        fetchPromise,
        new Promise<never>((_resolve, reject) => {
          controller.signal.addEventListener('abort', () => reject(new PackageStageError('graph_metadata_incomplete')), { once: true });
        }),
      ]);
      validateResponse(response, url, packageName, session.limits.responseBytes);
      const nextAggregate = session.aggregateBytes + response.body.byteLength;
      if (nextAggregate > session.limits.aggregateResponseBytes) fail();
      const body = Uint8Array.from(response.body);
      const entry = Object.freeze({
        sequence: session.entries.length + 1,
        packageName,
        status: 200 as const,
        responseBytes: body.byteLength,
        bodySha256: sha256(body),
      });
      session.aggregateBytes = nextAggregate;
      session.packages.add(packageName);
      session.entries.push(entry);
      return body;
    } catch (error) {
      session.rejected = true;
      session.armed = false;
      if (error instanceof PackageStageError) throw error;
      throw new PackageStageError('graph_metadata_invalid');
    } finally {
      session.outstanding -= 1;
      clearTimeout(timeout);
      outerSignal?.removeEventListener('abort', abort);
    }
  }

  disarmComplete(opaqueSession: object): AuthenticatedBrokerLedger {
    const session = this.#session(opaqueSession);
    session.armed = false;
    if (session.rejected || session.outstanding !== 0 || session.entries.length === 0) fail();
    const unsigned = deepFreeze({
      ledgerVersion: 1 as const,
      planHash: session.planHash,
      routeTokenDigest: session.routeTokenDigest,
      requestCount: session.entries.length,
      uniquePackageCount: session.packages.size,
      aggregateResponseBytes: session.aggregateBytes,
      entries: Object.freeze([...session.entries]),
      rejectedRequestCount: 0 as const,
      outstandingRequestCount: 0 as const,
      terminalState: 'disarmed_complete' as const,
    });
    const ledger = deepFreeze({ ...unsigned, ledgerDigest: sha256(canonicalJson(unsigned)) });
    this.#ledgers.add(ledger);
    return ledger;
  }

  authenticatesLedger(value: unknown): value is AuthenticatedBrokerLedger {
    return typeof value === 'object' && value !== null && this.#ledgers.has(value);
  }

  #session(value: object): BrokerSession {
    if (!this.#sessions.has(value)) fail();
    return value as BrokerSession;
  }
}

function parseBrokerPath(request: BrokerRequest, routeToken: string): string {
  assertExactKeys(request, ['method', 'path', 'headers']);
  if (request.method !== 'GET' || request.path.includes('?') || request.path.includes('#')) fail();
  assertAllowedIncomingHeaders(request.headers);
  const prefix = `/${routeToken}/`;
  if (!request.path.startsWith(prefix)) fail();
  const encoded = request.path.slice(prefix.length);
  if (encoded.length === 0 || encoded.includes('/')) fail();
  let decoded: string;
  try { decoded = decodeURIComponent(encoded); } catch { fail(); }
  if (!PACKAGE_NAME.test(decoded) || canonicalEncodedPackageName(decoded) !== encoded) fail();
  return decoded;
}

function canonicalEncodedPackageName(name: string): string {
  return name.startsWith('@') ? name.replace('/', '%2f') : name;
}

function assertAllowedIncomingHeaders(headers: Readonly<Record<string, string | undefined>>): void {
  for (const [name, value] of Object.entries(headers)) {
    const lower = name.toLowerCase();
    if (lower === 'accept' && (value === 'application/json'
      || value === 'application/vnd.npm.install-v1+json')) continue;
    if (lower === 'host' && typeof value === 'string' && value.length <= 255) continue;
    if (lower === 'connection' && value?.toLowerCase() === 'close') continue;
    if (['user-agent', 'accept-encoding'].includes(lower)
      && typeof value === 'string' && value.length <= 1024 && !/[\u0000-\u001f\u007f]/u.test(value)) continue;
    fail();
  }
}

function validateResponse(
  response: PublicPackumentResponse,
  expectedUrl: string,
  packageName: string,
  maxBytes: number,
): void {
  if (response.status !== 200 || response.redirected || response.finalUrl !== expectedUrl
    || response.contentType.toLowerCase().split(';', 1)[0] !== 'application/json'
    || !(response.body instanceof Uint8Array) || response.body.byteLength === 0
    || response.body.byteLength > maxBytes) fail();
  const text = new TextDecoder('utf-8', { fatal: true }).decode(response.body);
  const parsed = parseStrictJsonDocument(text);
  if (!isRecord(parsed) || parsed.name !== packageName) fail();
}

export function parseStrictJsonDocument(text: string): unknown {
  assertJsonBoundsAndNoDuplicateKeys(text, 64, 100_000);
  try { return JSON.parse(text); } catch { fail(); }
}

/** JSON scanner used before JSON.parse so duplicate keys cannot be hidden by last-value wins. */
function assertJsonBoundsAndNoDuplicateKeys(text: string, maxDepth: number, maxKeys: number): void {
  let index = 0;
  let keys = 0;
  const whitespace = () => { while (/\s/u.test(text[index] ?? '')) index += 1; };
  const string = (): string => {
    if (text[index] !== '"') fail();
    const start = index;
    index += 1;
    while (index < text.length) {
      const char = text[index];
      if (char === '"') {
        index += 1;
        try { return JSON.parse(text.slice(start, index)) as string; } catch { fail(); }
      }
      if (char === '\\') index += 2;
      else index += 1;
    }
    fail();
  };
  const value = (depth: number): void => {
    if (depth > maxDepth) fail();
    whitespace();
    if (text[index] === '{') {
      index += 1; whitespace();
      const seen = new Set<string>();
      if (text[index] === '}') { index += 1; return; }
      while (true) {
        whitespace(); const key = string();
        if (seen.has(key) || ++keys > maxKeys) fail();
        seen.add(key); whitespace();
        if (text[index++] !== ':') fail();
        value(depth + 1); whitespace();
        if (text[index] === '}') { index += 1; return; }
        if (text[index++] !== ',') fail();
      }
    }
    if (text[index] === '[') {
      index += 1; whitespace();
      if (text[index] === ']') { index += 1; return; }
      while (true) {
        value(depth + 1); whitespace();
        if (text[index] === ']') { index += 1; return; }
        if (text[index++] !== ',') fail();
      }
    }
    if (text[index] === '"') { string(); return; }
    const match = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/u.exec(text.slice(index));
    if (match === null) fail();
    index += match[0].length;
  };
  value(1); whitespace();
  if (index !== text.length) fail();
}

export function validateMetadataBrokerLimits(limits: MetadataBrokerLimits): void {
  assertExactKeys(limits, [
    'uniquePackageNames', 'totalRequests', 'concurrentRequests', 'responseBytes',
    'aggregateResponseBytes', 'requestTimeoutMs',
  ]);
  const integer = (value: number, min: number, max: number) => Number.isSafeInteger(value) && value >= min && value <= max;
  if (!integer(limits.uniquePackageNames, 1, 256)
    || !integer(limits.totalRequests, limits.uniquePackageNames, 512)
    || !integer(limits.concurrentRequests, 1, 8)
    || !integer(limits.responseBytes, 1, 8 * 1024 * 1024)
    || !integer(limits.aggregateResponseBytes, limits.responseBytes, 128 * 1024 * 1024)
    || !integer(limits.requestTimeoutMs, 1, 15_000)) fail();
}

function assertExactKeys(input: object, expected: readonly string[]): void {
  if (canonicalJson(Object.keys(input).sort()) !== canonicalJson([...expected].sort())) fail();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function fail(): never {
  throw new PackageStageError('graph_metadata_invalid');
}

function sha256(input: string | Uint8Array): string {
  return createHash('sha256').update(input).digest('hex');
}

function deepFreeze<T>(input: T): T {
  if (typeof input !== 'object' || input === null || Object.isFrozen(input)) return input;
  for (const value of Object.values(input)) deepFreeze(value);
  return Object.freeze(input);
}
