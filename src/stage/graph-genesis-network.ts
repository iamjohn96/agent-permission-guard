import { createHash, timingSafeEqual } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { request as httpsRequest, type RequestOptions as HttpsRequestOptions } from 'node:https';
import { isIP, type LookupFunction } from 'node:net';

import { canonicalJson } from '../audit/canonical-json.js';
import { parseStrictJsonDocument } from './graph-genesis-broker.js';
import type {
  AuthenticatedGraphGenesisExecutionCapsule,
  GraphGenesisAuditGate,
  HardenedGraphGenesisAuthorization,
  HardenedGraphGenesisAuthorizationVerifier,
  HardenedGraphGenesisPlan,
  HardenedGraphGenesisPlanAuthority,
} from './graph-genesis-hardening.js';
import { PackageStageError } from './profile.js';

const PACKAGE_NAME = /^(?:@[a-z0-9][a-z0-9._-]*\/[a-z0-9][a-z0-9._-]*|[a-z0-9][a-z0-9._-]*)$/u;
const SYSTEM_RESOLVERS = new WeakSet<object>();
const NODE_PINNED_CLIENTS = new WeakSet<object>();

export type ResolvedAddress = Readonly<{ address: string; family: 4 | 6 }>;

export interface RegistryAddressResolver {
  resolve(hostname: 'registry.npmjs.org', signal: AbortSignal): Promise<readonly ResolvedAddress[]>;
}

export class SystemRegistryAddressResolver implements RegistryAddressResolver {
  constructor() { SYSTEM_RESOLVERS.add(this); }

  async resolve(hostname: 'registry.npmjs.org', signal: AbortSignal): Promise<readonly ResolvedAddress[]> {
    if (signal.aborted) failMetadataIncomplete();
    const addresses = await lookup(hostname, { all: true, verbatim: true });
    if (signal.aborted) failMetadataIncomplete();
    return Object.freeze(addresses.map((item) => {
      if (item.family !== 4 && item.family !== 6) failMetadata();
      return Object.freeze({ address: item.address, family: item.family });
    }));
  }
}

export type PinnedHttpsRequest = Readonly<{
  url: string;
  hostname: 'registry.npmjs.org';
  address: string;
  family: 4 | 6;
  headers: Readonly<{
    accept: 'application/vnd.npm.install-v1+json, application/json';
    acceptEncoding: 'identity';
  }>;
  timeoutMs: number;
  maximumBytes: number;
}>;

export type PinnedHttpsResponse = Readonly<{
  status: number;
  contentType: string;
  contentEncoding: string;
  finalUrl: string;
  redirected: false;
  body: Uint8Array;
}>;

export interface PinnedHttpsClient {
  readonly implementationKind: 'production' | 'synthetic';
  request(input: PinnedHttpsRequest, signal: AbortSignal): Promise<PinnedHttpsResponse>;
}

export class NodePinnedHttpsClient implements PinnedHttpsClient {
  readonly implementationKind = 'production' as const;

  constructor() { NODE_PINNED_CLIENTS.add(this); }

  async request(input: PinnedHttpsRequest, signal: AbortSignal): Promise<PinnedHttpsResponse> {
    return await requestPinnedHttps(input, signal, Object.freeze({ port: 443 }));
  }
}

/** Uses the identical streaming/TLS core with an in-memory test CA and local high port. */
export function createLocalTlsPinnedHttpsClientForTest(port: number, ca: string): PinnedHttpsClient {
  if (!Number.isSafeInteger(port) || port < 1024 || port > 65535 || ca.length === 0 || ca.length > 64 * 1024) failMetadata();
  return Object.freeze({
    implementationKind: 'synthetic' as const,
    request: async (input: PinnedHttpsRequest, signal: AbortSignal) => requestPinnedHttps(input, signal, { port, ca }),
  });
}

async function requestPinnedHttps(
  input: PinnedHttpsRequest,
  signal: AbortSignal,
  connection: Readonly<{ port: number; ca?: string }>,
): Promise<PinnedHttpsResponse> {
    if (signal.aborted) throw new PackageStageError('graph_metadata_incomplete');
    return await new Promise((resolvePromise, reject) => {
      let settled = false;
      const url = new URL(input.url);
      const fail = () => {
        if (settled) return;
        settled = true;
        reject(new PackageStageError('graph_metadata_incomplete'));
      };
      const pinnedLookup: LookupFunction = (_hostname, options, callback) => {
        if (options.all === true) callback(null, [{ address: input.address, family: input.family }]);
        else callback(null, input.address, input.family);
      };
      const options: HttpsRequestOptions = {
        protocol: 'https:',
        hostname: input.hostname,
        servername: input.hostname,
        port: connection.port,
        method: 'GET',
        path: url.pathname,
        headers: {
          Host: input.hostname,
          Accept: input.headers.accept,
          'Accept-Encoding': input.headers.acceptEncoding,
          Connection: 'close',
        },
        agent: false,
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2',
        ...(connection.ca === undefined ? {} : { ca: connection.ca }),
        lookup: pinnedLookup,
      };
      const request = httpsRequest(options, (response) => {
        const rawContentLength = response.headers['content-length'];
        const contentLength = rawContentLength === undefined ? undefined : Number(rawContentLength);
        if (contentLength !== undefined && (!Number.isSafeInteger(contentLength) || contentLength < 0
          || contentLength > input.maximumBytes)) {
          response.destroy();
          fail();
          return;
        }
        const chunks: Buffer[] = [];
        let bytes = 0;
        response.on('data', (chunk: Buffer) => {
          bytes += chunk.byteLength;
          if (bytes > input.maximumBytes) { response.destroy(); fail(); return; }
          chunks.push(Buffer.from(chunk));
        });
        response.once('error', fail);
        response.once('aborted', fail);
        response.once('end', () => {
          if (settled) return;
          settled = true;
          resolvePromise(Object.freeze({
            status: response.statusCode ?? 0,
            contentType: String(response.headers['content-type'] ?? ''),
            contentEncoding: String(response.headers['content-encoding'] ?? 'identity'),
            finalUrl: input.url,
            redirected: false as const,
            body: Uint8Array.from(Buffer.concat(chunks)),
          }));
        });
      });
      const abort = () => { request.destroy(); fail(); };
      const totalTimeout = setTimeout(abort, input.timeoutMs);
      totalTimeout.unref();
      signal.addEventListener('abort', abort, { once: true });
      request.setTimeout(input.timeoutMs, abort);
      request.once('error', fail);
      request.once('close', () => {
        clearTimeout(totalTimeout);
        signal.removeEventListener('abort', abort);
      });
      request.end();
    });
}

export interface HardenedPublicMetadataTransport {
  readonly implementationKind: 'production' | 'synthetic';
  fetchPackage(packageName: string, limits: Readonly<{ timeoutMs: number; maximumBytes: number }>, signal: AbortSignal): Promise<PinnedHttpsResponse>;
}

export class BoundedNpmPublicMetadataTransport implements HardenedPublicMetadataTransport {
  readonly implementationKind: PinnedHttpsClient['implementationKind'];
  constructor(
    private readonly resolver: RegistryAddressResolver,
    private readonly client: PinnedHttpsClient,
  ) {
    this.implementationKind = SYSTEM_RESOLVERS.has(resolver) && NODE_PINNED_CLIENTS.has(client)
      ? 'production' : 'synthetic';
  }

  async fetchPackage(
    packageName: string,
    limits: Readonly<{ timeoutMs: number; maximumBytes: number }>,
    signal: AbortSignal,
  ): Promise<PinnedHttpsResponse> {
    if (!PACKAGE_NAME.test(packageName) || !Number.isSafeInteger(limits.timeoutMs) || limits.timeoutMs < 1
      || limits.timeoutMs > 15_000 || !Number.isSafeInteger(limits.maximumBytes)
      || limits.maximumBytes < 1 || limits.maximumBytes > 8 * 1024 * 1024) failMetadata();
    const startedAt = Date.now();
    const addresses = await resolveWithDeadline(this.resolver, signal, limits.timeoutMs);
    if (addresses.length === 0 || addresses.length > 32 || addresses.some((item) => !isPublicAddress(item))) failMetadata();
    const selected = [...addresses].sort((left, right) => Buffer.from(`${left.family}:${left.address}`).compare(Buffer.from(`${right.family}:${right.address}`)))[0]!;
    const encoded = packageName.startsWith('@') ? packageName.replace('/', '%2f') : packageName;
    const url = `https://registry.npmjs.org/${encoded}`;
    const remainingMs = limits.timeoutMs - (Date.now() - startedAt);
    if (remainingMs < 1 || signal.aborted) failMetadataIncomplete();
    const response = await this.client.request(Object.freeze({
      url,
      hostname: 'registry.npmjs.org' as const,
      address: selected.address,
      family: selected.family,
      headers: Object.freeze({
        accept: 'application/vnd.npm.install-v1+json, application/json' as const,
        acceptEncoding: 'identity' as const,
      }),
      timeoutMs: remainingMs,
      maximumBytes: limits.maximumBytes,
    }), signal);
    if (response.status !== 200 || response.redirected || response.finalUrl !== url
      || !['application/json', 'application/vnd.npm.install-v1+json']
        .includes(response.contentType.toLowerCase().split(';', 1)[0] ?? '')
      || !['', 'identity'].includes(response.contentEncoding.toLowerCase())
      || response.body.byteLength === 0 || response.body.byteLength > limits.maximumBytes) failMetadata();
    let text: string;
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(response.body); } catch { failMetadata(); }
    const document = parseStrictJsonDocument(text);
    if (!isRecord(document) || document.name !== packageName) failMetadata();
    return Object.freeze({ ...response, body: Uint8Array.from(response.body) });
  }
}

export type HardenedBrokerLedgerEntry = Readonly<{
  sequence: number;
  packageName: string;
  responseBytes: number;
  bodySha256: string;
}>;

export type AuthenticatedHardenedBrokerLedger = Readonly<{
  ledgerVersion: 2;
  planHash: string;
  startedRequestCount: number;
  uniquePackageCount: number;
  aggregateResponseBytes: number;
  entries: readonly HardenedBrokerLedgerEntry[];
  terminalState: 'disarmed_complete';
  ledgerDigest: string;
}>;

type BrokerSession = {
  readonly plan: HardenedGraphGenesisPlan;
  readonly capsule: AuthenticatedGraphGenesisExecutionCapsule;
  readonly audit: GraphGenesisAuditGate;
  readonly transport: HardenedPublicMetadataTransport;
  readonly onFailure: () => void | Promise<void>;
  readonly controller: AbortController;
  readonly names: Set<string>;
  readonly entries: HardenedBrokerLedgerEntry[];
  state: 'disarmed' | 'armed' | 'failing' | 'incomplete' | 'complete';
  startedRequests: number;
  activeRequests: number;
  reservedBytes: number;
  committedBytes: number;
};

export class HardenedMetadataBrokerAuthority {
  readonly #sessions = new WeakSet<object>();
  readonly #ledgers = new WeakSet<object>();
  readonly #usedAuthorizations = new WeakSet<object>();

  constructor(private readonly plans: HardenedGraphGenesisPlanAuthority) {}

  prepareSession(input: Readonly<{
    plan: HardenedGraphGenesisPlan;
    capsule: AuthenticatedGraphGenesisExecutionCapsule;
    authorization: HardenedGraphGenesisAuthorization;
    authorizationVerifier: HardenedGraphGenesisAuthorizationVerifier;
    audit: GraphGenesisAuditGate;
    transport: HardenedPublicMetadataTransport;
    onFailure: () => void | Promise<void>;
    mode: 'production' | 'synthetic';
    now?: Date;
  }>): object {
    const now = input.now ?? new Date();
    if (!this.plans.authenticatesPair(input.plan, input.capsule)
      || !input.authorizationVerifier.authenticatesAuthorization(input.authorization)
      || this.#usedAuthorizations.has(input.authorization)
      || input.authorization.planHash !== input.plan.planHash
      || input.authorization.implementationKind !== input.mode
      || input.transport.implementationKind !== input.mode
      || Date.parse(input.authorization.expiresAt) <= now.getTime()
      || input.audit.planHash !== input.plan.planHash
      || (input.mode === 'production' && input.audit.implementationKind !== 'production')) failMetadata();
    this.#usedAuthorizations.add(input.authorization);
    const session: BrokerSession = {
      plan: input.plan,
      capsule: input.capsule,
      audit: input.audit,
      transport: input.transport,
      onFailure: input.onFailure,
      controller: new AbortController(),
      names: new Set(),
      entries: [],
      state: 'disarmed',
      startedRequests: 0,
      activeRequests: 0,
      reservedBytes: 0,
      committedBytes: 0,
    };
    this.#sessions.add(session);
    return session;
  }

  async arm(opaque: object): Promise<void> {
    const session = this.#session(opaque);
    if (session.state !== 'disarmed') failMetadata();
    await session.audit.record('authorization_finalized');
    await session.audit.record('broker_armed');
    session.state = 'armed';
  }

  async handle(opaque: object, method: string, path: string, headers: Readonly<Record<string, string | undefined>>): Promise<Uint8Array> {
    const session = this.#session(opaque);
    let packageName: string;
    let sequence: number | undefined;
    try {
      packageName = parseLocalRequest(method, path, headers, session.capsule.routeToken);
      sequence = reserve(session, packageName);
      await session.audit.record('metadata_request_started', { sequence, packageName });
      if (session.state !== 'armed') failMetadata();
      const response = await session.transport.fetchPackage(packageName, {
        timeoutMs: session.plan.limits.broker.requestTimeoutMs,
        maximumBytes: session.plan.limits.broker.responseBytes,
      }, session.controller.signal);
      if (session.state !== 'armed' || session.controller.signal.aborted) failMetadata();
      const nextCommitted = session.committedBytes + response.body.byteLength;
      if (nextCommitted > session.plan.limits.broker.aggregateResponseBytes) failMetadata();
      await session.audit.record('metadata_response_validated', {
        sequence,
        packageName,
        responseBytes: response.body.byteLength,
      });
      if (session.state !== 'armed') failMetadata();
      const entry = Object.freeze({
        sequence,
        packageName,
        responseBytes: response.body.byteLength,
        bodySha256: sha256(response.body),
      });
      session.entries.push(entry);
      session.committedBytes = nextCommitted;
      session.reservedBytes -= session.plan.limits.broker.responseBytes;
      session.reservedBytes += response.body.byteLength;
      return Uint8Array.from(response.body);
    } catch (error) {
      await this.#fail(session);
      if (error instanceof PackageStageError) throw error;
      throw new PackageStageError('graph_metadata_invalid');
    } finally {
      if (sequence !== undefined) session.activeRequests -= 1;
    }
  }

  async complete(opaque: object): Promise<AuthenticatedHardenedBrokerLedger> {
    const session = this.#session(opaque);
    if (session.state !== 'armed' || session.activeRequests !== 0 || session.entries.length === 0
      || session.entries.length !== session.startedRequests) {
      await this.#fail(session);
      failMetadata();
    }
    session.state = 'complete';
    const unsigned = deepFreeze({
      ledgerVersion: 2 as const,
      planHash: session.plan.planHash,
      startedRequestCount: session.startedRequests,
      uniquePackageCount: session.names.size,
      aggregateResponseBytes: session.committedBytes,
      entries: Object.freeze([...session.entries].sort((left, right) => left.sequence - right.sequence)),
      terminalState: 'disarmed_complete' as const,
    });
    const ledger = deepFreeze({ ...unsigned, ledgerDigest: sha256(canonicalJson(unsigned)) });
    this.#ledgers.add(ledger);
    return ledger;
  }

  async abort(opaque: object): Promise<void> {
    await this.#fail(this.#session(opaque));
  }

  authenticatesLedger(value: unknown): value is AuthenticatedHardenedBrokerLedger {
    return typeof value === 'object' && value !== null && this.#ledgers.has(value);
  }

  async #fail(session: BrokerSession): Promise<void> {
    if (session.state === 'incomplete' || session.state === 'failing' || session.state === 'complete') return;
    session.state = 'failing';
    session.controller.abort();
    try { await session.onFailure(); } catch { /* terminal state still remains incomplete */ }
    try { await session.audit.record('genesis_incomplete', { externalReadMayHaveOccurred: session.startedRequests > 0 }); } catch { /* preserve failure */ }
    session.state = 'incomplete';
  }

  #session(value: object): BrokerSession {
    if (!this.#sessions.has(value)) failMetadata();
    return value as BrokerSession;
  }
}

function reserve(session: BrokerSession, packageName: string): number {
  if (session.state !== 'armed') failMetadata();
  const limits = session.plan.limits.broker;
  if (session.startedRequests >= limits.totalRequests || session.activeRequests >= limits.concurrentRequests) failMetadata();
  const newName = !session.names.has(packageName);
  if (newName && session.names.size >= limits.uniquePackageNames) failMetadata();
  if (session.reservedBytes + limits.responseBytes > limits.aggregateResponseBytes) failMetadata();
  session.startedRequests += 1;
  session.activeRequests += 1;
  session.reservedBytes += limits.responseBytes;
  if (newName) session.names.add(packageName);
  return session.startedRequests;
}

function parseLocalRequest(method: string, path: string, headers: Readonly<Record<string, string | undefined>>, token: string): string {
  if (method !== 'GET' || path.includes('?') || path.includes('#') || hasSensitiveHeader(headers)) failMetadata();
  const expectedPrefix = `/${token}/`;
  const actualPrefix = path.slice(0, expectedPrefix.length);
  if (!safeEqual(actualPrefix, expectedPrefix)) failMetadata();
  const encoded = path.slice(expectedPrefix.length);
  if (encoded.length === 0 || encoded.includes('/')) failMetadata();
  let name: string;
  try { name = decodeURIComponent(encoded); } catch { failMetadata(); }
  const canonical = name.startsWith('@') ? name.replace('/', '%2f') : name;
  if (!PACKAGE_NAME.test(name) || encoded !== canonical) failMetadata();
  return name;
}

function hasSensitiveHeader(headers: Readonly<Record<string, string | undefined>>): boolean {
  const sensitive = new Set(['authorization', 'cookie', 'proxy-authorization', 'npm-auth-token']);
  return Object.keys(headers).some((name) => sensitive.has(name.toLowerCase()));
}

function safeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

export class HardenedLoopbackBrokerListener {
  #server: Server | undefined;
  #session: object | undefined;
  #port: number | undefined;

  constructor(private readonly broker: HardenedMetadataBrokerAuthority) {}

  async listen(): Promise<number> {
    if (this.#server !== undefined) failMetadata();
    const server = createServer({ maxHeaderSize: 16 * 1024, requestTimeout: 5_000, headersTimeout: 5_000 },
      (request, response) => { void this.#respond(request, response); });
    server.keepAliveTimeout = 1;
    server.maxRequestsPerSocket = 1;
    server.maxHeadersCount = 32;
    server.setTimeout(5_000, (socket) => socket.destroy());
    await new Promise<void>((resolvePromise, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => resolvePromise());
    });
    this.#server = server;
    const address = server.address();
    if (address === null || typeof address === 'string' || address.address !== '127.0.0.1') {
      await this.close();
      failMetadata();
    }
    this.#port = address.port;
    return address.port;
  }

  arm(session: object): void {
    if (this.#server === undefined || this.#session !== undefined) failMetadata();
    this.#session = session;
  }

  async close(): Promise<void> {
    const server = this.#server;
    this.#server = undefined;
    this.#session = undefined;
    this.#port = undefined;
    if (server === undefined) return;
    server.closeAllConnections();
    await new Promise<void>((resolvePromise) => server.close(() => resolvePromise()));
  }

  async #respond(request: IncomingMessage, response: ServerResponse): Promise<void> {
    response.setHeader('Connection', 'close');
    const session = this.#session;
    if (session === undefined) {
      response.writeHead(404, { 'Content-Type': 'application/json' });
      response.end('{"error":"request_rejected"}');
      return;
    }
    const requestUrl = request.url;
    const hostValues = request.headersDistinct.host ?? [];
    const malformed = requestUrl === undefined || requestUrl.length > 2_048 || request.headers.upgrade !== undefined
      || request.headers['transfer-encoding'] !== undefined || Number(request.headers['content-length'] ?? 0) !== 0
      || hostValues.length !== 1 || hostValues[0] !== `127.0.0.1:${this.#port}`
      || ['authorization', 'cookie', 'proxy-authorization', 'npm-auth-token']
        .some((name) => (request.headersDistinct[name] ?? []).length > 0);
    if (malformed) {
      this.#session = undefined;
      await this.broker.abort(session);
      response.writeHead(502, { 'Content-Type': 'application/json' });
      response.end('{"error":"request_failed"}');
      return;
    }
    const headers = Object.fromEntries(Object.entries(request.headers).map(([name, value]) => [name, Array.isArray(value) ? value.join(',') : value]));
    try {
      const body = await this.broker.handle(session, request.method ?? '', requestUrl!, headers);
      response.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': body.byteLength });
      response.end(body);
    } catch {
      this.#session = undefined;
      response.writeHead(502, { 'Content-Type': 'application/json' });
      response.end('{"error":"request_failed"}');
    }
  }
}

export function isPublicAddress(input: ResolvedAddress): boolean {
  if (isIP(input.address) !== input.family) return false;
  const bytes = input.family === 4 ? parseIpv4(input.address) : parseIpv6(input.address);
  if (bytes === undefined) return false;
  if (input.family === 4) return !NON_PUBLIC_V4.some(([prefix, bits]) => hasPrefix(bytes, prefix, bits));
  const mapped = ipv4Mapped(bytes);
  if (mapped !== undefined) return isPublicAddress({ address: mapped.join('.'), family: 4 });
  return !NON_PUBLIC_V6.some(([prefix, bits]) => hasPrefix(bytes, prefix, bits));
}

const NON_PUBLIC_V4: readonly [readonly number[], number][] = [
  [[0, 0, 0, 0], 8], [[10, 0, 0, 0], 8], [[100, 64, 0, 0], 10], [[127, 0, 0, 0], 8],
  [[169, 254, 0, 0], 16], [[172, 16, 0, 0], 12], [[192, 0, 0, 0], 24], [[192, 0, 2, 0], 24],
  [[192, 88, 99, 0], 24], [[192, 168, 0, 0], 16], [[198, 18, 0, 0], 15], [[198, 51, 100, 0], 24],
  [[203, 0, 113, 0], 24], [[224, 0, 0, 0], 4], [[240, 0, 0, 0], 4],
];

const NON_PUBLIC_V6: readonly [readonly number[], number][] = [
  [new Array(16).fill(0), 128], [[...new Array(15).fill(0), 1], 128],
  [[0x01, 0x00, ...new Array(14).fill(0)], 64],
  [[0xfc, ...new Array(15).fill(0)], 7], [[0xfe, 0x80, ...new Array(14).fill(0)], 10],
  [[0xff, ...new Array(15).fill(0)], 8], [[0x20, 0x01, ...new Array(14).fill(0)], 23],
  [[0x20, 0x01, 0x0d, 0xb8, ...new Array(12).fill(0)], 32],
  [[0x20, 0x01, 0x00, 0x02, ...new Array(12).fill(0)], 48],
  [[0x00, 0x64, 0xff, 0x9b, ...new Array(12).fill(0)], 96],
  [[0x00, 0x64, 0xff, 0x9b, 0x00, 0x01, ...new Array(10).fill(0)], 48],
  [[0x20, 0x02, ...new Array(14).fill(0)], 16],
  [[0x3f, 0xff, ...new Array(14).fill(0)], 20],
  [[0x5f, 0x00, ...new Array(14).fill(0)], 16],
];

function parseIpv4(value: string): number[] | undefined {
  const parts = value.split('.').map(Number);
  return parts.length === 4 && parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255) ? parts : undefined;
}

function parseIpv6(value: string): number[] | undefined {
  const [headText, tailText, extra] = value.toLowerCase().split('::');
  if (extra !== undefined) return undefined;
  const parse = (text: string | undefined): number[] | undefined => {
    if (text === undefined || text === '') return [];
    const output: number[] = [];
    for (const part of text.split(':')) {
      if (!/^[a-f0-9]{1,4}$/u.test(part)) return undefined;
      const value16 = Number.parseInt(part, 16);
      output.push(value16 >> 8, value16 & 0xff);
    }
    return output;
  };
  const head = parse(headText);
  const tail = parse(tailText);
  if (head === undefined || tail === undefined) return undefined;
  if (tailText === undefined) return head.length === 16 ? head : undefined;
  const zeroBytes = 16 - head.length - tail.length;
  return zeroBytes >= 2 ? [...head, ...new Array(zeroBytes).fill(0), ...tail] : undefined;
}

function ipv4Mapped(bytes: readonly number[]): number[] | undefined {
  return bytes.slice(0, 10).every((byte) => byte === 0) && bytes[10] === 0xff && bytes[11] === 0xff
    ? bytes.slice(12) : undefined;
}

function hasPrefix(address: readonly number[], prefix: readonly number[], bits: number): boolean {
  const full = Math.floor(bits / 8);
  const remainder = bits % 8;
  for (let index = 0; index < full; index += 1) if (address[index] !== prefix[index]) return false;
  if (remainder === 0) return true;
  const mask = (0xff << (8 - remainder)) & 0xff;
  return ((address[full] ?? 0) & mask) === ((prefix[full] ?? 0) & mask);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

async function resolveWithDeadline(
  resolver: RegistryAddressResolver,
  signal: AbortSignal,
  timeoutMs: number,
): Promise<readonly ResolvedAddress[]> {
  if (signal.aborted) failMetadataIncomplete();
  return await new Promise((resolvePromise, reject) => {
    let settled = false;
    const finishError = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      signal.removeEventListener('abort', finishError);
      reject(new PackageStageError('graph_metadata_incomplete'));
    };
    const timeout = setTimeout(finishError, timeoutMs);
    timeout.unref();
    signal.addEventListener('abort', finishError, { once: true });
    void resolver.resolve('registry.npmjs.org', signal).then((addresses) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      signal.removeEventListener('abort', finishError);
      resolvePromise(addresses);
    }, finishError);
  });
}

function failMetadata(): never { throw new PackageStageError('graph_metadata_invalid'); }
function failMetadataIncomplete(): never { throw new PackageStageError('graph_metadata_incomplete'); }

function sha256(value: string | Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
}

function deepFreeze<T>(input: T): T {
  if (typeof input !== 'object' || input === null || Object.isFrozen(input)) return input;
  for (const value of Object.values(input)) deepFreeze(value);
  return Object.freeze(input);
}
