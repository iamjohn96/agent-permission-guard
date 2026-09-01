import type {
  InstallMetadataProvider,
  InstallRequest,
  InstallResolution,
  ResolvedPackageMetadata,
} from './types.js';

const INSTALL_METADATA = 'application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8';
const EXACT_VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const DIST_TAG = /^[a-zA-Z][a-zA-Z0-9._-]*$/;

export type RegistryResponse = Readonly<{
  status: number;
  contentType: string;
  body: unknown;
}>;

export interface NpmRegistryTransport {
  getPackage(url: URL): Promise<RegistryResponse>;
}

export class FetchNpmRegistryTransport implements NpmRegistryTransport {
  constructor(private readonly options: Readonly<{
    timeoutMs?: number;
    maximumBytes?: number;
  }> = {}) {}

  async getPackage(url: URL): Promise<RegistryResponse> {
    const timeoutMs = this.options.timeoutMs ?? 5_000;
    const maximumBytes = this.options.maximumBytes ?? 5_000_000;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60_000) {
      throw new Error('npm registry timeout must be between 100 and 60000 milliseconds');
    }
    if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1_024 || maximumBytes > 20_000_000) {
      throw new Error('npm registry response limit must be between 1024 and 20000000 bytes');
    }
    const response = await fetch(url, {
      method: 'GET',
      headers: { Accept: INSTALL_METADATA },
      redirect: 'error',
      signal: AbortSignal.timeout(timeoutMs),
    });
    const contentType = response.headers.get('content-type') ?? '';
    if (response.status !== 200 || !isJsonContentType(contentType)) {
      await response.body?.cancel();
      return { status: response.status, contentType, body: undefined };
    }
    const contentLength = Number(response.headers.get('content-length') ?? 0);
    if (Number.isFinite(contentLength) && contentLength > maximumBytes) {
      await response.body?.cancel();
      throw new Error('npm registry metadata response is too large');
    }
    const body = await readBoundedJson(response, maximumBytes);
    return {
      status: response.status,
      contentType,
      body,
    };
  }
}

export class NpmRegistryMetadataProvider implements InstallMetadataProvider {
  readonly #registry: URL;
  readonly #cache = new Map<string, Readonly<{ expiresAt: number; resolution: InstallResolution }>>();

  constructor(private readonly options: Readonly<{
    registry: string;
    transport: NpmRegistryTransport;
    now?: () => Date;
    cacheTtlMs?: number;
    maximumCacheEntries?: number;
  }>) {
    this.#registry = validateRegistryUrl(options.registry);
    const cacheTtlMs = options.cacheTtlMs ?? 300_000;
    const maximumCacheEntries = options.maximumCacheEntries ?? 128;
    if (!Number.isSafeInteger(cacheTtlMs) || cacheTtlMs < 0 || cacheTtlMs > 3_600_000) {
      throw new Error('Registry cache TTL must be between 0 and 3600000 milliseconds');
    }
    if (!Number.isSafeInteger(maximumCacheEntries) || maximumCacheEntries < 1 || maximumCacheEntries > 1_000) {
      throw new Error('Registry cache size must be between 1 and 1000 entries');
    }
  }

  async resolve(request: InstallRequest): Promise<InstallResolution> {
    const now = (this.options.now ?? (() => new Date()))().getTime();
    if (!Number.isFinite(now)) return { status: 'unavailable', reason: 'Registry clock was invalid' };
    const cacheKey = `${request.packageName}\0${request.requestedSpecifier}`;
    const cached = this.#cache.get(cacheKey);
    if (cached !== undefined && cached.expiresAt > now) return cached.resolution;

    const url = new URL(encodeURIComponent(request.packageName), this.#registry);
    let response: RegistryResponse;
    try {
      response = await this.options.transport.getPackage(url);
    } catch {
      return { status: 'unavailable', reason: 'npm registry metadata request failed' };
    }

    const resolution = resolveResponse(request, response, this.#registry, new Date(now));
    if (resolution.status === 'resolved' || resolution.status === 'unresolved') {
      this.store(cacheKey, resolution, now);
    }
    return resolution;
  }

  private store(cacheKey: string, resolution: InstallResolution, now: number): void {
    const maximumCacheEntries = this.options.maximumCacheEntries ?? 128;
    if (!this.#cache.has(cacheKey) && this.#cache.size >= maximumCacheEntries) {
      const oldest = this.#cache.keys().next().value as string | undefined;
      if (oldest !== undefined) this.#cache.delete(oldest);
    }
    this.#cache.delete(cacheKey);
    this.#cache.set(cacheKey, {
      expiresAt: now + (this.options.cacheTtlMs ?? 300_000),
      resolution,
    });
  }
}

function resolveResponse(
  request: InstallRequest,
  response: RegistryResponse,
  registry: URL,
  observedAt: Date,
): InstallResolution {
  if (response.status === 404) return { status: 'unresolved', reason: 'Package was not found in the npm registry' };
  if (response.status !== 200) return { status: 'unavailable', reason: `npm registry returned HTTP ${response.status}` };
  if (!isJsonContentType(response.contentType)) {
    return { status: 'contradictory', reason: 'npm registry returned an unsupported content type' };
  }
  const packument = asRecord(response.body);
  if (packument === undefined || packument.name !== request.packageName) {
    return { status: 'contradictory', reason: 'npm registry package identity did not match the request' };
  }
  const versions = asRecord(packument.versions);
  const distTags = asRecord(packument['dist-tags']);
  if (versions === undefined || distTags === undefined) {
    return { status: 'contradictory', reason: 'npm registry metadata was missing versions or dist-tags' };
  }

  const version = resolveVersion(request.requestedSpecifier, versions, distTags);
  if (version === undefined) {
    return { status: 'unresolved', reason: 'Requested package version or tag did not resolve exactly' };
  }
  const versionDocument = asRecord(versions[version]);
  const dist = asRecord(versionDocument?.dist);
  if (
    versionDocument === undefined
    || versionDocument.name !== request.packageName
    || versionDocument.version !== version
    || dist === undefined
    || typeof dist.tarball !== 'string'
  ) {
    return { status: 'contradictory', reason: 'Resolved npm version metadata was inconsistent' };
  }

  const executableBins = normalizeExecutableBins(request.packageName, versionDocument.bin);
  const metadata: ResolvedPackageMetadata = Object.freeze({
    packageName: request.packageName,
    version,
    registry: registry.toString(),
    observedAt: observedAt.toISOString(),
    lifecycleScripts: Object.freeze(versionDocument.hasInstallScript === true ? ['install'] : []),
    ...(typeof dist.tarball === 'string' ? { tarballUrl: dist.tarball } : {}),
    ...(typeof dist.integrity === 'string' ? { integrity: dist.integrity } : {}),
    ...(executableBins === undefined ? {} : { executableBins: Object.freeze(executableBins) }),
    advisories: Object.freeze([]),
    possibleTyposquat: false,
    packageIsNew: false,
    publisherIsNew: false,
    repositoryMissing: false,
    provenanceInconsistent: false,
    mutableSource: false,
    evidenceComplete: false,
  });
  return { status: 'resolved', metadata };
}

function normalizeExecutableBins(
  packageName: string,
  input: unknown,
): Readonly<Record<string, string>> | undefined {
  const defaultName = packageName.includes('/') ? packageName.slice(packageName.lastIndexOf('/') + 1) : packageName;
  if (typeof input === 'string' && input.length > 0 && defaultName.length > 0) {
    return { [defaultName]: input };
  }
  const record = asRecord(input);
  if (record === undefined) return undefined;
  const bins = Object.entries(record).filter(
    (entry): entry is [string, string] => /^[a-zA-Z0-9._-]+$/.test(entry[0])
      && typeof entry[1] === 'string'
      && entry[1].length > 0,
  );
  return bins.length === 0 ? undefined : Object.fromEntries(bins);
}

function resolveVersion(
  requested: string,
  versions: Readonly<Record<string, unknown>>,
  distTags: Readonly<Record<string, unknown>>,
): string | undefined {
  if (EXACT_VERSION.test(requested)) return versions[requested] === undefined ? undefined : requested;
  if (!DIST_TAG.test(requested)) return undefined;
  const tagged = distTags[requested];
  return typeof tagged === 'string' && EXACT_VERSION.test(tagged) && versions[tagged] !== undefined
    ? tagged
    : undefined;
}

function validateRegistryUrl(input: string): URL {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new Error('Registry must be a valid HTTPS URL');
  }
  if (
    url.protocol !== 'https:'
    || url.username.length > 0
    || url.password.length > 0
    || url.search.length > 0
    || url.hash.length > 0
  ) {
    throw new Error('Registry must be an HTTPS URL without credentials, query, or fragment');
  }
  url.pathname = `${url.pathname.replace(/\/+$/, '')}/`;
  return url;
}

function isJsonContentType(value: string): boolean {
  const mediaType = value.split(';', 1)[0]?.trim().toLowerCase();
  return mediaType === 'application/json' || mediaType === 'application/vnd.npm.install-v1+json';
}

function asRecord(value: unknown): Readonly<Record<string, unknown>> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Readonly<Record<string, unknown>>
    : undefined;
}

async function readBoundedJson(response: Response, maximumBytes: number): Promise<unknown> {
  if (response.body === null) return undefined;
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      total += next.value.byteLength;
      if (total > maximumBytes) throw new Error('npm registry metadata response is too large');
      chunks.push(next.value);
    }
  } catch (error) {
    await reader.cancel().catch(() => undefined);
    throw error;
  }
  const combined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder().decode(combined)) as unknown;
  } catch {
    throw new Error('npm registry metadata response was not valid JSON');
  }
}
