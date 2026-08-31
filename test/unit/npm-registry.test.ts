import { describe, expect, it, vi } from 'vitest';

import {
  FetchNpmRegistryTransport,
  NpmRegistryMetadataProvider,
  type NpmRegistryTransport,
  type RegistryResponse,
} from '../../src/install/npm-registry.js';
import { parseInstallRequest } from '../../src/install/parser.js';
import { evaluateInstallPolicy } from '../../src/install/policy.js';

const workingDirectory = '/tmp/apg-registry-test';

describe('npm registry metadata provider', () => {
  it('resolves exact versions from abbreviated metadata without claiming complete evidence', async () => {
    const transport = new FakeRegistryTransport([okPackument('yaml', '2.9.0', true)]);
    const provider = createProvider(transport);
    const request = parseInstallRequest('npm', ['yaml@2.9.0'], workingDirectory);

    const resolution = await provider.resolve(request);

    expect(resolution).toMatchObject({
      status: 'resolved',
      metadata: {
        packageName: 'yaml',
        version: '2.9.0',
        lifecycleScripts: ['install'],
        evidenceComplete: false,
      },
    });
    expect(evaluateInstallPolicy(resolution)).toMatchObject({ effectiveDecision: 'ask' });
    expect(evaluateInstallPolicy(resolution).reasonCodes).toEqual([
      'lifecycle_scripts',
      'limited_registry_evidence',
    ]);
  });

  it('locks a dist-tag to the exact version returned in the same document', async () => {
    const transport = new FakeRegistryTransport([okPackument('yaml', '2.9.0', false)]);
    const provider = createProvider(transport);
    const request = parseInstallRequest('npx', ['yaml@latest'], workingDirectory);

    await expect(provider.resolve(request)).resolves.toMatchObject({
      status: 'resolved',
      metadata: { version: '2.9.0' },
    });
  });

  it('fails closed on version ranges that need a full semver resolver', async () => {
    const transport = new FakeRegistryTransport([okPackument('yaml', '2.9.0', false)]);
    const provider = createProvider(transport);
    const request = parseInstallRequest('npm', ['yaml@^2.0.0'], workingDirectory);

    await expect(provider.resolve(request)).resolves.toMatchObject({ status: 'unresolved' });
  });

  it('encodes scoped package names and never adds credentials to the request URL', async () => {
    const transport = new FakeRegistryTransport([okPackument('@scope/pkg', '1.0.0', false)]);
    const provider = createProvider(transport);
    const request = parseInstallRequest('npm', ['@scope/pkg@1.0.0'], workingDirectory);

    await provider.resolve(request);

    expect(transport.urls).toHaveLength(1);
    expect(transport.urls[0]?.href).toBe('https://registry.npmjs.org/%40scope%2Fpkg');
    expect(transport.urls[0]?.username).toBe('');
    expect(transport.urls[0]?.password).toBe('');
  });

  it('rejects inconsistent registry identity and does not cache transient failures', async () => {
    const transport = new FakeRegistryTransport([
      okPackument('different-package', '2.9.0', false),
      new Error('temporary private network detail'),
    ]);
    const provider = createProvider(transport);
    const request = parseInstallRequest('npm', ['yaml@2.9.0'], workingDirectory);

    await expect(provider.resolve(request)).resolves.toMatchObject({ status: 'contradictory' });
    const unavailable = await provider.resolve(request);
    expect(unavailable).toMatchObject({ status: 'unavailable' });
    expect(JSON.stringify(unavailable)).not.toContain('private network detail');
    expect(transport.urls).toHaveLength(2);
  });

  it('uses a short in-memory cache scoped to the exact package request', async () => {
    let now = 1_000;
    const transport = new FakeRegistryTransport([
      okPackument('yaml', '2.9.0', false),
      okPackument('yaml', '2.9.0', false),
      okPackument('yaml', '2.9.0', false),
    ]);
    const provider = createProvider(transport, () => new Date(now));
    const exact = parseInstallRequest('npm', ['yaml@2.9.0'], workingDirectory);
    const tagged = parseInstallRequest('npm', ['yaml@latest'], workingDirectory);

    await provider.resolve(exact);
    await provider.resolve(exact);
    expect(transport.urls).toHaveLength(1);

    await provider.resolve(tagged);
    expect(transport.urls).toHaveLength(2);

    now += 300_001;
    await provider.resolve(exact);
    expect(transport.urls).toHaveLength(3);
  });

  it.each([
    'http://registry.npmjs.org',
    'https://user:secret@registry.npmjs.org',
    'https://registry.npmjs.org?token=secret',
    'not-a-url',
  ])('rejects unsafe registry configuration: %s', (registry) => {
    expect(() => new NpmRegistryMetadataProvider({
      registry,
      transport: new FakeRegistryTransport([]),
    })).toThrow(/Registry/);
  });
});

describe('npm registry fetch transport', () => {
  it('uses a bounded anonymous GET and rejects redirects by policy', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      name: 'yaml',
      'dist-tags': {},
      versions: {},
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/vnd.npm.install-v1+json' },
    }));
    try {
      const transport = new FetchNpmRegistryTransport();
      await transport.getPackage(new URL('https://registry.npmjs.org/yaml'));

      expect(fetchMock).toHaveBeenCalledOnce();
      const [, options] = fetchMock.mock.calls[0] ?? [];
      expect(options).toMatchObject({ method: 'GET', redirect: 'error' });
      expect(options?.headers).toEqual({
        Accept: 'application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8',
      });
      expect(JSON.stringify(options?.headers)).not.toMatch(/authorization|token|cookie/i);
    } finally {
      fetchMock.mockRestore();
    }
  });

  it('rejects a declared oversized response before parsing it', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{}', {
      status: 200,
      headers: {
        'Content-Type': 'application/vnd.npm.install-v1+json',
        'Content-Length': '5000001',
      },
    }));
    try {
      const transport = new FetchNpmRegistryTransport();
      await expect(transport.getPackage(new URL('https://registry.npmjs.org/yaml'))).rejects.toThrow(/too large/);
    } finally {
      fetchMock.mockRestore();
    }
  });
});

class FakeRegistryTransport implements NpmRegistryTransport {
  readonly urls: URL[] = [];

  constructor(private readonly responses: Array<RegistryResponse | Error>) {}

  async getPackage(url: URL): Promise<RegistryResponse> {
    this.urls.push(new URL(url));
    const response = this.responses.shift();
    if (response instanceof Error) throw response;
    if (response === undefined) throw new Error('No fake registry response configured');
    return response;
  }
}

function createProvider(
  transport: NpmRegistryTransport,
  now: () => Date = () => new Date('2026-08-31T00:00:00.000Z'),
): NpmRegistryMetadataProvider {
  return new NpmRegistryMetadataProvider({
    registry: 'https://registry.npmjs.org/',
    transport,
    now,
    cacheTtlMs: 300_000,
  });
}

function okPackument(packageName: string, version: string, hasInstallScript: boolean): RegistryResponse {
  return {
    status: 200,
    contentType: 'application/vnd.npm.install-v1+json; charset=utf-8',
    body: {
      name: packageName,
      'dist-tags': { latest: version },
      versions: {
        [version]: {
          name: packageName,
          version,
          hasInstallScript,
          dist: {
            tarball: `https://registry.npmjs.org/${encodeURIComponent(packageName)}/-/${version}.tgz`,
            integrity: 'sha512-test',
          },
        },
      },
    },
  };
}
