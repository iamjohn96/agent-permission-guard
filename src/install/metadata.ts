import type {
  InstallMetadataProvider,
  InstallRequest,
  InstallResolution,
} from './types.js';

export class InMemoryInstallMetadataProvider implements InstallMetadataProvider {
  readonly #resolutions: ReadonlyMap<string, InstallResolution>;

  constructor(entries: readonly Readonly<{
    request: Pick<InstallRequest, 'runner' | 'packageName' | 'requestedSpecifier'>;
    resolution: InstallResolution;
  }>[]) {
    this.#resolutions = new Map(entries.map((entry) => [requestKey(entry.request), entry.resolution]));
  }

  async resolve(request: InstallRequest): Promise<InstallResolution> {
    return this.#resolutions.get(requestKey(request)) ?? {
      status: 'unavailable',
      reason: 'No offline metadata fixture exists for this exact request',
    };
  }
}

function requestKey(
  request: Pick<InstallRequest, 'runner' | 'packageName' | 'requestedSpecifier'>,
): string {
  return `${request.runner}\0${request.packageName}\0${request.requestedSpecifier}`;
}
