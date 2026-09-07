import { createHash, timingSafeEqual } from 'node:crypto';

import { PackageStageError, parseSha512Integrity } from './profile.js';
import type { PackageGraphNode, PackageStageLimits } from './types.js';

export type VerifiedPackageArtifact = Readonly<{
  installPath: string;
  tarballUrl: string;
  sha512Integrity: string;
  compressedBytes: number;
}>;

export class PackageArtifactIntegrityAuthority {
  readonly #authenticated = new WeakSet<object>();
  readonly #verifiedPaths = new Set<string>();
  #aggregateBytes = 0;

  constructor(private readonly limits: Pick<PackageStageLimits, 'compressedArtifactBytes' | 'totalCompressedBytes'>) {
    if (
      !Number.isSafeInteger(limits.compressedArtifactBytes)
      || limits.compressedArtifactBytes <= 0
      || !Number.isSafeInteger(limits.totalCompressedBytes)
      || limits.totalCompressedBytes < limits.compressedArtifactBytes
    ) {
      throw new PackageStageError('plan_invalid');
    }
  }

  async verify(
    node: PackageGraphNode,
    source: AsyncIterable<Uint8Array>,
    signal?: AbortSignal,
  ): Promise<VerifiedPackageArtifact> {
    if (this.#verifiedPaths.has(node.installPath)) throw new PackageStageError('integrity_invalid');
    const expected = parseSha512Integrity(node.sha512Integrity);
    const hash = createHash('sha512');
    let artifactBytes = 0;

    try {
      for await (const chunk of source) {
        if (signal?.aborted === true) throw new PackageStageError('artifact_cancelled');
        if (!(chunk instanceof Uint8Array)) throw new PackageStageError('integrity_invalid');
        artifactBytes += chunk.byteLength;
        if (
          artifactBytes > this.limits.compressedArtifactBytes
          || this.#aggregateBytes + artifactBytes > this.limits.totalCompressedBytes
        ) {
          throw new PackageStageError('artifact_too_large');
        }
        hash.update(chunk);
      }
    } catch (error) {
      if (error instanceof PackageStageError) throw error;
      throw new PackageStageError(signal?.aborted === true ? 'artifact_cancelled' : 'integrity_invalid');
    }
    if (signal?.aborted === true) throw new PackageStageError('artifact_cancelled');

    const observed = hash.digest();
    if (observed.length !== expected.length || !timingSafeEqual(observed, expected)) {
      throw new PackageStageError('integrity_mismatch');
    }

    const result = Object.freeze({
      installPath: node.installPath,
      tarballUrl: node.tarballUrl,
      sha512Integrity: node.sha512Integrity,
      compressedBytes: artifactBytes,
    });
    this.#aggregateBytes += artifactBytes;
    this.#verifiedPaths.add(node.installPath);
    this.#authenticated.add(result);
    return result;
  }

  authenticates(candidate: unknown): candidate is VerifiedPackageArtifact {
    return typeof candidate === 'object' && candidate !== null && this.#authenticated.has(candidate);
  }

  assertAuthenticates(candidate: unknown): asserts candidate is VerifiedPackageArtifact {
    if (!this.authenticates(candidate)) throw new PackageStageError('integrity_invalid');
  }

  get aggregateVerifiedBytes(): number {
    return this.#aggregateBytes;
  }
}
