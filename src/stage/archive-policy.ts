import { PackageStageError } from './profile.js';
import type {
  ArchiveEntryDescription,
  ArchivePreflightResult,
  PackageStageLimits,
  ValidatedArchiveEntry,
} from './types.js';

const ENTRY_KEYS = new Set([
  'path',
  'type',
  'size',
  'mode',
  'linkTarget',
  'sparse',
  'hasExtendedAttributes',
]);

export class PortableArchivePolicy {
  #aggregateExpandedBytes = 0;
  #aggregateEntries = 0;

  constructor(private readonly limits: PackageStageLimits) {}

  preflight(input: readonly ArchiveEntryDescription[]): ArchivePreflightResult {
    if (!Array.isArray(input) || input.length === 0) throw new PackageStageError('archive_invalid');
    const entries: ValidatedArchiveEntry[] = [];
    const exactPaths = new Set<string>();
    const portablePaths = new Set<string>();
    let expandedBytes = 0;

    for (const entry of input) {
      assertEntryShape(entry);
      if (entry.type !== 'file' && entry.type !== 'directory') {
        throw new PackageStageError('archive_invalid');
      }
      if (
        entry.sparse === true
        || entry.hasExtendedAttributes === true
        || entry.linkTarget !== undefined
        || !Number.isSafeInteger(entry.size)
        || entry.size < 0
        || !Number.isSafeInteger(entry.mode)
        || entry.mode < 0
        || entry.mode > 0o7777
        || (entry.mode & 0o6000) !== 0
        || (entry.type === 'directory' && entry.size !== 0)
      ) {
        throw new PackageStageError('archive_invalid');
      }

      const relativePath = archiveRelativePath(entry.path, this.limits);
      const segments = relativePath.split('/');
      if (segments.includes('node_modules') || segments.includes('.npmrc')) {
        throw new PackageStageError('archive_invalid');
      }
      const portableKey = relativePath.toLocaleLowerCase('en-US');
      if (exactPaths.has(relativePath) || portablePaths.has(portableKey)) {
        throw new PackageStageError('archive_invalid');
      }
      exactPaths.add(relativePath);
      portablePaths.add(portableKey);

      if (entry.type === 'file') {
        if (entry.size > this.limits.regularFileBytes) {
          throw new PackageStageError('archive_limit_exceeded');
        }
        expandedBytes += entry.size;
      }
      if (
        expandedBytes > this.limits.uncompressedArtifactBytes
        || this.#aggregateExpandedBytes + expandedBytes > this.limits.totalUncompressedBytes
      ) {
        throw new PackageStageError('archive_limit_exceeded');
      }

      entries.push(Object.freeze({
        relativePath,
        type: entry.type,
        size: entry.size,
        normalizedMode: entry.type === 'directory' ? 0o755 : (entry.mode & 0o111) === 0 ? 0o644 : 0o755,
      }));
    }

    if (
      entries.length > this.limits.archiveEntries
      || this.#aggregateEntries + entries.length > this.limits.archiveEntries
    ) {
      throw new PackageStageError('archive_limit_exceeded');
    }
    entries.sort((left, right) => compareText(left.relativePath, right.relativePath));
    this.#aggregateExpandedBytes += expandedBytes;
    this.#aggregateEntries += entries.length;
    return Object.freeze({
      entries: Object.freeze(entries),
      entryCount: entries.length,
      expandedBytes,
    });
  }
}

function archiveRelativePath(path: string, limits: PackageStageLimits): string {
  if (
    typeof path !== 'string'
    || path.length === 0
    || path.startsWith('/')
    || path.includes('\\')
    || path.includes('\0')
    || /[\u0000-\u001f\u007f]/u.test(path)
    || path.normalize('NFC') !== path
    || Buffer.byteLength(path, 'utf8') > limits.relativePathBytes
  ) {
    throw new PackageStageError('archive_invalid');
  }
  const segments = path.split('/');
  if (
    segments[0] !== 'package'
    || segments.length < 2
    || segments.length - 1 > limits.pathDepth
    || segments.some((segment) => segment.length === 0 || segment === '.' || segment === '..')
  ) {
    throw new PackageStageError('archive_invalid');
  }
  return segments.slice(1).join('/');
}

function assertEntryShape(input: unknown): asserts input is ArchiveEntryDescription {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw new PackageStageError('archive_invalid');
  }
  const keys = Object.keys(input);
  if (
    !keys.includes('path')
    || !keys.includes('type')
    || !keys.includes('size')
    || !keys.includes('mode')
    || keys.some((key) => !ENTRY_KEYS.has(key))
  ) {
    throw new PackageStageError('archive_invalid');
  }
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
