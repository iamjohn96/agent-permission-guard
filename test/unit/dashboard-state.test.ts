import { chmodSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { writeDashboardStateFile } from '../../src/dashboard/state-file.js';

const temporaryPaths: string[] = [];

afterEach(() => {
  for (const path of temporaryPaths.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe('dashboard state file', () => {
  it('writes private state atomically and removes its own file', () => {
    const directory = temporaryDirectory();
    const statePath = join(directory, 'dashboard.json');
    const url = dashboardUrl('a');
    const stateFile = writeDashboardStateFile(statePath, url, 1234, new Date('2026-08-25T00:00:00.000Z'));
    const state = JSON.parse(readFileSync(statePath, 'utf8')) as Record<string, unknown>;

    expect(state).toEqual({
      version: 1,
      url,
      pid: 1234,
      started_at: '2026-08-25T00:00:00.000Z',
    });
    if (process.platform !== 'win32') {
      expect(statSync(directory).mode & 0o777).toBe(0o700);
      expect(statSync(statePath).mode & 0o777).toBe(0o600);
    }
    expect(readdirSync(directory)).toEqual(['dashboard.json']);

    stateFile.remove();
    expect(existsSync(statePath)).toBe(false);
  });

  it('does not remove state written by a newer APG process', () => {
    const directory = temporaryDirectory();
    const statePath = join(directory, 'dashboard.json');
    const first = writeDashboardStateFile(statePath, dashboardUrl('a'), 111);
    const second = writeDashboardStateFile(statePath, dashboardUrl('b'), 222);

    first.remove();
    expect(existsSync(statePath)).toBe(true);
    expect(readFileSync(statePath, 'utf8')).toContain('222');

    second.remove();
    expect(existsSync(statePath)).toBe(false);
  });

  it('rejects an unsafe parent directory and non-loopback URL', () => {
    const directory = temporaryDirectory();
    if (process.platform !== 'win32') chmodSync(directory, 0o755);

    if (process.platform !== 'win32') {
      expect(() => writeDashboardStateFile(join(directory, 'dashboard.json'), dashboardUrl('a')))
        .toThrow(/group or other access/);
    }
    expect(() => writeDashboardStateFile(
      join(temporaryDirectory(), 'dashboard.json'),
      `https://example.com/#token=${'t'.repeat(43)}`,
    )).toThrow(/tokenized 127\.0\.0\.1/);
  });
});

function temporaryDirectory(): string {
  const path = mkdtempSync(join(tmpdir(), 'apg-dashboard-state-'));
  chmodSync(path, 0o700);
  temporaryPaths.push(path);
  return path;
}

function dashboardUrl(seed: string): string {
  return `http://127.0.0.1:47831/#token=${seed.repeat(43)}`;
}
