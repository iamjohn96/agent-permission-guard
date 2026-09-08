import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { lstat } from 'node:fs/promises';
import { createServer, type Server } from 'node:net';
import { networkInterfaces } from 'node:os';
import { dirname, join } from 'node:path';
import { promisify } from 'node:util';

import { parseStrictJsonDocument } from './graph-genesis-broker.js';
import type { SeatbeltSelfTestObservations } from './graph-genesis-containment.js';
import type {
  ContainmentProbeBinding,
  ContainmentProbeExecutor,
  AuthenticatedRuntimeFileSnapshot,
} from './graph-genesis-hardening.js';
import type { GraphGenesisWorkspace } from './graph-genesis.js';
import type { SeatbeltLoopbackProfile } from './graph-genesis-containment.js';
import { PackageStageError } from './profile.js';

const execFileAsync = promisify(execFile);

/** Local-only production probe. It never resolves DNS or attempts a public/LAN connection. */
export class LocalSeatbeltContainmentProbeExecutor implements ContainmentProbeExecutor {
  readonly implementationKind = 'local_observed' as const;

  async run(
    binding: ContainmentProbeBinding,
    _profile: SeatbeltLoopbackProfile,
    runtime: Readonly<{
      node: AuthenticatedRuntimeFileSnapshot;
      probe: AuthenticatedRuntimeFileSnapshot;
      sandboxExec: AuthenticatedRuntimeFileSnapshot;
      workspace: GraphGenesisWorkspace;
    }>,
  ): Promise<SeatbeltSelfTestObservations> {
    if (process.platform !== 'darwin' || process.arch !== 'arm64') failProbe();
    const localAddress = Object.values(networkInterfaces()).flat()
      .find((item) => item?.family === 'IPv4' && !item.internal)?.address;
    if (localAddress === undefined) failProbe();
    const outsidePath = join(dirname(runtime.workspace.rootRealpath), `.apg-containment-denied-${randomBytes(8).toString('hex')}`);
    const listeners: Array<Readonly<{ server: Server; port: number }>> = [];
    try {
      const alternate = await localListener('127.0.0.1');
      listeners.push(alternate);
      const nonLoopback = await localListener(localAddress);
      listeners.push(nonLoopback);
      const ipv6 = await localListener('::1');
      listeners.push(ipv6);
      if (await exists(outsidePath)) failProbe();
      const result = await execFileAsync(runtime.sandboxExec.absolutePath, [
        '-f', join(runtime.workspace.rootRealpath, 'broker-profile.sb'),
        runtime.node.absolutePath,
        '--permission', '--allow-net',
        `--allow-fs-read=${runtime.probe.absolutePath}`,
        `--allow-fs-read=${runtime.workspace.rootRealpath}`,
        `--allow-fs-write=${runtime.workspace.rootRealpath}`,
        runtime.probe.absolutePath,
        String(binding.allowedPort), String(alternate.port), localAddress, String(nonLoopback.port),
        String(ipv6.port), outsidePath,
      ], {
        cwd: runtime.workspace.rootRealpath,
        env: {},
        timeout: 10_000,
        maxBuffer: 64 * 1024,
        windowsHide: true,
      });
      if (Buffer.byteLength(result.stdout) > 64 * 1024 || Buffer.byteLength(result.stderr) > 64 * 1024
        || await exists(outsidePath)) failProbe();
      const document = parseStrictJsonDocument(String(result.stdout));
      if (!isObservations(document)) failProbe();
      return Object.freeze({ ...document });
    } catch { failProbe(); }
    finally { await Promise.all(listeners.map(({ server }) => closeServer(server))); }
  }
}

async function localListener(host: string): Promise<Readonly<{ server: Server; port: number }>> {
  const server = createServer((socket) => socket.destroy());
  try {
    await new Promise<void>((resolvePromise, reject) => {
      server.once('error', reject);
      server.listen(0, host, () => resolvePromise());
    });
    const address = server.address();
    if (address === null || typeof address === 'string') failProbe();
    return Object.freeze({ server, port: address.port });
  } catch {
    server.close();
    failProbe();
  }
}

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((resolvePromise) => server.close(() => resolvePromise()));
}

async function exists(path: string): Promise<boolean> {
  try { await lstat(path); return true; } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
    failProbe();
  }
}

function isObservations(value: unknown): value is SeatbeltSelfTestObservations {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  const keys = [
    'approvedLoopbackPortConnected', 'alternateLoopbackPortDenied', 'nonLoopbackLocalAddressDenied',
    'ipv6LoopbackDenied', 'outsideWorkspaceWriteDenied', 'childProcessDenied', 'workerThreadDenied',
    'addonGrantAbsent', 'publicNetworkAttempted',
  ];
  return Object.keys(record).length === keys.length && keys.every((key) => typeof record[key] === 'boolean');
}

function failProbe(): never { throw new PackageStageError('artifact_plan_invalid'); }
