import { spawn } from 'node:child_process';
import { realpathSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { connect } from 'node:net';
import { fileURLToPath } from 'node:url';
import { Worker } from 'node:worker_threads';

async function connection(address: string, port: string): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = connect({ host: address, port: Number(port) });
    const finish = (connected: boolean) => { socket.destroy(); resolve(connected); };
    socket.once('connect', () => finish(true));
    socket.once('error', () => finish(false));
    socket.setTimeout(1_000, () => finish(false));
  });
}

async function childDenied(): Promise<boolean> {
  return new Promise((resolve) => {
    try {
      const child = spawn('/usr/bin/true', [], { stdio: 'ignore' });
      child.once('error', () => resolve(true));
      child.once('exit', () => resolve(false));
    } catch { resolve(true); }
  });
}

async function workerDenied(): Promise<boolean> {
  return new Promise((resolve) => {
    try {
      const worker = new Worker('0', { eval: true });
      worker.once('error', () => resolve(true));
      worker.once('online', () => { void worker.terminate(); resolve(false); });
    } catch { resolve(true); }
  });
}

async function writeDenied(path: string): Promise<boolean> {
  try { await writeFile(path, 'must-not-exist', { flag: 'wx' }); return false; } catch { return true; }
}

export async function runGraphGenesisContainmentProbe(argv: readonly string[]): Promise<void> {
  const [approvedPort, alternatePort, nonLoopbackAddress, nonLoopbackPort, ipv6Port, outsidePath] = argv;
  if ([approvedPort, alternatePort, nonLoopbackAddress, nonLoopbackPort, ipv6Port, outsidePath]
    .some((value) => value === undefined)) throw new Error('Invalid containment probe arguments');
  const result = {
    approvedLoopbackPortConnected: await connection('127.0.0.1', approvedPort!),
    alternateLoopbackPortDenied: !(await connection('127.0.0.1', alternatePort!)),
    nonLoopbackLocalAddressDenied: !(await connection(nonLoopbackAddress!, nonLoopbackPort!)),
    ipv6LoopbackDenied: !(await connection('::1', ipv6Port!)),
    outsideWorkspaceWriteDenied: await writeDenied(outsidePath!),
    childProcessDenied: await childDenied(),
    workerThreadDenied: await workerDenied(),
    addonGrantAbsent: process.permission?.has('addon') !== true,
    publicNetworkAttempted: false,
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && realpathSync(invokedPath) === fileURLToPath(import.meta.url)) {
  await runGraphGenesisContainmentProbe(process.argv.slice(2));
}
