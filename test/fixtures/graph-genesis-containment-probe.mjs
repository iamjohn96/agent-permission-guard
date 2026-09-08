import { spawn } from 'node:child_process';
import { writeFile } from 'node:fs/promises';
import { connect } from 'node:net';
import { Worker } from 'node:worker_threads';

const [approvedPortText, alternatePortText, nonLoopbackAddress, nonLoopbackPortText, ipv6PortText, outsidePath] = process.argv.slice(2);

function connection(address, port) {
  return new Promise((resolve) => {
    const socket = connect({ host: address, port: Number(port) });
    const finish = (connected) => { socket.destroy(); resolve(connected); };
    socket.once('connect', () => finish(true));
    socket.once('error', () => finish(false));
    socket.setTimeout(1000, () => finish(false));
  });
}

async function childDenied() {
  return new Promise((resolve) => {
    try {
      const child = spawn('/usr/bin/true', [], { stdio: 'ignore' });
      child.once('error', () => resolve(true));
      child.once('exit', () => resolve(false));
    } catch { resolve(true); }
  });
}

async function workerDenied() {
  return new Promise((resolve) => {
    try {
      const worker = new Worker('0', { eval: true });
      worker.once('error', () => resolve(true));
      worker.once('online', () => { void worker.terminate(); resolve(false); });
    } catch { resolve(true); }
  });
}

async function writeDenied() {
  try { await writeFile(outsidePath, 'must-not-exist', { flag: 'wx' }); return false; } catch { return true; }
}

const result = {
  approvedLoopbackPortConnected: await connection('127.0.0.1', approvedPortText),
  alternateLoopbackPortDenied: !(await connection('127.0.0.1', alternatePortText)),
  nonLoopbackLocalAddressDenied: !(await connection(nonLoopbackAddress, nonLoopbackPortText)),
  ipv6LoopbackDenied: !(await connection('::1', ipv6PortText)),
  outsideWorkspaceWriteDenied: await writeDenied(),
  childProcessDenied: await childDenied(),
  workerThreadDenied: await workerDenied(),
  addonGrantAbsent: process.permission?.has('addon') !== true,
  publicNetworkAttempted: false,
};

process.stdout.write(`${JSON.stringify(result)}\n`);
