import process from 'node:process';

process.stderr.write(Buffer.alloc(8 * 1024, 0x41));
process.stdin.resume();
setInterval(() => undefined, 1_000);
