import process from 'node:process';

const header = Buffer.alloc(4);
header.writeUInt32BE(0xffff_ffff, 0);
process.stdout.write(header);
