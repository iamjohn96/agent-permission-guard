import { captureLocalGraphGenesisPreflight } from './graph-genesis-preflight.js';

// Internal explicit entry point, never imported by the product CLI.
const controller = new AbortController();
const cancel = () => controller.abort();
process.once('SIGINT', cancel);
process.once('SIGTERM', cancel);
try {
  if (process.argv.length !== 2) throw new Error('preflight_arguments_rejected');
  const report = await captureLocalGraphGenesisPreflight({ signal: controller.signal });
  process.stdout.write(`${JSON.stringify(report)}\n`);
  process.exitCode = report.status === 'local_preflight_passed' ? 0 : 1;
} catch {
  process.stderr.write('preflight_failed\n');
  process.exitCode = 1;
} finally {
  process.removeListener('SIGINT', cancel);
  process.removeListener('SIGTERM', cancel);
}
