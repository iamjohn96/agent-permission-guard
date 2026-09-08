import { createHash, randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from '../audit/canonical-json.js';
import { RuntimeTreeSnapshotAuthority, buildGraphGenesisLaunch } from './graph-genesis.js';
import {
  RuntimeFileSnapshotAuthority, FinalizedGraphGenesisWorkspaceAuthority, HardenedGraphGenesisPlanAuthority,
  NodeHostPlatformProbeExecutor, NodeRuntimeVersionProbeExecutor, OwnedHostPlatformAuthority,
  OwnedRuntimeVersionAuthority, OwnedContainmentProbeAuthority, computeWorkspaceBinding,
  type GraphGenesisPlanProjection,
} from './graph-genesis-hardening.js';
import { SeatbeltLoopbackContainmentAuthority } from './graph-genesis-containment.js';
import { LocalSeatbeltContainmentProbeExecutor } from './graph-genesis-containment-runner.js';
import { HardenedMetadataBrokerAuthority, HardenedLoopbackBrokerListener } from './graph-genesis-network.js';
import { PreflightRoot } from './graph-genesis-preflight-root.js';
import { PreflightSqliteAudit, repositoryRoot, sqliteNativePath, type PreflightAuditResult } from './graph-genesis-preflight-audit.js';

const MiB = 1024 * 1024;
const LIMITS = Object.freeze({
  broker: Object.freeze({ uniquePackageNames: 128, totalRequests: 256, concurrentRequests: 4,
    responseBytes: 4 * MiB, aggregateResponseBytes: 64 * MiB, requestTimeoutMs: 10_000 }),
  completeTimeoutMs: 120_000, stdoutBytes: 256 * 1024, stderrBytes: 256 * 1024,
  packageJsonBytes: 64 * 1024, packageLockBytes: 4 * MiB,
});
type Phase = 'input' | 'runtime' | 'version' | 'workspace' | 'containment' | 'plan' | 'audit' | 'revalidation' | 'closing';
type Check = 'not_attempted' | 'passed' | 'failed';
export type LocalGraphGenesisPreflightReport = Readonly<{
  reportVersion: 1;
  sourceBaseline: '3860338';
  status: 'local_preflight_passed' | 'local_preflight_failed' | 'local_preflight_quarantined';
  capturedAt: string;
  closedAt: string;
  runtimeManifestDigest?: string;
  projection?: GraphGenesisPlanProjection;
  checks: Readonly<{ runtime: Check; version: Check; containment: Check; audit: Check; revalidation: Check }>;
  audit?: PreflightAuditResult;
  cleanup: 'passed' | 'quarantined' | 'not_needed';
  sessionClosed: boolean;
  executionAuthorized: false;
  planReusable: false;
  npmVersionEvidence: 'npm_manifest_version';
  publicDns: 'not_attempted';
  registry: 'not_attempted';
  npmCli: 'not_attempted';
  packageExecution: 'not_attempted';
  productionExecution: 'blocked';
  failureCode?: string;
}>;

/** Fixed production preparation composition. No runner, approval, transport or path injection. */
export async function captureLocalGraphGenesisPreflight(options: Readonly<{ signal?: AbortSignal }> = {}): Promise<LocalGraphGenesisPreflightReport> {
  const capturedAt = new Date().toISOString();
  const started = performance.now();
  const controller = new AbortController();
  let externalSignal: AbortSignal | undefined;
  const cancel = () => controller.abort();
  const timer = setTimeout(cancel, 60_000);
  timer.unref();
  let phase: Phase = 'input';
  let failureCode: string | undefined;
  let root: PreflightRoot | undefined;
  let listener: HardenedLoopbackBrokerListener | undefined;
  let audit: PreflightSqliteAudit | undefined;
  let auditResult: PreflightAuditResult | undefined;
  let projection: GraphGenesisPlanProjection | undefined;
  let runtimeManifestDigest: string | undefined;
  let cleanup: LocalGraphGenesisPreflightReport['cleanup'] = 'not_needed';
  let sessionClosed = true;
  const checks: { runtime: Check; version: Check; containment: Check; audit: Check; revalidation: Check } = {
    runtime: 'not_attempted', version: 'not_attempted', containment: 'not_attempted', audit: 'not_attempted', revalidation: 'not_attempted',
  };
  const guard = () => {
    if (controller.signal.aborted || externalSignal?.aborted) throw new Error('preflight_cancelled');
    if (performance.now() - started >= 60_000) { controller.abort(); throw new Error('preflight_deadline'); }
  };
  try {
    if (typeof options !== 'object' || options === null || Array.isArray(options)
      || Reflect.ownKeys(options).some((key) => key !== 'signal')) {
      throw new Error('preflight_input_invalid');
    }
    const descriptor = Object.getOwnPropertyDescriptor(options, 'signal');
    if (descriptor !== undefined && (!('value' in descriptor) || descriptor.value !== undefined && !(descriptor.value instanceof AbortSignal))) {
      throw new Error('preflight_input_invalid');
    }
    externalSignal = descriptor?.value as AbortSignal | undefined;
    externalSignal?.addEventListener('abort', cancel, { once: true });
    guard();
    // A source loader or alternate runtime is not the reviewed capture entry point.
    if (!import.meta.url.endsWith('/dist/src/stage/graph-genesis-preflight.js')
      || process.platform !== 'darwin' || process.arch !== 'arm64' || process.version !== 'v26.3.1'
      || process.execArgv.length !== 0 || process.env.NODE_OPTIONS !== undefined) throw new Error('preflight_runtime_invalid');
    phase = 'runtime';
    const files = new RuntimeFileSnapshotAuthority();
    const trees = new RuntimeTreeSnapshotAuthority();
    const stageRoot = dirname(fileURLToPath(import.meta.url));
    const repo = repositoryRoot();
    const require = createRequire(import.meta.url);
    const sqliteRoot = dirname(require.resolve('better-sqlite3/package.json'));
    const node = await files.capture('node', process.execPath); guard();
    const npmCli = await files.capture('npm_cli', '/opt/homebrew/lib/node_modules/npm/bin/npm-cli.js'); guard();
    const npmTree = await trees.capture(dirname(dirname(npmCli.absolutePath))); guard();
    const sandboxExec = await files.capture('sandbox_exec', '/usr/bin/sandbox-exec'); guard();
    const brokerRuntime = await files.capture('broker_runtime', fileURLToPath(import.meta.url)); guard();
    const probeRuntime = await files.capture('probe_runtime', join(repo, 'test/fixtures/graph-genesis-containment-probe.mjs')); guard();
    const brokerTree = await trees.capture(stageRoot); guard();
    const sqliteTree = await trees.capture(join(sqliteRoot, 'lib')); guard();
    const schemas = await trees.capture(join(repo, 'migrations')); guard();
    const otherFiles = [];
    for (const path of [sqliteNativePath(), join(sqliteRoot, 'package.json'), join(repo, 'package.json'),
      join(repo, 'dist/src/audit/canonical-json.js'), '/usr/bin/sw_vers', '/usr/sbin/sysctl']) {
      otherFiles.push(await files.capture('broker_runtime', path)); guard();
    }
    runtimeManifestDigest = createHash('sha256').update(canonicalJson({
      treeDigests: [brokerTree.treeDigest, sqliteTree.treeDigest, schemas.treeDigest, npmTree.treeDigest],
      fileDigests: [node, npmCli, sandboxExec, brokerRuntime, probeRuntime, ...otherFiles].map((file) => file.snapshotDigest),
    })).digest('hex');
    checks.runtime = 'passed';
    const hosts = new OwnedHostPlatformAuthority(new NodeHostPlatformProbeExecutor(controller.signal));
    const versions = new OwnedRuntimeVersionAuthority(files, trees, new NodeRuntimeVersionProbeExecutor(controller.signal));
    phase = 'version';
    const host = await hosts.observe(); guard();
    const runtimeVersions = await versions.observe({ node, npmCli, npmTree }); guard();
    checks.version = 'passed';
    const workspaces = new FinalizedGraphGenesisWorkspaceAuthority(trees);
    const probes = new OwnedContainmentProbeAuthority(files, workspaces, new LocalSeatbeltContainmentProbeExecutor(controller.signal));
    const plans = new HardenedGraphGenesisPlanAuthority(files, trees, probes, versions, workspaces, hosts);
    listener = new HardenedLoopbackBrokerListener(new HardenedMetadataBrokerAuthority(plans));
    const brokerPort = await listener.listen(); guard();
    phase = 'workspace';
    root = await PreflightRoot.create(); guard();
    const profile = new SeatbeltLoopbackContainmentAuthority().prepare({
      osBuild: host.osBuild, sandboxExecSha256: sandboxExec.sha256, allowedPort: brokerPort,
    });
    const workspace = await workspaces.initialize(join(root.path, 'workspace'), profile.profileText); guard();
    phase = 'containment';
    const containmentEvidence = await probes.observe({
      osBuild: host.osBuild, hostEvidenceDigest: host.evidenceDigest, nodeSnapshotDigest: node.snapshotDigest,
      probeSnapshotDigest: probeRuntime.snapshotDigest, sandboxExecSnapshotDigest: sandboxExec.snapshotDigest,
      workspaceBinding: computeWorkspaceBinding(workspace), profileDigest: profile.profileDigest, allowedPort: brokerPort,
    }, profile, { node, probe: probeRuntime, sandboxExec, workspace }); guard();
    checks.containment = 'passed';
    phase = 'plan';
    const routeToken = randomBytes(16).toString('hex');
    const launch = buildGraphGenesisLaunch({ sandboxExecPath: sandboxExec.absolutePath,
      profilePath: join(workspace.rootRealpath, 'broker-profile.sb'), nodePath: node.absolutePath,
      npmCliPath: npmCli.absolutePath, npmRuntimeRoot: npmTree.rootRealpath, workspaceRoot: workspace.rootRealpath, brokerPort, routeToken });
    const prepared = plans.prepare({ host, node, npmCli, sandboxExec, brokerRuntime, probeRuntime, npmTree, brokerTree,
      runtimeVersions, containmentEvidence, workspace, brokerPort, routeToken, launch, limits: LIMITS });
    projection = prepared.projection;
    phase = 'audit';
    audit = await PreflightSqliteAudit.create(root, prepared.plan.planHash, runtimeManifestDigest); guard();
    audit.append('plan_captured'); guard();
    audit.append('audit_checked'); guard();
    phase = 'revalidation';
    await plans.revalidatePair(prepared.plan, prepared.capsule); guard();
    for (const tree of [sqliteTree, schemas]) { await trees.revalidate(tree); guard(); }
    for (const file of otherFiles) { await files.revalidate(file); guard(); }
    const currentHost = await hosts.observe(); guard();
    if (currentHost.evidenceDigest !== host.evidenceDigest) throw new Error('preflight_host_drift');
    listener.assertDisarmedPort(brokerPort);
    checks.revalidation = 'passed';
    phase = 'audit';
    audit.append('session_closing'); guard();
    auditResult = await audit.verifyReopened(); guard();
    checks.audit = 'passed';
    // No prepared plan/capsule escapes this block. No authorized broker session exists.
  } catch {
    failureCode = controller.signal.aborted || externalSignal?.aborted ? 'preflight_cancelled_or_deadline' : `preflight_${phase}_failed`;
    if (phase in checks) checks[phase as keyof typeof checks] = 'failed';
  } finally {
    phase = 'closing';
    controller.abort();
    clearTimeout(timer);
    externalSignal?.removeEventListener('abort', cancel);
    try { await listener?.close(); } catch { sessionClosed = false; failureCode = 'preflight_listener_close_failed'; }
    try { audit?.close(); } catch { sessionClosed = false; failureCode = 'preflight_audit_close_failed'; }
    if (root !== undefined) {
      try {
        if (!sessionClosed) throw new Error('preflight_close_incomplete');
        await root.cleanup(); cleanup = 'passed';
      } catch { cleanup = 'quarantined'; failureCode = 'preflight_cleanup_ambiguous'; }
    }
  }
  if (failureCode === undefined && (externalSignal?.aborted || performance.now() - started >= 60_000)) {
    failureCode = 'preflight_cancelled_or_deadline';
  }
  return Object.freeze({ reportVersion: 1, sourceBaseline: '3860338',
    status: cleanup === 'quarantined' ? 'local_preflight_quarantined' : failureCode === undefined ? 'local_preflight_passed' : 'local_preflight_failed',
    capturedAt, closedAt: new Date().toISOString(), ...(runtimeManifestDigest === undefined ? {} : { runtimeManifestDigest }),
    ...(projection === undefined ? {} : { projection }), checks: Object.freeze(checks), ...(auditResult === undefined ? {} : { audit: auditResult }),
    cleanup, sessionClosed, executionAuthorized: false, planReusable: false, npmVersionEvidence: 'npm_manifest_version',
    publicDns: 'not_attempted', registry: 'not_attempted', npmCli: 'not_attempted', packageExecution: 'not_attempted',
    productionExecution: 'blocked', ...(failureCode === undefined ? {} : { failureCode }),
  });
}
