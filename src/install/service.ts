import type { ApprovalCoordinator, ApprovalOutcome, ApprovalTicket } from '../approval/types.js';
import { approvalArguments, type InstallAuditAdapter } from './audit.js';
import { evaluateInstallPolicy } from './policy.js';
import type {
  InstallGuardResult,
  InstallExecutionResult,
  InstallExecutionPlanner,
  InstallMetadataProvider,
  InstallPolicyEvaluation,
  InstallRequest,
  InstallResolution,
  InstallRunnerAdapter,
  ResolvedPackageMetadata,
} from './types.js';

const EXACT_VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

export class InstallGuardService {
  constructor(private readonly dependencies: Readonly<{
    metadata: InstallMetadataProvider;
    approvals: ApprovalCoordinator;
    audit: InstallAuditAdapter;
    planner: InstallExecutionPlanner;
    runner: InstallRunnerAdapter;
  }>) {}

  async run(
    input: InstallRequest,
    approvalTtlMs: number,
    options: Readonly<{ timeoutMs?: number; signal?: AbortSignal }> = {},
  ): Promise<InstallGuardResult> {
    const request = snapshotRequest(input);
    const resolution = validateInstallResolution(request, await this.dependencies.metadata.resolve(request));
    const baseEvaluation = evaluateInstallPolicy(resolution);
    const evaluation = executionEvaluation(baseEvaluation, resolution.status === 'resolved');

    if (evaluation.effectiveDecision === 'deny') {
      const audit = this.dependencies.audit.begin(request, evaluation);
      audit.markBlocked('denied');
      return { status: 'denied', evaluation };
    }

    if (resolution.status !== 'resolved') throw new Error('Resolved metadata is required after execution evaluation');
    let plan;
    try {
      plan = await this.dependencies.planner.create(request, resolution.metadata, options.timeoutMs ?? 300_000);
    } catch {
      const audit = this.dependencies.audit.begin(request, evaluation);
      audit.markFailed('install_plan_failed');
      return { status: 'failed', evaluation };
    }
    const audit = this.dependencies.audit.begin(plan, evaluation);

    if (evaluation.effectiveDecision === 'ask') {
      let ticket: ApprovalTicket | undefined;
      try {
        ticket = this.dependencies.approvals.request({
          kind: 'install',
          serverId: 'install-guard',
          toolName: `${request.runner} install`,
          arguments: approvalArguments(plan),
          risk: evaluation.risk,
          reasonCodes: evaluation.reasonCodes,
        }, approvalTtlMs);
        audit.markApprovalRequested(ticket.request);
      } catch (error) {
        ticket?.cancel();
        audit.markFailed('install_approval_unavailable');
        throw error;
      }
      if (ticket === undefined) throw new Error('Install approval ticket was not created');
      const outcome = await waitForApproval(ticket, options.signal);
      audit.markApprovalResolved(ticket.request.id, outcome);
      if (outcome !== 'approved') {
        const status = outcomeStatus(outcome);
        audit.markBlocked(status);
        return { status, evaluation, plan };
      }
    }

    audit.markExecuting();
    let execution: InstallExecutionResult;
    try {
      execution = await this.dependencies.runner.run(
        plan,
        options.signal,
      );
    } catch {
      audit.markFailed('install_runner_failed');
      return { status: 'failed', evaluation, plan };
    }
    try {
      audit.markCompleted(execution);
    } catch {
      try {
        audit.markFailed('install_audit_completion_failed');
      } catch {
        // The caller still receives the completed execution result and an explicit audit failure.
      }
      return { status: 'audit_failed', evaluation, plan, execution };
    }
    const status = execution.status === 'completed' && execution.verification?.status === 'failed'
      ? 'verification_failed'
      : execution.status;
    return { status, evaluation, plan, execution };
  }
}

async function waitForApproval(
  ticket: ApprovalTicket,
  signal: AbortSignal | undefined,
): Promise<ApprovalOutcome> {
  if (signal?.aborted === true) ticket.cancel();
  const cancel = () => ticket.cancel();
  signal?.addEventListener('abort', cancel, { once: true });
  try {
    return await ticket.outcome;
  } finally {
    signal?.removeEventListener('abort', cancel);
  }
}

function executionEvaluation(
  evaluation: InstallPolicyEvaluation,
  hasResolvedMetadata: boolean,
): InstallPolicyEvaluation {
  if (evaluation.effectiveDecision === 'deny') return evaluation;
  if (!hasResolvedMetadata) {
    return {
      ...evaluation,
      effectiveDecision: 'deny',
      reasonCodes: Object.freeze([...evaluation.reasonCodes, 'execution_requires_resolved_metadata']),
    };
  }
  return {
    ...evaluation,
    effectiveDecision: 'ask',
    reasonCodes: evaluation.reasonCodes.includes('local_install_execution')
      ? evaluation.reasonCodes
      : Object.freeze([...evaluation.reasonCodes, 'local_install_execution']),
  };
}

function snapshotRequest(request: InstallRequest): InstallRequest {
  return Object.freeze({
    runner: request.runner,
    packageName: request.packageName,
    requestedSpecifier: request.requestedSpecifier,
    options: Object.freeze([...request.options]),
    workingDirectory: request.workingDirectory,
  });
}

export function validateInstallResolution(
  request: InstallRequest,
  resolution: InstallResolution,
): InstallResolution {
  if (resolution.status !== 'resolved') {
    if (resolution.status !== 'unresolved' && !EXACT_VERSION.test(request.requestedSpecifier)) {
      return { status: 'unresolved', reason: 'Metadata failed before the mutable version could be resolved exactly' };
    }
    return resolution;
  }
  if (resolution.metadata.packageName !== request.packageName || !EXACT_VERSION.test(resolution.metadata.version)) {
    return { status: 'contradictory', reason: 'Resolved metadata does not match the requested package identity' };
  }
  return { status: 'resolved', metadata: snapshotMetadata(resolution.metadata) };
}

function snapshotMetadata(metadata: ResolvedPackageMetadata): ResolvedPackageMetadata {
  return Object.freeze({
    ...metadata,
    lifecycleScripts: Object.freeze([...metadata.lifecycleScripts]),
    ...(metadata.executableBins === undefined
      ? {}
      : { executableBins: Object.freeze({ ...metadata.executableBins }) }),
    advisories: Object.freeze(metadata.advisories.map((item) => Object.freeze({ ...item }))),
  });
}

function outcomeStatus(
  outcome: Exclude<ApprovalOutcome, 'approved'>,
): 'approval_denied' | 'approval_expired' | 'approval_cancelled' {
  if (outcome === 'denied') return 'approval_denied';
  if (outcome === 'expired') return 'approval_expired';
  return 'approval_cancelled';
}
