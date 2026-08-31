import type { ApprovalCoordinator, ApprovalOutcome, ApprovalTicket } from '../approval/types.js';
import { approvalArguments, type InstallAuditAdapter } from './audit.js';
import { evaluateInstallPolicy } from './policy.js';
import type {
  InstallGuardResult,
  InstallExecutionResult,
  InstallMetadataProvider,
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
    runner: InstallRunnerAdapter;
  }>) {}

  async run(input: InstallRequest, approvalTtlMs: number): Promise<InstallGuardResult> {
    const request = snapshotRequest(input);
    const resolution = validateResolution(request, await this.dependencies.metadata.resolve(request));
    const evaluation = evaluateInstallPolicy(resolution);
    const audit = this.dependencies.audit.begin(request, evaluation);

    if (evaluation.effectiveDecision === 'deny') {
      audit.markBlocked('denied');
      return { status: 'denied', evaluation };
    }

    if (evaluation.effectiveDecision === 'ask') {
      let ticket: ApprovalTicket | undefined;
      try {
        ticket = this.dependencies.approvals.request({
          kind: 'install',
          serverId: 'install-guard',
          toolName: `${request.runner} install`,
          arguments: approvalArguments(request),
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
      const outcome = await ticket.outcome;
      audit.markApprovalResolved(ticket.request.id, outcome);
      if (outcome !== 'approved') {
        const status = outcomeStatus(outcome);
        audit.markBlocked(status);
        return { status, evaluation };
      }
    }

    audit.markExecuting();
    let execution: InstallExecutionResult;
    try {
      execution = await this.dependencies.runner.run(
        request,
        resolution.status === 'resolved' ? resolution.metadata : undefined,
      );
    } catch {
      audit.markFailed('install_runner_failed');
      return { status: 'failed', evaluation };
    }
    try {
      audit.markCompleted(execution);
    } catch {
      try {
        audit.markFailed('install_audit_completion_failed');
      } catch {
        // The caller still receives the completed execution result and an explicit audit failure.
      }
      return { status: 'audit_failed', evaluation, execution };
    }
    return { status: execution.status, evaluation, execution };
  }
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

function validateResolution(request: InstallRequest, resolution: InstallResolution): InstallResolution {
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
