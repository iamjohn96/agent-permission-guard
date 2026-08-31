import type { ApprovalOutcome, ApprovalRequestView } from '../approval/types.js';
import type { AuditCall, AuditRecorder } from '../audit/recorder.js';
import type { InstallExecutionResult, InstallPolicyEvaluation, InstallRequest } from './types.js';

export interface InstallAuditCall {
  markApprovalRequested(request: ApprovalRequestView): void;
  markApprovalResolved(approvalId: string, outcome: ApprovalOutcome): void;
  markExecuting(): void;
  markBlocked(status: 'denied' | 'approval_denied' | 'approval_expired' | 'approval_cancelled'): void;
  markCompleted(result: InstallExecutionResult): void;
  markFailed(code: string): void;
}

export class InstallAuditAdapter {
  constructor(private readonly recorder: AuditRecorder) {}

  begin(request: InstallRequest, evaluation: InstallPolicyEvaluation): InstallAuditCall {
    const call = this.recorder.begin({
      serverId: 'install-guard',
      toolName: `${request.runner}_install`,
      arguments: approvalArguments(request),
    }, {
      action: evaluation.effectiveDecision === 'allow' ? 'forward' : evaluation.effectiveDecision,
      evaluation: {
        baseDecision: evaluation.effectiveDecision,
        effectiveDecision: evaluation.effectiveDecision,
        matchedRuleId: 'install_guard_builtin_v0',
        reasonCodes: evaluation.reasonCodes,
        risk: evaluation.risk,
      },
    });

    return adaptCall(call);
  }
}

export function approvalArguments(request: InstallRequest): Readonly<Record<string, unknown>> {
  return {
    runner: request.runner,
    package: `${request.packageName}@${request.requestedSpecifier}`,
    options: [...request.options],
    workingDirectory: request.workingDirectory,
  };
}

function adaptCall(call: AuditCall): InstallAuditCall {
  return {
    markApprovalRequested: (request) => call.markApprovalRequested(request),
    markApprovalResolved: (approvalId, outcome) => call.markApprovalResolved(approvalId, outcome),
    markExecuting: () => call.markForwarding(),
    markBlocked: (status) => call.markBlocked(status),
    markCompleted: (result) => call.markExecutionResult(
      {
        status: result.status,
        exitCode: result.exitCode,
        durationMs: result.durationMs,
      },
      result.status === 'failed',
    ),
    markFailed: (code) => call.markFailed(code),
  };
}
