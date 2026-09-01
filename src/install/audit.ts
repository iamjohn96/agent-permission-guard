import type { ApprovalOutcome, ApprovalRequestView } from '../approval/types.js';
import type { AuditCall, AuditRecorder } from '../audit/recorder.js';
import type {
  InstallExecutionPlan,
  InstallExecutionResult,
  InstallPolicyEvaluation,
  InstallRequest,
} from './types.js';

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

  begin(request: InstallRequest | InstallExecutionPlan, evaluation: InstallPolicyEvaluation): InstallAuditCall {
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

export function approvalArguments(
  request: InstallRequest | InstallExecutionPlan,
): Readonly<Record<string, unknown>> {
  if ('planHash' in request) {
    return {
      runner: request.runner,
      package: `${request.packageName}@${request.resolvedVersion}`,
      originalSpecifier: request.originalSpecifier,
      options: [...request.options],
      workingDirectory: request.workingDirectory,
      executable: request.executable.path,
      runtimeExecutable: request.runtimeExecutable.path,
      arguments: [...request.arguments],
      planHash: request.planHash,
      integrity: request.integrity,
      registry: request.registry,
      lifecycleScripts: [...request.lifecycleScripts],
      packageDownload: true,
      localProjectMutation: request.runner === 'npm',
      packageCodeExecution: request.runner === 'npx' || request.lifecycleScripts.length > 0,
    };
  }
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
        signal: result.signal,
        durationMs: result.durationMs,
        output: result.output === undefined ? undefined : {
          stdoutBytes: result.output.stdoutBytes,
          stderrBytes: result.output.stderrBytes,
          truncated: result.output.truncated,
        },
        verification: result.verification,
      },
      result.status !== 'completed' || result.verification?.status === 'failed',
    ),
    markFailed: (code) => call.markFailed(code),
  };
}
