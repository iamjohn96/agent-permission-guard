import { createHash, randomUUID } from 'node:crypto';
import {
  closeSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';

import type {
  CallInterceptor,
  InterceptorDecision,
  ToolCallContext,
} from '../gateway/call-interceptor.js';
import { evaluatePolicy } from './evaluator.js';
import { parsePolicyYaml } from './loader.js';
import type { PolicyDocument } from './schema.js';

export class PolicyConflictError extends Error {
  override readonly name = 'PolicyConflictError';
}

export type PolicyView = Readonly<{
  source: string;
  revision: string;
}>;

export class LivePolicyController implements CallInterceptor {
  private policy: PolicyDocument;
  private source: string;
  private revision: string;
  readonly path: string;

  constructor(policyPath: string) {
    this.path = resolve(policyPath);
    const metadata = lstatSync(this.path);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new Error('Policy path must be a regular file, not a symbolic link');
    }
    const source = readFileSync(this.path, 'utf8');
    this.policy = parsePolicyYaml(source);
    this.source = source;
    this.revision = hashSource(source);
  }

  async evaluate(context: ToolCallContext): Promise<InterceptorDecision> {
    const evaluation = evaluatePolicy(this.policy, context);
    if (evaluation.effectiveDecision === 'allow') return { action: 'forward', evaluation };
    const reason = evaluation.reasonCodes.join(', ');
    return evaluation.effectiveDecision === 'deny'
      ? { action: 'deny', reason, evaluation }
      : { action: 'ask', reason, evaluation };
  }

  getView(): PolicyView {
    return { source: this.source, revision: this.revision };
  }

  getApprovalTtlMs(): number {
    return this.policy.defaults.approval_ttl_seconds * 1_000;
  }

  update(source: string, expectedRevision: string): PolicyView {
    if (expectedRevision !== this.revision) {
      throw new PolicyConflictError('Policy changed since it was opened; reload before saving');
    }
    const nextPolicy = parsePolicyYaml(source);
    const diskSource = readFileSync(this.path, 'utf8');
    if (hashSource(diskSource) !== this.revision) {
      throw new PolicyConflictError('Policy file changed outside APG; reload the process before saving');
    }

    const directory = dirname(this.path);
    const temporaryPath = join(directory, `.${basename(this.path)}.apg-${process.pid}-${randomUUID()}.tmp`);
    let temporaryCreated = false;
    try {
      const temporary = openSync(temporaryPath, 'wx', 0o600);
      temporaryCreated = true;
      try {
        writeFileSync(temporary, source, 'utf8');
        fsyncSync(temporary);
      } finally {
        closeSync(temporary);
      }
      renameSync(temporaryPath, this.path);
      temporaryCreated = false;
      try {
        const directoryHandle = openSync(directory, 'r');
        try { fsyncSync(directoryHandle); } finally { closeSync(directoryHandle); }
      } catch { /* file rename is already atomic; directory sync is best effort */ }
    } finally {
      if (temporaryCreated) {
        try { unlinkSync(temporaryPath); } catch { /* best-effort temporary cleanup */ }
      }
    }

    this.policy = nextPolicy;
    this.source = source;
    this.revision = hashSource(source);
    return this.getView();
  }
}

function hashSource(source: string): string {
  return createHash('sha256').update(source).digest('hex');
}
