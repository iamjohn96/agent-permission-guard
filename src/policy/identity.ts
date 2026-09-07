import { createHash } from 'node:crypto';

import { canonicalReceiptJson, type ReceiptPolicyIdentity } from '../audit/receipt.js';
import type { PolicyDocument } from './schema.js';

export function policyIdentity(
  policy: PolicyDocument,
  evaluatorName: string = 'apg_mcp_policy',
  evaluatorVersion: string = '1',
): ReceiptPolicyIdentity {
  return Object.freeze({
    schemaVersion: policy.version,
    contentDigest: sha256(canonicalReceiptJson({
      format: 'apg-validated-policy-v1',
      policy,
    })),
    evaluatorName,
    evaluatorVersion,
  });
}

export function staticPolicyIdentity(
  schemaVersion: number,
  evaluatorName: string,
  evaluatorVersion: string,
  model: unknown,
): ReceiptPolicyIdentity {
  return Object.freeze({
    schemaVersion,
    contentDigest: sha256(canonicalReceiptJson({
      format: 'apg-static-policy-v1',
      evaluatorName,
      evaluatorVersion,
      model,
    })),
    evaluatorName,
    evaluatorVersion,
  });
}

function sha256(value: string): string {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}
