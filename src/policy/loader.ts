import { parseDocument } from 'yaml';
import { ZodError } from 'zod';

import { PolicyDocumentSchema, type PolicyDocument } from './schema.js';

const MAX_POLICY_BYTES = 1_048_576;

export class PolicyLoadError extends Error {
  override readonly name = 'PolicyLoadError';
}

export function parsePolicyYaml(source: string): PolicyDocument {
  if (Buffer.byteLength(source, 'utf8') > MAX_POLICY_BYTES) {
    throw new PolicyLoadError(`Policy exceeds the ${MAX_POLICY_BYTES}-byte limit`);
  }

  const document = parseDocument(source, {
    prettyErrors: false,
    strict: true,
    uniqueKeys: true,
  });

  if (document.errors.length > 0) {
    throw new PolicyLoadError(`Invalid YAML policy: ${document.errors[0]?.message ?? 'unknown error'}`);
  }

  try {
    return PolicyDocumentSchema.parse(document.toJS());
  } catch (error) {
    if (error instanceof ZodError) {
      const issue = error.issues[0];
      const path = issue?.path.join('.') || 'policy';
      throw new PolicyLoadError(`Invalid policy at ${path}: ${issue?.message ?? 'unknown error'}`);
    }
    throw error;
  }
}
