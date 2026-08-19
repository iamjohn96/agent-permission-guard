const SECRET_KEY = /(?:api[_-]?key|authorization|cookie|credential|password|private[_-]?key|secret|token)/i;
const MAX_DEPTH = 12;
const MAX_COLLECTION_ITEMS = 100;
const MAX_STRING_LENGTH = 512;

export function redactForAudit(value: unknown): unknown {
  return redact(value, 0, new WeakSet<object>());
}

function redact(value: unknown, depth: number, ancestors: WeakSet<object>): unknown {
  if (depth > MAX_DEPTH) return '[TRUNCATED:DEPTH]';
  if (typeof value === 'string') {
    return value.length <= MAX_STRING_LENGTH
      ? value
      : `${value.slice(0, MAX_STRING_LENGTH)}[TRUNCATED]`;
  }
  if (typeof value === 'number' || typeof value === 'boolean' || value === null) return value;
  if (typeof value === 'bigint') return value.toString();
  if (value === undefined) return '[UNDEFINED]';
  if (typeof value !== 'object') return `[${String(typeof value).toUpperCase()}]`;
  if (ancestors.has(value)) return '[CIRCULAR]';

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const result = value.slice(0, MAX_COLLECTION_ITEMS).map((item) => redact(item, depth + 1, ancestors));
      if (value.length > MAX_COLLECTION_ITEMS) result.push(`[TRUNCATED:${value.length - MAX_COLLECTION_ITEMS}_ITEMS]`);
      return result;
    }

    const entries = Object.entries(value as Record<string, unknown>).slice(0, MAX_COLLECTION_ITEMS);
    const result: Record<string, unknown> = {};
    for (const [key, nested] of entries) {
      result[key] = SECRET_KEY.test(key) ? '[REDACTED]' : redact(nested, depth + 1, ancestors);
    }
    if (Object.keys(value).length > MAX_COLLECTION_ITEMS) {
      result.__truncated__ = `${Object.keys(value).length - MAX_COLLECTION_ITEMS} fields`;
    }
    return result;
  } finally {
    ancestors.delete(value);
  }
}
