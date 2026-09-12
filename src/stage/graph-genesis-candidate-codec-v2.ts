import { canonicalJson } from '../audit/canonical-json.js';
import {
  PEER_SEMANTICS_V2_CONTRACT,
  validateCandidateV2Payload,
  type ExactGraphCandidateV2,
} from './exact-production-graph-v2.js';

const MAX_CANDIDATE_BYTES = PEER_SEMANTICS_V2_CONTRACT.limits.candidateBytes;

/** Memory-only codec. Encoding and decoding produce plain evidence, never compiler authority. */
export function encodeExactGraphCandidateV2(candidate: ExactGraphCandidateV2): string {
  try {
    const encoded = canonicalJson(validateCandidateV2Payload(candidate));
    if (Buffer.byteLength(encoded) > MAX_CANDIDATE_BYTES) invalid();
    return encoded;
  } catch {
    invalid();
  }
}

export function decodeExactGraphCandidateV2(encoded: string, lowerByteLimit?: number): ExactGraphCandidateV2 {
  try {
    const byteLimit = candidateByteLimit(lowerByteLimit);
    if (typeof encoded !== 'string' || Buffer.byteLength(encoded) > byteLimit) invalid();
    assertNoDuplicateJsonKeys(encoded);
    const parsed: unknown = JSON.parse(encoded);
    const validated = validateCandidateV2Payload(parsed);
    if (encoded !== canonicalJson(validated)) invalid();
    return validated;
  } catch {
    invalid();
  }
}

function candidateByteLimit(value: unknown): number {
  if (value === undefined) return MAX_CANDIDATE_BYTES;
  if (
    typeof value !== 'number'
    || !Number.isSafeInteger(value)
    || value <= 0
    || value > MAX_CANDIDATE_BYTES
  ) invalid();
  return value;
}

/** A lexical pass is necessary because JSON.parse discards duplicate object keys. */
function assertNoDuplicateJsonKeys(text: string): void {
  let cursor = 0;
  const skipWhitespace = (): void => {
    while (/\s/u.test(text[cursor] ?? '')) cursor += 1;
  };
  const parseString = (): string => {
    if (text[cursor] !== '"') invalid();
    const start = cursor;
    cursor += 1;
    while (cursor < text.length) {
      const character = text[cursor];
      if (character === '"') {
        cursor += 1;
        try {
          return JSON.parse(text.slice(start, cursor)) as string;
        } catch {
          invalid();
        }
      }
      if (character === '\\') {
        cursor += 1;
        if (cursor >= text.length) invalid();
        if (text[cursor] === 'u') {
          if (!/^[0-9a-fA-F]{4}$/u.test(text.slice(cursor + 1, cursor + 5))) invalid();
          cursor += 5;
          continue;
        }
        if (!'"\\/bfnrt'.includes(text[cursor]!)) invalid();
        cursor += 1;
        continue;
      }
      if (character === undefined || character.charCodeAt(0) < 0x20) invalid();
      cursor += 1;
    }
    invalid();
  };
  const parseValue = (depth: number): void => {
    if (depth > 64) invalid();
    skipWhitespace();
    const character = text[cursor];
    if (character === '{') {
      parseObject(depth + 1);
      return;
    }
    if (character === '[') {
      parseArray(depth + 1);
      return;
    }
    if (character === '"') {
      parseString();
      return;
    }
    for (const literal of ['true', 'false', 'null']) {
      if (text.startsWith(literal, cursor)) {
        cursor += literal.length;
        return;
      }
    }
    const match = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/uy.exec(text.slice(cursor));
    if (match?.index !== 0) invalid();
    cursor += match[0].length;
  };
  const parseObject = (depth: number): void => {
    cursor += 1;
    skipWhitespace();
    const keys = new Set<string>();
    if (text[cursor] === '}') {
      cursor += 1;
      return;
    }
    while (true) {
      skipWhitespace();
      const key = parseString();
      if (keys.has(key)) invalid();
      keys.add(key);
      skipWhitespace();
      if (text[cursor] !== ':') invalid();
      cursor += 1;
      parseValue(depth);
      skipWhitespace();
      if (text[cursor] === '}') {
        cursor += 1;
        return;
      }
      if (text[cursor] !== ',') invalid();
      cursor += 1;
    }
  };
  const parseArray = (depth: number): void => {
    cursor += 1;
    skipWhitespace();
    if (text[cursor] === ']') {
      cursor += 1;
      return;
    }
    while (true) {
      parseValue(depth);
      skipWhitespace();
      if (text[cursor] === ']') {
        cursor += 1;
        return;
      }
      if (text[cursor] !== ',') invalid();
      cursor += 1;
    }
  };

  parseValue(0);
  skipWhitespace();
  if (cursor !== text.length) invalid();
}

function invalid(): never {
  throw new Error('candidate_codec_v2_invalid');
}
