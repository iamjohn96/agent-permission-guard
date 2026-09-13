import { describe, expect, it } from 'vitest';

import * as executionModule from '../../src/stage/graph-genesis-v2-execution-production.js';

describe('dormant V2 execution production boundary', () => {
  it('exports proof vocabulary only: no raw ledger, constructor, clock, binding, or phase API exists to call', () => {
    // Regression for raw arbitrary callers fabricating start/arm/spawn/terminal.
    expect(Object.keys(executionModule)).toEqual([]);
    expect('DormantV2ExecutionLedger' in executionModule).toBe(false);
  });
});
