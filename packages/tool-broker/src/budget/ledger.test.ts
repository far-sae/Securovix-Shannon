import { describe, it, expect } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BudgetLedger } from './ledger.js';

function tmpFile(): string {
  return join(mkdtempSync(join(tmpdir(), 'broker-budget-')), 'budget.json');
}

describe('BudgetLedger', () => {
  it('consumes within budget and refuses past it', () => {
    const l = new BudgetLedger(tmpFile(), { toolInvocations: 2 });
    expect(l.tryConsume('toolInvocations', 1).ok).toBe(true);
    expect(l.tryConsume('toolInvocations', 1).ok).toBe(true);
    const third = l.tryConsume('toolInvocations', 1);
    expect(third.ok).toBe(false);
    expect(third.reason).toBe('budget');
  });

  it('treats an unset limit as unlimited', () => {
    const l = new BudgetLedger(tmpFile(), {});
    expect(l.tryConsume('httpRequests', 1000).ok).toBe(true);
  });

  it('persists spend across reopen (no reset)', () => {
    const f = tmpFile();
    const l1 = new BudgetLedger(f, { toolInvocations: 5 });
    l1.tryConsume('toolInvocations', 3);
    const l2 = new BudgetLedger(f, { toolInvocations: 5 });
    expect(l2.tryConsume('toolInvocations', 3).ok).toBe(false);
    expect(l2.tryConsume('toolInvocations', 2).ok).toBe(true);
  });
});
