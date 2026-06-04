import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import type { BudgetKind } from '../types.js';

type Limits = Partial<Record<BudgetKind, number>>;
type Spent = Record<string, number>;

export interface ConsumeResult {
  ok: boolean;
  reason?: 'budget';
  remaining?: number;
}

export class BudgetLedger {
  private spent: Spent;

  constructor(
    private readonly path: string,
    private readonly limits: Limits,
  ) {
    this.spent = existsSync(path) ? (JSON.parse(readFileSync(path, 'utf-8')) as Spent) : {};
  }

  tryConsume(kind: BudgetKind, amount: number): ConsumeResult {
    const limit = this.limits[kind];
    const current = this.spent[kind] ?? 0;
    if (limit !== undefined && current + amount > limit) {
      return { ok: false, reason: 'budget', remaining: Math.max(0, limit - current) };
    }
    this.spent[kind] = current + amount;
    this.persist();
    return { ok: true, remaining: limit === undefined ? undefined : limit - this.spent[kind] };
  }

  private persist(): void {
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.spent));
    renameSync(tmp, this.path);
  }
}
