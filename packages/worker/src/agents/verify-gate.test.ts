import { describe, expect, it } from 'vitest';
import { sstiArithmeticSignal, verifyReproduction } from './verify-gate.js';

describe('verifyReproduction', () => {
  it('marks reproduced when the signal matches the re-executed output', async () => {
    const r = await verifyReproduction(async () => 'Hello 49!', sstiArithmeticSignal(7, 7));
    expect(r.reproduced).toBe(true);
    expect(r.output).toBe('Hello 49!');
  });

  it('does NOT reproduce when the payload is echoed but not evaluated', async () => {
    const r = await verifyReproduction(async () => 'Hello {{7*7}}!', sstiArithmeticSignal(7, 7));
    expect(r.reproduced).toBe(false);
  });

  it('does NOT reproduce when the product is absent', async () => {
    const r = await verifyReproduction(async () => 'Hello world!', sstiArithmeticSignal(7, 7));
    expect(r.reproduced).toBe(false);
  });
});

describe('sstiArithmeticSignal', () => {
  it('uses distinct factors to avoid coincidental matches', () => {
    const sig = sstiArithmeticSignal(13, 17); // 221 — unlikely to appear by chance
    expect(sig('result: 221')).toBe(true);
    expect(sig('result: 220')).toBe(false);
  });
});
