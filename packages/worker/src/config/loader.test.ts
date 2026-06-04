import { describe, expect, it } from 'vitest';
import { isErr, isOk } from '../result.js';
import { validateConfig } from './loader.js';
import type { ShannonConfig } from './schema.js';

const base: ShannonConfig = { target: { url: 'https://example.com' } };

describe('validateConfig — broker', () => {
  it('accepts a valid broker block', () => {
    const r = validateConfig({
      ...base,
      broker: {
        allowStateChanging: false,
        scope: { allowlistCidrs: ['10.0.0.0/8'] },
        budgets: { maxToolInvocations: 100, maxHttpRequests: 5000 },
        oob: { mode: 'reflected-only' },
      },
    });
    expect(isOk(r)).toBe(true);
  });

  it('rejects an invalid CIDR', () => {
    const r = validateConfig({ ...base, broker: { scope: { allowlistCidrs: ['10.0.0.0/33'] } } });
    expect(isErr(r)).toBe(true);
  });

  it('rejects a non-positive budget', () => {
    const r = validateConfig({ ...base, broker: { budgets: { maxToolInvocations: 0 } } });
    expect(isErr(r)).toBe(true);
  });

  it('rejects an unknown oob mode', () => {
    const r = validateConfig({
      ...base,
      broker: { oob: { mode: 'carrier-pigeon' as unknown as 'reflected-only' } },
    });
    expect(isErr(r)).toBe(true);
  });
});
