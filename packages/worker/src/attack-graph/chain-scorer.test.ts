import { describe, expect, it } from 'vitest';
import type { VulnCategory } from './types.js';

// Compile-time assertion: each new category is assignable to VulnCategory.
const NEW_CATEGORIES: VulnCategory[] = [
  'rce-ssti',
  'rce-deser',
  'token-forgery',
  'prompt-injection',
  'graphql-idor',
  'request-smuggling',
];

describe('VulnCategory widening', () => {
  it('accepts the six new Track B categories', () => {
    expect(NEW_CATEGORIES).toHaveLength(6);
  });
});
