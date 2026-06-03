import { describe, it, expect } from 'vitest';
import { createContainer } from './container.js';

describe('createContainer', () => {
  it('builds without a workspace and exposes no standalone evidenceHasher', () => {
    const c = createContainer();
    expect('evidenceHasher' in c).toBe(false);
    expect(c.evidenceStore).toBeUndefined(); // no workspace → no store
    expect(c.configLoader).toBeDefined();
  });
});
