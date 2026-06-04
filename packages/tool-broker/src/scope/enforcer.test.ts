import { describe, it, expect } from 'vitest';
import { ScopeEnforcer } from './enforcer.js';
import type { ScopeConfig } from '../types.js';

const cfg: ScopeConfig = {
  targetHost: 'app.example.com',
  targetIps: ['93.184.216.34'],
  allowlistCidrs: ['203.0.113.0/24'],
  allowPrivateCidrs: [],
  focusPaths: [],
  avoidPaths: ['/logout'],
};

describe('ScopeEnforcer.evaluate', () => {
  const e = new ScopeEnforcer(cfg);

  it('allows the pinned target IP', () => {
    expect(e.evaluate('93.184.216.34', '/api/users').allowed).toBe(true);
  });
  it('allows an allowlisted CIDR', () => {
    expect(e.evaluate('203.0.113.7', '/').allowed).toBe(true);
  });
  it('hard-blocks cloud metadata even if someone allowlists nothing', () => {
    const d = e.evaluate('169.254.169.254', '/latest/meta-data/');
    expect(d.allowed).toBe(false);
    expect(d.reason).toBe('denied-metadata');
  });
  it('hard-blocks RFC1918 and loopback by default', () => {
    expect(e.evaluate('10.1.2.3', '/').reason).toBe('denied-private');
    expect(e.evaluate('127.0.0.1', '/').reason).toBe('denied-loopback');
  });
  it('blocks an out-of-scope public IP', () => {
    const d = e.evaluate('8.8.8.8', '/');
    expect(d.allowed).toBe(false);
    expect(d.reason).toBe('out-of-scope-host');
  });
  it('honours avoidPaths even for an in-scope IP', () => {
    const d = e.evaluate('93.184.216.34', '/logout');
    expect(d.allowed).toBe(false);
    expect(d.reason).toBe('path-avoided');
  });
  it('re-allows a private CIDR only when explicitly opted in', () => {
    const e2 = new ScopeEnforcer({ ...cfg, allowPrivateCidrs: ['10.0.0.0/8'] });
    expect(e2.evaluate('10.1.2.3', '/').allowed).toBe(true);
  });
  it('enforces focusPaths when set (deny anything not matching)', () => {
    const e3 = new ScopeEnforcer({ ...cfg, focusPaths: ['/api/'] });
    expect(e3.evaluate('93.184.216.34', '/api/users').allowed).toBe(true);
    expect(e3.evaluate('93.184.216.34', '/admin').reason).toBe('path-not-allowed');
  });
});
