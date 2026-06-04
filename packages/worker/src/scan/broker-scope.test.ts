import { verifyScopeToken } from '@shannon/tool-broker';
import { describe, expect, it } from 'vitest';
import type { ShannonConfig } from '../config/schema.js';
import {
  brokerCapableCategories,
  brokerCategoriesFor,
  buildBrokerScanFields,
  deriveScopeConfig,
} from './broker-scope.js';

const KEY = 'test-scope-hmac-key';

function cfg(over: Partial<ShannonConfig> = {}): ShannonConfig {
  return { target: { url: 'https://app.example.com/api' }, ...over };
}

describe('brokerCapableCategories', () => {
  it('matches the CLASS_CONFIGS keys (the proven Track-B classes)', () => {
    const caps = brokerCapableCategories();
    expect(caps).toContain('rce-ssti');
    expect(caps).toContain('token-forgery');
    expect(caps).toContain('graphql-idor');
    expect(caps).toContain('authz-bypass');
    expect(caps).toContain('rce-deser');
    expect(caps).toContain('prompt-injection');
  });
});

describe('brokerCategoriesFor', () => {
  it('returns all capable classes when none requested', () => {
    expect(brokerCategoriesFor(cfg({ broker: {} }))).toEqual(brokerCapableCategories());
  });

  it('intersects the requested allowlist with what is capable', () => {
    const out = brokerCategoriesFor(cfg({ broker: { categories: ['rce-ssti', 'token-forgery'] } }));
    expect(out.sort()).toEqual(['rce-ssti', 'token-forgery']);
  });

  it('drops unknown requested classes', () => {
    const out = brokerCategoriesFor(cfg({ broker: { categories: ['rce-ssti', 'not-a-class'] } }));
    expect(out).toEqual(['rce-ssti']);
  });
});

describe('deriveScopeConfig', () => {
  it('extracts the host and sorts every list deterministically', () => {
    const scope = deriveScopeConfig(
      cfg({
        target: { url: 'https://app.example.com/api', urls: { focus: ['/b', '/a'], avoid: ['/z'] } },
        broker: { scope: { allowlistCidrs: ['10.0.2.0/24', '10.0.1.0/24'] } },
      }),
      ['9.9.9.9', '1.1.1.1'],
    );
    expect(scope.targetHost).toBe('app.example.com');
    expect(scope.targetIps).toEqual(['1.1.1.1', '9.9.9.9']);
    expect(scope.allowlistCidrs).toEqual(['10.0.1.0/24', '10.0.2.0/24']);
    expect(scope.focusPaths).toEqual(['/a', '/b']);
    expect(scope.avoidPaths).toEqual(['/z']);
  });
});

describe('buildBrokerScanFields', () => {
  it('returns nothing when there is no broker block (fail-safe off)', () => {
    expect(buildBrokerScanFields(cfg(), { scopeKey: KEY, targetIps: ['1.1.1.1'] })).toEqual({});
  });

  it('returns nothing when no scope key is available', () => {
    expect(buildBrokerScanFields(cfg({ broker: {} }), { targetIps: ['1.1.1.1'] })).toEqual({});
  });

  it('returns nothing when the allowlist excludes every capable class', () => {
    const out = buildBrokerScanFields(cfg({ broker: { categories: ['not-a-class'] } }), {
      scopeKey: KEY,
      targetIps: ['1.1.1.1'],
    });
    expect(out).toEqual({});
  });

  it('signs a verifiable scope token and selects categories when enabled', () => {
    const config = cfg({ broker: {} });
    const targetIps = ['1.1.1.1'];
    const out = buildBrokerScanFields(config, { scopeKey: KEY, targetIps });
    expect(out.brokerCategories).toEqual(brokerCapableCategories());
    expect(out.scopeToken).toBeTypeOf('string');
    // The token must verify against the exact canonical scope the broker will rebuild.
    const scope = deriveScopeConfig(config, targetIps);
    expect(verifyScopeToken(out.scopeToken as string, scope, KEY)).toBe(true);
    // …and must NOT verify against a different scope or a different key.
    expect(verifyScopeToken(out.scopeToken as string, scope, 'wrong-key')).toBe(false);
  });
});
