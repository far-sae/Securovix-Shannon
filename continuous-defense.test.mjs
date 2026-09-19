import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildDefenseCycle, nextDefenseRun } from './packages/dashboard/continuous-defense.mjs';

test('continuous defense measures real coverage without claiming inventory-only assets are protected', () => {
  const now = Date.parse('2026-09-19T12:00:00Z');
  const cycle = buildDefenseCycle({
    now,
    assets: [
      { type: 'web', locator: 'https://app.example.com', status: 'active', coverage: 'inventory' },
      { type: 'cidr', locator: '203.0.113.0/24', status: 'active', coverage: 'inventory' },
    ],
    routes: [{ host: 'app.example.com', mode: 'enforce' }],
  });
  assert.deepEqual(cycle.snapshot.assets, { total: 2, covered: 1, uncovered: 1 });
  assert.equal(cycle.snapshot.routes.enforcing, 1);
  assert.ok(cycle.learning.lessons.some((lesson) => lesson.type === 'coverage-gap'));
});

test('continuous defense learns from dispositions but never rewrites enforcement', () => {
  const now = Date.parse('2026-09-19T12:00:00Z');
  const cycle = buildDefenseCycle({
    now,
    events: [
      { cls: 'sqli', severity: 'critical', status: 'open', enforced: false, createdAt: now - 1000 },
      { cls: 'sqli', severity: 'high', status: 'contained', enforced: true, createdAt: now - 2000 },
      { cls: 'prompt-injection', severity: 'medium', status: 'false-positive', enforced: false, createdAt: now - 3000 },
    ],
  });
  assert.equal(cycle.learning.classes[0].name, 'sqli');
  assert.equal(cycle.learning.classes[0].recurring, true);
  assert.equal(cycle.learning.changesEnforcementAutomatically, false);
  assert.deepEqual(cycle.actions.escalations, ['sqli']);
  assert.ok(cycle.learning.lessons.some((lesson) => lesson.type === 'false-positive'));
});

test('continuous defense cadence is bounded', () => {
  assert.equal(nextDefenseRun(1000, 0), 1000 + 24 * 3_600_000);
  assert.equal(nextDefenseRun(1000, 500), 1000 + 168 * 3_600_000);
});

test('collector coverage expires when sensor heartbeats stop', () => {
  const now = Date.parse('2026-09-19T12:00:00Z');
  const fresh = buildDefenseCycle({
    now,
    assets: [
      { type: 'cloud', locator: 'aws:1', status: 'active', coverage: 'online', config: { lastSeenAt: now - 60_000 } },
    ],
  });
  const stale = buildDefenseCycle({
    now,
    assets: [
      {
        type: 'cloud',
        locator: 'aws:1',
        status: 'active',
        coverage: 'online',
        config: { lastSeenAt: now - 16 * 60_000 },
      },
    ],
  });
  assert.equal(fresh.snapshot.assets.covered, 1);
  assert.equal(stale.snapshot.assets.covered, 0);
});
