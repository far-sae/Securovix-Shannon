// Tests for the continuous-monitoring scheduling helpers.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { diffToDelta, dueMonitors } from './packages/dashboard/monitor-schedule.mjs';

const HOUR = 3_600_000;

test('dueMonitors: never-run and interval-elapsed are due; recent and disabled are not', () => {
  const now = 100 * HOUR;
  const monitors = [
    { id: 'a', intervalHours: 24, lastRunAt: 0 }, // never run → due
    { id: 'b', intervalHours: 6, lastRunAt: now - 7 * HOUR }, // 7h ago, 6h interval → due
    { id: 'c', intervalHours: 24, lastRunAt: now - 2 * HOUR }, // 2h ago, 24h interval → not due
    { id: 'd', intervalHours: 1, lastRunAt: 0, enabled: false }, // disabled → not due
  ];
  const due = dueMonitors(monitors, now).map((m) => m.id);
  assert.deepEqual(due.sort(), ['a', 'b']);
});

test('dueMonitors: defaults to a 24h interval when unset', () => {
  const now = 100 * HOUR;
  assert.equal(dueMonitors([{ id: 'x', lastRunAt: now - 23 * HOUR }], now).length, 0, 'under 24h → not due');
  assert.equal(dueMonitors([{ id: 'x', lastRunAt: now - 25 * HOUR }], now).length, 1, 'over 24h → due');
});

test('diffToDelta: maps added→new, removed→resolved, passes firstRun through', () => {
  const diff = {
    added: [{ cls: 'sqli', target: 'https://x/s', severity: 'critical' }],
    removed: [{ tool: 'xss-probe', cls: 'xss', target: 'https://x/p', severity: 'high' }],
  };
  const delta = diffToDelta(diff, { firstRun: false, previousScanAt: '2026-07-15' });
  assert.equal(delta.firstRun, false);
  assert.equal(delta.previousScanAt, '2026-07-15');
  assert.equal(delta.new.length, 1);
  assert.equal(delta.new[0].cls, 'sqli');
  assert.equal(delta.resolved.length, 1);
  assert.equal(delta.resolved[0].severity, 'high');
});

test('diffToDelta: a first run marks firstRun so no alert fires', () => {
  const delta = diffToDelta({ added: [{ cls: 'sqli', target: 't' }] }, { firstRun: true });
  assert.equal(delta.firstRun, true);
});
