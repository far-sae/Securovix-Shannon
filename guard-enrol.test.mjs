// Enrolling a machine: how long an install command works, and who may enrol a machine again.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ENROLL_TOKEN_TTL_MS, createEndpointService, sameNetwork } from './packages/dashboard/guard/endpoint.mjs';

const HOUR = 60 * 60_000;
const MIN = 60_000;

// The two stores enrolment touches, kept in memory.
function table() {
  const rows = new Map();
  return {
    get: async (id) => rows.get(id) || null,
    save: async (row) => {
      rows.set(row.id, row);
      return row;
    },
    list: async (filter = {}) =>
      [...rows.values()].filter((row) => Object.entries(filter).every(([k, v]) => row[k] === v)),
  };
}
function service() {
  const clock = { t: Date.UTC(2026, 10, 17, 9, 0, 0) };
  const store = { agents: table(), endpoint: table(), commands: table(), samples: table(), hashes: table() };
  const endpoints = createEndpointService({ store, engine: {}, cape: { configured: () => false }, now: () => clock.t });
  return { clock, store, endpoints };
}
const machine = (extra = {}) => ({
  hostname: 'FINANCE-PC',
  os: 'windows',
  version: '0.1.2',
  machineId: 'machine-one',
  ...extra,
});
const refused = (status, pattern) => (error) => error.status === status && pattern.test(error.message);

test('an install command works for 24 hours, then a new one is needed', async () => {
  const { clock, endpoints } = service();
  const made = await endpoints.createEnrollToken('org-a');
  assert.equal(made.expiresAt, clock.t + ENROLL_TOKEN_TTL_MS);
  assert.equal(ENROLL_TOKEN_TTL_MS, 24 * HOUR);

  clock.t += 23 * HOUR;
  const first = await endpoints.enroll({ token: made.token, ...machine() }, '203.0.113.10');
  assert.match(first.token, /^svxa_/);

  clock.t += 2 * HOUR;
  await assert.rejects(
    endpoints.enroll(
      { token: made.token, ...machine({ machineId: 'machine-two', hostname: 'HR-PC' }) },
      '203.0.113.11',
    ),
    refused(401, /has expired: a command works for 24 hours/),
  );
  // The machine that enrolled in time keeps working: its own credential is not the install command.
  assert.ok(await endpoints.authenticate(`Bearer ${first.token}`));

  const fresh = await endpoints.createEnrollToken('org-a');
  const second = await endpoints.enroll(
    { token: fresh.token, ...machine({ machineId: 'machine-two', hostname: 'HR-PC' }) },
    '203.0.113.11',
  );
  assert.notEqual(second.agentId, first.agentId);
});

test('a machine that is online can be enrolled again only from where it connects from', async () => {
  const { clock, endpoints } = service();
  const { token } = await endpoints.createEnrollToken('org-a');
  const first = await endpoints.enroll({ token, ...machine() }, '203.0.113.10');
  const agent = await endpoints.authenticate(`Bearer ${first.token}`);
  await endpoints.checkIn(agent, { version: '0.1.2' }, '203.0.113.10');

  // Someone else holding a copy of the command, who knows the machine's id, from another network.
  clock.t += 5 * MIN;
  await assert.rejects(
    endpoints.enroll({ token, ...machine() }, '198.51.100.77'),
    refused(409, /FINANCE-PC is already enrolled and is online from another network/),
  );
  assert.ok(await endpoints.authenticate(`Bearer ${first.token}`), 'the real machine keeps its credential');

  // The owner updating or reinstalling on the machine itself: same address, a new credential.
  const again = await endpoints.enroll({ token, ...machine({ version: '0.1.3' }) }, '203.0.113.10');
  assert.equal(again.agentId, first.agentId, 'still one record for the machine');
  assert.equal(await endpoints.authenticate(`Bearer ${first.token}`), null, 'the old credential is replaced');
  assert.ok(await endpoints.authenticate(`Bearer ${again.token}`));
});

test('a machine that has been silent for half an hour can be enrolled again from anywhere', async () => {
  const { clock, endpoints } = service();
  const { token } = await endpoints.createEnrollToken('org-a');
  const first = await endpoints.enroll({ token, ...machine() }, '203.0.113.10');
  clock.t += 29 * MIN;
  await assert.rejects(endpoints.enroll({ token, ...machine() }, '198.51.100.77'), refused(409, /already enrolled/));
  clock.t += 2 * MIN;
  const moved = await endpoints.enroll({ token, ...machine() }, '198.51.100.77');
  assert.equal(moved.agentId, first.agentId);
});

test('a different machine is not affected, and one organization’s command cannot enrol into another', async () => {
  const { endpoints } = service();
  const a = await endpoints.createEnrollToken('org-a');
  const b = await endpoints.createEnrollToken('org-b');
  const one = await endpoints.enroll({ token: a.token, ...machine() }, '203.0.113.10');
  const other = await endpoints.enroll(
    { token: a.token, ...machine({ machineId: 'machine-two', hostname: 'HR-PC' }) },
    '198.51.100.77',
  );
  assert.notEqual(other.agentId, one.agentId, 'another machine enrols from any network');
  const elsewhere = await endpoints.enroll({ token: b.token, ...machine() }, '198.51.100.77');
  assert.notEqual(elsewhere.agentId, one.agentId, 'the same machine id in another organization is another record');
  assert.ok(await endpoints.authenticate(`Bearer ${one.token}`), 'and does not touch the first organization’s machine');
  const forged = a.token.replace('org-a', 'org-b');
  await assert.rejects(endpoints.enroll({ token: forged, ...machine() }, '203.0.113.10'), refused(401, /not valid/));
});

test('"the same place" means the same address, or the same IPv6 /64', () => {
  assert.equal(sameNetwork('203.0.113.10', '203.0.113.10'), true);
  assert.equal(sameNetwork('203.0.113.10', '::ffff:203.0.113.10'), true, 'the same IPv4 address written the IPv6 way');
  assert.equal(sameNetwork('203.0.113.10', '203.0.113.11'), false);
  assert.equal(
    sameNetwork('2001:db8:1:2:aaaa::1', '2001:db8:1:2:bbbb::9'),
    true,
    'a machine rotates the second half of its IPv6 address',
  );
  assert.equal(sameNetwork('2001:db8:1:2::1', '2001:db8:1:3::1'), false);
  assert.equal(sameNetwork('203.0.113.10', '2001:db8::1'), false);
  assert.equal(sameNetwork(null, null), true, 'nothing to compare without a proxy in front');
  assert.equal(sameNetwork('203.0.113.10', null), false);
  assert.equal(sameNetwork('not-an-address', 'also-not'), false);
});
