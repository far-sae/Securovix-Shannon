// A demo tenant for Guard: two weeks of ordinary office activity, then attacks on request.
// It lets a pilot (or a test) see the whole loop — detect, explain, contain, undo — without a
// real Microsoft 365 or Google tenant. Every address and domain here is reserved for
// documentation (RFC 5737, RFC 2606), so nothing points at a real person or network.
import { ProviderError } from './http.mjs';

export const DEMO_DOMAIN = 'demo-company.example';
const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;
const LONDON = { country: 'GB', city: 'London', lat: 51.5072, lon: -0.1276 };
const LAGOS = { country: 'NG', city: 'Lagos', lat: 6.5244, lon: 3.3792 };
const OFFICE_IP = '198.51.100.10';
const ATTACKER_IP = '203.0.113.66';
const SPRAY_IP = '203.0.113.99';
export const DEMO_USERS = ['amira', 'ben', 'chen'].map((name) => `${name}@${DEMO_DOMAIN}`);
export const SCENARIOS = Object.freeze({
  'account-takeover':
    'MFA fatigue, a sign-in from Lagos, a hidden forwarding rule, a mail-reading app and a download spike on one account',
  'password-spray': 'One address tries a common password against twelve accounts',
  'data-theft': 'An insider downloads 80 files and shares one with a personal Gmail address',
});

const signin = (id, user, at, extra = {}) => ({
  id,
  provider: 'simulation',
  type: 'signin.success',
  at,
  user: { email: user },
  ip: OFFICE_IP,
  geo: LONDON,
  device: { id: `${user}-laptop`, os: 'Windows 11', browser: 'Edge' },
  app: 'Office 365',
  outcome: 'success',
  ...extra,
});

function history(now) {
  const events = [];
  const start = now - 14 * DAY;
  for (let day = 0; day < 14; day += 1) {
    const morning = Math.floor((start + day * DAY) / DAY) * DAY + 9 * HOUR;
    DEMO_USERS.forEach((user, u) => {
      events.push(signin(`sim:hist:${day}:${u}`, user, morning + u * 7 * MIN));
      for (let f = 0; f < 3; f += 1)
        events.push({
          id: `sim:hist:${day}:${u}:dl${f}`,
          provider: 'simulation',
          type: 'file.download',
          at: morning + (2 + f) * HOUR,
          user: { email: user },
          ip: OFFICE_IP,
          target: { file: `Report-${day}-${f}.xlsx` },
        });
    });
  }
  return events.filter((e) => e.at < now - HOUR);
}

function scenarioEvents(name, at, seq) {
  const id = (suffix) => `sim:${name}:${seq}:${suffix}`;
  const victim = DEMO_USERS[0];
  if (name === 'account-takeover') {
    const events = [signin(id('office'), victim, at - 40 * MIN)];
    for (let i = 0; i < 6; i += 1)
      events.push({
        id: id(`deny${i}`),
        provider: 'simulation',
        type: 'mfa.denied',
        at: at - (14 - i) * MIN,
        user: { email: victim },
        ip: ATTACKER_IP,
        geo: LAGOS,
        app: 'Office 365',
      });
    events.push(
      signin(id('attacker'), victim, at - 7 * MIN, {
        ip: ATTACKER_IP,
        geo: LAGOS,
        device: { id: 'unknown-linux', os: 'Linux', browser: 'Chrome' },
      }),
    );
    events.push({
      id: id('rule'),
      provider: 'simulation',
      type: 'mailrule.created',
      at: at - 5 * MIN,
      user: { email: victim },
      ip: ATTACKER_IP,
      target: {
        name: '.',
        forwardTo: ['collect.invoices@proton.me'],
        redirectTo: [],
        delete: true,
        moveToFolder: 'RSS Feeds',
        markAsRead: true,
        keywords: ['invoice', 'payment'],
      },
    });
    events.push({
      id: id('consent'),
      provider: 'simulation',
      type: 'oauth.consent',
      at: at - 4 * MIN,
      user: { email: victim },
      ip: ATTACKER_IP,
      target: {
        app: 'Mail Backup Pro',
        clientId: 'sim-app-mailbackup',
        scopes: ['Mail.ReadWrite', 'Mail.Send', 'offline_access'],
        tenantWide: false,
      },
    });
    for (let i = 0; i < 60; i += 1)
      events.push({
        id: id(`dl${i}`),
        provider: 'simulation',
        type: 'file.download',
        at: at - 3 * MIN + i * 2000,
        user: { email: victim },
        ip: ATTACKER_IP,
        target: { file: `Finance/Client-${i}.pdf` },
      });
    return {
      events,
      tenant: {
        rule: { user: victim, name: '.' },
        grant: { clientId: 'sim-app-mailbackup', app: 'Mail Backup Pro', user: victim },
      },
    };
  }
  if (name === 'password-spray') {
    const events = [];
    for (let i = 0; i < 12; i += 1)
      events.push({
        id: id(`spray${i}`),
        provider: 'simulation',
        type: 'signin.failure',
        at: at - 20 * MIN + i * MIN,
        user: { email: `staff${String(i + 1).padStart(2, '0')}@${DEMO_DOMAIN}` },
        ip: SPRAY_IP,
        outcome: 'failure',
        detail: 'Invalid username or password',
      });
    return { events, tenant: {} };
  }
  if (name === 'data-theft') {
    const insider = DEMO_USERS[1];
    const events = [];
    for (let i = 0; i < 80; i += 1)
      events.push({
        id: id(`dl${i}`),
        provider: 'simulation',
        type: 'file.download',
        at: at - 30 * MIN + i * 15_000,
        user: { email: insider },
        ip: OFFICE_IP,
        target: { file: `Clients/Contract-${i}.docx` },
      });
    events.push({
      id: id('share'),
      provider: 'simulation',
      type: 'file.share',
      at: at - 5 * MIN,
      user: { email: insider },
      ip: OFFICE_IP,
      target: { file: 'Clients/Pricing-2027.xlsx', to: 'ben.private@gmail.com' },
    });
    return { events, tenant: {} };
  }
  throw new ProviderError(`Unknown scenario "${name}".`);
}

function tenantOf(state) {
  state.sim ||= { seeded: false, pending: [], seq: 0 };
  state.sim.tenant ||= { disabled: {}, rules: [], grants: [], signedOutAt: {}, mustChangePassword: {} };
  return state.sim;
}

export function queueScenario(state, name, at = Date.now()) {
  if (!SCENARIOS[name])
    throw new ProviderError(`Unknown scenario "${name}". Choose one of: ${Object.keys(SCENARIOS).join(', ')}.`);
  const sim = tenantOf(state);
  if (sim.pending.length >= 5) throw new ProviderError('Five scenarios are already waiting for the next sync.');
  sim.pending.push({ name, at });
  return sim.pending.length;
}

export function createSimulationProvider() {
  return {
    id: 'simulation',
    validate: () => ({ config: { domains: [DEMO_DOMAIN] }, secret: null }),
    async test() {
      return {
        ok: true,
        checks: [{ name: 'Demo tenant', ok: true, detail: 'Simulated data, no real accounts.' }],
        domains: [DEMO_DOMAIN],
        name: 'Demo Company (simulated)',
      };
    },
    async collect(_connection, _secret, { state = {}, now = Date.now() } = {}) {
      const sim = tenantOf(state);
      const events = [];
      if (!sim.seeded) {
        events.push(...history(now));
        sim.seeded = true;
      }
      for (const item of sim.pending.splice(0)) {
        sim.seq += 1;
        const out = scenarioEvents(item.name, Math.min(item.at, now), sim.seq);
        events.push(...out.events);
        if (out.tenant.rule) sim.tenant.rules.push(out.tenant.rule);
        if (out.tenant.grant) sim.tenant.grants.push(out.tenant.grant);
      }
      return { events, state, errors: [] };
    },
    async act(connection, _secret, type, params = {}, undoData = null) {
      connection.state = connection.state || {};
      const sim = tenantOf(connection.state);
      const t = sim.tenant;
      const user = String(params.user || '').toLowerCase();
      switch (type) {
        case 'revoke-sessions':
          t.signedOutAt[user] = Date.now();
          return { detail: `Signed ${user} out of every session (simulated).` };
        case 'force-password-reset':
          t.mustChangePassword[user] = true;
          return { detail: `${user} must choose a new password at next sign-in (simulated).` };
        case 'disable-user':
          t.disabled[user] = true;
          return { detail: `Disabled ${user} (simulated).`, undo: {} };
        case 'enable-user':
          delete t.disabled[user];
          return { detail: `Re-enabled ${user} (simulated).` };
        case 'remove-inbox-rule': {
          const index = t.rules.findIndex((r) => r.user === user && r.name === params.ruleName);
          if (index < 0) throw new ProviderError(`No inbox rule named "${params.ruleName}" in ${user}'s mailbox.`);
          const [rule] = t.rules.splice(index, 1);
          return { detail: `Removed the inbox rule "${params.ruleName}" (simulated).`, undo: { rules: [rule] } };
        }
        case 'restore-inbox-rule':
          t.rules.push(...(undoData?.rules || []));
          return { detail: `Restored the inbox rule for ${user} (simulated).` };
        case 'revoke-oauth-grant': {
          const before = t.grants.length;
          const removed = t.grants.filter((g) => g.clientId === params.clientId);
          t.grants = t.grants.filter((g) => g.clientId !== params.clientId);
          if (before === t.grants.length)
            throw new ProviderError(`"${params.app || params.clientId}" has no access to revoke.`);
          return { detail: `Revoked "${params.app || params.clientId}" (simulated).`, undo: { grants: removed } };
        }
        case 'restore-oauth-grant':
          t.grants.push(...(undoData?.grants || []));
          return { detail: `Restored "${params.app || params.clientId}" (simulated).` };
        default:
          throw new ProviderError(`The demo tenant cannot perform "${type}".`);
      }
    },
  };
}
