// "This request is the owner's own test."
//
// The AI Agent and its scheduled monitor send attack-shaped requests to a site its organization
// owns. When that site runs Defender, every one of those requests used to arrive in the dashboard as
// a critical attack, and real attacks were lost among them.
//
// So the dashboard signs a short-lived mark and the checking engine sends it, as a request header,
// to the site under test. Defender on the site passes the mark back with its report, and the
// dashboard files a report that carries a valid mark as the organization's own test.
//
// What the mark is not: permission. The site inspects, bans and blocks a marked request exactly like
// any other, so a stolen mark gets nothing through. It only changes how the report is filed, and
// only for the organization and the site it was signed for, until it expires.
import { createHmac, timingSafeEqual } from 'node:crypto';

export const OWN_TEST_HEADER = 'x-securovix-test';
// Longer than a run takes (it is signed when the run starts), short enough that an old mark is useless.
// A run that outlasts it is not harmed: its later requests are simply reported as attacks.
export const OWN_TEST_TTL_MS = 60 * 60_000;
// A scan runs for much longer than an AI Agent run, so its mark lasts longer.
export const OWN_TEST_SCAN_TTL_MS = 6 * 60 * 60_000;
// agent / team / monitor: AI Agent runs. scan: a New Scan. tool: one request sent by hand from the
// AI Agent page (request replay, custom check).
const KINDS = new Set(['agent', 'team', 'monitor', 'scan', 'tool']);
const SHAPE = /^v1\.([a-z]{1,12})\.([0-9a-z]{1,12})\.([A-Za-z0-9_-]{43})$/;

// The site a URL or a "host/path?query" string belongs to: its host name in lower case, without the
// port and without a leading "www.". A site and its www twin are one site here, because the plain
// name usually just redirects to the other.
export function siteName(value) {
  const text = String(value || '').trim();
  if (!text) return '';
  let host = '';
  try {
    host = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `http://${text}`).hostname;
  } catch {
    host = text
      .replace(/^[a-z][a-z0-9+.-]*:\/\//i, '')
      .split(/[/?#]/)[0]
      .replace(/:\d+$/, '');
  }
  return host
    .toLowerCase()
    .replace(/^www\./, '')
    .replace(/\.$/, '');
}

const mac = (secret, orgId, site, kind, expires) =>
  createHmac('sha256', secret).update(`defender-own-test:v1:${orgId}:${site}:${kind}:${expires}`).digest('base64url');

/**
 * A mark for one run. Returns { header, value, site }, or null when there is nothing to sign with
 * (the run then goes unmarked, and its requests are reported as attacks, which is the safe side).
 */
export function signOwnTest(secret, { orgId, target, kind = 'agent', now = Date.now(), ttlMs = OWN_TEST_TTL_MS } = {}) {
  const site = siteName(target);
  if (!secret || !orgId || !site || !KINDS.has(kind)) return null;
  const expires = Math.floor(now + ttlMs);
  return {
    header: OWN_TEST_HEADER,
    value: `v1.${kind}.${expires.toString(36)}.${mac(secret, orgId, site, kind, expires)}`,
    site,
  };
}

/**
 * Is this mark one the dashboard signed for this organization and this site, and still in date?
 * Returns { kind } or null. `url` is the reported address ("host/path?query" or a full URL).
 */
export function verifyOwnTest(secret, token, { orgId, url, now = Date.now() } = {}) {
  if (!secret || !orgId || typeof token !== 'string' || token.length > 200) return null;
  const m = SHAPE.exec(token);
  if (!m || !KINDS.has(m[1])) return null;
  const expires = Number.parseInt(m[2], 36);
  if (!Number.isSafeInteger(expires) || expires < now) return null;
  const site = siteName(url);
  if (!site) return null;
  const expected = Buffer.from(mac(secret, orgId, site, m[1], expires));
  const given = Buffer.from(m[3]);
  if (expected.length !== given.length || !timingSafeEqual(expected, given)) return null;
  return { kind: m[1] };
}

// A scan runs in a process of its own. The dashboard hands it the mark it signed, in the
// SHANNON_TEST_MARK variable, as { header, value, site }. Returns the mark in the shape the checking
// engine uses, or null when there is none or it is not well formed.
export function markFromEnv(env = process.env) {
  try {
    const given = JSON.parse(env.SHANNON_TEST_MARK || 'null');
    if (!given || given.header !== OWN_TEST_HEADER || typeof given.value !== 'string' || !SHAPE.test(given.value))
      return null;
    const site = siteName(given.site);
    if (!site) return null;
    return { header: OWN_TEST_HEADER, value: given.value, site, applies: (url) => siteName(url) === site };
  } catch {
    return null;
  }
}

// A stored Defender event that was filed as the organization's own test.
export const isOwnTest = (event) => Boolean(event?.metadata?.ownTest);

/**
 * One stored event per test run, not one per request.
 *
 * An hourly monitor sends about ten attack-shaped requests a run. Stored one by one they would fill
 * the event history with the organization's own tests and push real attacks out of it. So the first
 * marked report of a run creates one event, and the rest of that run's reports are counted on it:
 * how many requests Defender caught, how many it blocked, and of which kinds.
 *
 * `append(event)` stores a new event; `update(orgId, id, { metadata })` saves a changed one. The
 * count in memory is always current; saving is held back for `settleMs` so a burst of reports is
 * one write, and so the write lands after the event itself has been stored.
 */
export function createOwnTestLedger({ append, update, newId, settleMs = 2000, now = Date.now, maxRuns = 500 } = {}) {
  const runs = new Map(); // organization + source + mark -> { event, timer, startedAt }
  const save = (run) => {
    if (run.timer) return;
    run.timer = setTimeout(() => {
      run.timer = null;
      try {
        update(run.event.orgId, run.event.id, { metadata: run.event.metadata });
      } catch {}
    }, settleMs);
    run.timer.unref?.();
  };
  const count = (event, detection, at) => {
    const was = event.metadata.ownTest;
    // At most 24 kinds are counted by name in one run; anything further is counted as "other".
    const named = String(detection?.cls || 'unknown').slice(0, 60);
    const cls = Object.hasOwn(was.classes, named) || Object.keys(was.classes).length < 24 ? named : 'other';
    event.metadata = {
      ...event.metadata,
      ownTest: {
        ...was,
        requests: was.requests + 1,
        blocked: was.blocked + (detection?.enforced === true ? 1 : 0),
        classes: { ...was.classes, [cls]: (was.classes[cls] || 0) + 1 },
        lastAt: at,
      },
    };
  };
  return {
    /** Count one marked report. Returns the run's event. */
    record({ orgId, userId = null, source = 'sdk', token, kind, site, detection, at, metadata = {} }) {
      const key = `${orgId}|${source}|${token}`;
      const when = at || new Date(now()).toISOString();
      let run = runs.get(key);
      if (run) {
        count(run.event, detection, when);
        save(run);
        return run.event;
      }
      // A mark is dead after OWN_TEST_TTL_MS, so its run can be forgotten then.
      for (const [k, old] of runs) if (now() - old.startedAt > OWN_TEST_TTL_MS || runs.size >= maxRuns) runs.delete(k);
      const event = {
        id: newId(),
        orgId,
        userId,
        at: when,
        method: 'TEST',
        url: String(site || '').slice(0, 300),
        cls: 'own-test',
        enforced: false,
        srcIp: detection?.srcIp ? String(detection.srcIp).slice(0, 64) : null,
        severity: 'info',
        source,
        status: 'closed',
        metadata: { ...metadata, ownTest: { kind, requests: 0, blocked: 0, classes: {}, lastAt: when } },
        createdAt: now(),
      };
      count(event, detection, when);
      run = { event, timer: null, startedAt: now() };
      runs.set(key, run);
      append(event);
      return event;
    },
  };
}
