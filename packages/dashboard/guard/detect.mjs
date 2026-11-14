// Guard detection: normalized identity/cloud events in, alerts out.
//
// Three layers, as in the spec. Known threats: sign-ins from addresses on threat feeds or the
// organization's blocklist, and the provider's own risk flag. Unknown threats: per-person
// baselines (countries, devices, normal download volume) and per-address failure windows, so
// impossible travel, a first-ever country, MFA fatigue, password spraying and a download spike
// are caught without any signature. Persistence: inbox rules, forwarding, risky app consents,
// new admins, MFA switched off.
//
// Pure: state comes in and goes out, nothing is read from or written to storage here.
import { createHash } from 'node:crypto';
import {
  HIDING_FOLDERS,
  LURE_WORDS,
  PERSONAL_MAIL_DOMAINS,
  PRIVILEGED_ROLES,
  RISKY_SCOPES,
  RULES,
  maxSeverity,
  mitreFor,
} from './catalog.mjs';

const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

export const DETECTION_DEFAULTS = Object.freeze({
  learnSignins: 10, // a baseline needs this many successful sign-ins...
  learnDays: 7, // ...spanning this many days before "new country" or "new device" can fire
  travelKm: 500,
  travelKmh: 900, // faster than an airliner
  fatigueDenials: 5,
  fatigueWindow: 10 * MIN,
  bruteFailures: 10,
  bruteWindow: 15 * MIN,
  sprayUsers: 10,
  sprayWindow: 30 * MIN,
  downloadFloor: 50, // never call fewer than this many downloads in an hour a spike
  downloadSigma: 4,
  shareBurst: 20,
  quietPeriod: HOUR, // a windowed rule fires once per person per hour, not on every event
});

export function userKey(user) {
  return String(user?.email || user?.id || '')
    .trim()
    .toLowerCase();
}

export function emptyBaseline(key) {
  return {
    key,
    signins: 0,
    firstSeenAt: null,
    countries: {},
    devices: {},
    last: null,
    recent: { mfaDenied: [], failures: [] },
    downloads: { bucket: 0, count: 0, mean: 0, variance: 0, hours: 0 },
    shares: { bucket: 0, count: 0 },
    quietUntil: {},
  };
}

export function emptyOrgState() {
  return { ipFailures: {}, seen: [] };
}

function haversineKm(a, b) {
  const rad = (d) => (d * Math.PI) / 180;
  const dLat = rad(b.lat - a.lat);
  const dLon = rad(b.lon - a.lon);
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(rad(a.lat)) * Math.cos(rad(b.lat)) * Math.sin(dLon / 2) ** 2;
  return 2 * 6371 * Math.asin(Math.min(1, Math.sqrt(h)));
}

const hasGeo = (geo) =>
  geo && Number.isFinite(geo.lat) && Number.isFinite(geo.lon) && !(geo.lat === 0 && geo.lon === 0);
const place = (geo) => [geo?.city, geo?.country].filter(Boolean).join(', ') || 'an unknown place';
const domainOf = (address) =>
  String(address || '')
    .toLowerCase()
    .split('@')[1] || '';

function trimTimes(list, now, window) {
  while (list.length && list[0] < now - window) list.shift();
  if (list.length > 2000) list.splice(0, list.length - 2000);
  return list;
}

function snapshot(event) {
  return {
    id: event.id,
    type: event.type,
    at: event.at,
    user: event.user?.email || event.user?.id || null,
    ip: event.ip || null,
    place: event.geo ? place(event.geo) : null,
    app: event.app || null,
    outcome: event.outcome || null,
    target: event.target || null,
  };
}

function alertId(orgId, rule, key) {
  return `gal_${createHash('sha256').update(`${orgId}|${rule}|${key}`).digest('hex').slice(0, 24)}`;
}

export function isExternal(address, orgDomains) {
  const domain = domainOf(address);
  if (!domain) return false;
  return !orgDomains.has(domain) && ![...orgDomains].some((own) => domain.endsWith(`.${own}`));
}

export function riskyScopes(scopes) {
  const wanted = new Set(RISKY_SCOPES);
  return (scopes || []).map((s) => String(s).trim()).filter((s) => wanted.has(s.toLowerCase()));
}

// Judges one inbox rule. Returns null for an ordinary rule (sort newsletters into a folder).
export function judgeInboxRule(rule, orgDomains) {
  const reasons = [];
  let severity = null;
  let forwarding = false;
  const targets = [...(rule.forwardTo || []), ...(rule.redirectTo || [])].map((x) => String(x).toLowerCase());
  const outside = targets.filter((address) => isExternal(address, orgDomains));
  if (outside.length) {
    forwarding = true;
    severity = 'high';
    reasons.push(`forwards mail to ${outside.join(', ')} outside the organization`);
  }
  if (rule.delete) {
    severity = maxSeverity(severity || 'medium', 'medium');
    reasons.push('deletes matching mail');
  }
  const folder = String(rule.moveToFolder || '').toLowerCase();
  if (folder && HIDING_FOLDERS.some((name) => folder.includes(name))) {
    severity = maxSeverity(severity || 'medium', 'medium');
    reasons.push(`moves mail into "${rule.moveToFolder}", a folder people rarely open`);
  }
  if (rule.markAsRead && (rule.delete || folder)) reasons.push('marks it as read');
  const words = (rule.keywords || []).map((w) => String(w).toLowerCase());
  const lures = words.filter((w) => LURE_WORDS.some((lure) => w.includes(lure)));
  if (reasons.length && lures.length) {
    severity = maxSeverity(severity, 'high');
    reasons.push(`only for mail mentioning ${lures.map((w) => `"${w}"`).join(', ')}`);
  }
  if (!reasons.length) return null;
  return { severity, forwarding, reasons };
}

/**
 * @param {Array} events normalized events (any order)
 * @param {object} state { orgId, connectionId, baselines: Map, orgState, badIps: Map, blocked: Set,
 *   orgDomains: Set, trustedApps: Set, options }
 * @returns {{ alerts: Array, baselines: Map, orgState: object, processed: number }}
 */
export function detect(events, state) {
  const opts = { ...DETECTION_DEFAULTS, ...(state.options || {}) };
  const orgId = state.orgId;
  const baselines = state.baselines || new Map();
  const orgState = state.orgState || emptyOrgState();
  const seen = new Set(orgState.seen || []);
  const badIps = state.badIps || new Map();
  const blocked = state.blocked || new Set();
  const orgDomains = state.orgDomains || new Set();
  const trustedApps = new Set([...(state.trustedApps || [])].map((x) => String(x).toLowerCase()));
  const alerts = new Map();
  let processed = 0;

  const raise = (rule, { key, severity, event, user, ip, explanation, extra = {}, evidence }) => {
    const id = alertId(orgId, rule, key);
    if (alerts.has(id)) return;
    alerts.set(id, {
      id,
      orgId,
      connectionId: state.connectionId || null,
      rule,
      title: RULES[rule].title,
      severity,
      at: event.at,
      user: user !== undefined ? user : event.user?.email || event.user?.id || null,
      ip: ip !== undefined ? ip : event.ip || null,
      mitre: mitreFor(rule),
      explanation,
      evidence: (evidence || [event]).slice(-20).map(snapshot),
      recommended: RULES[rule].actions,
      context: extra,
    });
  };
  const quiet = (base, rule, at) => {
    if ((base.quietUntil[rule] || 0) > at) return true;
    base.quietUntil[rule] = at + opts.quietPeriod;
    return false;
  };

  const sorted = [...(events || [])].filter((e) => e && Number.isFinite(e.at)).sort((a, b) => a.at - b.at);
  for (const event of sorted) {
    if (event.id && seen.has(event.id)) continue;
    if (event.id) {
      seen.add(event.id);
      orgState.seen.push(event.id);
    }
    processed += 1;
    const key = userKey(event.user);
    const base = key ? baselines.get(key) || emptyBaseline(key) : null;
    if (base) baselines.set(key, base);
    const who = event.user?.email || event.user?.id || 'Someone';

    switch (event.type) {
      case 'signin.success': {
        const mature =
          base.signins >= opts.learnSignins &&
          base.firstSeenAt != null &&
          event.at - base.firstSeenAt >= opts.learnDays * DAY;
        const bad = event.ip && (blocked.has(event.ip) ? { source: 'your blocklist' } : badIps.get(event.ip));
        if (bad) {
          raise('bad-ip-signin', {
            key: `${key}|${event.id}`,
            severity: 'critical',
            event,
            explanation: `${who} signed in successfully from ${event.ip}, an address on ${bad.source}${bad.label ? ` (${bad.label})` : ''}. Treat the password as stolen.`,
          });
        }
        if (event.risk === 'high') {
          raise('provider-risk', {
            key: `${key}|${event.id}`,
            severity: 'high',
            event,
            explanation: `${event.provider === 'google' ? 'Google' : 'Microsoft'} marked ${who}'s sign-in from ${event.ip || 'an unknown address'} as high risk.`,
          });
        }
        if (hasGeo(event.geo) && base.last && hasGeo(base.last.geo) && base.last.ip !== event.ip) {
          const km = haversineKm(base.last.geo, event.geo);
          const hours = Math.max((event.at - base.last.at) / HOUR, 1 / 60);
          const kmh = km / hours;
          if (km >= opts.travelKm && kmh >= opts.travelKmh) {
            raise('impossible-travel', {
              key: `${key}|${event.id}`,
              severity: 'high',
              event,
              evidence: [{ ...base.last, id: base.last.id, type: 'signin.success', user: event.user }, event],
              explanation: `${who} signed in from ${place(base.last.geo)} and then from ${place(event.geo)} ${Math.round(km)} km away, ${hours < 1 ? `${Math.round(hours * 60)} minutes` : `${hours.toFixed(1)} hours`} later. Nobody travels at ${Math.round(kmh)} km/h, so one of these sign-ins is probably not them.`,
              extra: { km: Math.round(km), kmh: Math.round(kmh), from: place(base.last.geo), to: place(event.geo) },
            });
          }
        }
        const country = event.geo?.country;
        if (mature && country && !base.countries[country]) {
          raise('new-country', {
            key: `${key}|${country}`,
            severity: 'medium',
            event,
            explanation: `${who} signed in from ${place(event.geo)} for the first time. In the last ${Math.round((event.at - base.firstSeenAt) / DAY)} days they only signed in from ${Object.keys(base.countries).join(', ') || 'elsewhere'}.`,
            extra: { country, known: Object.keys(base.countries) },
          });
        }
        // MFA fatigue that ends in a success is the dangerous version: the person gave in.
        const denials = trimTimes(base.recent.mfaDenied, event.at, 30 * MIN);
        if (denials.length >= opts.fatigueDenials) {
          raise('mfa-fatigue', {
            key: `${key}|success|${denials[0]}`,
            severity: 'critical',
            event,
            explanation: `${who} denied ${denials.length} sign-in approval requests and then a sign-in succeeded from ${event.ip || 'an unknown address'}. The usual pattern: an attacker with the password spams push requests until the person taps Approve.`,
          });
        }
        base.signins += 1;
        base.firstSeenAt ??= event.at;
        if (country) base.countries[country] = event.at;
        if (event.device?.id) base.devices[event.device.id] = event.at;
        if (denials.length >= opts.fatigueDenials) denials.length = 0;
        // Only located sign-ins move the travel anchor; an unlocated one would pair an old place
        // with a new time and invent impossible travel.
        if (hasGeo(event.geo)) base.last = { id: event.id, at: event.at, ip: event.ip || null, geo: event.geo };
        break;
      }
      case 'signin.failure': {
        if (event.ip && (blocked.has(event.ip) || badIps.has(event.ip))) {
          const bad = blocked.has(event.ip) ? { source: 'your blocklist' } : badIps.get(event.ip);
          raise('bad-ip-signin', {
            key: `${key}|fail|${event.ip}|${Math.floor(event.at / HOUR)}`,
            severity: 'high',
            event,
            explanation: `Someone tried to sign in as ${who} from ${event.ip}, an address on ${bad.source}. The attempt failed.`,
          });
        }
        const failures = trimTimes(base.recent.failures, event.at, opts.bruteWindow);
        failures.push(event.at);
        if (failures.length >= opts.bruteFailures && !quiet(base, 'brute-force', event.at)) {
          raise('brute-force', {
            key: `${key}|${failures[0]}`,
            severity: 'medium',
            event,
            explanation: `${failures.length} failed sign-ins for ${who} in ${Math.round(opts.bruteWindow / MIN)} minutes, the latest from ${event.ip || 'an unknown address'}.`,
          });
        }
        if (event.ip) {
          if (!orgState.ipFailures[event.ip]) orgState.ipFailures[event.ip] = [];
          const list = orgState.ipFailures[event.ip];
          list.push([event.at, key]);
          while (list.length && list[0][0] < event.at - opts.sprayWindow) list.shift();
          if (list.length > 300) list.splice(0, list.length - 300);
          const users = new Set(list.map(([, u]) => u));
          if (users.size >= opts.sprayUsers) {
            raise('password-spray', {
              key: `${event.ip}|${Math.floor(list[0][0] / opts.sprayWindow)}`,
              severity: 'high',
              event,
              user: null,
              explanation: `${event.ip} tried to sign in as ${users.size} different people in ${Math.round(opts.sprayWindow / MIN)} minutes. That is password spraying: one common password tried against many accounts.`,
              extra: { users: [...users].slice(0, 25) },
            });
          }
        }
        break;
      }
      case 'signin.risk': {
        raise('provider-risk', {
          key: `${key}|${event.id}`,
          severity: 'high',
          event,
          explanation: `${event.provider === 'google' ? 'Google' : 'Microsoft'} reported a ${event.detail || 'suspicious sign-in'} for ${who}${event.ip ? ` from ${event.ip}` : ''}.`,
        });
        break;
      }
      case 'mfa.denied': {
        const denials = trimTimes(base.recent.mfaDenied, event.at, opts.fatigueWindow);
        denials.push(event.at);
        if (denials.length >= opts.fatigueDenials && !quiet(base, 'mfa-fatigue', event.at)) {
          raise('mfa-fatigue', {
            key: `${key}|${denials[0]}`,
            severity: 'high',
            event,
            explanation: `${who} received and denied ${denials.length} sign-in approval requests in ${Math.round(opts.fatigueWindow / MIN)} minutes. Someone has their password and is trying to wear them down.`,
          });
        }
        break;
      }
      case 'mailrule.created':
      case 'mailrule.updated': {
        const verdict = judgeInboxRule(event.target || {}, orgDomains);
        if (!verdict) break;
        const rule = verdict.forwarding ? 'mail-forwarding' : 'inbox-rule';
        raise(rule, {
          key: `${key}|${event.target?.name || ''}|${event.id}`,
          severity: verdict.severity,
          event,
          explanation: `${who} ${event.type === 'mailrule.created' ? 'created' : 'changed'} an inbox rule${event.target?.name ? ` named "${event.target.name}"` : ''} that ${verdict.reasons.join(', ')}. Attackers who take over a mailbox use rules like this to read or hide mail.`,
          extra: { ruleName: event.target?.name || null },
        });
        break;
      }
      case 'forwarding.set': {
        const to = String(event.target?.to || '').toLowerCase();
        if (!to || !isExternal(to, orgDomains)) break;
        raise('mail-forwarding', {
          key: `${key}|fwd|${to}|${event.id}`,
          severity: 'high',
          event,
          explanation: `All of ${who}'s mail is now forwarded to ${to}, outside the organization.`,
          extra: { to },
        });
        break;
      }
      case 'oauth.consent': {
        const app = String(event.target?.app || 'an app');
        if (trustedApps.has(app.toLowerCase()) || trustedApps.has(String(event.target?.clientId || '').toLowerCase()))
          break;
        const risky = riskyScopes(event.target?.scopes);
        if (!risky.length) break;
        const tenantWide = event.target?.tenantWide === true;
        raise('oauth-consent', {
          key: `${key}|${event.target?.clientId || app}|${risky.join(',')}`,
          severity: tenantWide || risky.length > 2 ? 'high' : 'medium',
          event,
          explanation: `${who} gave "${app}" access to ${risky.join(', ')}${tenantWide ? ' for the whole organization' : ''}. An app with this access can read or send mail or files without a password, and it keeps working after a password change.`,
          extra: { clientId: event.target?.clientId || null, app, scopes: risky },
        });
        break;
      }
      case 'file.download': {
        const bucket = Math.floor(event.at / HOUR);
        const d = base.downloads;
        if (d.bucket !== bucket) {
          if (d.bucket && d.count >= 0) {
            // Exponentially weighted mean and variance of hourly downloads, per person.
            const alpha = 0.1;
            const diff = d.count - d.mean;
            d.mean += alpha * diff;
            d.variance = (1 - alpha) * (d.variance + alpha * diff * diff);
            d.hours += 1;
          }
          d.bucket = bucket;
          d.count = 0;
        }
        d.count += 1;
        // The baseline learns from clock hours; the alert looks at a sliding hour, so a burst
        // that straddles 10:00 is not split in two.
        if (!base.recent.downloads) base.recent.downloads = [];
        const recent = trimTimes(base.recent.downloads, event.at, HOUR);
        recent.push(event.at);
        const limit = Math.max(opts.downloadFloor, d.mean + opts.downloadSigma * Math.sqrt(d.variance));
        if (recent.length >= limit && !quiet(base, 'mass-download', event.at)) {
          raise('mass-download', {
            key: `${key}|${bucket}`,
            severity: 'high',
            event,
            explanation: `${who} downloaded ${recent.length} files within an hour${d.hours >= 24 ? `; in an hour when they download anything, it is usually about ${Math.max(1, Math.round(d.mean))}` : ''}. The last one came from ${event.ip || 'an unknown address'}.`,
            extra: { count: recent.length, usual: Math.round(d.mean) },
          });
        }
        break;
      }
      case 'file.share': {
        const to = String(event.target?.to || '').toLowerCase();
        const anonymous = event.target?.anonymous === true;
        const external = anonymous || (to && isExternal(to, orgDomains));
        if (!external) break;
        const s = base.shares;
        const bucket = Math.floor(event.at / HOUR);
        if (s.bucket !== bucket) Object.assign(s, { bucket, count: 0 });
        s.count += 1;
        const personal = PERSONAL_MAIL_DOMAINS.includes(domainOf(to));
        if (anonymous || personal) {
          raise('external-share', {
            key: `${key}|${event.target?.file || ''}|${to || 'anyone'}`,
            severity: personal ? 'high' : 'medium',
            event,
            explanation: anonymous
              ? `${who} created a link that lets anyone open "${event.target?.file || 'a file'}" without signing in.`
              : `${who} shared "${event.target?.file || 'a file'}" with ${to}, a personal address.`,
          });
        } else if (s.count >= opts.shareBurst && !quiet(base, 'external-share', event.at)) {
          raise('external-share', {
            key: `${key}|burst|${bucket}`,
            severity: 'high',
            event,
            explanation: `${who} shared ${s.count} files outside the organization within an hour.`,
          });
        }
        break;
      }
      case 'role.assigned': {
        const role = String(event.target?.role || '');
        if (!PRIVILEGED_ROLES.some((name) => role.toLowerCase().includes(name))) break;
        const member = event.target?.member || who;
        raise('admin-granted', {
          key: `${member}|${role}|${event.id}`,
          severity: 'high',
          event,
          user: member,
          explanation: `${member} was given the "${role}" role${event.actor ? ` by ${event.actor}` : ''}. Attackers add themselves as admins to keep control after they are found.`,
          extra: { role, actor: event.actor || null },
        });
        break;
      }
      case 'mfa.disabled': {
        raise('mfa-disabled', {
          key: `${key}|${event.id}`,
          severity: event.target?.orgWide ? 'critical' : 'high',
          event,
          explanation: event.target?.orgWide
            ? `Multi-factor sign-in was weakened for the whole organization${event.actor ? ` by ${event.actor}` : ''}: ${event.target?.detail || 'policy changed'}.`
            : `Multi-factor sign-in was turned off or a sign-in method was removed for ${who}${event.actor ? ` by ${event.actor}` : ''}.`,
        });
        break;
      }
      default:
        break;
    }
  }
  if (orgState.seen.length > 5000) orgState.seen = orgState.seen.slice(-5000);
  const ips = Object.keys(orgState.ipFailures);
  if (ips.length > 5000) for (const ip of ips.slice(0, ips.length - 5000)) delete orgState.ipFailures[ip];
  return { alerts: [...alerts.values()], baselines, orgState, processed };
}

// Shannon -> Guard: a Defender event that matches a vulnerability Shannon proved is an attack on a
// known hole, not background noise. Matching is by attack class and request path.
export function exploitAttempts(defenseEvents, findings, { orgId, since = 0 } = {}) {
  const open = (findings || [])
    .filter((f) => !['resolved', 'false-positive', 'risk-accepted'].includes(f.status))
    .map((f) => {
      const details = f.details || {};
      let path = '';
      try {
        path = new URL(String(details.target || '')).pathname;
      } catch {}
      return { finding: f, cls: String(details.cls || details.tool || ''), path };
    })
    .filter((x) => x.cls && x.path);
  if (!open.length) return [];
  const alerts = new Map();
  for (const event of defenseEvents || []) {
    const at = Number(event.createdAt || Date.parse(event.at) || 0);
    if (at < since) continue;
    let path = '';
    try {
      path = new URL(String(event.url || ''), 'http://x').pathname;
    } catch {}
    const hit = open.find((x) => x.cls === event.cls && x.path === path);
    if (!hit) continue;
    const id = alertId(orgId, 'exploit-attempt', `${hit.finding.id}|${event.srcIp || ''}|${Math.floor(at / HOUR)}`);
    if (alerts.has(id)) continue;
    alerts.set(id, {
      id,
      orgId,
      connectionId: null,
      rule: 'exploit-attempt',
      title: RULES['exploit-attempt'].title,
      severity: 'critical',
      at,
      user: null,
      ip: event.srcIp || null,
      mitre: mitreFor('exploit-attempt'),
      explanation: `${event.srcIp || 'Someone'} sent a ${event.cls} attack to ${path}, where Shannon proved a vulnerability ("${hit.finding.title}"). ${event.enforced ? 'Securovix Defender blocked this request' : 'Securovix Defender only recorded this request; it was not blocked'}. Fix the code and re-test, or put the WAF rule for this finding in front of the app until it ships.`,
      evidence: [
        {
          id: event.id,
          type: 'defender.event',
          at,
          user: null,
          ip: event.srcIp || null,
          place: null,
          app: event.source || null,
          outcome: event.enforced ? 'blocked' : 'allowed',
          target: { url: event.url, method: event.method, cls: event.cls },
        },
      ],
      recommended: RULES['exploit-attempt'].actions,
      context: { findingId: hit.finding.id, path, cls: event.cls, blocked: !!event.enforced },
    });
  }
  return [...alerts.values()];
}
