// Alerts -> incidents, the plain-English summary, and the security score. Pure.
import { createHash } from 'node:crypto';
import { ACTIONS, RULES, SEVERITY_RANK, maxSeverity } from './catalog.mjs';

const HOUR = 3_600_000;
export const INCIDENT_WINDOW = 24 * HOUR;
export const MAX_ALERTS_PER_INCIDENT = 50;

// One incident per person (or per address for spraying, per finding for exploit attempts) per
// day of activity, so an account takeover shows up as one story instead of five alerts.
export function incidentKey(alert) {
  if (alert.rule === 'exploit-attempt') return `finding:${alert.context?.findingId || alert.ip || 'unknown'}`;
  // Endpoint alerts: one incident per machine. An RDP spread is about the source, not one host.
  if (alert.rule === 'rdp-spread') return `ip:${alert.ip || 'unknown'}`;
  if (alert.host?.id) return `host:${alert.host.id}`;
  if (alert.user) return `user:${String(alert.user).toLowerCase()}`;
  return `ip:${alert.ip || 'unknown'}`;
}

function incidentId(orgId, key, firstAt) {
  return `gin_${createHash('sha256').update(`${orgId}|${key}|${firstAt}`).digest('hex').slice(0, 20)}`;
}

const KIND_ORDER = [
  'signin',
  'spray',
  'persistence',
  'exfiltration',
  'exploit',
  'execution',
  'credential',
  'host-persistence',
  'lateral',
  'evasion',
  'malware',
  'ransomware',
  'health',
];

function uniqueMitre(alerts) {
  const out = new Map();
  for (const a of alerts) for (const m of a.mitre || []) out.set(m.id, m);
  return [...out.values()];
}

export function recommendedActions(alerts) {
  const out = new Map();
  for (const alert of alerts) {
    for (const type of alert.recommended || []) {
      const spec = ACTIONS[type];
      if (!spec) continue;
      const params = {};
      if (spec.needs.includes('user')) {
        if (!alert.user) continue;
        params.user = alert.user;
      }
      if (spec.needs.includes('ip')) {
        if (!alert.ip) continue;
        params.ip = alert.ip;
      }
      if (spec.needs.includes('host')) {
        if (!alert.host?.id) continue;
        params.host = alert.host.id;
        params.hostName = alert.host.name || null;
      }
      if (spec.needs.includes('pid')) {
        if (alert.context?.pid == null || alert.context?.killed) continue;
        params.pid = alert.context.pid;
        params.processName = alert.context.processName || null;
      }
      if (spec.needs.includes('path')) {
        if (!alert.context?.path) continue;
        params.path = alert.context.path;
        if (alert.context.sha256) params.sha256 = alert.context.sha256;
      }
      if (spec.needs.includes('ruleName')) {
        if (!alert.context?.ruleName) continue;
        params.ruleName = alert.context.ruleName;
      }
      if (spec.needs.includes('clientId')) {
        if (!alert.context?.clientId) continue;
        params.clientId = alert.context.clientId;
        params.app = alert.context.app || null;
        if (alert.user) params.user = alert.user; // Google revokes per person
      }
      const key = `${type}|${JSON.stringify(params)}`;
      if (!out.has(key))
        out.set(key, {
          type,
          label: spec.label,
          params,
          reversible: spec.reversible,
          connectionId: alert.connectionId || null,
        });
    }
  }
  return [...out.values()];
}

// The account-takeover chain: a suspicious sign-in followed by something that keeps access or
// takes data. Either on its own can be innocent; together they rarely are.
export function isRansomware(alerts) {
  return alerts.some((a) => RULES[a.rule]?.kind === 'ransomware');
}

// Hands-on-keyboard intrusion on a machine: credential theft or lateral movement together with
// anything else suspicious on the same host.
export function isHostIntrusion(alerts) {
  const kinds = new Set(alerts.map((a) => RULES[a.rule]?.kind));
  return (kinds.has('credential') || kinds.has('lateral')) && kinds.size > 1;
}

export function isTakeoverChain(alerts) {
  const kinds = new Set(alerts.map((a) => RULES[a.rule]?.kind));
  return kinds.has('signin') && (kinds.has('persistence') || kinds.has('exfiltration'));
}

// Explanations quote command lines and Windows paths; escape Markdown so a backslash or an
// underscore shows as typed instead of being eaten as formatting.
export const markdownText = (text) => String(text || '').replace(/([\\`*_[\]])/g, '\\$1');

export function actionTarget(p = {}) {
  if (p.ruleName) return ` ("${p.ruleName}")`;
  if (p.app) return ` (${p.app})`;
  if (p.processName)
    return ` (${p.processName}${p.pid != null ? `, PID ${p.pid}` : ''} on ${p.hostName || 'the machine'})`;
  if (p.path) return ` (${p.path} on ${p.hostName || 'the machine'})`;
  if (p.hostName) return ` (${p.hostName})`;
  if (p.user) return ` (${p.user})`;
  if (p.ip) return ` (${p.ip})`;
  return '';
}

export function describeIncident(incident) {
  const alerts = [...(incident.alerts || [])].sort((a, b) => a.at - b.at);
  const hostName = incident.key.startsWith('host:')
    ? alerts.find((a) => a.host?.name)?.host.name || incident.key.slice(5)
    : null;
  const subject = incident.key.startsWith('user:')
    ? incident.key.slice(5)
    : incident.key.startsWith('ip:')
      ? incident.key.slice(3)
      : hostName;
  const rules = [...new Set(alerts.map((a) => a.rule))];
  let title;
  if (isRansomware(alerts)) title = `Likely ransomware: ${subject}`;
  else if (isHostIntrusion(alerts)) title = `Likely hands-on intrusion: ${subject}`;
  else if (isTakeoverChain(alerts)) title = `Likely account takeover: ${subject}`;
  else if (rules.length === 1) title = `${RULES[rules[0]]?.title || rules[0]}${subject ? `: ${subject}` : ''}`;
  else title = `${alerts.length} suspicious events${subject ? ` for ${subject}` : ''}`;
  const lines = alerts.map(
    (a) => `- ${new Date(a.at).toISOString().slice(0, 16).replace('T', ' ')} UTC: ${markdownText(a.explanation)}`,
  );
  const actions = recommendedActions(alerts);
  const healthOnly = alerts.length > 0 && alerts.every((a) => RULES[a.rule]?.kind === 'health');
  const what = healthOnly
    ? 'Nothing here shows an attack. Check that the machine is switched on and connected, and that the Guard service is running. If this machine is often switched off, turn off "Alert when offline" for it on the Guard page.'
    : isRansomware(alerts)
      ? 'Treat this as ransomware until proven otherwise. Isolate the machine now (it keeps talking to Securovix only), do not switch it off, and check your backups are offline and intact. Then find how it got in: look at the other alerts on this machine.'
      : isHostIntrusion(alerts)
        ? 'Someone is working on this machine by hand: collecting passwords or reaching other machines. Isolate it, then reset the passwords of everyone who signed in to it recently, starting with admins.'
        : alerts.some((a) => a.host?.id)
          ? 'Check with whoever uses this machine whether they ran this. If not, stop the process and isolate the machine.'
          : isTakeoverChain(alerts)
            ? 'This looks like someone else is using the account. Sign them out everywhere, force a password change, then undo what they set up (rules, app access, roles).'
            : alerts.some((a) => a.rule === 'exploit-attempt')
              ? 'Someone is attacking a weakness Shannon already proved. Ship the fix and re-test; until then keep the WAF rule in place.'
              : 'Check with the person whether this was them. If not, act on the steps below.';
  // Paragraphs are separated by blank lines so Markdown does not fold them into the last bullet.
  const paragraphs = [
    [
      `**What happened.** ${alerts.length === 1 ? 'One event' : `${alerts.length} related events`} between ${new Date(alerts[0]?.at || incident.firstSeenAt).toISOString().slice(0, 16).replace('T', ' ')} and ${new Date(alerts.at(-1)?.at || incident.lastSeenAt).toISOString().slice(0, 16).replace('T', ' ')} UTC:`,
      ...lines,
    ].join('\n'),
    `**What it means.** ${what}`,
  ];
  if (actions.length)
    paragraphs.push(
      `**Recommended.** ${actions.map((a) => a.label + markdownText(actionTarget(a.params))).join('; ')}.`,
    );
  const techniques = uniqueMitre(alerts);
  if (techniques.length)
    paragraphs.push(`**MITRE ATT&CK.** ${techniques.map((m) => `${m.id} ${m.name} (${m.tactic})`).join('; ')}.`);
  const summary = paragraphs.join('\n\n');
  return { title, summary, actions };
}

/**
 * Folds new alerts into the open incidents.
 * @returns {{ changed: Array, created: Array }} incidents to save; `created` also listed in changed
 */
export function groupAlerts(openIncidents, alerts, { orgId, now = Date.now() } = {}) {
  const byKey = new Map();
  for (const incident of openIncidents || []) {
    if (incident.status === 'closed') continue;
    const current = byKey.get(incident.key);
    if (!current || current.lastSeenAt < incident.lastSeenAt) byKey.set(incident.key, incident);
  }
  const changed = new Map();
  const created = [];
  for (const alert of [...(alerts || [])].sort((a, b) => a.at - b.at)) {
    const key = incidentKey(alert);
    let incident = byKey.get(key);
    if (incident && alert.at - incident.lastSeenAt > INCIDENT_WINDOW) incident = null;
    if (incident && (incident.alerts || []).some((a) => a.id === alert.id)) continue;
    if (!incident) {
      incident = {
        id: incidentId(orgId, key, alert.at),
        orgId,
        key,
        status: 'open',
        severity: alert.severity,
        title: '',
        summary: '',
        aiSummary: null,
        mitre: [],
        alerts: [],
        actions: [],
        actionsTaken: [],
        firstSeenAt: alert.at,
        lastSeenAt: alert.at,
        detectedAt: now,
        containedAt: null,
        closedAt: null,
        closedBy: null,
        createdAt: now,
        updatedAt: now,
      };
      created.push(incident);
      byKey.set(key, incident);
    } else if (incident.status === 'contained') {
      // New activity after containment means containment did not hold.
      incident.status = 'open';
      incident.containedAt = null;
      incident.reopened = (incident.reopened || 0) + 1;
    }
    incident.alerts = [...(incident.alerts || []), alert].slice(-MAX_ALERTS_PER_INCIDENT);
    incident.alertCount = (incident.alertCount || 0) + 1;
    incident.lastSeenAt = Math.max(incident.lastSeenAt, alert.at);
    incident.firstSeenAt = Math.min(incident.firstSeenAt, alert.at);
    rebuildIncident(incident, now);
    changed.set(incident.id, incident);
  }
  return { changed: [...changed.values()], created };
}

/** Recomputes everything derived from an incident's alerts: severity, techniques, title, summary. */
export function rebuildIncident(incident, now = Date.now()) {
  incident.severity = incident.alerts.reduce((s, a) => maxSeverity(s, a.severity), 'info');
  if (isTakeoverChain(incident.alerts) || isRansomware(incident.alerts) || isHostIntrusion(incident.alerts))
    incident.severity = 'critical';
  incident.mitre = uniqueMitre(incident.alerts);
  incident.kinds = [...new Set(incident.alerts.map((a) => RULES[a.rule]?.kind))].sort(
    (a, b) => KIND_ORDER.indexOf(a) - KIND_ORDER.indexOf(b),
  );
  Object.assign(incident, describeIncident(incident));
  incident.aiSummary = null; // stale once the evidence changes
  incident.updatedAt = now;
  return incident;
}

export function publicIncident(incident) {
  return {
    ...incident,
    alerts: (incident.alerts || []).map((a) => ({ ...a })),
    // Detect: first suspicious event -> Guard raised it (bounded by the provider's log delay and
    // the sync interval). Contain: Guard raised it -> containment held (bounded by people, or
    // seconds with autopilot).
    timeToDetectMs: incident.detectedAt ? Math.max(0, incident.detectedAt - incident.firstSeenAt) : null,
    timeToContainMs:
      incident.containedAt && incident.detectedAt ? Math.max(0, incident.containedAt - incident.detectedAt) : null,
  };
}

const INCIDENT_POINTS = { critical: 15, high: 8, medium: 3, low: 1, info: 0 };
const FINDING_POINTS = { critical: 10, high: 5, medium: 2, low: 0, info: 0 };

// A 0-100 score with every deduction spelled out, so the number is never a mystery.
export function securityScore({ incidents = [], connections = [], findings = [], kevMatches = [] } = {}) {
  const deductions = [];
  const real = connections.filter((c) => c.provider !== 'simulation' && c.enabled !== false);
  if (!real.length)
    deductions.push({
      points: 15,
      reason: 'Microsoft 365 or Google Workspace is not connected, so sign-ins and mailboxes are not watched.',
    });
  const broken = connections.filter((c) => c.lastError && c.enabled !== false);
  if (broken.length)
    deductions.push({
      points: Math.min(10, 5 * broken.length),
      reason: `${broken.length} connection${broken.length > 1 ? 's are' : ' is'} failing to sync.`,
    });
  const open = incidents.filter((i) => i.status === 'open');
  const incidentPoints = Math.min(
    45,
    open.reduce((sum, i) => sum + (INCIDENT_POINTS[i.severity] || 0), 0),
  );
  if (incidentPoints)
    deductions.push({
      points: incidentPoints,
      reason: `${open.length} open incident${open.length > 1 ? 's' : ''} not yet contained.`,
    });
  const openFindings = findings.filter((f) => !['resolved', 'false-positive', 'risk-accepted'].includes(f.status));
  const findingPoints = Math.min(
    30,
    openFindings.reduce((sum, f) => sum + (FINDING_POINTS[f.severity] || 0), 0),
  );
  if (findingPoints)
    deductions.push({
      points: findingPoints,
      reason: `${openFindings.length} open Shannon finding${openFindings.length > 1 ? 's' : ''}.`,
    });
  const kev = kevMatches.filter((m) => m.status !== 'resolved' && (m.source === 'cisa-kev' || m.details?.kev));
  if (kev.length)
    deductions.push({
      points: Math.min(20, 10 * kev.length),
      reason: `${kev.length} known-exploited vulnerabilit${kev.length > 1 ? 'ies' : 'y'} (CISA KEV) in your software.`,
    });
  const score = Math.max(0, 100 - deductions.reduce((sum, d) => sum + d.points, 0));
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
  return { score, grade, deductions };
}

export const severityRank = (s) => SEVERITY_RANK[s] ?? 0;
