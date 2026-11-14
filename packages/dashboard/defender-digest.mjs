// defender-digest.mjs — the weekly attack summary: what was blocked, who was banned, where it came
// from. Pure functions; the server decides who receives it and when.

export const DAY = 86_400_000;

const LABELS = {
  sqli: 'SQL injection',
  xss: 'Cross-site scripting',
  'path-traversal': 'Path traversal',
  nosql: 'NoSQL injection',
  'llm-prompt-injection': 'Prompt injection',
  'cmd-injection': 'Command injection',
  'rce-ssti': 'Template injection',
  ssrf: 'Server-side request forgery',
  xxe: 'XML external entity',
  honeypot: 'Scanner probing bait paths',
  'scanner-tool': 'Known attack tool',
  crlf: 'Header injection',
  'graphql-idor': 'GraphQL introspection',
};
const SOURCES = { self: 'Securovix dashboard', sdk: 'Your apps (SDK)', edge: 'Edge proxy' };

export const classLabel = (cls) => LABELS[cls] || String(cls || 'Other');

/** The most recent complete Monday-to-Monday week in UTC. `key` is that week's Monday (YYYY-MM-DD). */
export function lastCompleteWeek(now = Date.now()) {
  const d = new Date(now);
  const sinceMonday = (d.getUTCDay() + 6) % 7;
  const to = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() - sinceMonday);
  const from = to - 7 * DAY;
  return { from, to, key: new Date(from).toISOString().slice(0, 10) };
}

const escapeHtml = (value) =>
  String(value ?? '').replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c],
  );

const top = (items, keyOf, limit) => {
  const counts = new Map();
  for (const item of items) {
    const key = keyOf(item);
    if (key) counts.set(key, (counts.get(key) || 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0]))).slice(0, limit);
};

const dayLabel = (ms) => new Date(ms).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', timeZone: 'UTC' });
const plural = (n, word) => `${n.toLocaleString('en-GB')} ${word}${n === 1 ? '' : 's'}`;

/**
 * @param {object[]} events  Defense events inside the period ({ cls, enforced, srcIp, source, method, createdAt }).
 * @param {object} opts      { orgName, from, to, previousTotal, dashboardUrl, capped }
 * @returns {{subject, text, html, totals}|null}  null when there is nothing to report.
 */
export function buildDefenseDigest(
  events,
  { orgName = '', from, to, previousTotal = null, dashboardUrl = '', capped = false } = {},
) {
  const rows = Array.isArray(events) ? events : [];
  const bans = rows.filter((e) => e.cls === 'repeat-offender' || e.method === 'BAN');
  const attacks = rows.filter((e) => !bans.includes(e));
  if (!attacks.length && !bans.length) return null;

  const blocked = attacks.filter((e) => e.enforced === true).length;
  const totals = {
    attacks: attacks.length,
    blocked,
    detectedOnly: attacks.length - blocked,
    bans: bans.length,
    sources: new Set(attacks.map((e) => e.srcIp).filter(Boolean)).size,
  };
  const byClass = top(attacks, (e) => e.cls, 8);
  const byAddress = top(attacks, (e) => e.srcIp, 5);
  const byOrigin = top(attacks, (e) => SOURCES[e.source] || e.source, 3);
  const byDay = top(attacks, (e) => (e.createdAt ? new Date(Number(e.createdAt)).toISOString().slice(0, 10) : null), 1);

  // Inclusive end date: a week that ends at Monday 00:00 is shown as ending on the Sunday.
  const period = `${dayLabel(from)} – ${dayLabel(to - 1)}`;
  const more = capped ? '+' : '';
  const subject = `Securovix Defender weekly summary: ${plural(totals.attacks, 'attack')}${more}, ${totals.blocked.toLocaleString('en-GB')} blocked (${period})`;

  let trend = '';
  if (Number.isFinite(previousTotal) && previousTotal !== null) {
    if (previousTotal === 0) trend = totals.attacks ? 'There were none the week before.' : '';
    else {
      const change = Math.round(((totals.attacks - previousTotal) / previousTotal) * 100);
      trend =
        change === 0
          ? 'About the same as the week before.'
          : `${Math.abs(change)}% ${change > 0 ? 'more' : 'fewer'} than the week before (${previousTotal.toLocaleString('en-GB')}).`;
    }
  }

  const headline = `${plural(totals.attacks, 'attack')}${more} detected, ${totals.blocked.toLocaleString('en-GB')} blocked${
    totals.detectedOnly ? `, ${totals.detectedOnly.toLocaleString('en-GB')} recorded without blocking` : ''
  }.`;
  const banLine = totals.bans
    ? `${totals.bans.toLocaleString('en-GB')} address${totals.bans === 1 ? '' : 'es'} banned for repeated attacks.`
    : '';
  const busiest = byDay[0]
    ? `Busiest day: ${dayLabel(Date.parse(byDay[0][0]))} (${byDay[0][1].toLocaleString('en-GB')}).`
    : '';
  const scope = orgName ? `${orgName}, ${period}` : period;

  const section = (title, list, labelOf = (k) => k) =>
    list.length
      ? [`${title}`, ...list.map(([key, count]) => `  ${labelOf(key)}: ${count.toLocaleString('en-GB')}`), '']
      : [];
  const text = [
    `Securovix Defender weekly summary (${scope})`,
    '',
    headline,
    ...[
      trend,
      banLine,
      busiest,
      capped ? 'Counts are a minimum: only the most recent 2,000 events are kept.' : '',
    ].filter(Boolean),
    '',
    ...section('Attack types', byClass, classLabel),
    ...section('Where the attacks were aimed', byOrigin),
    ...section('Most active source addresses', byAddress),
    totals.detectedOnly
      ? 'Attacks recorded without blocking were either seen in monitor mode or matched a broad pattern that is reported but never blocked.'
      : '',
    dashboardUrl ? `Open the Defender page: ${dashboardUrl}/#defender` : '',
    '',
    'You receive this because you are an owner or admin of this organization. Turn it off on the Defender page.',
  ]
    .filter((line, index, all) => !(line === '' && all[index - 1] === ''))
    .join('\n')
    .trim();

  const table = (title, list, labelOf = (k) => k) =>
    list.length
      ? `<h3 style="font:600 14px system-ui,sans-serif;margin:20px 0 6px">${escapeHtml(title)}</h3><table style="border-collapse:collapse;font:14px system-ui,sans-serif;width:100%">${list
          .map(
            ([key, count]) =>
              `<tr><td style="padding:4px 0;border-bottom:1px solid #e5e7eb">${escapeHtml(labelOf(key))}</td><td style="padding:4px 0;border-bottom:1px solid #e5e7eb;text-align:right">${count.toLocaleString('en-GB')}</td></tr>`,
          )
          .join('')}</table>`
      : '';
  const html = `<div style="max-width:560px;margin:0 auto;color:#111827;font:14px/1.5 system-ui,sans-serif">
<h2 style="font:600 18px system-ui,sans-serif;margin:0 0 4px">Securovix Defender weekly summary</h2>
<p style="margin:0 0 14px;color:#6b7280">${escapeHtml(scope)}</p>
<p style="margin:0 0 6px;font-size:16px"><b>${escapeHtml(headline)}</b></p>
${[trend, banLine, busiest, capped ? 'Counts are a minimum: only the most recent 2,000 events are kept.' : '']
  .filter(Boolean)
  .map((line) => `<p style="margin:0 0 4px">${escapeHtml(line)}</p>`)
  .join('\n')}
${table('Attack types', byClass, classLabel)}
${table('Where the attacks were aimed', byOrigin)}
${table('Most active source addresses', byAddress)}
${dashboardUrl ? `<p style="margin:20px 0 0"><a href="${escapeHtml(dashboardUrl)}/#defender">Open the Defender page</a></p>` : ''}
<p style="margin:20px 0 0;color:#6b7280;font-size:12px">You receive this because you are an owner or admin of this organization. Turn it off on the Defender page.</p>
</div>`;

  return { subject, text, html, totals, period, byClass, byAddress, byOrigin };
}
