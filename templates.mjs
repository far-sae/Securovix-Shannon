#!/usr/bin/env node
/**
 * Shannon template engine — a Nuclei-style, data-driven check runner so coverage can grow by
 * adding JSON files (no code). Each template fetches one or more paths and asserts matchers
 * (status / word / regex over body or headers). Templates should be SPECIFIC (status + a
 * distinctive content word) to preserve the zero-false-positive guarantee.
 *
 * Template shape:
 *   { "id","name","severity","remediation",
 *     "requests":[{ "path":"/x","method":"GET","headers":{},"body":"" }],
 *     "matchers-condition":"and|or",
 *     "matchers":[ { "part":"status|body|header", "status":200 },
 *                  { "part":"body","words":["a","b"],"condition":"and|or" },
 *                  { "part":"body","regex":"^ref: refs/" } ] }
 */

import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

export function loadTemplates(dir) {
  if (!existsSync(dir)) return [];
  const out = [];
  for (const f of readdirSync(dir)) {
    if (!/\.json$/i.test(f)) continue;
    try {
      out.push(JSON.parse(readFileSync(join(dir, f), 'utf-8')));
    } catch {
      /* skip malformed template */
    }
  }
  return out;
}

function matchOne(m, ctx) {
  const part = m.part || 'body';
  const hay = part === 'status' ? String(ctx.status) : part === 'header' ? ctx.headersText : ctx.body;
  if (m.status !== undefined) return Number(ctx.status) === Number(m.status);
  if (m.words) {
    const results = m.words.map((w) => hay.includes(w));
    return (m.condition || 'or') === 'and' ? results.every(Boolean) : results.some(Boolean);
  }
  if (m.regex) {
    try {
      return new RegExp(m.regex, 'i').test(hay);
    } catch {
      return false;
    }
  }
  return false;
}

// fetchFn(url, opts) -> { status, body, headers }. Returns one finding per matched template.
export async function runTemplates(origin, templates, fetchFn) {
  const findings = [];
  for (const t of templates) {
    const matchers = t.matchers || [];
    if (!matchers.length) continue;
    const cond = t['matchers-condition'] || 'and';
    for (const req of t.requests || [{ path: '/' }]) {
      const url = origin + (req.path || '/');
      const { status, body, headers } = await fetchFn(url, {
        method: req.method || 'GET',
        headers: req.headers,
        body: req.body,
      });
      if (!status) continue;
      const headersText =
        headers && headers[Symbol.iterator] ? [...headers].map(([k, v]) => `${k}: ${v}`).join('\n') : '';
      const results = matchers.map((m) => matchOne(m, { status, body: body || '', headersText }));
      const matched = cond === 'or' ? results.some(Boolean) : results.every(Boolean);
      if (matched) {
        findings.push({
          id: t.id,
          name: t.name || t.id,
          severity: t.severity || 'info',
          target: url,
          remediation: t.remediation,
        });
        break; // one finding per template
      }
    }
  }
  return findings;
}
