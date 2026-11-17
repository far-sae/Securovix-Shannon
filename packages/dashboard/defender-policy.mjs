// Website protection settings: what an organization chooses in Settings, and what its websites
// are sent. One set of settings per organization; every site that carries the organization's key
// reads it and applies it within a minute.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { ENFORCE_CLASSES } from '../defender-sdk/signatures.mjs';

/** The blocking rules, in the words shown to the person switching them on and off. */
export const DEFENDER_RULES = [
  {
    id: 'sqli',
    label: 'Database attacks (SQL injection)',
    what: 'Text that breaks out of a database query to read or change data.',
  },
  { id: 'xss', label: 'Script injection (XSS)', what: 'Markup that would run script in a visitor’s browser.' },
  {
    id: 'path-traversal',
    label: 'File path tricks',
    what: 'Requests that climb out of the site’s folder to read system files.',
  },
  { id: 'cmd-injection', label: 'Server commands', what: 'Text that would run a command on the server.' },
  {
    id: 'rce-ssti',
    label: 'Code in templates (incl. Log4Shell)',
    what: 'Expressions that make a template engine or logger run code.',
  },
  {
    id: 'ssrf',
    label: 'Internal address requests',
    what: 'Links that make the server fetch cloud credentials or internal services.',
  },
  { id: 'xxe', label: 'XML external files', what: 'XML that makes the server read a file or address it names.' },
  {
    id: 'nosql',
    label: 'Database operator tricks (NoSQL)',
    what: 'Query operators sent where a value was expected, to skip a login.',
  },
  {
    id: 'llm-prompt-injection',
    label: 'AI prompt attacks',
    what: 'Messages that tell an AI assistant to drop its instructions.',
  },
];

export const DEFAULT_POLICY = Object.freeze({
  enabled: true,
  // Watch-only until the owner has seen what would be blocked on their own traffic.
  mode: 'monitor',
  disabled: [],
  skip: [],
  honeypot: false,
  scanners: false,
  ban: { enabled: false, threshold: 5, minutes: 15 },
  rateLimit: { enabled: false, perMinute: 300 },
});

const MAX_SKIP = 50;
const int = (value, fallback, min, max) => {
  const n = Math.trunc(Number(value));
  return Number.isFinite(n) ? Math.max(min, Math.min(max, n)) : fallback;
};

/**
 * Checks settings sent from the Settings page.
 * @returns {{ ok: true, policy: object } | { ok: false, error: string }}
 */
export function normalizePolicy(input) {
  const src = input && typeof input === 'object' && !Array.isArray(input) ? input : {};
  if (src.mode !== undefined && src.mode !== 'monitor' && src.mode !== 'enforce')
    return { ok: false, error: 'Choose "watch only" or "block attacks".' };
  const disabled = Array.isArray(src.disabled) ? src.disabled.map(String) : [];
  const unknown = disabled.find((id) => !ENFORCE_CLASSES.includes(id));
  if (unknown) return { ok: false, error: `"${unknown.slice(0, 40)}" is not a rule.` };

  // One page per line (or an array). A page is a path on the site: it starts with "/".
  const lines = (Array.isArray(src.skip) ? src.skip : String(src.skip ?? '').split('\n'))
    .map((line) => String(line).trim())
    .filter(Boolean);
  if (lines.length > MAX_SKIP) return { ok: false, error: `At most ${MAX_SKIP} pages can be left uninspected.` };
  for (const line of lines) {
    // biome-ignore lint/suspicious/noControlCharactersInRegex: control characters are what is refused
    if (!line.startsWith('/') || line.length > 200 || /[\s\u0000-\u001f?#]/.test(line))
      return {
        ok: false,
        error: `"${line.slice(0, 60)}" is not a page path. Write it like /api/webhooks (it must start with "/", with no spaces, "?" or "#").`,
      };
    if (line === '/')
      return {
        ok: false,
        error:
          'Leaving "/" uninspected would switch protection off for the whole site. Use the on/off switch for that.',
      };
  }

  return {
    ok: true,
    policy: {
      enabled: src.enabled !== false,
      mode: src.mode === 'enforce' ? 'enforce' : 'monitor',
      disabled: [...new Set(disabled)],
      skip: [...new Set(lines)],
      honeypot: src.honeypot === true,
      scanners: src.scanners === true,
      ban: {
        enabled: src.ban?.enabled === true,
        threshold: int(src.ban?.threshold, DEFAULT_POLICY.ban.threshold, 2, 50),
        minutes: int(src.ban?.minutes, DEFAULT_POLICY.ban.minutes, 1, 1440),
      },
      rateLimit: {
        enabled: src.rateLimit?.enabled === true,
        perMinute: int(src.rateLimit?.perMinute, DEFAULT_POLICY.rateLimit.perMinute, 10, 100_000),
      },
    },
  };
}

/** What a stored record gives a website: always complete, whatever was stored. */
export function policyFor(stored) {
  const checked = normalizePolicy({ ...DEFAULT_POLICY, ...(stored || {}) });
  return checked.ok ? checked.policy : { ...DEFAULT_POLICY };
}

// ── One-file install ────────────────────────────────────────────────────────────────────────────
// The adapter and the rule file as a single module, so a customer adds one file to their project.
const SDK = fileURLToPath(new URL('../defender-sdk/', import.meta.url));
const FROM_RULES = /(?:import|export) \{[^}]*\} from '\.\/signatures\.mjs';\n?/g;
const bundles = new Map();

/** @param {'web'|'express'} kind  'web' for Vercel / Next.js / Cloudflare Workers, 'express' for Express. */
export function sdkBundle(kind) {
  if (kind !== 'web' && kind !== 'express') return null;
  if (!bundles.has(kind)) {
    const read = (name) => readFileSync(`${SDK}${name}`, 'utf8').replaceAll('\r\n', '\n');
    const adapter = read(kind === 'web' ? 'web.mjs' : 'index.mjs').replace(FROM_RULES, '');
    bundles.set(
      kind,
      `// Securovix Defender — ${kind === 'web' ? 'Fetch API adapter (Vercel, Next.js, Cloudflare Workers)' : 'Express middleware'}, one file.\n// Generated by the Securovix dashboard from its own copy. AGPL-3.0-only. Do not edit: download again to update.\n\n${read('signatures.mjs')}\n// ── adapter ─────────────────────────────────────────────────────────────────────────────────────\n\n${adapter}`,
    );
  }
  return bundles.get(kind);
}
