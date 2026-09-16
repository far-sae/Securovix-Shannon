// signatures.mjs — standalone attack signatures. ZERO dependencies, by design.
//
// This is the single source of truth for what the Defender ENFORCES. It lives in the SDK package so
// the package is self-contained: a customer installs @securovix/defender into their own app and gets
// exactly this file, not the 122KB scanner engine. The dashboard's own classifier imports these same
// predicates, so there is one definition of "enforceable", not a copy that can drift.
//
// Two tiers, and the split is the whole point:
//
//   ENFORCE — specific enough to drop live traffic on. A false positive here is an outage for
//             someone's real users, so the bar is: it must not match ordinary requests.
//
//   DETECT  — reported to the operator, never blocked. These come from the offensive engine, where
//             they only ever had to re-test a payload the scanner itself had just sent. Against real
//             traffic they match constantly: `sqli` fires on any apostrophe ("O'Brien"), `xss` on any
//             HTML tag (a CMS body), `crlf` on any newline in a textarea, `cmd-injection` on ordinary
//             prose ("Design & code; also coffee"). Useful signal; unusable as a blocking rule.

const dec = (s) => {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
};

const surface = (url, body) => `${dec(String(url || ''))} ${dec(String(body || ''))}`;

// ── Tier 1: ENFORCE ─────────────────────────────────────────────────────────────────────────────

const PATH_TRAVERSAL = /(\.\.[/\\])|%2e%2e(%2f|%5c)|etc\/passwd|win\.ini/i;

const NOSQL = /\[\$(ne|eq|gt|lt|gte|lte|regex|where|in|nin)\]|\$where|"\$(ne|gt|regex)"/i;

// Deliberately tighter than the engine's own prompt-injection filter, which also matches ordinary
// prose ("please ignore my previous instructions about the invoice", "the reveal was prompt and
// dramatic"). To enforce, the request must target the MODEL's own configuration — its system or
// developer prompt, its instructions — not merely contain those words. The first two alternatives
// are the engine's computed-marker oracles, which never occur in natural text.
const PROMPT_INJECTION = new RegExp(
  [
    'reversed:\\s*sxpi',
    'result of \\d{3,}\\s*[*+]\\s*\\d{3,}',
    '(?:ignore|disregard|forget|override)\\b[^.]{0,40}\\byour\\s+(?:previous\\s+|prior\\s+|above\\s+|earlier\\s+|initial\\s+|original\\s+|system\\s+)*(?:instructions|prompt|rules)',
    '(?:ignore|disregard|forget|override)\\b[^.]{0,40}\\b(?:system|developer)\\s+(?:prompt|instructions|message)',
    '(?:reveal|print|show|output|repeat|dump|echo|display)\\b[^.]{0,20}\\byour\\s+(?:system\\s+|initial\\s+|original\\s+|full\\s+)*(?:prompt|instructions)',
    'you\\s+are\\s+now\\b[^.]{0,40}\\b(?:ignore|instead|no longer|disregard)',
  ].join('|'),
  'i',
);

export const ENFORCE_SIGNATURES = {
  'path-traversal': PATH_TRAVERSAL,
  nosql: NOSQL,
  'llm-prompt-injection': PROMPT_INJECTION,
};

export const ENFORCE_CLASSES = Object.keys(ENFORCE_SIGNATURES);

// ── Tier 2: DETECT-ONLY ─────────────────────────────────────────────────────────────────────────

export const DETECT_SIGNATURES = {
  'rce-ssti': /\{\{.*\}\}|\$\{.*\}|#\{.*\}|<%.*%>|\*\{.*\}/,
  xss: /<[a-z/!][^>]*>|<\/[a-z]/i,
  sqli: /%27|'|(--\s)|(\bunion\b.*\bselect\b)|\b(sleep|pg_sleep|benchmark)\s*\(|waitfor\s+delay/i,
  'cmd-injection': /(%3b|;)\s*[a-z]|(%7c|\|)\s*[a-z]|\$\(|%24%28|%60|`/i,
  crlf: /%0d%0a|%0d|%0a/i,
  'graphql-idor': /__schema|IntrospectionQuery|__type/i,
};

/**
 * The class this request may be ENFORCED on, or null.
 *
 * Evaluated independently of detection on purpose. A composite matcher reports the first class that
 * matches, and the detect-only signatures are checked first in the engine's ordering — so
 * `?path=../../etc/passwd&name=O'Brien` would report `sqli` and, if enforcement followed detection,
 * sail straight through. Appending one character must not disable a block.
 */
export function matchEnforceable(url, body) {
  const s = surface(url, body);
  for (const cls of ENFORCE_CLASSES) {
    try {
      if (ENFORCE_SIGNATURES[cls].test(s)) return cls;
    } catch {}
  }
  return null;
}

/** The class this request is detected as, or null. Reporting only — never a reason to block. */
export function matchDetectable(url, body) {
  const s = surface(url, body);
  for (const cls of Object.keys(DETECT_SIGNATURES)) {
    try {
      if (DETECT_SIGNATURES[cls].test(s)) return cls;
    } catch {}
  }
  return null;
}

/**
 * Full verdict for one request, with no dependency on the scanner engine.
 * `enforce` is true only when an ENFORCE-tier signature matched.
 */
export function inspect(url, body) {
  const enforceable = matchEnforceable(url, body);
  if (enforceable) {
    return { attack: true, cls: enforceable, enforce: true, signal: `signature match: ${enforceable}` };
  }
  const detected = matchDetectable(url, body);
  if (detected) {
    return {
      attack: true,
      cls: detected,
      enforce: false,
      signal: `signature match: ${detected} (detect-only class — not enforced inline)`,
    };
  }
  return { attack: false, cls: null, enforce: false, signal: 'no deterministic signature matched' };
}
