// PATCH GENERATOR — turn a located vulnerable line into a suggested fix. Deterministic and CONSERVATIVE
// by design: it only auto-rewrites when the pattern is unambiguous (SQLi string-concat → parameterized
// query, the most common web bug); for everything else it returns a targeted, line-level how-to NOTE
// rather than a fabricated rewrite (a wrong patch is worse than none). Every output is explicitly
// labeled a SUGGESTION to review — never an auto-merge. An LLM diff is layered on top by the server
// when a key is present; this module needs none.

const SUGGEST_DISCLAIMER =
  'Suggested fix — review before applying. Do not auto-merge; verify against the surrounding code.';

// Line-level guidance per class when no confident auto-rewrite applies.
const NOTES = {
  'cmd-injection':
    'Replace exec(string) with execFile(cmd, [args]) — pass the user value as a separate argv element (no shell) and allowlist the command.',
  xss: 'Do not interpolate user input into HTML. Use context-aware escaping (or textContent), and set a strict CSP.',
  'stored-dom-xss':
    'Output-encode at render time; avoid innerHTML/document.write; use textContent or a trusted sanitizer.',
  'path-traversal':
    'Confine to an allowlisted base dir: path.join(BASE, path.basename(input)) and reject ".." / encoded traversal.',
  ssrf: 'Validate the URL against an allowlist and block internal/metadata IPs (169.254.169.254, RFC1918, localhost) before fetching.',
  'open-redirect': 'Only redirect to an allowlisted path/host; never to a raw user-supplied absolute URL.',
  nosql:
    'Cast the value to a string / expected type and reject object/operator inputs ($ne/$gt/$where) — use a schema/ODM.',
  'api-data-exposure':
    'Return an explicit response DTO/allowlist; never serialize the full model or expose hashes/tokens/PII.',
  'mass-assignment': 'Bind only an explicit allowlist of fields; never pass req.body straight into create/update.',
};

// SQLi: rewrite  X('...sql...' + expr)  →  X('...sql...?', [expr])  for the single-concat case.
function sqliTransform(line) {
  const m = line.match(/^(.*?\b(?:query|execute|raw)\s*\(\s*)(['"`])([\s\S]*?)\2\s*\+\s*([\s\S]+?)(\s*\)\s*;?)$/i);
  if (!m) return null;
  const [, head, q, sqlText, expr, tail] = m;
  // Only the single-concat case is safe to auto-parameterize. If the concatenated expression still
  // contains a string literal (multi-part SQL: '..'+a+'..'+b), we cannot safely rewrite it → fall back
  // to guidance rather than emit a wrong patch.
  if (/['"`]/.test(expr)) return null;
  return {
    after: `${head}${q}${sqlText}?${q}, [${expr.trim()}]${tail}`,
    note: 'Use a parameterized query: replace the concatenation with a ? placeholder and pass the value in a params array so it can never be parsed as SQL.',
  };
}

export function generatePatch({ finding = {}, snippet = '', guidance = '' } = {}) {
  const cls = (finding.cls || finding.tool || '')
    .replace(/^impact[-:]/, '')
    .replace(/-extract$|-context$|-metadata$/, '');
  const before = String(snippet).replace(/\s+$/, '');
  if (!before.trim()) return null;

  if (cls === 'sqli' || cls === 'sqli-auth-bypass') {
    const t = sqliTransform(before.trim());
    if (t)
      return {
        applicable: true,
        cls,
        before,
        after: t.after,
        note: t.note,
        confidence: 'high',
        disclaimer: SUGGEST_DISCLAIMER,
      };
  }
  const note = NOTES[cls] || guidance || 'Apply input validation and least-privilege controls.';
  return { applicable: false, cls, before, after: null, note, confidence: 'guidance', disclaimer: SUGGEST_DISCLAIMER };
}

// Apply a one-line rewrite to the full source (preserving the original line's indentation) so the caller
// gets the corrected file to paste back / copy. Returns null on an out-of-range line — never guesses.
export function applyLineFix(code, line, after) {
  if (typeof code !== 'string' || !Number.isInteger(line) || after == null) return null;
  const lines = code.split(/\r?\n/);
  if (line < 1 || line > lines.length) return null;
  const indent = (lines[line - 1].match(/^\s*/) || [''])[0];
  lines[line - 1] = indent + String(after).trim();
  return lines.join('\n');
}
