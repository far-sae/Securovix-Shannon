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
//             someone's real users, so the bar is: it must not match ordinary requests. SQL
//             injection, XSS, command injection, template injection, SSRF and XXE are enforced only
//             in their strict, structural form; the loose versions stay in the detect tier.
//
//   DETECT  — reported to the operator, never blocked. These come from the offensive engine, where
//             they only ever had to re-test a payload the scanner itself had just sent. Against real
//             traffic they match constantly: `sqli` fires on any apostrophe ("O'Brien"), `xss` on any
//             HTML tag (a CMS body), `crlf` on any newline in a textarea, `cmd-injection` on ordinary
//             prose ("Design & code; also coffee"). Useful signal; unusable as a blocking rule.
//
// Accuracy is measured, not assumed: defender-accuracy.test.mjs runs a labelled list of ordinary
// requests (none may be blocked) and attacks (the listed ones must be) through every signature.

// ── What gets matched ───────────────────────────────────────────────────────────────────────────
// A signature must look at what the application behind the Defender will see, not at the bytes on
// the wire. Each step below closes a way to hide a payload from a rule that looked at raw text.

// Percent-escapes are decoded one run at a time. Decoding the whole string at once fails as a whole
// on a single stray "%" ("discount=100%"), which used to switch decoding off for the entire request.
const ESCAPE_RUN = /(?:%[0-9a-f]{2})+/gi;
const byteWise = (run) => run.replace(/%([0-9a-f]{2})/gi, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16)));
const dec = (s) =>
  String(s).replace(ESCAPE_RUN, (run) => {
    try {
      return decodeURIComponent(run);
    } catch {
      return byteWise(run);
    }
  });

// In a query string and a form body "+" is a space, and browsers send it that way by default. Both
// readings are matched: "+" as a space, and "+" as itself.
const plusAsSpace = (s) => (s.includes('+') ? `${dec(s)}\n${dec(s.replaceAll('+', ' '))}` : dec(s));

// A JSON body is matched as its keys and string values, one per line, the way the application
// receives them. Matching the JSON text instead lets "\n", "\t", "\"" and "\u003c" stand in for the
// characters a rule is looking for. A key is written as "key": so key rules can tell it from a value.
const MAX_JSON_NODES = 200_000;
class Key {
  constructor(name) {
    this.name = name;
  }
}
function jsonText(body) {
  const first = /\S/.exec(body)?.[0];
  if (first !== '{' && first !== '[') return null;
  let value;
  try {
    value = JSON.parse(body);
  } catch {
    return null;
  }
  const out = [];
  const stack = [value];
  for (let nodes = 0; stack.length && nodes < MAX_JSON_NODES; nodes++) {
    const item = stack.pop();
    if (typeof item === 'string') out.push(item);
    else if (item instanceof Key) out.push(`"${item.name}":`);
    else if (Array.isArray(item)) for (let i = item.length - 1; i >= 0; i--) stack.push(item[i]);
    else if (item && typeof item === 'object') {
      const keys = Object.keys(item);
      for (let i = keys.length - 1; i >= 0; i--) {
        stack.push(item[keys[i]]);
        stack.push(new Key(keys[i]));
      }
    }
  }
  return out.join('\n');
}

/**
 * The text the signatures run over. `all` is the URL and the body on separate lines (never glued
 * with a space: that let one swallow the other's end-of-value); `url`, `path` and `body` are the
 * parts, for the few rules that treat them differently.
 */
function views(url, body) {
  const rawUrl = String(url || '');
  const rawBody = String(body || '');
  const urlText = plusAsSpace(rawUrl);
  let bodyText = '';
  if (rawBody) {
    const flat = jsonText(rawBody);
    bodyText = flat === null ? plusAsSpace(rawBody) : dec(flat);
  }
  return {
    url: urlText,
    path: dec(rawUrl.split('?')[0]),
    body: bodyText,
    all: bodyText ? `${urlText}\n${bodyText}` : urlText,
  };
}

// ── Linear-time helpers ─────────────────────────────────────────────────────────────────────────
// A request body is attacker-controlled and can be megabytes long, so every check here must run in
// time proportional to its length. Patterns of the form /open.*close/ or /<tag[^>]*attr/ do not:
// given thousands of openers and no closer, the regex engine rescans the rest of the input from each
// one, and a 100KB body of "{{{{{{…" took seconds — a request that stalls the server it is meant to
// protect. The same goes for two optional whitespace runs in a row (/\s*x?\s*/): on a long run of
// spaces the engine tries every way to split it. These helpers give the same answers with one pass.

// Everything `.` refuses to cross: LF, CR and the two Unicode line separators (U+2028, U+2029).
const LINE_BREAK = new RegExp(`[${String.fromCharCode(10, 13, 0x2028, 0x2029)}]`);

/** Same answer as /first.*then/ (both on one line). `first` must not be a global regex. */
export function sameLine(s, first, then) {
  const text = String(s || '');
  if (!first.test(text)) return false;
  for (const line of text.split(LINE_BREAK)) {
    const m = first.exec(line);
    if (m && then.test(line.slice(m.index + m[0].length))) return true;
  }
  return false;
}

const TEMPLATE_PAIRS = [
  ['{{', '}}'],
  ['${', '}'],
  ['#{', '}'],
  ['<%', '%>'],
  ['*{', '}'],
];

/** Same answer as /\{\{.*\}\}|\$\{.*\}|#\{.*\}|<%.*%>|\*\{.*\}/. */
export function hasTemplateMarkers(s) {
  const text = String(s || '');
  if (!TEMPLATE_PAIRS.some(([open]) => text.includes(open))) return false;
  for (const line of text.split(LINE_BREAK)) {
    for (const [open, close] of TEMPLATE_PAIRS) {
      const i = line.indexOf(open);
      if (i !== -1 && line.indexOf(close, i + open.length) !== -1) return true;
    }
  }
  return false;
}

/** Same answer as /<[a-z/!][^>]*>|<\/[a-z]/i. */
export function hasHtmlTag(s) {
  const text = String(s || '');
  const m = /<[a-z/!]/i.exec(text);
  return (m !== null && text.indexOf('>', m.index + 2) !== -1) || /<\/[a-z]/i.test(text);
}

/** Same answer as /%27|'|(--\s)|(\bunion\b.*\bselect\b)|\b(sleep|pg_sleep|benchmark)\s*\(|waitfor\s+delay/i. */
export function hasLooseSqli(s) {
  const text = String(s || '');
  return (
    /%27|'|(--\s)|\b(sleep|pg_sleep|benchmark)\s*\(|waitfor\s+delay/i.test(text) ||
    sameLine(text, /\bunion\b/i, /\bselect\b/i)
  );
}

// Where the tag that starts at `from` ends: the first ">" that is not inside a quoted attribute
// value (<img src=">" onerror=…> is one tag). -1 when it never ends.
function tagEnd(s, from) {
  let quote = '';
  for (let i = from; i < s.length; i++) {
    const c = s[i];
    if (quote) {
      if (c === quote) quote = '';
    } else if (c === '"' || c === "'") quote = c;
    else if (c === '>') return i;
  }
  return -1;
}

// True when `inner` matches inside a tag that `open` starts.
function inTag(s, open, inner) {
  const re = new RegExp(open.source, 'gi');
  // A quote that never closes would make every later tag scan to the end of the input. After the
  // first one, tags end at the next ">" whatever the quotes say, which keeps the scan to one pass.
  let quoteAware = true;
  for (let m = re.exec(s); m; m = re.exec(s)) {
    let end = quoteAware ? tagEnd(s, m.index) : -1;
    if (end === -1) {
      quoteAware = false;
      end = s.indexOf('>', m.index);
    }
    if (inner.test(end === -1 ? s.slice(m.index) : s.slice(m.index, end))) return true;
    if (end === -1) return false;
    re.lastIndex = end;
  }
  return false;
}

// ── Tier 1: ENFORCE ─────────────────────────────────────────────────────────────────────────────

// Path traversal. "../" on its own is everywhere in ordinary content: Markdown image links, import
// statements, "cd ../project", a tsconfig "extends". So one step up is a block only in the URL's
// path, where no browser sends it. Elsewhere it takes the shape of an attack: two steps up, a step
// up into a sensitive place, an encoding trick, or a system file given as the whole value.
const TRAVERSAL_ANYWHERE = new RegExp(
  [
    '\\.\\.[/\\\\]\\.\\.[/\\\\]',
    // ....// and ..;/ — written to survive a filter that strips "../" once, or a path parameter
    '\\.\\.\\.\\.[/\\\\][/\\\\]',
    '\\.\\.;\\/',
    // still encoded after one decode: the request was encoded twice
    '\\.\\.%(?:2f|5c|252f|255c)|%2e%2e(?:[/\\\\]|%2f|%5c)|%252e%252e',
    '\\.\\.[/\\\\](?:etc|proc|root|windows|winnt|\\.env|\\.git|\\.ssh|\\.aws|\\.htpasswd|web\\.config|wp-config|id_rsa)(?![\\w-])',
    '(?:^|[/\\\\=])win\\.ini\\b',
  ].join('|'),
  'im',
);
// One step up, not part of an ellipsis ("Loading.../done").
const TRAVERSAL_IN_PATH = /(?<!\.)\.\.(?:[/\\]|$)/;
const TRAVERSAL_IN_URL =
  /(?:^|[=&])\/?etc\/(?:\.?\/)*(?:passwd|shadow)\b|(?:^|[=&])\/proc\/self\/(?:environ|cmdline|maps)\b/im;
// In a body the system file must be the value itself, so prose that mentions /etc/passwd passes.
const TRAVERSAL_IN_BODY = /(?:^|[=&"'])\/(?:etc\/(?:\.?\/)*(?:passwd|shadow)|proc\/self\/(?:environ|cmdline|maps))\b/im;
const PATH_TRAVERSAL = {
  // Called with the text alone (no parts), every rule applies to all of it.
  test(s, parts) {
    if (TRAVERSAL_ANYWHERE.test(s)) return true;
    return (
      TRAVERSAL_IN_PATH.test(parts ? parts.path : s) ||
      TRAVERSAL_IN_URL.test(parts ? parts.url : s) ||
      TRAVERSAL_IN_BODY.test(parts ? parts.body : s)
    );
  },
};

// NoSQL operator injection: an operator where a value was expected. Only in key position — the
// bracket form of a query string or form (password[$ne]=x) and a JSON key ({"password":{"$ne":…}}).
// "$where" in prose, a PHP variable, and JSON Schema / Extended JSON keys ($schema, $ref, $oid,
// $date) are not operators and pass.
const NOSQL =
  /\[\$(?:ne|eq|gt|gte|lt|lte|regex|where|in|nin|exists|not)\]|"\$(?:ne|gt|gte|lt|lte|regex|where|nin|exists|not)"\s*:/i;

// Deliberately tighter than the engine's own prompt-injection filter, which also matches ordinary
// prose ("please ignore my previous instructions about the invoice", "the reveal was prompt and
// dramatic"). To enforce, the request must target the MODEL's own configuration — its system or
// developer prompt, its earlier instructions — not merely contain those words. "Could you repeat
// your instructions?" and a guardrail a customer writes into their own prompt ("if the user asks you
// to ignore your instructions, refuse") are ordinary and pass. The first alternative is the
// engine's computed-marker oracle, which never occurs in natural text.
const PROMPT_INJECTION = new RegExp(
  [
    'reversed:\\s*sxpi',
    '(?:ignore|disregard|forget|override)\\b[^.]{0,40}\\byour\\s+(?:previous\\s+|prior\\s+|above\\s+|earlier\\s+|initial\\s+|original\\s+|system\\s+)+(?:instructions|prompt|rules)',
    '(?:ignore|disregard|forget)\\b[^.]{0,40}\\b(?:system|developer)\\s+(?:prompt|instructions|message)',
    'override\\b[^.]{0,40}\\b(?:system|developer)\\s+(?:prompt|instructions)',
    '(?:reveal|print|show|output|repeat|dump|echo|display)\\b[^.]{0,20}\\byour\\s+(?:system\\s+|initial\\s+|original\\s+|full\\s+|hidden\\s+)+(?:prompt|instructions)',
    'you\\s+are\\s+now\\b[^.]{0,40}\\b(?:ignore|disregard|no longer\\s+(?:follow|obey|bound|restricted|limited|an?\\s+(?:ai|assistant|language model)))',
  ].join('|'),
  'i',
);

// SQL injection, STRUCTURE only. The detect tier below fires on any apostrophe; these require the
// shape of an injection — a quote that breaks out and then does something only SQL does: a
// tautology (' OR '1'='1), a comment that cuts the query (admin'--), a stacked statement
// ('; DROP TABLE), UNION SELECT against a column list, a timing call, or a catalog read. Names like
// O'Brien, prose that mentions SQL, and code or query languages with quotes and operators
// (city = 'Paris' AND age > 30, status='500' OR status='404') must not match: in those the thing
// compared after AND/OR is a column name, while an injected tautology compares two literals.
const SQLI_STRICT = new RegExp(
  [
    // quote, boolean operator, then a comparison of literals — the classic tautology
    "'\\s*(?:\\)\\s*)?(?:or|and|\\|\\||&&)\\s*(?:\\(\\s*)?(?:'[^'\\n]{0,40}'|\\d+)\\s*(?:=|<|>|\\blike\\b)\\s*(?:\\(\\s*)?['\\d]",
    '"\\s*(?:\\)\\s*)?(?:or|and|\\|\\||&&)\\s*(?:\\(\\s*)?(?:"[^"\\n]{0,40}"|\\d+)\\s*(?:=|<|>)\\s*(?:\\(\\s*)?["\\d]',
    // quote immediately followed by a comment that truncates the rest of the query. Nothing may sit
    // between them: "She said 'yes' -- finally!" and a glob like '/*.js' are ordinary.
    "'--(?=\\s|$|&|\")|'#(?=$|\\n|&|\")|'\\/\\*(?:\\*\\/|\\s|$)",
    // quote, then "or true" / "order by N", then a comment that cuts the query
    "'\\s*(?:or|\\|\\|)\\s+true\\b\\s*(?:--|#|\\/\\*)",
    "'\\s*order\\s+by\\s+\\d+\\s*(?:--|#|\\/\\*)",
    // a timing call wrapped in a subquery
    '\\(\\s*select\\s+(?:pg_)?sleep\\s*\\(',
    // stacked statement after a quote
    "'\\s*(?:\\)\\s*)?;\\s*(?:drop\\s+(?:table|database)|delete\\s+from|insert\\s+into|update\\s+\\w+\\s+set|truncate\\s+table|exec(?:ute)?\\s|shutdown\\b|select\\s+pg_\\w+\\s*\\(|select\\s+sleep\\s*\\()",
    // UNION SELECT that is clearly probing columns, or that follows a quote / bracket
    '\\bunion\\s+(?:all\\s+)?select\\s+(?:null\\b|\\d+\\s*,|@@|char\\(|concat\\(|group_concat\\()',
    '[\'")]\\s*union\\s+(?:all\\s+)?select\\b',
    // time-based blind probes
    '[\'")]\\s*(?:(?:and|or|\\|\\|)\\s*)?(?:\\(\\s*)?(?:select\\s+)?(?:sleep|pg_sleep)\\s*\\(\\s*\\d',
    "\\bwaitfor\\s+delay\\s+'\\d",
    '\\bbenchmark\\s*\\(\\s*\\d{4,}\\s*,',
    // error-based extraction and catalog reads
    '\\b(?:extractvalue|updatexml)\\s*\\(',
    '\\bselect\\b[^&]{0,80}\\bfrom\\s+(?:information_schema|pg_catalog|sysobjects|sqlite_master|mysql\\.user)\\b',
  ].join('|'),
  'i',
);

// Cross-site scripting, EXECUTION only. The detect tier fires on any HTML tag; these require markup
// that runs script: a <script> tag, an inline event handler, a javascript: URL that does something,
// or an embedded HTML document. <p>, <b>, ordinary links, the placeholders javascript:void(0) and
// javascript:;, and prose ("JavaScript: The Good Parts") must not match.
const XSS_FLAT = new RegExp(
  [
    '<script\\b',
    // a call, anywhere a URL can start
    '(?:^|[\\s"\'=(:&?])javascript\\s*:\\s*(?!void\\s*\\(\\s*0\\s*\\))[a-z_$][\\w$.]*\\s*[(`]',
    // any other code, when the scheme is the start of a value
    '(?:^|[="\'(&?])javascript:(?!(?:void\\s*\\(\\s*0\\s*\\))?(?:\\s*;)?\\s*(?:$|["\'>&]))\\S',
    '\\b(?:src|data|href)\\s*=\\s*(?:[\'"]\\s*)?data:text\\/html',
  ].join('|'),
  'im',
);
const XSS_HANDLER = /[\s/"']on[a-z]{3,}\s*=/i;
const XSS_SRCDOC = /\bsrcdoc\s*=/i;
// The two "attribute inside a tag" checks go through inTag() so they stay linear (see above).
const XSS_STRICT = {
  test: (s) => XSS_FLAT.test(s) || inTag(s, /<[a-z]/, XSS_HANDLER) || inTag(s, /<iframe\b/, XSS_SRCDOC),
};

// OS command injection, COMMAND SHAPE only. The detect tier fires on "; a" — any semicolon followed
// by a letter. These require a shell separator followed by a command doing what an attacker does
// first: read a system file, fetch a payload, probe identity or timing, or open a shell. A single
// `&` is never a separator here (it separates query parameters), and neither is a newline (it
// separates lines of ordinary text).
const SEP = '(?:;|\\|\\|?|&&)';
const CMD_STRICT = new RegExp(
  [
    // read a system file; ${IFS} and "<" stand in for the space a filter looks for
    `${SEP}\\s*(?:cat|less|more|head|tail|type)(?:\\s+|\\$\\{IFS\\}|<)(?:\\/(?:etc|proc|var|root|home)\\/|c:\\\\)`,
    // fetch a payload or send data out; a flag may take a value (-O /tmp/x.sh)
    `${SEP}\\s*(?:wget|curl)\\s+(?:-[\\w-]+\\s+(?:[^\\s-]\\S*\\s+)?)*https?:\\/\\/`,
    // identity and timing probes that end the value
    `${SEP}\\s*(?:whoami|uname\\s+-a|sleep(?:\\s+|\\$\\{IFS\\})\\d+)\\s*(?:$|[;|&#"'}\\]>])`,
    `${SEP}\\s*ping\\s+-[cn]\\s+\\d+\\b`,
    // command substitution around a probe
    '\\$\\(\\s*(?:id|whoami|uname|sleep\\s+\\d|cat\\s+\\/|curl\\s|wget\\s|nslookup\\s|ping\\s)[^)]{0,80}\\)',
    // shells and reverse shells
    `${SEP}\\s*(?:\\/bin\\/(?:ba|z|da)?sh\\b|(?:ba)?sh\\s+-[ci]\\b|nc(?:at)?\\s+(?:-[^\\Wel]*[el]\\w*\\s|\\d{1,3}\\.\\d+\\.\\d+\\.\\d+\\s+\\d)|cmd(?:\\.exe)?\\s+\\/c\\b|powershell(?:\\.exe)?\\s+-)`,
    '\\/dev\\/tcp\\/\\d',
  ].join('|'),
  'im',
);

// Server-side template injection / expression injection. The detect tier fires on any {{…}} or ${…}.
// These require a template expression that is the multiplication probe scanners send ({{7*7}}), or
// one that reaches for interpreter internals, plus the Log4Shell lookup. Ordinary {{name}}
// placeholders, and arithmetic written out in a tutorial ({{ 1 + 1 }}, ${1 + 1}), must not match.
const INTERNALS =
  '(?:__class__|__mro__|__subclasses__|__globals__|__builtins__|__import__|constructor\\.constructor|getRuntime\\(|ProcessBuilder|process\\.mainModule|child_process|java\\.lang\\.|freemarker\\.template|\\.popen\\(|os\\.system)';
const SSTI_FLAT = new RegExp(
  [
    '\\{\\{\\s?\\(?\\d+\\*[\'"]?\\d+[\'"]?\\)?\\s?\\}\\}',
    '[$#*]\\{\\d+\\*\\d+\\}',
    '<%=?\\s*\\d+\\*\\d+\\s*%>',
    'freemarker\\.template\\.utility\\.(?:Execute|ObjectConstructor|JythonRuntime)',
    '\\$\\{\\s*jndi\\s*:',
    '\\$\\{\\$\\{(?:::-|lower:|upper:|env:|sys:)',
  ].join('|'),
  'i',
);
// Spring's type operator. Case matters: "connect(java.lang.String)" in a stack trace is not it.
const SSTI_SPEL = /\bT\(\s*java\.lang\./;
// Internals named inside a template expression. Two stages so ordinary text costs one cheap scan:
// the lookbehind (bounded to 80 characters) only runs once an internal name is actually present.
const SSTI_NAMES = new RegExp(INTERNALS, 'i');
const SSTI_IN_EXPR = new RegExp(`(?<=(?:\\{\\{|\\{%|[$#*]\\{|<%=?)[^}%]{0,80})${INTERNALS}`, 'i');
const SSTI_STRICT = {
  test: (s) => SSTI_FLAT.test(s) || SSTI_SPEL.test(s) || (SSTI_NAMES.test(s) && SSTI_IN_EXPR.test(s)),
};
// The Log4Shell lookup is normally delivered in a request header, which is logged.
const LOOKUP_IN_HEADER = /\$\{\s*jndi\s*:|\$\{\$\{(?:::-|lower:|upper:|env:|sys:)/i;

// Server-side request forgery. Only destinations no visitor has a reason to send: cloud metadata
// services (also written as one number, in hex or in octal to slip past a filter), schemes used to
// reach internal services, system files by file:, and loopback in hex / decimal / octal. The
// address must be where a URL or host goes, so a sentence that mentions 169.254.169.254 passes.
// Plain http://localhost is NOT matched — sign-in flows for command-line tools redirect there.
const SSRF_STRICT = new RegExp(
  [
    '(?:^|[=/@"\':])(?:169\\.254\\.169\\.254|169\\.254\\.170\\.2|100\\.100\\.100\\.200|metadata\\.google\\.internal|\\[?fd00:ec2::254\\]?|2852039166|0xa9fea9fe|0xa9\\.0xfe\\.0xa9\\.0xfe|0251\\.0376\\.0251\\.0376|\\[::ffff:a9fe:a9fe\\]|168\\.63\\.129\\.16|metadata\\.goog)\\.?(?=$|[/:"\'\\s&?#\\]])',
    '(?:^["\']?|[=:,\\[]\\s*["\']?)(?:gopher|dict|tftp|netdoc|jar):\\/\\/',
    '(?:^["\']?|[=:,\\[]\\s*["\']?)file:\\/{1,3}(?:localhost\\/)?(?:etc\\/|proc\\/|root\\/|var\\/run\\/secrets|(?:[\\w.-]+\\/){0,6}\\.env\\b|c:[\\\\/]+windows)',
    'https?:\\/\\/(?:0x7f[0-9a-f.]*|2130706433|017700000001|0177\\.0+\\.0+\\.0*1)(?=$|[/:"\'\\s&?#])',
  ].join('|'),
  'im',
);

// XML external entity. Only an EXTERNAL entity declaration (SYSTEM / PUBLIC). Internal entities are
// left alone — design tools write them into ordinary SVG files.
const XXE_STRICT = /<!ENTITY\s+(?:%\s*)?[^\s"'<>%]+\s+(?:SYSTEM|PUBLIC)\s+["']/i;

export const ENFORCE_SIGNATURES = {
  'path-traversal': PATH_TRAVERSAL,
  nosql: NOSQL,
  'llm-prompt-injection': PROMPT_INJECTION,
  sqli: SQLI_STRICT,
  xss: XSS_STRICT,
  'cmd-injection': CMD_STRICT,
  'rce-ssti': SSTI_STRICT,
  ssrf: SSRF_STRICT,
  xxe: XXE_STRICT,
};

export const ENFORCE_CLASSES = Object.keys(ENFORCE_SIGNATURES);

// ── Tier 2: DETECT-ONLY ─────────────────────────────────────────────────────────────────────────

// Each entry answers .test(text). The first three are functions rather than regexes because their
// natural patterns (/\{\{.*\}\}/, /<[a-z][^>]*>/, /union.*select/) are quadratic on hostile input.
export const DETECT_SIGNATURES = {
  'rce-ssti': { test: hasTemplateMarkers },
  xss: { test: hasHtmlTag },
  sqli: { test: hasLooseSqli },
  'cmd-injection': /(%3b|;)\s*[a-z]|(%7c|\|)\s*[a-z]|\$\(|%24%28|%60|`/i,
  crlf: /%0d%0a|%0d|%0a/i,
  'graphql-idor': /__schema|IntrospectionQuery|__type/i,
};

// Header values as one text, capped: headers are small, and a huge one is not worth scanning whole.
function headerText(headers) {
  if (!headers || typeof headers !== 'object') return '';
  let out = '';
  for (const value of typeof headers.values === 'function' ? headers.values() : Object.values(headers)) {
    out += `${Array.isArray(value) ? value.join('\n') : String(value ?? '')}\n`;
    if (out.length > 32_768) break;
  }
  return out;
}

/**
 * The class this request may be ENFORCED on, or null. `headers` is optional: a plain object or a
 * Fetch `Headers`. Only the Log4Shell lookup is looked for there. `disabled` is optional: the classes
 * a site has switched off (an array or a Set); they are never returned.
 *
 * Evaluated independently of detection on purpose. A composite matcher reports the first class that
 * matches, and the detect-only signatures are checked first in the engine's ordering — so
 * `?path=../../etc/passwd&name=O'Brien` would report `sqli` and, if enforcement followed detection,
 * sail straight through. Appending one character must not disable a block.
 */
export function matchEnforceable(url, body, headers, disabled) {
  const off = disabled ? new Set(disabled) : null;
  const parts = views(url, body);
  for (const cls of ENFORCE_CLASSES) {
    if (off?.has(cls)) continue;
    try {
      if (ENFORCE_SIGNATURES[cls].test(parts.all, parts)) return cls;
    } catch {}
  }
  try {
    if (headers && !off?.has('rce-ssti') && LOOKUP_IN_HEADER.test(headerText(headers))) return 'rce-ssti';
  } catch {}
  return null;
}

// ── Honeypot paths ──────────────────────────────────────────────────────────────────────────────
// Files and admin panels that a Node app never serves, but every vulnerability scanner asks for:
// leaked .env files, git metadata, WordPress/PHP admin pages, cloud credentials. A real visitor has
// no reason to request them, so a hit is a scanner. Matched on the PATH only, never the query or
// body. Opt-in for customer apps (a site that really runs WordPress would trip it); on by default
// for the Securovix dashboard, which serves none of these.
export const HONEYPOT_PATHS = new RegExp(
  [
    '^/\\.env(?:\\.[\\w-]+)?$',
    '^/\\.(?:git|svn|hg|aws|ssh|docker)(?:/|$)',
    '^/\\.(?:htpasswd|htaccess|DS_Store|npmrc|bash_history)$',
    '^/(?:wp-admin|wp-includes|wp-content)(?:/|$)',
    '^/(?:wp-login|wp-config|xmlrpc)\\.php',
    '^/(?:phpmyadmin|pma|myadmin|adminer)(?:/|$)',
    '^/(?:server-status|server-info)$',
    '^/(?:cgi-bin|vendor/phpunit|actuator|boaform)(?:/|$)',
    '^/HNAP1(?:/|$)',
    '\\.(?:php|asp|aspx|jsp|cgi)$',
    '^/[\\w.-]*(?:backup|dump|database|db)\\.(?:sql|sql\\.gz|zip|tar\\.gz|bak)$',
  ].join('|'),
  'i',
);

export function matchHoneypot(path, pattern = HONEYPOT_PATHS) {
  try {
    return pattern.test(String(path || ''));
  } catch {
    return false;
  }
}

// ── Attack tools ────────────────────────────────────────────────────────────────────────────────
// Scanners and exploitation tools that announce themselves in the User-Agent header. Nothing a
// visitor's browser, a search engine or an ordinary HTTP library sends matches these. The last
// alternative is a Log4Shell lookup placed in the header itself. Opt-in for customer apps, whose
// own security team may run one of these tools on purpose; on by default for the dashboard.
export const SCANNER_AGENTS =
  /\b(?:sqlmap|nikto|nuclei|masscan|zgrab|wpscan|acunetix|nessus|openvas|dirbuster|gobuster|feroxbuster|dirsearch|ffuf|wfuzz|havij|netsparker|arachni|w3af|skipfish|commix|whatweb|joomscan|fimap|xsser|zmeu|morfeus|l9explore|l9tcpid|jaeles|nmap scripting engine|burp ?collaborator)\b|\$\{\s*jndi\s*:/i;

export function matchScannerAgent(userAgent, pattern = SCANNER_AGENTS) {
  try {
    return pattern.test(String(userAgent || ''));
  } catch {
    return false;
  }
}

/** An on/off option: `true` selects the built-in list, a RegExp replaces it, anything else is off. */
export const listOption = (option, builtin) => (option === true ? builtin : option instanceof RegExp ? option : null);

/**
 * Verdict for one request including the two checks that are not about the payload: an attack tool's
 * User-Agent and a honeypot path. Pass `scanners` / `honeypot` as a RegExp to enable each, and
 * `headers` (a plain object or a Fetch `Headers`) to have them checked for the Log4Shell lookup.
 */
export function inspectRequest({
  url = '',
  path,
  body = '',
  userAgent = '',
  headers = null,
  honeypot = null,
  scanners = null,
  disabled = null,
} = {}) {
  if (scanners && matchScannerAgent(userAgent, scanners)) {
    return { attack: true, cls: 'scanner-tool', enforce: true, signal: 'request sent by a known attack tool' };
  }
  if (honeypot && matchHoneypot(path ?? String(url).split('?')[0], honeypot)) {
    return { attack: true, cls: 'honeypot', enforce: true, signal: 'request for a scanner-bait path' };
  }
  return inspect(url, body, headers, disabled);
}

/** The class this request is detected as, or null. Reporting only — never a reason to block. */
export function matchDetectable(url, body) {
  const s = views(url, body).all;
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
export function inspect(url, body, headers, disabled) {
  const enforceable = matchEnforceable(url, body, headers, disabled);
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
