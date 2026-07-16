// Deterministic CODE LOCATOR — the first step from a black-box finding toward a fix/patch. Given a
// proven finding (its class + endpoint URL + query params) and source code, it points at the likely
// vulnerable line(s): a sink pattern for that vuln class, corroborated (within a small window) by the
// route path and/or the parameter name from the finding. No LLM. Output is RANKED CANDIDATES for a
// human (or a later patch step) to confirm — never claimed as certain (black-box → code is a best-effort
// mapping). This is the bridge between the AI Agent (live app) and the Code Scan (source) sides.

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// Sink patterns per finding class (the dangerous call where user input reaches something powerful).
const SINKS = {
  sqli: [
    /\b(query|execute|exec|raw)\s*\(/i,
    /\bSELECT\b[\s\S]{0,80}\bFROM\b/i,
    /sequelize\.query|knex\.raw|db\.query|cursor\.execute/i,
  ],
  'sqli-auth-bypass': [/\b(query|execute|exec|raw)\s*\(/i, /\bWHERE\b[\s\S]{0,60}(password|user)/i],
  'cmd-injection': [
    /\b(exec|execSync|spawn|spawnSync|execFile)\s*\(/i,
    /child_process|os\.system|subprocess|Runtime\.getRuntime|shell_exec|popen/i,
    /`[^`]*\$\{/,
  ],
  'path-traversal': [
    /\b(readFile|readFileSync|createReadStream|sendFile|open|openSync)\s*\(/i,
    /fs\.[a-z]+\(|path\.join\(/i,
  ],
  ssrf: [/\b(fetch|axios|got|request|urlopen)\s*\(/i, /https?\.(get|request)\(|requests\.(get|post)\(|HttpClient/i],
  xss: [
    /innerHTML|dangerouslySetInnerHTML|document\.write|\.html\(|res\.send\(|res\.write\(/i,
    /\brender\(|\.render\(/i,
  ],
  'stored-dom-xss': [/innerHTML|dangerouslySetInnerHTML|document\.write|\.html\(|res\.send\(|res\.write\(/i],
  nosql: [/\b(find|findOne|aggregate|updateOne|deleteOne)\s*\(/i, /\$where|\$ne|\$gt|\$regex/],
  'open-redirect': [/\b(redirect|sendRedirect)\s*\(|res\.location|window\.location/i],
  'mass-assignment': [
    /new\s+\w+\(\s*req\.(body|params)|\.create\(\s*req\.body|Object\.assign\([^,]+,\s*req\.body|\.update\(\s*req\.body/i,
  ],
  csrf: [/\.(post|put|delete|patch)\s*\(/i],
  'api-data-exposure': [/res\.json\(|\.json\(|JSON\.stringify\(|serialize\(|toJSON/i],
  crlf: [/setHeader\(|writeHead\(|res\.header\(|location\s*=/i],
};

export function locateFinding({ finding = {}, files = [], max = 8, window = 2 } = {}) {
  const cls = finding.cls || finding.tool || '';
  const baseCls = cls.replace(/^impact[-:]/, '').replace(/-extract$|-context$|-metadata$/, '');
  const sinks = SINKS[baseCls] || SINKS[cls] || [];
  if (!sinks.length) return [];

  let pathSegs = [];
  let params = [];
  try {
    const u = new URL(finding.target);
    pathSegs = u.pathname.split('/').filter((s) => s && !/^\d+$/.test(s) && s.length > 1);
    params = [...u.searchParams.keys()];
  } catch {}
  const routeRe = pathSegs.length ? new RegExp(pathSegs.map(escapeRe).join('|'), 'i') : null;
  const paramRe = params.length ? new RegExp(`\\b(${params.map(escapeRe).join('|')})\\b`) : null;
  const routeDefRe = /\.(get|post|put|delete|patch|use|route|all)\s*\(/i;

  const candidates = [];
  for (const f of files) {
    const lines = String(f.content || '').split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      if (!sinks.some((re) => re.test(lines[i]))) continue; // anchor on a sink line
      const win = lines.slice(Math.max(0, i - window), i + window + 1).join('\n');
      let score = 3;
      const why = [`${baseCls} sink`];
      if (routeRe && routeDefRe.test(win) && routeRe.test(win)) {
        score += 2;
        why.push('route handler');
      }
      if (paramRe && paramRe.test(win)) {
        score += 2;
        why.push('uses the flagged parameter');
      }
      if (/req\.(query|body|params)|request\.(GET|POST|args|form)|\$_(GET|POST|REQUEST)/.test(win)) {
        score += 1;
        why.push('reads request input');
      }
      if (score >= 4)
        candidates.push({
          file: f.path || 'source',
          line: i + 1,
          snippet: lines[i].trim().slice(0, 160),
          score,
          why: why.join(' + '),
        });
    }
  }
  candidates.sort((a, b) => b.score - a.score || a.line - b.line);
  // de-dupe by file:line, keep the highest score
  const seen = new Set();
  return candidates.filter((c) => !seen.has(`${c.file}:${c.line}`) && seen.add(`${c.file}:${c.line}`)).slice(0, max);
}
