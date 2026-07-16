// Deterministic CODE LOCATOR — the first step from a black-box finding toward a fix/patch. Given a
// proven finding (its class + endpoint URL + query params) and source code, it points at the likely
// vulnerable line(s): a sink pattern for that vuln class, corroborated (within a small window) by the
// route path and/or the parameter name from the finding. No LLM. Output is RANKED CANDIDATES for a
// human (or a later patch step) to confirm — never claimed as certain (black-box → code is a best-effort
// mapping). This is the bridge between the AI Agent (live app) and the Code Scan (source) sides.

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// Sink patterns per finding class — the dangerous call where user input reaches something powerful.
// Broadened across languages: JS/TS, Python, PHP, Java/Kotlin, C#/.NET, Go, Ruby, Rust, C/C++, Perl.
const SINKS = {
  sqli: [
    // query/exec calls across ORMs & drivers
    /\b(query|execute|executemany|executeQuery|executeUpdate|executeReader|executeNonQuery|executeScalar|prepareStatement|createStatement|createQuery|prepare|exec_query|find_by_sql|QueryRow|Queryx?)\s*\(/i,
    // raw SQL string being built
    /\bSELECT\b[\s\S]{0,120}\bFROM\b|\b(INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b/i,
    // driver/ORM idioms
    /mysqli_query|mysql_query|pg_query|pg_exec|sqlite_query|->query\(|->prepare\(|->exec\(|PDO|sequelize\.query|knex\.raw|db\.(query|exec|raw|Query|Exec)|cursor\.execute|SqlCommand|FromSqlRaw|sqlx::query|diesel|ActiveRecord|DB::(select|statement|raw)/i,
  ],
  'sqli-auth-bypass': [
    /\b(query|execute|prepare|executeQuery|prepareStatement)\s*\(/i,
    /\bWHERE\b[\s\S]{0,80}(password|passwd|pwd|user(name)?|email|login)/i,
  ],
  'cmd-injection': [
    /\b(exec|execSync|execFile|spawn|spawnSync|popen|system|passthru|shell_exec|proc_open|ProcessBuilder)\s*\(/i,
    /child_process|os\.(system|popen)|subprocess\.(run|call|Popen|check_output)|Runtime\.getRuntime|Runtime\.exec|Process\.Start|exec\.Command(Context)?|IO\.popen|Open3|Command::new|process::Command|Kernel\.(system|exec)/i,
    /`[^`]*\$\{|`[^`]*`|%x[\/({\[]|\bqx[\/({]/, // backtick/%x/qx command substitution (JS/Ruby/Perl/shell)
  ],
  'path-traversal': [
    /\b(readFile|readFileSync|createReadStream|sendFile|serveFile|ServeFile|readfile|fopen|file_get_contents|fread|readlines|open|openSync|include|require|include_once|require_once|ReadAllText|ReadAllBytes|OpenRead|OpenText|ReadFile|read_to_string)\s*\(/i,
    /fs\.[a-z]+\(|path\.join\(|os\.path\.join|pathlib|Paths\.get|Path\.Combine|new File\(|FileInputStream|FileReader|RandomAccessFile|File\.(read|open|ReadAllText|OpenRead)|File::open|fs::read|ioutil\.ReadFile|StreamReader|std::fs/i,
  ],
  ssrf: [
    /\b(fetch|axios|got|request|urlopen|urlretrieve|curl_exec|HttpClient|WebClient|RestClient|reqwest|Faraday|HTTParty)\s*[.(]/i,
    /https?\.(get|post|put|request|Get|Post|NewRequest)\(|requests\.(get|post|put|delete|head|patch)|urllib|http\.client|openConnection|HttpURLConnection|RestTemplate|WebClient|Net::HTTP|curl_setopt|Guzzle|client\.Do\(|hyper::|aiohttp|httpx/i,
  ],
  xss: [
    /innerHTML|outerHTML|dangerouslySetInnerHTML|document\.write|insertAdjacentHTML|\.html\(|res\.(send|write|end)\(|getWriter\(\)|Response\.Write|Html\.Raw|@Html\.Raw|render_template_string|mark_safe|\.html_safe|\.raw\(|Fprintf\(\s*w|out\.print(ln)?\(|echo\s+|\bprint\s+\$|<\?=|<%=/i,
  ],
  'stored-dom-xss': [
    /innerHTML|outerHTML|dangerouslySetInnerHTML|document\.write|insertAdjacentHTML|\.html\(|\.append\(|\.after\(|jQuery|\$\(/i,
  ],
  nosql: [
    /\b(find|findOne|findAll|aggregate|updateOne|updateMany|deleteOne|deleteMany|count|distinct)\s*\(/i,
    /\$where|\$ne|\$gt|\$lt|\$regex|\$in|collection\.|db\.\w+\.(find|update)/i,
  ],
  'open-redirect': [
    /\b(redirect|sendRedirect|redirect_to|Redirect|RedirectPermanent)\s*\(|res\.location|res\.redirect|window\.location|location\.href|location\.replace|header\(\s*['"]Location:|http\.Redirect|HttpResponseRedirect|RedirectView|['"]redirect:/i,
  ],
  'mass-assignment': [
    /new\s+\w+\(\s*(req\.(body|params)|request\.|params)\b|\.(create|update|save|new|build|insert)\(\s*(req\.body|request\.(POST|data|body)|params|\*\*)|Object\.assign\([^,]+,\s*(req\.body|request)|attributes\s*=\s*params|ModelState|BindModel|\.update_attributes|Mapper\.map/i,
  ],
  csrf: [
    /\.(post|put|delete|patch)\s*\(|@(Post|Put|Delete|Patch)Mapping|Route::(post|put|delete|patch)|\[Http(Post|Put|Delete)\]/i,
  ],
  'api-data-exposure': [
    /res\.json\(|\.json\(|JSON\.stringify\(|serialize\(|jsonify\(|to_json|render\s+json:|toJSON|c\.JSON\(|Ok\(Json|Response\(\s*json|write_json|Marshal\(/i,
  ],
  crlf: [/setHeader\(|writeHead\(|res\.header\(|addHeader\(|Header\.(Set|Add)\(|header\(|Location\s*[:=]/i],
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
  // Route-handler definition across frameworks (Express/Koa, Spring, Flask/Django/FastAPI, Laravel,
  // Gin/Echo/net-http, ASP.NET, Rails, Rocket/Actix…).
  const routeDefRe =
    /\.(get|post|put|delete|patch|use|route|all|map|handle|handleFunc|HandleFunc|GET|POST)\s*\(|@(Get|Post|Put|Delete|Patch|Request)Mapping|@(app|router|blueprint)\.(route|get|post|put|delete)|@(get|post|put|delete|route)\(|Route::(get|post|put|any|match)|\[Http(Get|Post|Put|Delete|Patch)\]|\[Route|MapGet|MapPost|def\s+\w+\s*\(|func\s+\w+\s*\(|(^|\s)(get|post|put|patch|delete)\s+['"]\//i;

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
      // User-controlled input across languages/frameworks.
      if (
        /req\.(query|body|params|headers|cookies)|request\.(GET|POST|args|form|values|json|data|query_params|params|cookies)|\$_(GET|POST|REQUEST|COOKIE|SERVER)|getParameter\(|getHeader\(|@(RequestParam|PathVariable|RequestBody|FromQuery|FromBody|FromRoute)|Request\.(Query|Form|Params|QueryString|Body)|r\.(URL\.Query|FormValue|PostFormValue|Header\.Get)|c\.(Query|Param|PostForm|GetHeader)|mux\.Vars|params\[|input->|Input::get|GetQueryParameter/i.test(
          win,
        )
      ) {
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
