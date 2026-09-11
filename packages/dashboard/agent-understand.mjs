// The AI Agent's deterministic "understanding" of a crawled target — what it appears to be, where the
// risk concentrates, and a prioritized plan mapping the discovered surface to Shannon's proof classes.
// Pure + no API key (matches the engine-is-truth model); the dashboard layers an optional LLM narrative
// on top. Kept in its own module so the mapping logic is unit-testable without booting the server.
//
// Input `surface` is the crawler.mjs shape: { origin, pages:[{url,status}], paramNames:[...],
// forms:[{url,method,params}], apiPaths:[...], requests }.
export function analyzeSurface(surface = {}) {
  const params = surface.paramNames || [];
  const forms = surface.forms || [];
  const apis = surface.apiPaths || [];
  const uniq = (a) => [...new Set(a)];
  const match = (list, re) => uniq(list.filter((p) => re.test(p)));

  const idP = match(params, /(^|_)(id|uid|user|account|order|invoice|doc|file|num|pid|oid)s?$/i);
  const urlP = match(params, /(url|uri|dest|redirect|next|callback|webhook|link|img|image|feed|proxy|remote|site)/i);
  const fileP = match(params, /(file|path|page|template|include|load|doc|view|dir)/i);
  const searchP = match(params, /^(q|s|query|search|keyword|term|name|title|message|comment|desc)$/i);
  const loginForms = forms.filter(
    (f) =>
      (f.params || []).some((p) => /pass|pwd/i.test(p)) &&
      (f.params || []).some((p) => /user|email|login|name/i.test(p)),
  );
  const postForms = forms.filter((f) => (f.method || 'get').toLowerCase() === 'post');
  const gql = apis.filter((p) => /graphql|graphiql/i.test(p));
  // LLM attack surface: params/paths that commonly front a language model (chat, ask, summarize, ...).
  const llmP = match(params, /^(prompt|message|msg|ask|question|chat|query|input|text|content)$/i);
  const llmPaths = uniq(
    (surface.pages || []).map((p) => p.url).filter((u) => /\/(chat|ask|assistant|summar|copilot|agent|ai)\b/i.test(u)),
  );
  const hasLlm = llmP.length > 0 || llmPaths.length > 0;

  const plan = [];
  const add = (severity, cls, why, targets) =>
    targets.length && plan.push({ severity, cls, why, targets: uniq(targets).slice(0, 6) });
  add(
    'critical',
    'SQL injection',
    'search / detail parameters that likely reach a database query',
    uniq(searchP.concat(idP)),
  );
  add(
    'high',
    'Broken access control (IDOR / BOLA)',
    "object-id parameters can be swapped to reach other users' data",
    idP,
  );
  add('high', 'SSRF', 'URL-valued parameters can make the server fetch attacker-chosen hosts (→ cloud metadata)', urlP);
  add('high', 'Path traversal / LFI', 'file / path parameters may read arbitrary files on the server', fileP);
  add('high', 'Reflected / Stored XSS', 'user-controlled text is rendered back into the page', searchP);
  add(
    'high',
    'Auth testing (brute-force / weak creds)',
    'a login form — test for missing rate-limiting and weak credentials',
    loginForms.map((f) => f.url),
  );
  add('high', 'GraphQL abuse (introspection / batching)', 'a GraphQL endpoint is exposed', gql);
  add(
    'high',
    'Prompt injection (LLM01) — direct & indirect',
    'an AI / chat feature is exposed; test whether attacker text overrides the model (proof-based, zero-FP)',
    llmPaths.concat(postForms.filter((f) => (f.params || []).some((p) => /prompt|message|content|comment|note/i.test(p))).map((f) => f.url)),
  );
  add(
    'medium',
    'CSRF',
    'state-changing POST forms — check for anti-CSRF tokens',
    postForms.map((f) => f.url),
  );
  add('medium', 'API excessive data exposure', 'JSON APIs may over-return sensitive fields', apis);
  add(
    'medium',
    'Open redirect',
    'redirect parameters can bounce users to attacker sites',
    match(params, /(redirect|next|return|dest|continue|url)/i),
  );
  const rank = { critical: 0, high: 1, medium: 2, low: 3 };
  plan.sort((a, b) => rank[a.severity] - rank[b.severity]);

  const traits = [];
  if (loginForms.length) traits.push('has authentication (a login form is present)');
  if (apis.length) traits.push(`exposes ${apis.length} API endpoint(s)`);
  if (gql.length) traits.push('uses GraphQL');
  if (idP.length) traits.push('addresses objects by id (an IDOR surface)');
  if (urlP.length) traits.push('accepts URL parameters (an SSRF surface)');
  if (hasLlm) traits.push('exposes an AI / LLM feature (a prompt-injection surface)');

  return {
    origin: surface.origin,
    stats: {
      pages: (surface.pages || []).length,
      params: params.length,
      forms: forms.length,
      apis: apis.length,
      requests: surface.requests || 0,
    },
    traits,
    parameters: { identifiers: idP, urls: urlP, files: fileP, search: searchP },
    loginForms: loginForms.map((f) => f.url),
    apis: apis.slice(0, 25),
    plan,
  };
}
