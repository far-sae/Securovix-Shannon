// GITHUB PR OPENER — the final auto-patch step. Given a repo + write token + the fixed file content,
// it creates a branch, commits the file, and opens a pull request via the GitHub REST API. The token is
// supplied per-request (stored only in the caller's browser, never persisted server-side — same model as
// the code-scan keys). fetchImpl is injected so the whole flow is unit-testable against a mock API.

const API = 'https://api.github.com';

// Accept "owner/repo", a GitHub URL, or an SSH remote → { owner, repo }.
export function parseRepo(input) {
  const s = String(input || '').trim();
  let m = s.match(/^https?:\/\/[^/]*github[^/]*\/([^/]+)\/([^/#?]+?)(?:\.git)?\/?$/i);
  if (!m) m = s.match(/^git@[^:]+:([^/]+)\/([^/]+?)(?:\.git)?$/i);
  if (!m) m = s.match(/^([\w.-]+)\/([\w.-]+?)(?:\.git)?$/);
  if (!m) return null;
  return { owner: m[1], repo: m[2] };
}

const slug = (s) =>
  String(s || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 32);
function hashStr(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  return Math.abs(h).toString(36);
}
export function fixBranchName(finding = {}, salt = '') {
  const cls = slug(finding.cls || finding.tool || 'vuln') || 'vuln';
  return `shannon-fix-${cls}-${hashStr(`${cls}|${salt}`)}`;
}

const b64 = (s) =>
  typeof Buffer !== 'undefined' ? Buffer.from(s, 'utf8').toString('base64') : btoa(unescape(encodeURIComponent(s)));

// Open a PR that fixes `path` with `content`. Returns { url, branch }. Throws with the GitHub error on
// failure. Every step is a real REST call; fetchImpl defaults to global fetch.
export async function openPullRequest(
  { token, repo, path, content, title, body, base },
  { fetchImpl = fetch, apiBase = API } = {},
) {
  if (!token) throw new Error('a GitHub token is required');
  const r = parseRepo(repo);
  if (!r) throw new Error(`could not parse repo "${repo}" (use owner/repo)`);
  if (!path) throw new Error('a file path is required');
  const { owner, repo: name } = r;

  const gh = async (method, url, payload) => {
    const res = await fetchImpl(`${apiBase}${url}`, {
      method,
      headers: {
        authorization: `Bearer ${token}`,
        accept: 'application/vnd.github+json',
        'user-agent': 'securovix-shannon',
        ...(payload ? { 'content-type': 'application/json' } : {}),
      },
      ...(payload ? { body: JSON.stringify(payload) } : {}),
    });
    let data = null;
    try {
      data = await res.json();
    } catch {}
    return { ok: res.ok, status: res.status, data };
  };
  const need = (resp, what) => {
    if (!resp.ok)
      throw new Error(`${what} failed (${resp.status}${resp.data?.message ? `: ${resp.data.message}` : ''})`);
    return resp.data;
  };

  // 1. default branch (unless a base was given)
  let baseBranch = base;
  if (!baseBranch) baseBranch = need(await gh('GET', `/repos/${owner}/${name}`), 'read repo').default_branch;
  // 2. base commit sha
  const baseSha = need(await gh('GET', `/repos/${owner}/${name}/git/ref/heads/${baseBranch}`), 'resolve base branch')
    .object.sha;
  // 3. create the fix branch
  const branch = fixBranchName({ cls: title }, `${path}:${baseSha}`);
  need(
    await gh('POST', `/repos/${owner}/${name}/git/refs`, { ref: `refs/heads/${branch}`, sha: baseSha }),
    'create branch',
  );
  // 4. existing file sha (404 = new file → no sha). Encode each path SEGMENT but keep the slashes —
  //    GitHub's contents API wants the real path, not a %2F-escaped blob.
  const encPath = path.split('/').map(encodeURIComponent).join('/');
  const existing = await gh('GET', `/repos/${owner}/${name}/contents/${encPath}?ref=${baseBranch}`);
  const fileSha = existing.ok ? existing.data?.sha : undefined;
  // 5. commit the fixed file on the branch
  need(
    await gh('PUT', `/repos/${owner}/${name}/contents/${encPath}`, {
      message: title || `fix: ${path}`,
      content: b64(content || ''),
      branch,
      ...(fileSha ? { sha: fileSha } : {}),
    }),
    'commit fix',
  );
  // 6. open the PR
  const pr = need(
    await gh('POST', `/repos/${owner}/${name}/pulls`, {
      title: title || `fix: ${path}`,
      head: branch,
      base: baseBranch,
      body: body || '',
    }),
    'open pull request',
  );
  return { url: pr.html_url, branch };
}
