// Tests for the GitHub PR opener — repo parsing, branch naming, and the full create-branch → commit →
// open-PR flow against a MOCK GitHub API (injected fetch), so the sequence is verified with no network.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fixBranchName, openPullRequest, parseRepo } from './packages/dashboard/github-pr.mjs';

test('parseRepo: owner/repo, https URL, and ssh remote all resolve', () => {
  assert.deepEqual(parseRepo('acme/webapp'), { owner: 'acme', repo: 'webapp' });
  assert.deepEqual(parseRepo('https://github.com/acme/webapp'), { owner: 'acme', repo: 'webapp' });
  assert.deepEqual(parseRepo('https://github.com/acme/webapp.git'), { owner: 'acme', repo: 'webapp' });
  assert.deepEqual(parseRepo('git@github.com:acme/webapp.git'), { owner: 'acme', repo: 'webapp' });
  assert.equal(parseRepo('not a repo'), null);
});

test('fixBranchName: deterministic, slugged, prefixed', () => {
  const b = fixBranchName({ cls: 'SQL injection' }, 'seed');
  assert.ok(/^shannon-fix-sql-injection-[a-z0-9]+$/.test(b), b);
  assert.equal(b, fixBranchName({ cls: 'SQL injection' }, 'seed'), 'same inputs → same branch');
});

// A tiny mock GitHub API: records the calls and returns canned responses by (method, path).
function mockGithub({ fileExists = true } = {}) {
  const calls = [];
  const ok = (data) => ({ ok: true, status: 200, json: async () => data });
  const created = (data) => ({ ok: true, status: 201, json: async () => data });
  const notFound = () => ({ ok: false, status: 404, json: async () => ({ message: 'Not Found' }) });
  const fetchImpl = async (url, opts) => {
    const method = opts.method;
    calls.push({ method, url, body: opts.body ? JSON.parse(opts.body) : null });
    if (method === 'GET' && /\/repos\/[^/]+\/[^/]+$/.test(url)) return ok({ default_branch: 'main' });
    if (method === 'GET' && /\/git\/ref\/heads\/main$/.test(url)) return ok({ object: { sha: 'BASESHA' } });
    if (method === 'POST' && /\/git\/refs$/.test(url)) return created({ ref: 'refs/heads/x' });
    if (method === 'GET' && /\/contents\//.test(url)) return fileExists ? ok({ sha: 'FILESHA' }) : notFound();
    if (method === 'PUT' && /\/contents\//.test(url)) return ok({ commit: { sha: 'COMMIT' } });
    if (method === 'POST' && /\/pulls$/.test(url))
      return created({ html_url: 'https://github.com/acme/webapp/pull/7' });
    return notFound();
  };
  return { fetchImpl, calls };
}

test('openPullRequest: creates the branch, commits the file (with existing sha), opens the PR', async () => {
  const { fetchImpl, calls } = mockGithub({ fileExists: true });
  const out = await openPullRequest(
    {
      token: 'ghp_x',
      repo: 'acme/webapp',
      path: 'routes/search.js',
      content: 'fixed code',
      title: 'fix(security): sqli',
      body: 'proof-based fix',
    },
    { fetchImpl },
  );
  assert.equal(out.url, 'https://github.com/acme/webapp/pull/7');
  // the flow happened in order
  const seq = calls.map((c) => `${c.method} ${c.url.split('github.com')[1]}`);
  assert.ok(
    seq.some((s) => /POST \/repos\/acme\/webapp\/git\/refs/.test(s)),
    'branch created',
  );
  const put = calls.find((c) => c.method === 'PUT');
  assert.ok(put.url.includes('/contents/routes/search.js'), 'path slashes preserved (not %2F-escaped)');
  assert.ok(put.body.content && put.body.branch === out.branch, 'file committed to the fix branch, base64 content');
  assert.equal(put.body.sha, 'FILESHA', 'existing file sha included so the commit updates, not conflicts');
  const pr = calls.find((c) => c.method === 'POST' && /\/pulls$/.test(c.url));
  assert.equal(pr.body.head, out.branch);
  assert.equal(pr.body.base, 'main');
});

test('openPullRequest: a new (non-existent) file commits without a sha', async () => {
  const { fetchImpl, calls } = mockGithub({ fileExists: false });
  await openPullRequest({ token: 't', repo: 'acme/webapp', path: 'new.js', content: 'x', title: 'fix' }, { fetchImpl });
  const put = calls.find((c) => c.method === 'PUT');
  assert.equal(put.body.sha, undefined, 'no sha for a brand-new file');
});

test('openPullRequest: surfaces a GitHub error instead of silently failing', async () => {
  const fetchImpl = async () => ({ ok: false, status: 401, json: async () => ({ message: 'Bad credentials' }) });
  await assert.rejects(
    () => openPullRequest({ token: 'bad', repo: 'acme/webapp', path: 'a.js', content: 'x' }, { fetchImpl }),
    /Bad credentials|failed/,
  );
});

test('openPullRequest: bad inputs throw clearly', async () => {
  await assert.rejects(() => openPullRequest({ token: '', repo: 'a/b', path: 'x' }, {}), /token/);
  await assert.rejects(() => openPullRequest({ token: 't', repo: 'garbage', path: 'x' }, {}), /parse repo/);
});
