// Validates the template LIBRARY (the JSON files) — every template is well-formed and stays zero-FP
// (gates on status + a distinctive content matcher), and the new checks fire on a matching response
// and abstain otherwise.
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { test } from 'node:test';
import { loadTemplates, runTemplates } from './templates.mjs';

const DIR = join(import.meta.dirname, 'templates');
const SEV = new Set(['critical', 'high', 'medium', 'low', 'info']);

test('every template file is well-formed and zero-FP-disciplined', () => {
  const templates = loadTemplates(DIR);
  assert.ok(templates.length >= 10, `expected the template library, got ${templates.length}`);
  const ids = new Set();
  for (const t of templates) {
    assert.ok(t.id && !ids.has(t.id), `unique id: ${t.id}`);
    ids.add(t.id);
    assert.ok(SEV.has(t.severity || 'info'), `${t.id}: valid severity`);
    assert.ok(Array.isArray(t.matchers) && t.matchers.length, `${t.id}: has matchers`);
    assert.ok(Array.isArray(t.requests) && t.requests.length, `${t.id}: has a request`);
    // zero-FP discipline: must assert a distinctive content matcher, not status alone
    assert.ok(
      t.matchers.some((m) => m.words || m.regex),
      `${t.id}: has a content matcher`,
    );
  }
});

test('new checks fire on a matching response and abstain otherwise', async () => {
  const templates = loadTemplates(DIR);
  const only = (id) => templates.filter((x) => x.id === id);
  const run = (tpls, byPath) =>
    runTemplates(
      'https://x',
      tpls,
      async (url) => byPath[url.replace('https://x', '')] || { status: 404, body: '', headers: [] },
    );

  const ssh = only('exposed-ssh-key');
  assert.ok(ssh.length, 'ssh-key template present');
  assert.equal(
    (await run(ssh, { '/.ssh/id_rsa': { status: 200, body: '-----BEGIN OPENSSH PRIVATE KEY-----\nb3B', headers: [] } }))
      .length,
    1,
  );
  assert.equal(
    (await run(ssh, { '/.ssh/id_rsa': { status: 200, body: 'Not Found', headers: [] } })).length,
    0,
    'abstains without a key',
  );

  const prom = only('prometheus-metrics');
  assert.equal(
    (await run(prom, { '/metrics': { status: 200, body: '# HELP go_x\n# TYPE go_x counter', headers: [] } })).length,
    1,
  );
  assert.equal(
    (await run(prom, { '/metrics': { status: 200, body: 'welcome home', headers: [] } })).length,
    0,
    'needs both # HELP and # TYPE',
  );

  const reg = only('docker-registry-catalog');
  assert.equal(
    (await run(reg, { '/v2/_catalog': { status: 200, body: '{"repositories":["app","db"]}', headers: [] } })).length,
    1,
  );
});
