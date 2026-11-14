import assert from 'node:assert/strict';
import { test } from 'node:test';

const { ALL_CLASSES, COMPLIANCE } = await import('./purple-engine.mjs');
const { CLASS_LABELS, SECURITY_AREAS, renderSecurityArea, renderSecurityIndex, renderSitemap, securityArea } =
  await import('./packages/dashboard/security-pages.mjs');
const { renderPricingPage } = await import('./packages/dashboard/pricing-page.mjs');
const { publicCatalog } = await import('./packages/dashboard/commerce.mjs');

test('landing pages advertise exactly the engine classes that exist, each on one page', () => {
  const listed = SECURITY_AREAS.flatMap((area) => area.engineClasses || []);
  assert.equal(new Set(listed).size, listed.length, 'a class is listed on two pages');
  for (const cls of listed) assert.ok(ALL_CLASSES.includes(cls), `page lists ${cls}, which the engine does not run`);
  for (const cls of ALL_CLASSES) assert.ok(listed.includes(cls), `engine class ${cls} is not on any landing page`);
  for (const cls of ALL_CLASSES) assert.ok(CLASS_LABELS[cls], `no label for ${cls}`);
});

test('module-backed areas point at real exported scanners', async () => {
  for (const area of SECURITY_AREAS.filter((item) => item.module)) {
    const mod = await import(`./${area.module.file}`);
    assert.equal(typeof mod[area.module.export], 'function', `${area.module.file} has no ${area.module.export}`);
    assert.ok(area.checks.length > 0);
  }
});

test('area pages render compliance tags from the engine and escape content', () => {
  const html = renderSecurityArea(securityArea('llm-security'), {
    baseUrl: 'https://securovix.example',
    compliance: COMPLIANCE,
  });
  assert.match(html, /Direct prompt injection/);
  assert.match(html, new RegExp(COMPLIANCE['llm-prompt-injection'].cwe));
  assert.match(html, /<link rel="canonical" href="https:\/\/securovix.example\/security-testing\/llm-security">/);
  const evil = renderSecurityArea({ ...securityArea('tls-ssl'), title: '<script>x</script>' }, { baseUrl: '"><x' });
  assert.doesNotMatch(evil, /<script>x<\/script>/);
  assert.doesNotMatch(evil, /href=""><x/);
  assert.equal(securityArea('nope'), null);
  const index = renderSecurityIndex({ baseUrl: '' });
  for (const area of SECURITY_AREAS) assert.match(index, new RegExp(`/security-testing/${area.slug}`));
  const sitemap = renderSitemap('https://securovix.example');
  assert.match(sitemap, /<loc>https:\/\/securovix.example\/pricing<\/loc>/);
});

test('pricing page shows launch prices and no buy links while commerce is off', () => {
  const off = renderPricingPage(publicCatalog({}, { freeLimits: { scans: 5, codeFiles: 25, agentRuns: 10 } }));
  assert.match(off, /Free during beta/);
  assert.match(off, /£49/);
  assert.match(off, /5 verified scans a day/);
  assert.doesNotMatch(off, /#billing\//);
  const on = renderPricingPage(publicCatalog({ SHANNON_COMMERCE_ENABLED: '1' }, { cardReady: true }));
  assert.doesNotMatch(on, /Free during beta/);
  assert.match(on, /href="\/#billing\/verified-url-scan"/);
});
