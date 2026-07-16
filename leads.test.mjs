// Tests for the "potential" (leads) tier — labeled, UNPROVEN, kept separate from confirmed findings.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { gatherLeads, reflectionLeads, surfaceLeads } from './packages/dashboard/leads.mjs';

const SURFACE = {
  origin: 'https://app.example',
  pages: [
    { url: 'https://app.example/' },
    { url: 'https://app.example/admin/' },
    { url: 'https://app.example/.git/config' },
    { url: 'https://app.example/search?q=x' },
    { url: 'https://app.example/about' },
  ],
  paramNames: ['q', 'api_key', 'theme'],
  apiPaths: ['/graphql', '/api/v1/orders'],
};

test('surfaceLeads: flags sensitive paths, sensitive params, and graphql — all tier=potential', () => {
  const leads = surfaceLeads(SURFACE);
  const kinds = leads.map((l) => l.kind);
  assert.ok(
    leads.every((l) => l.tier === 'potential' && l.severity === 'info'),
    'never confirmed severity',
  );
  assert.ok(leads.some((l) => l.kind === 'sensitive-path' && /admin/.test(l.target)));
  assert.ok(leads.some((l) => l.kind === 'sensitive-path' && /\.git/.test(l.target)));
  assert.ok(leads.some((l) => l.kind === 'sensitive-param' && l.target === 'api_key'));
  assert.ok(kinds.includes('graphql'));
  assert.ok(!leads.some((l) => l.target === 'theme' || /\/about/.test(l.target)), 'benign surface not flagged');
  assert.ok(
    leads.every((l) => /NOT proven|review|verify|ensure|discovered/i.test(l.note)),
    'every lead reads as unproven',
  );
});

test('reflectionLeads: flags a param that reflects the marker, abstains on one that does not', async () => {
  const fetchText = async (url) => {
    const v = new URL(url).searchParams.get('q') || '';
    // only /search reflects q; /item does not
    return /\/search/.test(url) ? `<div>results for ${v}</div>` : '<div>static</div>';
  };
  const surface = {
    pages: [{ url: 'https://app.example/search?q=x' }, { url: 'https://app.example/item?q=y' }],
  };
  const leads = await reflectionLeads(surface, { fetchText });
  assert.equal(leads.length, 1, 'only the reflecting param');
  assert.equal(leads[0].kind, 'reflection');
  assert.equal(leads[0].tier, 'potential');
  assert.ok(/POTENTIAL/.test(leads[0].note) && /NOT proven/.test(leads[0].note));
  assert.ok(/\/search/.test(leads[0].target));
});

test('reflectionLeads: no fetch impl → no leads (never invents)', async () => {
  assert.deepEqual(await reflectionLeads(SURFACE, {}), []);
});

test('gatherLeads: drops a lead on a path that already has a CONFIRMED finding', async () => {
  const fetchText = async () => `reflected ${'sxLEADr9x73qz'}`; // everything "reflects" → search would lead
  const withConfirmed = await gatherLeads(SURFACE, { fetchText, confirmedTargets: ['https://app.example/search?q=1'] });
  assert.ok(!withConfirmed.some((l) => /\/search/.test(l.target)), 'proven path is not also a lead');
  // but the admin/.git surface leads remain
  assert.ok(withConfirmed.some((l) => /admin/.test(l.target)));
});
