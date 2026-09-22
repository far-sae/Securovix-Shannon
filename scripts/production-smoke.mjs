const dashboard = String(process.env.SHANNON_SMOKE_DASHBOARD_URL || 'https://origin.securovix.com').replace(/\/$/, '');
const edge = String(process.env.SHANNON_SMOKE_EDGE_URL || 'https://defender.securovix.com').replace(/\/$/, '');
const sandbox = String(process.env.SHANNON_SMOKE_SANDBOX_URL || 'https://sandbox.securovix.com').replace(/\/$/, '');
const sandboxToken = String(process.env.SHANNON_SANDBOX_RUNNER_TOKEN || '');

function assertHttps(name, value) {
  const parsed = new URL(value);
  if (parsed.protocol !== 'https:') throw new Error(`${name} must use HTTPS`);
}

async function request(name, url, { expected, authorization } = {}) {
  const response = await fetch(url, {
    redirect: 'error',
    signal: AbortSignal.timeout(20_000),
    headers: authorization ? { authorization: `Bearer ${authorization}` } : {},
  });
  const text = await response.text();
  let body = null;
  try { body = JSON.parse(text); } catch {}
  if (!expected.includes(response.status)) {
    throw new Error(`${name} returned HTTP ${response.status}: ${text.slice(0, 240)}`);
  }
  console.log(`PASS  ${name.padEnd(31)} HTTP ${response.status}`);
  return body;
}

async function main() {
  assertHttps('Dashboard URL', dashboard);
  assertHttps('Defender Edge URL', edge);
  assertHttps('Sandbox URL', sandbox);

  const health = await request('Dashboard health', `${dashboard}/healthz`, { expected: [200] });
  if (health?.ok !== true || health?.service !== 'dashboard') throw new Error('Dashboard health payload is invalid');

  const readiness = await request('Dashboard readiness', `${dashboard}/readyz`, { expected: [200] });
  if (readiness?.ok !== true || readiness?.database?.backend !== 'supabase' || readiness?.durableJobs !== true) {
    throw new Error('Dashboard is live but Supabase or durable jobs are not ready');
  }

  const edgeHealth = await request('Defender Edge health', `${edge}/__edge/health`, { expected: [200] });
  if (edgeHealth?.ok !== true || !Number.isFinite(Number(edgeHealth.routes))) throw new Error('Defender Edge health payload is invalid');

  await request('Sandbox anonymous denial', `${sandbox}/health`, { expected: [401] });
  if (sandboxToken) {
    const sandboxHealth = await request('Sandbox authenticated health', `${sandbox}/health`, {
      expected: [200],
      authorization: sandboxToken,
    });
    if (sandboxHealth?.ok !== true || sandboxHealth?.docker !== true) throw new Error('Sandbox cannot reach Docker');
  } else {
    console.log('SKIP  Sandbox authenticated health   set SHANNON_SANDBOX_RUNNER_TOKEN locally to test');
  }

  await Promise.all([
    request('Terms page', `${dashboard}/terms`, { expected: [200] }),
    request('Privacy page', `${dashboard}/privacy`, { expected: [200] }),
    request('Security page', `${dashboard}/security`, { expected: [200] }),
  ]);

  console.log('\nProduction smoke checks passed. Authenticated user journeys still require the release checklist.');
}

main().catch((error) => {
  console.error(`FAIL  ${error.message}`);
  process.exitCode = 1;
});
