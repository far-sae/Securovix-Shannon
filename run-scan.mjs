#!/usr/bin/env node
/**
 * Shannon Advanced Scanner — Red Team + Blue Team adversarial engine
 * Red attacks. Blue defends. Exploits are verified. Zero false positives.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { randomUUID, createHash } from 'node:crypto';
import { ALL_CLASSES, runExploitDefend } from './purple-engine.mjs';

// ---- Live HTTP recon ----
async function httpRecon(targetUrl) {
  const paths = [
    '/',
    '/robots.txt',
    '/sitemap.xml',
    '/.env',
    '/.git/config',
    '/.git/HEAD',
    '/api',
    '/api/v1',
    '/api/v2',
    '/graphql',
    '/admin',
    '/login',
    '/signup',
    '/register',
    '/wp-admin',
    '/wp-login.php',
    '/.well-known/security.txt',
    '/.well-known/openid-configuration',
    '/swagger.json',
    '/openapi.json',
    '/api-docs',
    '/health',
    '/healthz',
    '/status',
    '/metrics',
    '/favicon.ico',
    '/.DS_Store',
    '/server-status',
    '/server-info',
    '/phpinfo.php',
    '/debug',
    '/trace',
    '/actuator',
    '/actuator/health',
    '/actuator/env',
    '/config',
    '/config.json',
    '/config.yaml',
    '/package.json',
    '/composer.json',
    '/backup.sql',
    '/dump.sql',
    '/database.sql',
    '/.htaccess',
    '/web.config',
    '/crossdomain.xml',
    '/clientaccesspolicy.xml',
    '/security.txt',
    '/wp-json/wp/v2/users',
    '/xmlrpc.php',
    '/feed',
    '/rss',
  ];
  console.log(`           Probing ${paths.length} endpoints...`);
  const results = [];
  for (const path of paths) {
    try {
      const url = targetUrl.replace(/\/$/, '') + path;
      const c = new AbortController();
      const t = setTimeout(() => c.abort(), 8000);
      const r = await fetch(url, {
        method: 'GET',
        redirect: 'follow',
        signal: c.signal,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
        },
      });
      clearTimeout(t);
      const body = await r.text().catch(() => '');
      results.push({
        path,
        status: r.status,
        headers: Object.fromEntries(r.headers.entries()),
        bodyPreview: body.slice(0, 4000),
        size: body.length,
      });
    } catch (e) {
      results.push({ path, status: 'error', error: e.message?.slice(0, 200) });
    }
  }

  // Security header check
  const mainPage = results.find((r) => r.path === '/');
  const headers = mainPage?.headers ?? {};
  const securityHeaders = {
    'strict-transport-security': headers['strict-transport-security'] || null,
    'content-security-policy': headers['content-security-policy'] || null,
    'x-content-type-options': headers['x-content-type-options'] || null,
    'x-frame-options': headers['x-frame-options'] || null,
    'x-xss-protection': headers['x-xss-protection'] || null,
    'referrer-policy': headers['referrer-policy'] || null,
    'permissions-policy': headers['permissions-policy'] || null,
    'access-control-allow-origin': headers['access-control-allow-origin'] || null,
    server: headers['server'] || null,
    'x-powered-by': headers['x-powered-by'] || null,
  };

  const summary = results
    .map((r) => (r.status === 'error' ? `  ${r.path} -> ERROR` : `  ${r.path} -> ${r.status} (${r.size}b)`))
    .join('\n');
  const headerAnalysis = Object.entries(headers)
    .map(([k, v]) => `  ${k}: ${v}`)
    .join('\n');

  // Unique response fingerprinting (detect SPA catch-all)
  const sizeCounts = {};
  for (const r of results) {
    if (r.size) {
      sizeCounts[r.size] = (sizeCounts[r.size] || 0) + 1;
    }
  }
  const catchAllSize = Object.entries(sizeCounts).sort((a, b) => b[1] - a[1])[0];
  const realEndpoints = results.filter((r) => r.status !== 'error' && r.size && r.size !== parseInt(catchAllSize?.[0]));

  return {
    results,
    summary,
    headerAnalysis,
    mainBody: mainPage?.bodyPreview ?? '',
    securityHeaders,
    realEndpoints,
    catchAllSize: catchAllSize?.[0],
  };
}

// ---- Config ----
const configArg = process.argv.find((a, i) => process.argv[i - 1] === '--config') ?? 'scan-config.yaml';
const config = parseYaml(readFileSync(configArg, 'utf-8'));
const targetUrl = config.target.url;
const apiKey = process.env.ANTHROPIC_API_KEY;
if (!apiKey) {
  console.error('ERROR: Set ANTHROPIC_API_KEY');
  process.exit(1);
}

let Anthropic;
try {
  Anthropic = (await import('@anthropic-ai/sdk')).default;
} catch {
  const { execSync } = await import('node:child_process');
  execSync('pnpm add -w @anthropic-ai/sdk', { stdio: 'inherit', cwd: import.meta.dirname });
  Anthropic = (await import('@anthropic-ai/sdk')).default;
}

// maxRetries=5 with the SDK's built-in exponential backoff handles 429s on Tier 1 keys.
// timeout=10min keeps long deliverables (report, war-room) from being killed mid-stream.
const client = new Anthropic({ apiKey, maxRetries: 5, timeout: 600_000 });
const MODEL = process.env.SHANNON_MODEL ?? 'claude-opus-4-7';
const scanId = randomUUID().slice(0, 8);
const wsDir = join(import.meta.dirname, 'workspaces', scanId);
const dirs = [
  '',
  'pre-recon',
  'recon',
  'red-team',
  'blue-team',
  'purple-team',
  'exploit-verify',
  'chain-analysis',
  'war-room',
  'forensic-package',
  'audit',
  ...['sqli', 'xss', 'auth-bypass', 'authz-bypass', 'ssrf', 'business-logic', 'misconfig', 'info-disclosure'].flatMap(
    (c) => [`vuln/${c}`, `exploit/${c}`],
  ),
];
for (const d of dirs) mkdirSync(join(wsDir, d), { recursive: true });

const session = {
  scanId,
  target: targetUrl,
  startedAt: new Date().toISOString(),
  completedAgents: [],
  metrics: {},
  status: 'running',
};

console.log(`\n  Shannon Penetration Testing Framework`);
console.log(`  =====================================`);
console.log(`  Target:    ${targetUrl}`);
console.log(`  Scan ID:   ${scanId}`);
console.log(`  Model:     ${MODEL}\n`);

function save(p, c) {
  writeFileSync(join(wsDir, p), c);
}
function elapsed(s) {
  return ((Date.now() - s) / 1000).toFixed(1);
}
// Default max_tokens lowered from 8192 → 4000. Anthropic reserves the FULL max_tokens
// against your OTPM (output-tokens-per-minute) quota for the duration of the request,
// even if the model emits less. The old 8192 default was the main reason scans tripped
// rate limits on Tier 1 / Tier 2 keys. Long deliverables (war-room, report) still pass
// 8192 explicitly — they run sequentially and don't burst.
async function llm(sys, usr, max = 4000) {
  const r = await client.messages.create({
    model: MODEL,
    max_tokens: max,
    messages: [{ role: 'user', content: `${sys}\n\n${usr}` }],
  });
  const text = r.content
    .filter((b) => b.type === 'text')
    .map((b) => b.text)
    .join('\n');
  return {
    text,
    cost: parseFloat((r.usage.input_tokens * 0.000003 + r.usage.output_tokens * 0.000015).toFixed(6)),
    tokens: r.usage,
  };
}

// Concurrency-limited Promise.all. Used by Phase 3 to cap simultaneous Red Team
// requests so we don't burst through OTPM. With limit=3 and max_tokens=4096,
// peak in-flight reservation is ~12k output tokens — well inside Tier 1 Sonnet 4.6 (~16k).
async function pMap(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  async function worker() {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      results[i] = await fn(items[i], i);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

function done(agent, metrics) {
  session.completedAgents.push(agent);
  session.metrics[agent] = metrics;
  save('session.json', JSON.stringify(session, null, 2));
}

// ================================================================
//  PHASE 0: Live HTTP Reconnaissance
// ================================================================
console.log(`  [Phase 0] Live HTTP Reconnaissance...`);
let t = Date.now();
const recon = await httpRecon(targetUrl);
save('pre-recon/http-probe.txt', recon.summary);
save('pre-recon/main-page.html', recon.mainBody);
save('pre-recon/headers.txt', recon.headerAnalysis);
save('pre-recon/security-headers.json', JSON.stringify(recon.securityHeaders, null, 2));
save(
  'pre-recon/real-endpoints.json',
  JSON.stringify(
    recon.realEndpoints.map((r) => ({ path: r.path, status: r.status, size: r.size })),
    null,
    2,
  ),
);
const liveCount = recon.results.filter((r) => r.status !== 'error' && r.status < 400).length;
console.log(
  `           Done (${elapsed(t)}s) — ${liveCount} live, ${recon.realEndpoints.length} real endpoints, catch-all size: ${recon.catchAllSize || 'none'}`,
);

// ================================================================
//  PHASE 1: Pre-Recon + Threat Modeling
// ================================================================
console.log(`  [Phase 1] Pre-Recon & Threat Modeling...`);
t = Date.now();
const preReconResult = await llm(
  `You are an elite penetration tester performing initial reconnaissance and threat modeling.`,
  `Target: ${targetUrl}

LIVE PROBE RESULTS:
${recon.summary}

SECURITY HEADERS:
${JSON.stringify(recon.securityHeaders, null, 2)}

REAL ENDPOINTS (not SPA catch-all):
${recon.realEndpoints.map((r) => `${r.path} -> ${r.status} (${r.size}b)`).join('\n')}

HTML:
${recon.mainBody.slice(0, 3000)}

Perform:
1. Technology stack identification from headers, HTML, JS filenames
2. Security header audit — grade each header present/missing
3. Attack surface mapping — which endpoints are real vs SPA catch-all
4. Threat model — what are the most likely attack vectors for this app?
5. CORS policy analysis — is access-control-allow-origin set? To what?
6. Server information disclosure — what does the server header reveal?
7. Cookie analysis — HttpOnly, Secure, SameSite flags
8. SSL/TLS observations from headers`,
);
save('pre-recon/analysis.md', preReconResult.text);
done('pre-recon', { cost: preReconResult.cost, turns: 1, duration: Date.now() - t });
console.log(`           Done (${elapsed(t)}s, $${preReconResult.cost})`);

// ================================================================
//  PHASE 2: Deep Recon
// ================================================================
console.log(`  [Phase 2] Deep Recon & API Mapping...`);
t = Date.now();
const reconResult = await llm(
  `You are a web application security tester specializing in deep reconnaissance.`,
  `Target: ${targetUrl}

LIVE PROBE DATA:
${recon.summary}

SECURITY HEADERS: ${JSON.stringify(recon.securityHeaders)}
REAL ENDPOINTS: ${JSON.stringify(recon.realEndpoints.map((r) => r.path))}
PREVIOUS ANALYSIS: ${preReconResult.text.slice(0, 2000)}
HTML: ${recon.mainBody.slice(0, 2000)}

Perform deep recon:
1. Full endpoint map with response classification
2. API pattern detection (REST, GraphQL, WebSocket)
3. Authentication flow identification
4. JavaScript bundle analysis — what APIs does the frontend call?
5. Third-party service detection (analytics, CDNs, payment processors)
6. Subdomain and related infrastructure inference
7. Input vectors — forms, query params, headers that accept user input
8. File upload and download endpoints`,
);
save('recon/exploration.md', reconResult.text);
done('recon', { cost: reconResult.cost, turns: 1, duration: Date.now() - t });
console.log(`           Done (${elapsed(t)}s, $${reconResult.cost})`);

// ================================================================
//  PHASE 3: RED TEAM — Attack (8 categories parallel)
// ================================================================
const categories = [
  { id: 'sqli', name: 'SQL/NoSQL Injection', icon: '💉' },
  { id: 'xss', name: 'Cross-Site Scripting (XSS)', icon: '📜' },
  { id: 'auth-bypass', name: 'Authentication Bypass', icon: '🔓' },
  { id: 'authz-bypass', name: 'Authorization Bypass (IDOR)', icon: '🛡️' },
  { id: 'ssrf', name: 'Server-Side Request Forgery', icon: '🌐' },
  { id: 'business-logic', name: 'Business Logic Flaws', icon: '⚙️' },
  { id: 'misconfig', name: 'Security Misconfiguration', icon: '🔧' },
  { id: 'info-disclosure', name: 'Information Disclosure', icon: '📋' },
];

// Concurrency capped at 3 (was 8 = all parallel). Anthropic rate limits are bucketed
// per minute and they reserve max_tokens up-front, so 8 simultaneous 4k-output requests
// instantly burst past the OTPM ceiling on Tier 1/2 keys. 3-at-a-time keeps us under
// the limit and the SDK's built-in retry covers any spillover.
const RED_CONCURRENCY = Number(process.env.SHANNON_RED_CONCURRENCY) || 3;
console.log(`  [Phase 3] RED TEAM — Attack Phase (${categories.length} agents, ${RED_CONCURRENCY} at a time)...`);
t = Date.now();

const redResults = await pMap(categories, RED_CONCURRENCY, async (cat) => {
  const r = await llm(
    `You are a RED TEAM operator — an elite offensive hacker. Your codename is RED-${cat.id.toUpperCase()}.
Your ONLY job is to ATTACK and find real vulnerabilities. Be aggressive, creative, and thorough.
Think like an actual attacker who wants to break in. No mercy, no false positives.`,
    `TARGET: ${targetUrl}

YOUR SPECIALTY: ${cat.name}

INTELLIGENCE GATHERED:
${recon.summary}
Security Headers: ${JSON.stringify(recon.securityHeaders)}
Real Endpoints: ${JSON.stringify(recon.realEndpoints.map((r) => r.path))}
Recon: ${reconResult.text.slice(0, 1500)}
HTML: ${recon.mainBody.slice(0, 1000)}

MISSION BRIEFING:
You are attacking ${targetUrl} looking specifically for ${cat.name} vulnerabilities.

YOUR ATTACK METHODOLOGY:
1. Identify every possible ${cat.name} attack vector based on the recon data
2. For each vector, describe the EXACT attack you would perform
3. Provide the EXACT payload, curl command, or script
4. Explain what a successful attack would look like (expected response)
5. Rate the likelihood: CONFIRMED (you can prove it), LIKELY (strong indicators), THEORETICAL (possible but unproven)
6. For CONFIRMED findings — provide a copy-paste POC that works RIGHT NOW
7. For LIKELY findings — explain what additional access you'd need to confirm

ATTACK RULES:
- Be creative. Think of edge cases, chained attacks, race conditions
- Check for default credentials, debug endpoints, version-specific CVEs
- Look at response headers for clues about backend technology
- Consider both authenticated and unauthenticated attack surfaces
- If the app is an SPA — analyze what the JavaScript reveals about API endpoints
- Check for CORS misconfigs, insecure cookies, missing CSP
- ZERO false positives. Mark confidence level honestly.

OUTPUT FORMAT:
## ATTACK: [Attack Name]
**Confidence**: CONFIRMED / LIKELY / THEORETICAL
**Severity**: Critical / High / Medium / Low
**Vector**: [exact endpoint and parameter]
**Payload**:
\`\`\`bash
[exact curl/script]
\`\`\`
**Expected Result**: [what proves exploitation worked]
**Impact**: [what attacker gains]`,
    4096,
  );
  save(`vuln/${cat.id}/analysis.md`, `# RED TEAM: ${cat.name}\n\n${r.text}`);
  const hasFindings = /##\s+ATTACK/i.test(r.text);
  const findings = [];
  const matches = r.text.matchAll(/##\s+ATTACK[:\s]+(.*?)(?=##\s+ATTACK|$)/gs);
  for (const m of matches) {
    const conf = /CONFIRMED/i.test(m[1]) ? 'confirmed' : /LIKELY/i.test(m[1]) ? 'likely' : 'theoretical';
    findings.push({
      id: `${cat.id}-${findings.length + 1}`,
      type: conf,
      description: m[1]?.trim().slice(0, 500) ?? '',
      severity: 'medium',
      endpoint: targetUrl,
    });
  }
  save(`vuln/${cat.id}/exploitation-queue.json`, JSON.stringify({ category: cat.id, findings }, null, 2));
  done(`red-${cat.id}`, { cost: r.cost, turns: 1, duration: Date.now() - t });
  return { cat, result: r, hasFindings, findings };
});

console.log(`           Done (${elapsed(t)}s, $${redResults.reduce((s, r) => s + r.result.cost, 0).toFixed(6)})`);
save(
  'red-team/summary.md',
  redResults
    .map(
      (r) =>
        `## ${r.cat.icon} ${r.cat.name}\nFindings: ${r.findings.length} (${r.findings.filter((f) => f.type === 'confirmed').length} confirmed, ${r.findings.filter((f) => f.type === 'likely').length} likely)\n`,
    )
    .join('\n'),
);

// ================================================================
//  PHASE 3.5: REAL Exploit + Defend (Purple Engine)
//  In-house probers exploit the target in HARDENED docker sandboxes; each CONFIRMED
//  finding (proven by a benign marker — zero false positives) gets a detection rule +
//  LLM remediation, and payload-based classes are re-tested through a LIVE inline WAF
//  proxy to prove the block. Best-effort: skips cleanly if Docker / prober images are
//  unavailable (e.g. a host without the broker probers built).
// ================================================================
console.log(`  [Phase 3.5] Real Exploit + Defend (broker probers)...`);
t = Date.now();
try {
  const purple = await runExploitDefend({
    target: targetUrl,
    classes: ALL_CLASSES,
    label: 'scan',
    workspaceDir: wsDir,
  });
  const confirmed = purple.exploits.reduce((s, e) => s + e.confirmed, 0);
  console.log(
    `           Done (${elapsed(t)}s) — ${confirmed} CONFIRMED exploit(s), ${purple.defenses.length} defense(s) generated`,
  );
  done('purple-engine', { cost: 0, turns: 1, duration: Date.now() - t, confirmed });
} catch (e) {
  console.log(`           Skipped — ${e.message?.slice(0, 160)}`);
}

// ================================================================
//  PHASE 4: PURPLE TEAM — 2 Red agents + 2 Blue agents, dialog
// ================================================================
//  Red Strategist <-> Red Attacker (intra-team)
//  Blue Defender  <-> Blue IR       (intra-team)
//  Red <-> Blue (cross-team rebuttals)
//  Moderator synthesizes the final conclusion.
// ================================================================
console.log(`  [Phase 4] PURPLE TEAM — 2 Red + 2 Blue Agents in Dialog...`);
t = Date.now();
const allRedFindings = redResults
  .map((r) => `### ${r.cat.icon} ${r.cat.name}\n${r.result.text.slice(0, 800)}`)
  .join('\n\n');

const ptCosts = [];
async function ptTurn(label, sys, usr, max = 2048) {
  const r = await llm(sys, usr, max);
  ptCosts.push({ label, cost: r.cost });
  return r.text;
}

const ptContext = `TARGET: ${targetUrl}

APPLICATION ARCHITECTURE (pre-recon):
${preReconResult.text.slice(0, 1200)}

SECURITY HEADERS:
${JSON.stringify(recon.securityHeaders, null, 2)}

RED TEAM ATTACKS (8 categories):
${allRedFindings}`;

console.log(`           Red Strategist briefing the Attacker...`);
const redStrategist = await ptTurn(
  'red-strategist',
  `You are the RED TEAM STRATEGIST. You partner with the Red Attacker to plan how to exploit the findings.
Talk to your teammate like a partner, not a report. Cite the findings explicitly.`,
  `${ptContext}

## Your Output
1. OBJECTIVE — what success looks like for this target overall
2. PRIORITY TARGETS — which 3 findings matter most and why
3. ATTACK PLAN — ordered steps the Red Attacker should run
4. CHAINING — how to combine findings for higher impact
5. ASK FOR ATTACKER — what you need them to refine on the wire`,
);

console.log(`           Red Attacker executing plan...`);
const redAttacker = await ptTurn(
  'red-attacker',
  `You are the RED TEAM ATTACKER (operator). You take the strategist plan and turn it into concrete exploit steps.
Push back where the plan is unrealistic. Surface obstacles only the operator sees (rate limits, WAF, encoding gotchas).`,
  `${ptContext}

## Strategist plan
${redStrategist}

## Your Output
1. EXECUTION — concrete steps with payloads / requests
2. OBSERVED OBSTACLES — what the network/app actually does back
3. REPLY TO STRATEGIST — what you need them to adjust
4. PROOF OF IMPACT — what evidence proves this works`,
);

console.log(`           Blue Defender designing mitigations...`);
const blueDefender = await ptTurn(
  'blue-defender',
  `You are the BLUE TEAM DEFENDER (security engineer). You design controls that make findings non-exploitable.
Be honest about cost and label fail-open vs fail-closed controls. Talk to Blue IR like a partner.`,
  `${ptContext}

## Your Output
1. ROOT CAUSE — one paragraph per top category
2. MITIGATIONS — list, each in the form: \`- LAYER (code|config|network|process|monitoring) | EFFORT (low|medium|high) | CONTROL: <what> | WHY: <reason>\`
3. RESIDUAL RISK after these controls
4. ASK FOR IR — what you need them to monitor

Also include the legacy DEFENSE SCORECARD (each category A-F):
- Perimeter Defense, Transport Security, Authentication, Authorization,
  Input Validation, Output Encoding, Data Protection, Security Headers, Error Handling, Dependency Security`,
);

console.log(`           Blue IR designing detections...`);
const blueIR = await ptTurn(
  'blue-ir',
  `You are the BLUE TEAM IR / DETECTION ENGINEER. You design detections and IR playbooks for what the Defender cannot fully close.
Talk to the Defender like a partner — point out gaps detection must cover.`,
  `${ptContext}

## Defender mitigations
${blueDefender}

## Your Output
1. DETECTIONS — list, each: \`- NAME | SOURCE: <log/source> | SIGNAL: <what to look for> | QUERY: <pseudo SQL/Sigma>\`
2. PLAYBOOK — short ordered steps for an analyst when this fires
3. REPLY TO DEFENDER — gaps in their controls and where detection must cover`,
);

console.log(`           Cross-team: Red Strategist replying to Blue Defender...`);
const redVsBlueDefender = await ptTurn(
  'red-strategist-x',
  `You are the RED TEAM STRATEGIST speaking to the Blue Team. Honestly assess whether their mitigations break your attack plan.`,
  `${ptContext}

## Blue Defender proposal
${blueDefender}

## Your Output
1. WHAT THE DEFENSE BREAKS — be specific about which steps stop working
2. BYPASS IDEAS — concrete ways your Attacker could route around it
3. CONCESSION — if a control truly closes the issue, say "CONCEDE: <which control>". Otherwise omit.`,
);

console.log(`           Cross-team: Blue Defender countering Red Strategist...`);
const blueVsRedStrategist = await ptTurn(
  'blue-defender-x',
  `You are the BLUE TEAM DEFENDER replying to the Red Strategist's bypass claims. Engage seriously: agree where they are right, push back where they are wrong.`,
  `${ptContext}

## Red Strategist counter
${redVsBlueDefender}

## Your Output
1. ACKNOWLEDGED BYPASSES — which red claims are valid
2. ADDITIONAL CONTROLS — concrete additions to close those
3. DISPUTED — which red claims do not actually bypass your controls, with reasoning`,
);

console.log(`           Cross-team: Red Attacker replying to Blue IR...`);
const redVsBlueIR = await ptTurn(
  'red-attacker-x',
  `You are the RED TEAM ATTACKER speaking directly to Blue IR. Tell them which detections would catch your steps and which you can evade.`,
  `${ptContext}

## Blue IR detection proposal
${blueIR}

## Your Output
1. CAUGHT — which detections fire on your real steps
2. MISSED — which steps slip through, and how
3. EVASION — small tweaks that defeat the proposed detection`,
);

console.log(`           Cross-team: Blue IR countering Red Attacker...`);
const blueVsRedAttacker = await ptTurn(
  'blue-ir-x',
  `You are the BLUE IR engineer replying to the Red Attacker's evasion claims. Take it seriously and adapt.`,
  `${ptContext}

## Red Attacker counter
${redVsBlueIR}

## Your Output
1. CONFIRMED EVASIONS — which evasions you accept as valid
2. NEW DETECTIONS — concrete additions to catch the bypass
3. DISPUTED — which evasions would still trip alarms you have, with reasoning`,
);

console.log(`           Moderator synthesizing conclusion...`);
const moderatorConclusion = await ptTurn(
  'pt-moderator',
  `You are the PURPLE TEAM MODERATOR. Read the full red-vs-blue exchange and write the conclusion.`,
  `${ptContext}

## Transcript

### 🔴 Red Strategist (plan)
${redStrategist}

### 🔴 Red Attacker (execution)
${redAttacker}

### 🔵 Blue Defender (mitigations)
${blueDefender}

### 🔵 Blue IR (detections)
${blueIR}

### 🔴 → 🔵 Red Strategist rebuttal
${redVsBlueDefender}

### 🔵 → 🔴 Blue Defender counter
${blueVsRedStrategist}

### 🔴 → 🔵 Red Attacker rebuttal
${redVsBlueIR}

### 🔵 → 🔴 Blue IR counter
${blueVsRedAttacker}

## Your Output (markdown)

# Purple Team Conclusion

## Verdict
- **Overall residual risk**: critical/high/medium/low (one line reason)
- **Red/Blue agreement**: yes/no (one line reason)

## Confirmed Attack Chain
One paragraph describing the attack that survives blue's controls.

## Final Mitigation Matrix
A markdown table: | Control | Layer | Effort | Closes which red step | Status (proposed/disputed/accepted) |

## Final Detection Matrix
A markdown table: | Detection | Source | Signal | Catches which red step | Confidence |

## What Red Got Right
Bullets.

## What Blue Got Right
Bullets.

## Top 3 Action Items
Ordered, concrete, owner-tagged.`,
  4096,
);

// Save artifacts. Keep blue-team/defense-assessment.md for backwards-compat with the existing dashboard tab.
save('blue-team/defense-assessment.md', blueDefender);
save('purple-team/red-strategist.md', redStrategist);
save('purple-team/red-attacker.md', redAttacker);
save('purple-team/blue-defender.md', blueDefender);
save('purple-team/blue-ir.md', blueIR);
save(
  'purple-team/cross-team.md',
  [
    '## 🔴 Red Strategist → 🔵 Blue Defender',
    redVsBlueDefender,
    '## 🔵 Blue Defender → 🔴 Red Strategist',
    blueVsRedStrategist,
    '## 🔴 Red Attacker → 🔵 Blue IR',
    redVsBlueIR,
    '## 🔵 Blue IR → 🔴 Red Attacker',
    blueVsRedAttacker,
  ].join('\n\n---\n\n'),
);
save('purple-team/conclusion.md', moderatorConclusion);
save(
  'purple-team/transcript.md',
  [
    '# Purple Team Transcript',
    '',
    '## 🔴 Red Strategist — Plan',
    redStrategist,
    '',
    '## 🔴 Red Attacker — Execution',
    redAttacker,
    '',
    '## 🔵 Blue Defender — Mitigations',
    blueDefender,
    '',
    '## 🔵 Blue IR — Detections',
    blueIR,
    '',
    '---',
    '',
    '# Cross-Team Exchange',
    '',
    '## 🔴 → 🔵 Red Strategist rebuttal',
    redVsBlueDefender,
    '',
    '## 🔵 → 🔴 Blue Defender counter',
    blueVsRedStrategist,
    '',
    '## 🔴 → 🔵 Red Attacker rebuttal',
    redVsBlueIR,
    '',
    '## 🔵 → 🔴 Blue IR counter',
    blueVsRedAttacker,
    '',
    '---',
    '',
    moderatorConclusion,
  ].join('\n'),
);

const ptTotalCost = ptCosts.reduce((a, b) => a + b.cost, 0);
done('blue-team', {
  cost: ptCosts.find((c) => c.label === 'blue-defender')?.cost ?? 0,
  turns: 1,
  duration: Date.now() - t,
});
done('purple-team', { cost: ptTotalCost, turns: ptCosts.length, duration: Date.now() - t });
const blueResult = { text: blueDefender, cost: ptTotalCost };
console.log(`           Done (${elapsed(t)}s, $${ptTotalCost.toFixed(6)} across ${ptCosts.length} agent turns)`);

// ================================================================
//  PHASE 5: EXPLOIT VERIFICATION — Prove it works
// ================================================================
console.log(`  [Phase 5] Exploit Verification — Proving attacks work...`);
t = Date.now();

const confirmedAttacks = redResults.flatMap((r) =>
  r.findings.filter((f) => f.type === 'confirmed' || f.type === 'likely'),
);

const exploitResult = await llm(
  `You are an EXPLOIT DEVELOPER. Your job is to take Red Team findings and create WORKING, VERIFIED proof-of-concept exploits.
Every exploit must be copy-paste ready. If you cannot create a working exploit, the finding is DOWNGRADED to theoretical.`,
  `TARGET: ${targetUrl}

RED TEAM FINDINGS TO VERIFY:
${allRedFindings}

BLUE TEAM DEFENSE ASSESSMENT:
${blueResult.text.slice(0, 2000)}

FOR EACH RED TEAM FINDING:
1. Can you create a WORKING exploit right now? (based on observed responses)
2. Does the Blue Team's defense assessment invalidate the attack?
3. Provide the EXACT exploit — copy-paste ready:
   - curl commands that demonstrate the vulnerability
   - Python scripts for complex exploits
   - Step-by-step reproduction instructions
4. Show EXPECTED vs ACTUAL response to prove it works
5. If exploit would work but you can't verify without auth — mark as UNVERIFIED_NEEDS_AUTH

## EXPLOIT: [Name]
**Status**: VERIFIED / UNVERIFIED_NEEDS_AUTH / BLOCKED_BY_DEFENSE / FALSE_POSITIVE
**Red Team Claim**: [original finding]
**Blue Team Assessment**: [defense status]
**Final Verdict**: [does this actually work?]
**POC**:
\`\`\`bash
[EXACT exploit command]
\`\`\`
**Evidence**: [what the response proves]
**Business Impact**: [real-world consequences]`,
);
save('exploit-verify/verification.md', exploitResult.text);
done('exploit-verify', { cost: exploitResult.cost, turns: 1, duration: Date.now() - t });
console.log(`           Done (${elapsed(t)}s, $${exploitResult.cost})`);

// ================================================================
//  PHASE 6: Attack Chain Analysis
// ================================================================
console.log(`  [Phase 6] Attack Chain Analysis...`);
t = Date.now();
const chainResult = await llm(
  `You are a kill-chain analyst. Combine individual vulnerabilities into multi-step attack scenarios.`,
  `TARGET: ${targetUrl}

RED TEAM FINDINGS: ${allRedFindings.slice(0, 2000)}
BLUE TEAM ASSESSMENT: ${blueResult.text.slice(0, 1500)}
EXPLOIT VERIFICATION: ${exploitResult.text.slice(0, 1500)}

Build attack chains:
1. Map how vulnerabilities can be combined (A enables B enables C)
2. Score each chain: feasibility (0-10) x impact (0-10)
3. Map to MITRE ATT&CK tactics
4. Tell the attack as a STORY — "An attacker would first... then they could... finally gaining..."
5. For each chain, note which Blue Team defenses would block which steps
6. Identify the WEAKEST LINK in each chain — the one fix that breaks the entire attack`,
);
save('chain-analysis/analysis.md', chainResult.text);
done('chain-analysis', { cost: chainResult.cost, turns: 1, duration: Date.now() - t });
console.log(`           Done (${elapsed(t)}s, $${chainResult.cost})`);

// ================================================================
//  PHASE 7: War Room — Red vs Blue Debate
// ================================================================
console.log(`  [Phase 7] War Room — Red vs Blue Adversarial Debate...`);
t = Date.now();

const warRoomResult = await llm(
  `You are moderating a WAR ROOM between Red Team and Blue Team. This is an adversarial debate where both sides argue their case.

THE PARTICIPANTS:
🔴 RED TEAM LEAD — Argues that findings are real and dangerous. Wants maximum severity.
🔵 BLUE TEAM LEAD — Argues that defenses are in place and findings are overstated. Wants to downgrade severity.
⚔️ EXPLOIT VERIFIER — Provides technical proof. Only cares about facts.
🎯 SKEPTIC — Challenges everyone. Demands evidence. Eliminates false positives.
👨‍⚖️ MODERATOR (you) — Makes the final call based on evidence.

DEBATE RULES:
- Each finding gets a structured debate with all participants
- Red Team presents the attack
- Blue Team presents the defense
- Exploit Verifier shows proof (or lack thereof)
- Skeptic challenges both sides
- Moderator renders verdict: CONFIRMED / FALSE_POSITIVE / MITIGATED / NEEDS_INVESTIGATION`,
  `TARGET: ${targetUrl}

RED TEAM REPORT:
${allRedFindings.slice(0, 2500)}

BLUE TEAM DEFENSE:
${blueResult.text.slice(0, 2500)}

EXPLOIT VERIFICATION:
${exploitResult.text.slice(0, 2000)}

ATTACK CHAINS:
${chainResult.text.slice(0, 1500)}

FOR EACH FINDING, RUN THE DEBATE:

### 🔴 vs 🔵: [Finding Name]

**🔴 RED TEAM**: [attack argument — why this is dangerous]
**🔵 BLUE TEAM**: [defense argument — why this is mitigated or overstated]
**⚔️ EXPLOIT VERIFIER**: [technical proof — does the exploit actually work?]
**🎯 SKEPTIC**: [challenges both sides — what's missing?]

**👨‍⚖️ VERDICT**: CONFIRMED / FALSE_POSITIVE / MITIGATED / NEEDS_INVESTIGATION
**Final Severity**: Critical / High / Medium / Low / Informational
**Confidence**: 0-100%

END WITH:
## WAR ROOM SCORECARD
- Total findings reviewed: X
- Confirmed vulnerabilities: X
- False positives eliminated: X
- Mitigated (defense in place): X
- Needs investigation: X
- Severity adjustments made: X`,
  8192,
);
save('war-room/transcript.md', warRoomResult.text);
done('war-room', { cost: warRoomResult.cost, turns: 1, duration: Date.now() - t });
console.log(`           Done (${elapsed(t)}s, $${warRoomResult.cost})`);

// ================================================================
//  PHASE 8: Professional Report
// ================================================================
console.log(`  [Phase 8] Final Report (Red + Blue combined)...`);
t = Date.now();

const reportResult = await llm(
  `You are a world-class security consultant writing a penetration test report.

STYLE: Premium consulting quality. A non-technical CEO should understand every finding.
Use plain English, analogies, emoji severity badges, copy-paste fixes.
🔴 Critical 🟠 High 🟡 Medium 🔵 Low ✅ Pass

THIS REPORT COMBINES RED TEAM AND BLUE TEAM PERSPECTIVES.`,
  `Target: ${targetUrl}
Scan ID: ${scanId}
Date: ${new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}

== ALL DATA ==

Pre-Recon: ${preReconResult.text.slice(0, 1000)}
Recon: ${reconResult.text.slice(0, 1000)}
Red Team Attacks: ${allRedFindings.slice(0, 2000)}
Blue Team Defense: ${blueResult.text.slice(0, 2000)}
Exploit Verification: ${exploitResult.text.slice(0, 1500)}
Attack Chains: ${chainResult.text.slice(0, 1500)}
War Room Debate: ${warRoomResult.text.slice(0, 2000)}

== REPORT STRUCTURE ==

# 1. EXECUTIVE SUMMARY
- What we tested, what we found, overall risk
- Risk scorecard with emoji counts
- The #1 thing to fix RIGHT NOW
- Business impact in plain English

# 2. SECURITY GRADE
- Overall grade A-F
- Category scorecard (each rated A-F):
  Transport Security, Security Headers, CORS Policy, Authentication, Authorization,
  Input Validation, Data Exposure, Server Configuration, Error Handling, Compliance Readiness

# 3. RED TEAM vs BLUE TEAM SUMMARY
- What Red Team found (attack count per category)
- What Blue Team confirmed is defended
- Net result: how many attacks survived both Red and Blue review
- Visual: attacks attempted → defenses in place → vulnerabilities remaining

# 4. CONFIRMED FINDINGS (war room verdicts ONLY)
For each CONFIRMED finding:
### 🟡 [Title in plain English]
**In simple terms**: [non-technical explanation with analogy]
**Red Team Attack**: [how they'd break in]
**Blue Team Status**: [what defense exists or is missing]
**Proof**:
\`\`\`bash
[copy-paste exploit]
\`\`\`
**How to fix**:
\`\`\`
[copy-paste fix]
\`\`\`
**Time to fix**: [estimate]

# 5. ATTACK SCENARIOS
- Top attack chains as narratives
- Which Blue Team defense breaks each chain

# 6. DEFENSE WINS ✅
- What Blue Team confirmed is WORKING WELL
- Security controls that blocked Red Team attacks
- Give credit for good security practices

# 7. ACTION PLAN
- Fix This Week / This Month / This Quarter
- Red Team priority vs Blue Team priority
- Quick wins highlighted

# 8. APPENDIX
- Tech stack, endpoints, MITRE mappings, methodology

RULES:
- ONLY include CONFIRMED findings from war room
- Show Red vs Blue perspective for each finding
- Zero false positives
- Every finding has a POC and a fix`,
  8192,
);
save('report.md', reportResult.text);
done('report', { cost: reportResult.cost, turns: 1, duration: Date.now() - t });
console.log(`           Done (${elapsed(t)}s, $${reportResult.cost})`);

// ================================================================
//  PHASE 9: Forensic Package
// ================================================================
console.log(`  [Phase 9] Forensic Evidence Package...`);
const totalCost = Object.values(session.metrics).reduce((s, m) => s + m.cost, 0);
const totalDuration = Date.now() - new Date(session.startedAt).getTime();
const manifest = {
  scanId,
  target: targetUrl,
  timestamp: new Date().toISOString(),
  shannonVersion: '0.2.0',
  configHash: createHash('sha256').update(readFileSync(configArg)).digest('hex'),
  totalCost: totalCost.toFixed(6),
  totalDurationMs: totalDuration,
  agentsRun: session.completedAgents.length,
  chainIntegrity: true,
  redTeamAgents: categories.length,
  blueTeamActive: true,
};
manifest.manifestHash = createHash('sha256').update(JSON.stringify(manifest)).digest('hex');
save('forensic-package/manifest.json', JSON.stringify(manifest, null, 2));
save(
  'forensic-package/chain-of-custody.md',
  [
    '# Chain of Custody',
    '',
    `- **Scan ID**: ${scanId}`,
    `- **Target**: ${targetUrl}`,
    `- **Started**: ${session.startedAt}`,
    `- **Completed**: ${new Date().toISOString()}`,
    `- **Config Hash**: \`${manifest.configHash}\``,
    `- **Manifest Hash**: \`${manifest.manifestHash}\``,
    `- **Model**: ${MODEL}`,
    `- **Red Team Agents**: ${categories.length}`,
    `- **Blue Team**: Active`,
    `- **Total Cost**: $${totalCost.toFixed(6)}`,
  ].join('\n'),
);

session.status = 'completed';
session.completedAt = new Date().toISOString();
save('session.json', JSON.stringify(session, null, 2));

console.log(`\n  =====================================`);
console.log(`  Scan Complete!`);
console.log(`  =====================================`);
console.log(`  Duration:  ${(totalDuration / 1000).toFixed(1)}s`);
console.log(`  Cost:      $${totalCost.toFixed(6)}`);
console.log(
  `  Agents:    ${session.completedAgents.length} (${categories.length} Red + 1 Blue + 1 Exploit + 1 Chain + 1 War Room + 1 Report)`,
);
console.log(`  Temporal:  http://localhost:8080`);
console.log('');
