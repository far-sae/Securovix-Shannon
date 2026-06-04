#!/usr/bin/env node
/**
 * Shannon Purple Engine — REAL exploit + REAL defense, then report.
 *
 *   EXPLOIT  In-house deterministic probers run in HARDENED docker sandboxes against the
 *            target. A finding is only recorded when the prober confirms it with a benign
 *            proof marker (SSTI 13*17->221, canary leak, etc.) — zero false positives.
 *   DEFEND   For each CONFIRMED exploit: (1) a concrete detection rule (WAF/SIEM signature)
 *            + LLM-written remediation, and (2) for payload-based classes, a LIVE inline
 *            filtering reverse-proxy that re-runs the exploit and proves it is now BLOCKED.
 *   REPORT   A combined attack/defense report (markdown + JSON), plus broker findings +
 *            compliance written where the dashboard already surfaces them.
 *
 * Usage:  node purple-engine.mjs --target https://example.com --label mysite [--workspace DIR]
 *         node purple-engine.mjs --lab ssti        # demo against the built-in SSTI lab
 */

import { execFile, execFileSync } from 'node:child_process';
import http from 'node:http';
import https from 'node:https';
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

// ---- env (.env is gitignored; process.env may not have the key) ----
function loadEnv() {
  try {
    for (const line of readFileSync(join(import.meta.dirname, '.env'), 'utf-8').split(/\r?\n/)) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)$/);
      if (m && !process.env[m[1]]) process.env[m[1]] = m[2].trim();
    }
  } catch {
    /* no .env */
  }
}

// ---- compliance map (mirrors packages/worker/src/compliance/mapper.ts) ----
const COMPLIANCE = {
  'rce-ssti': { owasp: 'A03:2021-Injection', cwe: 'CWE-1336', mitre: ['TA0002', 'TA0003'] },
  'authz-bypass': { owasp: 'A01:2021-Broken Access Control', cwe: 'CWE-285', mitre: ['TA0004', 'TA0005'] },
  'token-forgery': {
    owasp: 'A07:2021-Identification and Authentication Failures',
    cwe: 'CWE-347',
    mitre: ['TA0001', 'TA0006'],
  },
  'graphql-idor': { owasp: 'A01:2021-Broken Access Control', cwe: 'CWE-639', mitre: ['TA0007', 'TA0009'] },
  'rce-deser': { owasp: 'A08:2021-Software and Data Integrity Failures', cwe: 'CWE-502', mitre: ['TA0002', 'TA0003'] },
  'prompt-injection': { owasp: 'OWASP-LLM01:2025-Prompt Injection', cwe: 'CWE-1427', mitre: ['TA0001', 'TA0002'] },
};

// ---- per-class prober + inline-filter registry ----
// If the caller already placed the INJECT marker at the injectable position, honor it;
// otherwise best-effort append ?q=INJECT (a guess for unknown targets).
const withMarker = (b) => (b.includes('INJECT') ? b : `${b}${b.includes('?') ? '&' : '?'}q=INJECT`);
const CLASSES = {
  'rce-ssti': {
    image: 'shannon-ssti-probe:local',
    bin: 'ssti-probe',
    url: withMarker,
    blockable: true,
    filter: (u, body) => /\{\{.*\}\}|\$\{.*\}|#\{.*\}/.test(decodeURIComponent(u) + (body || '')),
  },
  'prompt-injection': {
    image: 'shannon-pi-probe:local',
    bin: 'pi-probe',
    url: (b) => b,
    blockable: true,
    filter: (u, body) =>
      /ignore\s+(previous|prior|all)\s+instructions|reveal.*(system\s+)?prompt/i.test(
        decodeURIComponent(u) + (body || ''),
      ),
  },
  'graphql-idor': {
    image: 'shannon-graphql-probe:local',
    bin: 'graphql-probe',
    url: (b) => b,
    blockable: true,
    filter: (u, body) => /__schema|IntrospectionQuery|__type/i.test(decodeURIComponent(u) + (body || '')),
  },
  'authz-bypass': { image: 'shannon-idor-probe:local', bin: 'idor-probe', url: withMarker, blockable: false },
  'token-forgery': { image: 'shannon-jwt-probe:local', bin: 'jwt-probe', url: (b) => b, blockable: false },
  'rce-deser': { image: 'shannon-deser-probe:local', bin: 'deser-probe', url: (b) => b, blockable: false },
};

const SANDBOX = [
  '--rm',
  '--cap-drop=ALL',
  '--security-opt=no-new-privileges',
  '--read-only',
  '--tmpfs',
  '/tmp',
  '--user',
  '65534:65534',
  '--memory',
  '512m',
  '--cpus',
  '1',
  '--pids-limit',
  '256',
  '--add-host=host.docker.internal:host-gateway',
];

function docker(args, opts = {}) {
  return execFileSync('docker', args, { stdio: 'pipe', timeout: 60_000, ...opts }).toString();
}
function imageExists(ref) {
  try {
    docker(['image', 'inspect', ref]);
    return true;
  } catch {
    return false;
  }
}

function parseFindings(stdout, c, targetUrl) {
  const findings = [];
  for (const line of (stdout || '').split(/\r?\n/)) {
    const t = line.trim();
    if (!t.startsWith('{')) continue;
    try {
      const o = JSON.parse(t);
      findings.push({
        tool: c.bin,
        severity: o.info?.severity || 'high',
        target: o.host || targetUrl,
        detail: o.info?.name || o['template-id'] || 'finding',
        raw: t,
      });
    } catch {
      /* not a finding line */
    }
  }
  return findings;
}

function proberArgv(cls, targetUrl, network) {
  const c = CLASSES[cls];
  return [
    'run',
    '--name',
    `sx-tool-${randomUUID().slice(0, 8)}`,
    '--network',
    network,
    ...SANDBOX,
    c.image,
    c.bin,
    c.url(targetUrl),
  ];
}

// Sync runner — used in the EXPLOIT phase (no in-process server needs the event loop).
function runProber(cls, targetUrl, network = 'bridge') {
  let stdout = '';
  try {
    stdout = docker(proberArgv(cls, targetUrl, network));
  } catch (e) {
    stdout = e.stdout ? e.stdout.toString() : '';
  }
  return parseFindings(stdout, CLASSES[cls], targetUrl);
}

// Async runner — REQUIRED for the inline re-test: the filtering proxy lives in THIS process,
// so blocking the event loop with execFileSync would starve it and the prober would hang.
function runProberAsync(cls, targetUrl, network = 'bridge') {
  return new Promise((resolve) => {
    execFile(
      'docker',
      proberArgv(cls, targetUrl, network),
      { timeout: 60_000, maxBuffer: 10 * 1024 * 1024 },
      (_err, stdout) => resolve(parseFindings(stdout, CLASSES[cls], targetUrl)),
    );
  });
}

// Live inline filtering reverse-proxy: forwards to `origin`, but returns 403 when the
// class's payload filter matches the request. Proves the mitigation actually blocks.
function startProxy(origin, filter, onBlock) {
  const o = new URL(origin);
  const agent = o.protocol === 'https:' ? https : http;
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (d) => {
      body += d;
    });
    req.on('end', () => {
      if (filter(req.url, body)) {
        onBlock();
        res.writeHead(403, { 'content-type': 'text/plain' });
        res.end('Blocked by Shannon WAF rule');
        return;
      }
      const fwd = agent.request(
        {
          hostname: o.hostname,
          port: o.port || (o.protocol === 'https:' ? 443 : 80),
          path: req.url,
          method: req.method,
          headers: { ...req.headers, host: o.host },
          timeout: 10_000,
        },
        (up) => {
          res.writeHead(up.statusCode || 502, up.headers);
          up.pipe(res);
        },
      );
      fwd.on('error', () => {
        res.writeHead(502);
        res.end('upstream error');
      });
      if (body) fwd.write(body);
      fwd.end();
    });
  });
  return new Promise((resolve) => server.listen(0, '0.0.0.0', () => resolve({ server, port: server.address().port })));
}

async function llmRemediation(target, cls, finding) {
  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) return null;
  const { default: Anthropic } = await import('@anthropic-ai/sdk');
  const client = new Anthropic({ apiKey: key, maxRetries: 3, timeout: 120_000 });
  const model = process.env.SHANNON_MODEL || 'claude-opus-4-7';
  const r = await client.messages.create({
    model,
    max_tokens: 900,
    messages: [
      {
        role: 'user',
        content:
          `A ${cls} vulnerability was CONFIRMED by exploitation on ${target}.\nEvidence: ${finding.detail}\nRaw: ${finding.raw}\n\n` +
          `Write a concise blue-team defense for THIS specific confirmed finding:\n` +
          `1. Root cause (1-2 sentences).\n2. Code remediation (concrete, with a short snippet).\n` +
          `3. A detection signature (WAF or SIEM rule) to catch this attack.\nKeep it under 200 words. Markdown.`,
      },
    ],
  });
  return r.content
    .filter((b) => b.type === 'text')
    .map((b) => b.text)
    .join('\n');
}

// Deterministic detection rule (always available, even without an LLM key).
function detectionRule(cls) {
  switch (cls) {
    case 'rce-ssti':
      return 'WAF: deny requests where any parameter matches /\\{\\{.*\\}\\}|\\$\\{.*\\}|#\\{.*\\}/ (template metacharacters).';
    case 'prompt-injection':
      return 'WAF/LLM-guard: deny inputs matching /ignore (previous|all) instructions|reveal.*(system )?prompt/i; isolate system prompt from user input.';
    case 'graphql-idor':
      return 'GraphQL: disable introspection in production; deny queries containing __schema/__type; enforce field-level authorization.';
    case 'authz-bypass':
      return 'Enforce object-level authorization on every record access (check owner/tenant); deny cross-identity object references.';
    case 'token-forgery':
      return 'JWT: reject alg=none and algorithm downgrades; pin the expected algorithm; verify signature with a strong server-side key.';
    case 'rce-deser':
      return 'Never deserialize untrusted input with pickle/native deserializers; use signed/whitelisted formats (JSON) only.';
    default:
      return 'Apply input validation and least-privilege controls.';
  }
}

export async function runExploitDefend({ target, classes, label, network = 'bridge', workspaceDir, proxyOrigin }) {
  // The inline proxy runs on the HOST, so it forwards to a host-reachable origin (e.g.
  // 127.0.0.1:port for a published lab); the prober (in a container) reaches both the real
  // target and the proxy via host.docker.internal. For external targets they're identical.
  proxyOrigin = proxyOrigin || target;
  loadEnv();
  const ws = workspaceDir;
  const log = (m) => console.log(`  ${m}`);
  const report = { target, label, startedAt: new Date().toISOString(), exploits: [], defenses: [] };

  log(`\n=== EXPLOIT phase — ${classes.length} class(es) against ${target} ===`);
  for (const cls of classes) {
    if (!CLASSES[cls] || !imageExists(CLASSES[cls].image)) {
      log(`- ${cls}: prober image missing, skipped`);
      continue;
    }
    const findings = runProber(cls, target, network);
    mkdirSync(join(ws, 'broker', cls), { recursive: true });
    writeFileSync(join(ws, 'broker', cls, 'findings.json'), JSON.stringify(findings, null, 2));
    if (findings.length) {
      const rows = findings.map((f) => ({
        ...COMPLIANCE[cls],
        category: cls,
        severity: f.severity,
        endpoint: f.target,
      }));
      const owaspCoverage = {},
        cweCoverage = {};
      for (const r of rows) {
        owaspCoverage[r.owasp] = (owaspCoverage[r.owasp] || 0) + 1;
        cweCoverage[r.cwe] = (cweCoverage[r.cwe] || 0) + 1;
      }
      writeFileSync(
        join(ws, 'broker', cls, 'compliance.json'),
        JSON.stringify({ owaspCoverage, cweCoverage, rows }, null, 2),
      );
      log(`- ${cls}: EXPLOITED — ${findings.length} confirmed (${findings[0].detail})`);
    } else {
      log(`- ${cls}: no confirmed exploit (correct zero-FP result)`);
    }
    report.exploits.push({ cls, confirmed: findings.length, findings });
  }

  const confirmed = report.exploits.filter((e) => e.confirmed > 0);
  log(`\n=== DEFEND phase — ${confirmed.length} confirmed finding-class(es) ===`);
  for (const e of confirmed) {
    for (const finding of e.findings) {
      const cls = e.cls;
      const rule = detectionRule(cls);
      let remediation = null;
      try {
        remediation = await llmRemediation(target, cls, finding);
      } catch (err) {
        log(`  (remediation LLM error: ${err.message})`);
      }

      // Live inline blocker + re-prove for payload-filterable classes.
      let inline = { applicable: CLASSES[cls].blockable, blocked: null };
      if (CLASSES[cls].blockable) {
        let blockHit = false;
        const { server, port } = await startProxy(proxyOrigin, CLASSES[cls].filter, () => {
          blockHit = true;
        });
        try {
          const tu = new URL(target);
          const proxyUrl = `http://host.docker.internal:${port}${tu.pathname}${tu.search}`;
          const after = await runProberAsync(cls, proxyUrl, network);
          inline.blocked = after.length === 0 && blockHit;
          log(
            `- ${cls}: defense rule built; inline re-test => ${inline.blocked ? 'BLOCKED ✅ (mitigation proven)' : 'still reachable ⚠'}`,
          );
        } finally {
          server.close();
        }
      } else {
        log(`- ${cls}: defense rule + remediation built (not payload-inline-blockable — requires code/authz fix)`);
      }

      const def = { cls, finding: finding.detail, detectionRule: rule, remediation, inline };
      report.defenses.push(def);
      mkdirSync(join(ws, 'defense', cls), { recursive: true });
      writeFileSync(join(ws, 'defense', cls, 'defense.json'), JSON.stringify(def, null, 2));
      writeFileSync(
        join(ws, 'defense', cls, 'defense.md'),
        `# Defense — ${cls}\n\n**Confirmed exploit:** ${finding.detail}\n\n**Detection rule:** ${rule}\n\n` +
          `**Inline block re-test:** ${inline.applicable ? (inline.blocked ? 'BLOCKED (mitigation proven live)' : 'not blocked') : 'n/a (not payload-blockable)'}\n\n` +
          `## Remediation\n\n${remediation || '_(no LLM key — see detection rule above)_'}\n`,
      );
    }
  }

  // Combined report
  report.completedAt = new Date().toISOString();
  mkdirSync(join(ws, 'purple'), { recursive: true });
  writeFileSync(join(ws, 'purple', 'exploit-defend.json'), JSON.stringify(report, null, 2));
  const md = [
    `# Purple Engine — Exploit + Defend`,
    ``,
    `**Target:** ${target}`,
    `**Run:** ${report.startedAt}`,
    ``,
    `## Confirmed exploits (${confirmed.reduce((s, e) => s + e.confirmed, 0)})`,
    confirmed.length
      ? confirmed.map((e) => `- **${e.cls}** — ${e.findings.map((f) => f.detail).join('; ')}`).join('\n')
      : '_None confirmed (zero false positives)._',
    ``,
    `## Defenses`,
    report.defenses.length
      ? report.defenses
          .map(
            (d) =>
              `### ${d.cls}\n- **Detection:** ${d.detectionRule}\n- **Inline block:** ${d.inline.applicable ? (d.inline.blocked ? '✅ proven blocked live' : '⚠ not blocked') : 'n/a'}\n\n${d.remediation || ''}`,
          )
          .join('\n\n')
      : '_No confirmed findings to defend._',
  ].join('\n');
  writeFileSync(join(ws, 'purple', 'exploit-defend-report.md'), md);
  log(`\n=== REPORT written to ${join(ws, 'purple', 'exploit-defend-report.md')} ===`);
  return report;
}

// ---- CLI ----
const isMain = process.argv[1] && process.argv[1].endsWith('purple-engine.mjs');
if (isMain) {
  const arg = (n) => {
    const i = process.argv.indexOf(n);
    return i >= 0 ? process.argv[i + 1] : undefined;
  };
  const lab = arg('--lab');
  const allClasses = Object.keys(CLASSES);
  (async () => {
    if (lab) {
      // Demo against a built-in lab (guaranteed vulnerable).
      const LAB = { ssti: { img: 'shannon-lab-ssti:local', cls: 'rce-ssti', port: 5000 } }[lab];
      if (!LAB) {
        console.error(`unknown lab: ${lab}`);
        process.exit(1);
      }
      const name = `sx-lab-${randomUUID().slice(0, 6)}`;
      const net = `sx-net-${randomUUID().slice(0, 6)}`;
      const ws = join(import.meta.dirname, 'workspaces', `purple-lab-${randomUUID().slice(0, 6)}`);
      mkdirSync(ws, { recursive: true });
      try {
        docker(['network', 'create', net]);
      } catch {}
      const hostPort = 5099;
      docker(['run', '-d', '--name', name, '--network', net, '-p', `${hostPort}:${LAB.port}`, LAB.img]);
      await new Promise((r) => setTimeout(r, 3000));
      try {
        await runExploitDefend({
          target: `http://host.docker.internal:${hostPort}/?name=INJECT`,
          proxyOrigin: `http://127.0.0.1:${hostPort}`,
          classes: [LAB.cls],
          label: `lab-${lab}`,
          network: 'bridge',
          workspaceDir: ws,
        });
      } finally {
        try {
          docker(['rm', '-f', name]);
        } catch {}
        try {
          docker(['network', 'rm', net]);
        } catch {}
      }
    } else {
      const target = arg('--target');
      if (!target) {
        console.error('usage: --target <url> | --lab ssti');
        process.exit(1);
      }
      const ws = join(import.meta.dirname, 'workspaces', `purple-${randomUUID().slice(0, 6)}`);
      mkdirSync(ws, { recursive: true });
      await runExploitDefend({
        target,
        classes: allClasses,
        label: arg('--label') || 'target',
        network: 'bridge',
        workspaceDir: ws,
      });
    }
  })().catch((e) => {
    console.error('purple-engine failed:', e);
    process.exit(1);
  });
}
