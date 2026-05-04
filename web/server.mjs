import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Anthropic from '@anthropic-ai/sdk';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, 'public');
const PORT = Number(process.env.PORT) || 3000;
const MODEL = process.env.RBSCAN_MODEL || 'claude-opus-4-7';

const LICENSES = new Map([
  ['RBSCAN-FREE-DEMO-2026',  { plan: 'free',  label: 'Free',       dailyLimit: 3   }],
  ['RBSCAN-PRO-DEMO-2026',   { plan: 'pro',   label: 'Pro',        dailyLimit: 100 }],
  ['RBSCAN-TEAM-DEMO-2026',  { plan: 'team',  label: 'Team',       dailyLimit: -1  }],
]);

const tokens = new Map();
const today = () => new Date().toISOString().slice(0, 10);
const newToken = () =>
  'rbtok_' + Math.random().toString(36).slice(2, 10) + Date.now().toString(36);

const SYSTEM_PROMPT = `You are a dual-mode source-code security analyzer that runs both Red Team (offensive) and Blue Team (defensive) passes over the user's submitted code.

RED TEAM job: enumerate every security flaw, bug, logic error, injection vector, authn/authz gap, data exposure, race condition, crypto misuse, dependency risk, or unsafe pattern in the code. For each, give severity, category, the relevant line numbers, a clear description, and a concrete proof-of-concept exploit (payload, request, or attack steps).

BLUE TEAM job: produce a fully patched version of the same code that fixes EVERY red-team finding while preserving the original public behavior. Explain each patch and tie it back to the finding IDs.

Respond with ONLY a single JSON object inside a \`\`\`json code fence. Schema:

{
  "language": "string (detected language)",
  "overallRisk": "critical" | "high" | "medium" | "low" | "clean",
  "redTeam": {
    "summary": "1-3 sentence executive summary of the attack surface",
    "findings": [
      {
        "id": "F1",
        "severity": "critical" | "high" | "medium" | "low" | "info",
        "category": "string (e.g. 'SQL Injection', 'Broken Access Control')",
        "title": "string",
        "description": "string",
        "lines": [12, 13],
        "exploit": "string (concrete PoC: payload, curl, or attack steps)"
      }
    ]
  },
  "blueTeam": {
    "summary": "1-3 sentence summary of the defensive strategy",
    "fixedCode": "string (the FULL corrected source code, ready to paste back)",
    "patches": [
      {
        "findingIds": ["F1"],
        "description": "what changed",
        "rationale": "why this resolves the finding"
      }
    ]
  }
}

Rules:
- If the code is clean, return overallRisk "clean" with an empty findings array and the original code as fixedCode.
- "fixedCode" MUST be the complete file, not a diff or snippet.
- Every patch must reference at least one finding id.
- Do not include any prose outside the JSON code fence.`;

function send(res, status, body, headers = {}) {
  const isString = typeof body === 'string' || Buffer.isBuffer(body);
  const payload = isString ? body : JSON.stringify(body);
  res.writeHead(status, {
    'content-type': isString ? (headers['content-type'] || 'text/plain') : 'application/json',
    'cache-control': 'no-store',
    ...headers,
  });
  res.end(payload);
}

async function readJson(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const text = Buffer.concat(chunks).toString('utf8');
  if (!text) return {};
  try { return JSON.parse(text); } catch { throw new Error('invalid json body'); }
}

function authToken(req) {
  const h = req.headers['authorization'] || '';
  const m = /^Bearer\s+(.+)$/i.exec(h);
  if (!m) return null;
  return tokens.get(m[1]) || null;
}

async function handleActivate(req, res) {
  const { key } = await readJson(req);
  const license = LICENSES.get(String(key || '').trim().toUpperCase());
  if (!license) return send(res, 402, { ok: false, error: 'Invalid or unpaid license key. Please subscribe.' });
  const token = newToken();
  tokens.set(token, {
    key,
    plan: license.plan,
    label: license.label,
    dailyLimit: license.dailyLimit,
    used: 0,
    day: today(),
  });
  return send(res, 200, {
    ok: true,
    token,
    plan: license.plan,
    label: license.label,
    dailyLimit: license.dailyLimit,
    used: 0,
  });
}

async function handleScan(req, res) {
  const session = authToken(req);
  if (!session) return send(res, 401, { ok: false, error: 'Subscription required. Activate a license to scan.' });
  if (session.day !== today()) { session.day = today(); session.used = 0; }
  if (session.dailyLimit !== -1 && session.used >= session.dailyLimit) {
    return send(res, 429, { ok: false, error: `Daily scan limit reached for the ${session.label} plan. Upgrade to keep scanning.` });
  }

  const { code, filename } = await readJson(req);
  if (!code || typeof code !== 'string') return send(res, 400, { ok: false, error: 'Provide source code in the "code" field.' });
  if (code.length > 60_000) return send(res, 413, { ok: false, error: 'Code exceeds 60KB. Trim it before scanning.' });

  if (!process.env.ANTHROPIC_API_KEY) {
    return send(res, 500, { ok: false, error: 'Server is missing ANTHROPIC_API_KEY env var.' });
  }

  let result;
  try {
    const client = new Anthropic();
    const resp = await client.messages.create({
      model: MODEL,
      max_tokens: 16000,
      system: [{ type: 'text', text: SYSTEM_PROMPT, cache_control: { type: 'ephemeral' } }],
      messages: [{
        role: 'user',
        content: `Analyze this source code${filename ? ` (file: ${filename})` : ''}:\n\n<code>\n${code}\n</code>`,
      }],
    });
    const text = resp.content
      .filter((b) => b.type === 'text')
      .map((b) => b.text)
      .join('\n');
    const fence = text.match(/```json\s*([\s\S]+?)\s*```/);
    const raw = fence ? fence[1] : text;
    result = JSON.parse(raw);
  } catch (err) {
    return send(res, 502, { ok: false, error: `Analyzer failed: ${err instanceof Error ? err.message : String(err)}` });
  }

  session.used += 1;
  return send(res, 200, {
    ok: true,
    plan: session.plan,
    label: session.label,
    used: session.used,
    dailyLimit: session.dailyLimit,
    result,
  });
}

async function handleSession(req, res) {
  const session = authToken(req);
  if (!session) return send(res, 401, { ok: false });
  if (session.day !== today()) { session.day = today(); session.used = 0; }
  return send(res, 200, {
    ok: true,
    plan: session.plan,
    label: session.label,
    used: session.used,
    dailyLimit: session.dailyLimit,
  });
}

async function serveStatic(req, res) {
  const url = req.url === '/' ? '/index.html' : req.url.split('?')[0];
  const safe = path.normalize(url).replace(/^([/\\])+/, '');
  const file = path.join(PUBLIC_DIR, safe);
  if (!file.startsWith(PUBLIC_DIR)) return send(res, 403, 'forbidden');
  try {
    const data = await fs.readFile(file);
    const ext = path.extname(file).toLowerCase();
    const types = { '.html': 'text/html; charset=utf-8', '.js': 'application/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' };
    return send(res, 200, data, { 'content-type': types[ext] || 'application/octet-stream' });
  } catch {
    return send(res, 404, 'not found');
  }
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'POST' && req.url === '/api/activate') return handleActivate(req, res);
    if (req.method === 'POST' && req.url === '/api/scan') return handleScan(req, res);
    if (req.method === 'GET'  && req.url === '/api/session') return handleSession(req, res);
    if (req.method === 'GET') return serveStatic(req, res);
    return send(res, 405, 'method not allowed');
  } catch (err) {
    return send(res, 500, { ok: false, error: err instanceof Error ? err.message : String(err) });
  }
});

server.listen(PORT, () => {
  console.log(`RedBlue Scan listening on http://localhost:${PORT}`);
  console.log(`Demo license keys (paywall stand-in):`);
  for (const [k, v] of LICENSES) console.log(`  ${v.label.padEnd(5)} -> ${k}  (limit: ${v.dailyLimit === -1 ? 'unlimited' : v.dailyLimit}/day)`);
  if (!process.env.ANTHROPIC_API_KEY) {
    console.log('\n  WARNING: ANTHROPIC_API_KEY not set. Activation works, but scans will fail.');
  }
});
