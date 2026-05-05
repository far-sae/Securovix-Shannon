import express from 'express';
import { readFileSync, writeFileSync, existsSync, readdirSync, mkdirSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { parse as parseYaml } from 'yaml';
import { spawn } from 'node:child_process';
import Anthropic from '@anthropic-ai/sdk';
import os from 'node:os';
import _crypto from 'node:crypto';
import { initDb, loadUsers, saveUsers, loadLeaderboard, saveLeaderboard, isSupabase } from './db.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..', '..');
const WORKSPACES = join(ROOT, 'workspaces');
const SHANNON_HOME = join(os.homedir(), '.shannon');
const LEADERBOARD_PATH = join(SHANNON_HOME, 'leaderboard.json');
const SETTINGS_PATH = join(ROOT, '.shannon-settings.json');
const PORT = process.env.PORT || 3000;

const app = express();
// Railway / Vercel / any reverse proxy: trust the X-Forwarded-* headers so
// req.protocol correctly reports "https" (not "http"). Without this the
// Google OAuth redirect URI is built with http://, which Google rejects.
app.set('trust proxy', 1);
app.use(express.json({ limit: '2mb' }));
// `extensions: ['html']` lets us serve `/terms` from `terms.html` etc.
app.use(express.static(join(__dirname, 'public'), { extensions: ['html'] }));

const runningScans = new Map();

// ============================================================
// Auth — local accounts (email/password + Google OAuth scaffold)
// User store: ~/.shannon/users.json. Sessions: HMAC-signed cookies.
// ============================================================
const USERS_PATH = join(SHANNON_HOME, 'users.json');
const SESSION_SECRET_PATH = join(SHANNON_HOME, '.session-secret');
function ensureSessionSecret() {
  try {
    if (!existsSync(SHANNON_HOME)) mkdirSync(SHANNON_HOME, { recursive: true });
    if (existsSync(SESSION_SECRET_PATH)) return readFileSync(SESSION_SECRET_PATH, 'utf-8').trim();
    const s = _crypto.randomBytes(32).toString('hex');
    writeFileSync(SESSION_SECRET_PATH, s);
    return s;
  } catch { return _crypto.randomBytes(32).toString('hex'); }
}
const SESSION_SECRET = process.env.SHANNON_SESSION_SECRET || ensureSessionSecret();
const SESSION_TTL_DAYS = 30;

// Two-tier plan system:
//   starter — free, includes Dashboard + New Scan (no Code Scan access)
//   pro     — £15/mo or £120/yr, adds the multi-LLM Code Scan war room
const PLAN_LIMITS = { starter: 0, pro: -1 };
const PLAN_LABELS = { starter: 'Starter', pro: 'Pro' };
const PLAN_PRICING = {
  starter: { monthly: 0,  yearly: 0,   currency: 'GBP' },
  pro:     { monthly: 15, yearly: 120, currency: 'GBP' },
};
const PLAN_FEATURES = {
  starter: ['Dashboard', 'New Scan (web pentest)', 'Settings & API keys'],
  pro:     ['Everything in Starter', 'Code Scan (multi-LLM war room)', 'Unlimited code scans', 'Findings + patches + report'],
};

// loadUsers / saveUsers now provided by db.mjs (Supabase or JSON-file backend).
function findUserByEmail(email) {
  const users = loadUsers();
  return Object.values(users).find(u => u.email === String(email || '').toLowerCase()) || null;
}
function hashPassword(pwd, salt) {
  const s = salt || _crypto.randomBytes(16).toString('hex');
  const h = _crypto.pbkdf2Sync(pwd, s, 120000, 32, 'sha256').toString('hex');
  return { hash: h, salt: s };
}
function verifyPassword(pwd, hash, salt) {
  const { hash: h } = hashPassword(pwd, salt);
  try { return _crypto.timingSafeEqual(Buffer.from(h, 'hex'), Buffer.from(hash, 'hex')); } catch { return false; }
}
function signSession(userId) {
  const payload = JSON.stringify({ uid: userId, iat: Date.now() });
  const b64 = Buffer.from(payload).toString('base64url');
  const sig = _crypto.createHmac('sha256', SESSION_SECRET).update(b64).digest('base64url');
  return b64 + '.' + sig;
}
function verifySession(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [b64, sig] = token.split('.');
  const expected = _crypto.createHmac('sha256', SESSION_SECRET).update(b64).digest('base64url');
  if (expected.length !== sig.length) return null;
  try {
    if (!_crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig))) return null;
    const payload = JSON.parse(Buffer.from(b64, 'base64url').toString());
    if (Date.now() - payload.iat > SESSION_TTL_DAYS * 86400_000) return null;
    return payload;
  } catch { return null; }
}
function parseCookies(req) {
  const c = req.headers.cookie || '';
  const out = {};
  for (const part of c.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
function setSessionCookie(res, userId) {
  const token = signSession(userId);
  res.setHeader('Set-Cookie', `shannon_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL_DAYS * 86400}`);
}
function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', 'shannon_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
}
function getUser(req) {
  const session = verifySession(parseCookies(req).shannon_session);
  if (!session) return null;
  const users = loadUsers();
  return users[session.uid] || null;
}
function publicUser(u) {
  if (!u) return null;
  return {
    id: u.id, email: u.email, name: u.name, picture: u.picture || null,
    googleLinked: !!u.googleId,
    subscription: u.subscription || null,
    createdAt: u.createdAt,
  };
}
function todayKey() { return new Date().toISOString().slice(0, 10); }

// --- Routes
app.get('/api/auth/me', (req, res) => {
  const u = getUser(req);
  // Always send googleConfigured — the login screen (401 path) needs it to
  // decide whether to enable the "Continue with Google" button.
  const googleConfigured = !!process.env.GOOGLE_CLIENT_ID;
  if (!u) return res.status(401).json({ ok: false, googleConfigured });
  res.json({ ok: true, user: publicUser(u), googleConfigured });
});

app.post('/api/auth/signup', (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  const name = String(req.body?.name || '').trim() || email.split('@')[0];
  // Terms + Privacy consent — required for legal record.
  if (!req.body?.acceptedTerms) return res.status(400).json({ error: 'You must accept the Terms of Service and Privacy Policy.' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  if (findUserByEmail(email)) return res.status(409).json({ error: 'An account with that email already exists.' });
  const users = loadUsers();
  const id = _crypto.randomBytes(8).toString('hex');
  const { hash, salt } = hashPassword(password);
  const acceptedAt = Number(req.body?.acceptedAt) || Date.now();
  users[id] = {
    id, email, name, passwordHash: hash, salt,
    createdAt: Date.now(),
    subscription: null,
    // Legal consent record — captured at signup time per UK GDPR Art. 7(1).
    consent: {
      termsVersion: '2026-05-04',
      privacyVersion: '2026-05-04',
      acceptedAt,
      ip: (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '').toString().split(',')[0].trim(),
      userAgent: String(req.headers['user-agent'] || '').slice(0, 240),
    },
  };
  saveUsers(users);
  setSessionCookie(res, id);
  res.json({ ok: true, user: publicUser(users[id]) });
});

app.post('/api/auth/login', (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  const u = findUserByEmail(email);
  if (!u || !u.passwordHash || !verifyPassword(password, u.passwordHash, u.salt)) {
    return res.status(401).json({ error: 'Wrong email or password.' });
  }
  setSessionCookie(res, u.id);
  res.json({ ok: true, user: publicUser(u) });
});

app.post('/api/auth/logout', (req, res) => { clearSessionCookie(res); res.json({ ok: true }); });

// Google OAuth — requires GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET env vars
app.get('/auth/google', (req, res) => {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  if (!clientId) return res.status(500).send('Google OAuth not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET env vars before restarting the server.');
  const redirectUri = `${req.protocol}://${req.get('host')}/auth/google/callback`;
  const url = 'https://accounts.google.com/o/oauth2/v2/auth?' + new URLSearchParams({
    client_id: clientId, redirect_uri: redirectUri, response_type: 'code',
    scope: 'openid email profile', access_type: 'online', prompt: 'select_account',
  });
  res.redirect(url);
});

app.get('/auth/google/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).send('Missing code.');
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  if (!clientId || !clientSecret) return res.status(500).send('Google OAuth not configured.');
  const redirectUri = `${req.protocol}://${req.get('host')}/auth/google/callback`;
  try {
    const tokenResp = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ code: String(code), client_id: clientId, client_secret: clientSecret, redirect_uri: redirectUri, grant_type: 'authorization_code' }),
    });
    const td = await tokenResp.json();
    if (!tokenResp.ok) throw new Error(td.error_description || td.error || 'token exchange failed');
    const userResp = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', { headers: { authorization: 'Bearer ' + td.access_token } });
    const profile = await userResp.json();
    if (!userResp.ok || !profile.email) throw new Error('userinfo failed');
    const users = loadUsers();
    let user = Object.values(users).find(u => u.googleId === profile.sub) || findUserByEmail(profile.email);
    if (!user) {
      const id = _crypto.randomBytes(8).toString('hex');
      user = { id, email: profile.email.toLowerCase(), name: profile.name || profile.email, picture: profile.picture || null, googleId: profile.sub, createdAt: Date.now(), subscription: null };
      users[id] = user;
    } else {
      if (!user.googleId) user.googleId = profile.sub;
      if (!user.picture && profile.picture) user.picture = profile.picture;
    }
    saveUsers(users);
    setSessionCookie(res, user.id);
    res.redirect('/');
  } catch (e) {
    res.status(500).send('Google sign-in failed: ' + e.message);
  }
});

// Subscription — mock checkout (real Stripe integration goes here later)
app.post('/api/auth/subscribe', (req, res) => {
  const u = getUser(req);
  if (!u) return res.status(401).json({ error: 'Login required.' });
  const plan = String(req.body?.plan || '');
  const cycle = req.body?.cycle === 'yearly' ? 'yearly' : 'monthly';
  if (!PLAN_LIMITS.hasOwnProperty(plan)) return res.status(400).json({ error: 'Invalid plan.' });
  const users = loadUsers();
  const pricing = PLAN_PRICING[plan];
  const renewsAt = plan === 'starter'
    ? null
    : Date.now() + (cycle === 'yearly' ? 365 : 30) * 86400_000;
  users[u.id].subscription = {
    plan, label: PLAN_LABELS[plan],
    dailyLimit: PLAN_LIMITS[plan],
    cycle,
    priceGbp: pricing[cycle],
    currency: pricing.currency,
    startedAt: Date.now(),
    renewsAt,
    used: 0, day: todayKey(),
  };
  saveUsers(users);
  res.json({ ok: true, user: publicUser(users[u.id]) });
});

app.get('/api/auth/plans', (_req, res) => {
  res.json({
    plans: Object.keys(PLAN_LIMITS).map(p => ({
      plan: p,
      label: PLAN_LABELS[p],
      pricing: PLAN_PRICING[p],
      features: PLAN_FEATURES[p],
      dailyLimit: PLAN_LIMITS[p],
    })),
  });
});

app.post('/api/auth/cancel', (req, res) => {
  const u = getUser(req);
  if (!u) return res.status(401).json({ error: 'Login required.' });
  const users = loadUsers();
  users[u.id].subscription = null;
  saveUsers(users);
  res.json({ ok: true, user: publicUser(users[u.id]) });
});

// ============================================================
// Code Scan (Red Team vs Blue Team) — owner bypass + paywall
// ============================================================
const CS_OWNER_DISABLED = process.env.SHANNON_OWNER_BYPASS === '0';
const CS_OWNER_USAGE = { used: 0, day: '' };
const csToday = () => new Date().toISOString().slice(0, 10);

function csIsLocalhost(req) {
  if (CS_OWNER_DISABLED) return false;
  const a = req.socket?.remoteAddress || '';
  return a === '::1' || a === '127.0.0.1' || a === '::ffff:127.0.0.1';
}

// Code Scan access — FREE FOR ALL.
// Subscription gating removed: every request gets an unlimited session.
// Logged-in users keep their userId so per-user usage stats still tally,
// anonymous users get an "owner" pseudo-session with no daily cap.
function csSession(req) {
  const u = getUser(req);
  if (u) {
    return {
      isOwner: false, userId: u.id, user: u,
      plan: 'free', label: 'Free',
      dailyLimit: -1, used: 0,
    };
  }
  if (CS_OWNER_USAGE.day !== csToday()) { CS_OWNER_USAGE.day = csToday(); CS_OWNER_USAGE.used = 0; }
  return { isOwner: true, plan: 'free', label: 'Free', dailyLimit: -1, used: CS_OWNER_USAGE.used };
}
function csIncrementUserUsage(userId) {
  const users = loadUsers();
  if (!users[userId]?.subscription) return;
  users[userId].subscription.used = (users[userId].subscription.used || 0) + 1;
  users[userId].subscription.day = csToday();
  saveUsers(users);
}

const CS_SYSTEM_PROMPT = `You are a dual-mode source-code security analyzer that runs both a Red Team (offensive) and a Blue Team (defensive) pass over the user's submitted code.

RED TEAM job: enumerate every security flaw, bug, logic error, injection vector, authn/authz gap, data exposure, race condition, crypto misuse, dependency risk, or unsafe pattern. For each, give severity, category, the relevant line numbers, a clear description, and a concrete proof-of-concept exploit (payload, request, or attack steps).

BLUE TEAM job: produce a fully patched version of the same code that fixes EVERY red-team finding while preserving the original public behavior. Explain each patch and tie it to finding IDs.

Respond with ONLY a single JSON object inside a \`\`\`json code fence. Schema:
{
  "language": "string",
  "overallRisk": "critical" | "high" | "medium" | "low" | "clean",
  "redTeam": {
    "summary": "string",
    "findings": [
      { "id": "F1", "severity": "critical"|"high"|"medium"|"low"|"info", "category": "string", "title": "string", "description": "string", "lines": [int], "exploit": "string" }
    ]
  },
  "blueTeam": {
    "summary": "string",
    "fixedCode": "string (FULL corrected source code)",
    "patches": [ { "findingIds": ["F1"], "description": "string", "rationale": "string" } ]
  }
}

Rules:
- "fixedCode" MUST be the complete file, not a diff.
- If the code is clean, return overallRisk "clean", an empty findings array, and the original code as fixedCode.
- Every patch must reference at least one finding id.
- Output ONLY the JSON code fence — no prose before or after.`;

app.get('/api/code-scan/me', (req, res) => {
  const u = getUser(req);
  const s = csSession(req);
  if (!s) {
    return res.json({
      subscribed: false,
      isOwner: false,
      authed: !!u,
      user: publicUser(u),
    });
  }
  return res.json({
    subscribed: true,
    authed: !!u,
    user: publicUser(u),
    isOwner: s.isOwner,
    plan: s.plan, label: s.label,
    used: s.used, dailyLimit: s.dailyLimit,
  });
});

// ============================================================
// Multi-Agent War Room (Red×2 vs Blue×2 across providers)
// ============================================================
// Provider catalogue — endpoints, default models, base capability scores.
// Scores update from each scan's output (see updateLeaderboard).
// Defaults to the latest generation (May 2026):
//   Anthropic: Claude Opus 4.7
//   OpenAI:    GPT-5
//   Google:    Gemini 2.5 Pro
//   Zhipu:     GLM-4-Plus  (latest stable)
const CS_PROVIDERS = {
  claude: { label: 'Claude Opus 4.7',  short: 'C', color: '#e26847', model: 'claude-opus-4-7',  base: 96 },
  openai: { label: 'GPT-5',            short: 'G', color: '#10a37f', model: 'gpt-5',            base: 94 },
  gemini: { label: 'Gemini 2.5 Pro',   short: 'g', color: '#5b94c4', model: 'gemini-2.5-pro',   base: 90 },
  glm:    { label: 'GLM-4-Plus',       short: 'Z', color: '#88b3a8', model: 'glm-4-plus',       base: 80 },
};
const CS_ROLES = [
  { id: 'r1', team: 'red',  name: 'Red Lead' },
  { id: 'r2', team: 'red',  name: 'Red Operator' },
  { id: 'b1', team: 'blue', name: 'Blue Architect' },
  { id: 'b2', team: 'blue', name: 'Blue Engineer' },
];

// Leaderboard load/save — thin aliases to db.mjs (Supabase or JSON fallback).
const csLoadLeaderboard = loadLeaderboard;
const csSaveLeaderboard = saveLeaderboard;
function csProviderScore(p) {
  const lb = csLoadLeaderboard();
  return lb[p]?.score ?? CS_PROVIDERS[p]?.base ?? 70;
}
function csUpdateLeaderboard(p, deltaScore, ms, chars, opts = {}) {
  const lb = csLoadLeaderboard();
  const stats = lb[p] || { score: CS_PROVIDERS[p]?.base ?? 70, runs: 0, wins: 0, totalMs: 0, totalChars: 0 };
  stats.score = Math.max(0, Math.min(100, +(stats.score + deltaScore).toFixed(2)));
  stats.runs += 1;
  stats.totalMs += ms || 0;
  stats.totalChars += chars || 0;
  if (opts.win) stats.wins += 1;
  stats.lastRun = Date.now();
  lb[p] = stats;
  csSaveLeaderboard(lb);
}

// Score a single turn's output (no fallback bonus, length & success bonus, errors penalised)
function csQualityDelta(text, fallback, errored) {
  if (errored) return -8;
  if (fallback) return -4;  // didn't run on the agent's native provider
  const len = (text || '').length;
  let q = 0.4;              // base credit for completing the turn
  if (len > 200) q += 0.4;
  if (len > 800) q += 0.6;
  if (len > 2000) q += 0.6;
  return Math.min(2.0, q);  // cap per-turn delta
}

// Auto-pick agents from the provider keys the user supplied, ranked by leaderboard score.
// Top score → Red Lead, then Red Operator, Blue Architect, Blue Engineer.
function csPickAgents(keys) {
  // Provider is "available" if it has its own key, OR is claude (which is always the fallback).
  const eligible = Object.keys(CS_PROVIDERS).filter(p => p === 'claude' ? !!keys?.claude : !!keys?.[p]);
  if (!eligible.includes('claude')) eligible.unshift('claude'); // claude must be present as fallback
  const ranked = [...eligible].sort((a, b) => csProviderScore(b) - csProviderScore(a));
  // Build a pool of 4 (repeat top providers if fewer than 4 keys are available)
  const pool = [];
  for (let i = 0; i < 4; i++) pool.push(ranked[i % ranked.length]);
  return CS_ROLES.map((role, i) => {
    const p = pool[i];
    const meta = CS_PROVIDERS[p];
    return {
      ...role,
      provider: p,
      model: meta.model,
      label: `${role.name} — ${meta.label}`,
      short: meta.short,
      color: meta.color,
      score: csProviderScore(p),
    };
  });
}

const CS_PHASES = [
  { id: 'red-recon',  agentId: 'r1', step: 'Red Lead surveys the attack surface' },
  { id: 'red-cross',  agentId: 'r2', step: 'Red Operator cross-checks findings, adds new vectors' },
  { id: 'blue-defend',agentId: 'b1', step: 'Blue Architect drafts patches' },
  { id: 'blue-harden',agentId: 'b2', step: 'Blue Engineer hardens patches' },
  { id: 'red-bypass', agentId: 'r1', step: 'Red Lead probes for patch bypasses' },
  { id: 'blue-final', agentId: 'b1', step: 'Blue Architect addresses bypasses' },
  { id: 'synth',      agentId: 'b2', step: 'Synthesize fixed code & full report' },
];

async function csCallProvider(provider, model, system, user, keys, maxTokens) {
  // The synthesis turn must hold the full fixed source code + markdown report, so we
  // bump max tokens for that turn. Earlier turns stay lean.
  const mt = maxTokens || 4000;
  if (provider === 'claude') {
    const apiKey = keys?.claude;
    if (!apiKey) throw new Error('No Anthropic API key supplied');
    const client = new Anthropic({ apiKey });
    const resp = await client.messages.create({
      model: model || 'claude-opus-4-7',
      max_tokens: mt,
      system,
      messages: [{ role: 'user', content: user }],
    });
    return (resp.content || []).filter(b => b.type === 'text').map(b => b.text).join('\n');
  }
  if (provider === 'openai') {
    if (!keys?.openai) throw new Error('No OpenAI key supplied');
    const r = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: { 'authorization': 'Bearer ' + keys.openai, 'content-type': 'application/json' },
      body: JSON.stringify({
        model: model || 'gpt-5',
        messages: [{ role: 'system', content: system }, { role: 'user', content: user }],
        max_tokens: mt, temperature: 0.4,
      }),
    });
    const j = await r.json();
    if (!r.ok) throw new Error(j.error?.message || `OpenAI HTTP ${r.status}`);
    return j.choices?.[0]?.message?.content || '';
  }
  if (provider === 'gemini') {
    if (!keys?.gemini) throw new Error('No Gemini key supplied');
    const m = model || 'gemini-2.5-pro';
    const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(m)}:generateContent?key=${encodeURIComponent(keys.gemini)}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: system }] },
        contents: [{ role: 'user', parts: [{ text: user }] }],
        generationConfig: { maxOutputTokens: mt, temperature: 0.4 },
      }),
    });
    const j = await r.json();
    if (!r.ok) throw new Error(j.error?.message || `Gemini HTTP ${r.status}`);
    return j.candidates?.[0]?.content?.parts?.map(p => p.text || '').join('') || '';
  }
  if (provider === 'glm') {
    if (!keys?.glm) throw new Error('No GLM key supplied');
    const r = await fetch('https://open.bigmodel.cn/api/paas/v4/chat/completions', {
      method: 'POST',
      headers: { 'authorization': 'Bearer ' + keys.glm, 'content-type': 'application/json' },
      body: JSON.stringify({
        model: model || 'glm-4-plus',
        messages: [{ role: 'system', content: system }, { role: 'user', content: user }],
        max_tokens: mt, temperature: 0.4,
      }),
    });
    const j = await r.json();
    if (!r.ok) throw new Error(j.error?.message || `GLM HTTP ${r.status}`);
    return j.choices?.[0]?.message?.content || '';
  }
  throw new Error('Unknown provider: ' + provider);
}

async function csCallAgent(agent, system, user, keys, maxTokens) {
  try {
    const text = await csCallProvider(agent.provider, agent.model, system, user, keys, maxTokens);
    return { text, fallback: false };
  } catch (err) {
    if (agent.provider === 'claude') throw err;
    const fbSystem = system + `\n\n[FALLBACK ROLEPLAY: The "${agent.label}" provider failed (${err.message}). Continue in-character as ${agent.label} but execute on Anthropic.]`;
    const text = await csCallProvider('claude', null, fbSystem, user, keys, maxTokens);
    return { text, fallback: true, fallbackReason: err.message };
  }
}

function csBuildSystem(agent, phase, isFinalSynth) {
  const role = agent.team === 'red' ? 'OFFENSIVE security researcher' : 'DEFENSIVE security engineer';
  const teamGoal = agent.team === 'red'
    ? 'Red Team — find every flaw and produce concrete exploits'
    : 'Blue Team — patch every flaw without breaking original behavior';
  let txt = `You are ${agent.label}, an ${role} in a multi-agent code-security war room. Your team: ${teamGoal}.

You will see a running transcript of every other agent's contribution. Address peers by name. Build on or critique their work — DO NOT repeat what others have said.

Keep your turn under ~600 words. Be concrete: name lines, name attack vectors, name patches.`;
  if (isFinalSynth) {
    txt += `

THIS IS THE FINAL SYNTHESIS TURN. Produce a single JSON object inside a \`\`\`json fence with this schema:
{
  "language": "string",
  "overallRisk": "critical"|"high"|"medium"|"low"|"clean",
  "redTeam": {
    "summary": "string",
    "findings": [ {"id":"F1","severity":"critical|high|medium|low|info","category":"string","title":"string","description":"string","lines":[int],"exploit":"string"} ]
  },
  "blueTeam": {
    "summary": "string",
    "fixedCode": "FULL corrected source code (complete file, not a diff)",
    "patches": [ {"findingIds":["F1"],"description":"string","rationale":"string"} ]
  },
  "report": "Markdown executive report covering: ## Summary, ## Findings (per finding with severity & PoC), ## Patch Strategy, ## Risk Assessment, ## Recommendations, ## Agent Collaboration Notes."
}

Consolidate everything from the transcript. Output ONLY the JSON fence — no prose outside it.`;
  }
  return txt;
}

function csBuildUser(code, filename, transcript, phase, isFinalSynth) {
  let u = `=== Source code under review${filename ? ` (file: ${filename})` : ''} ===\n<code>\n${code}\n</code>\n\n`;
  if (transcript.length > 0) {
    u += `=== War-room transcript so far ===\n`;
    for (const t of transcript) {
      const trim = t.text.length > 4000 ? t.text.slice(0, 4000) + '\n…(truncated)' : t.text;
      u += `\n--- [${t.label} · ${t.step}] ---\n${trim}\n`;
    }
  }
  u += `\n\n=== YOUR TURN ===\nStep: ${phase.step}\n`;
  u += isFinalSynth
    ? `Produce the final JSON deliverable per the system prompt schema. Consolidate all prior turns into definitive findings, patches, fixedCode, and a markdown report.`
    : `Contribute NEW analysis specific to this step. Reference peers by name. Be concrete.`;
  return u;
}

// Robust extractor for the final synthesis turn.
// Models occasionally truncate their output (no closing ``` fence, or the JSON itself
// gets cut off mid-string). When that happens, the strict JSON.parse fails and we used
// to drop the entire result on the floor — including the corrected code the user came
// for. This helper tries multiple strategies in order:
//   1. Strict parse of the ```json fence (happy path)
//   2. Strict parse of the largest {...} block we can find
//   3. String-level extraction of "fixedCode": "..." with proper escape handling
// On a partial recovery we return { _partial: true, ...recoveredFields } so the UI can
// show a yellow banner and STILL surface a Download fixed file button.
function csParseSynthesis(text) {
  if (!text) return { error: 'No synthesis text', raw: '' };

  // Strategy 1: ```json fenced block, optionally without closing fence (truncated).
  let body = null;
  const closed = text.match(/```json\s*([\s\S]+?)\s*```/);
  if (closed) {
    body = closed[1];
  } else {
    const open = text.match(/```json\s*([\s\S]+)$/);
    if (open) body = open[1].replace(/```\s*$/, '');
  }
  if (!body) {
    // No fence at all — try to pull the outermost JSON object from the raw text.
    const s = text.indexOf('{'), e = text.lastIndexOf('}');
    if (s >= 0 && e > s) body = text.slice(s, e + 1);
    else body = text;
  }

  // Strategy 2: strict parse on whatever we extracted.
  try {
    const obj = JSON.parse(body);
    return obj;
  } catch { /* fall through to salvage */ }

  // Strategy 2b: trim from the last balanced } and try again.
  const lastBrace = body.lastIndexOf('}');
  if (lastBrace > 0) {
    try {
      const obj = JSON.parse(body.slice(0, lastBrace + 1));
      return obj;
    } catch { /* fall through */ }
  }

  // Strategy 3: salvage individual fields with string-level extraction.
  // The big one is "fixedCode" — that's the file the user actually wants.
  const recovered = { _partial: true, raw: text.slice(0, 12000) };

  const fixedCode = csExtractStringField(body, 'fixedCode');
  if (fixedCode) {
    recovered.blueTeam = recovered.blueTeam || {};
    recovered.blueTeam.fixedCode = fixedCode;
  }
  const language = csExtractStringField(body, 'language');
  if (language) recovered.language = language;
  const overallRisk = csExtractStringField(body, 'overallRisk');
  if (overallRisk) recovered.overallRisk = overallRisk;
  const redSummary = csExtractStringField(body, 'summary'); // first occurrence — likely redTeam.summary
  if (redSummary) {
    recovered.redTeam = recovered.redTeam || {};
    recovered.redTeam.summary = redSummary;
  }
  // Try to grab the findings array even if truncated.
  const findings = csExtractFindingsArray(body);
  if (findings.length) {
    recovered.redTeam = recovered.redTeam || {};
    recovered.redTeam.findings = findings;
  }
  // If salvage gave us absolutely nothing useful, fall back to the original parse-error shape.
  if (!recovered.blueTeam?.fixedCode && !recovered.redTeam?.findings?.length) {
    return { error: 'Failed to parse final synthesis (no recoverable fields)', raw: text.slice(0, 12000) };
  }
  return recovered;
}

// Extract a single JSON string-field value from text, properly handling escaped quotes
// and backslashes. Returns null if not found or unterminated.
function csExtractStringField(text, fieldName) {
  const re = new RegExp('"' + fieldName + '"\\s*:\\s*"', 'g');
  const m = re.exec(text);
  if (!m) return null;
  let i = m.index + m[0].length;
  let out = '';
  while (i < text.length) {
    const c = text[i];
    if (c === '\\' && i + 1 < text.length) {
      const n = text[i + 1];
      // Standard JSON escapes
      if (n === 'n') out += '\n';
      else if (n === 't') out += '\t';
      else if (n === 'r') out += '\r';
      else if (n === '"') out += '"';
      else if (n === '\\') out += '\\';
      else if (n === '/') out += '/';
      else if (n === 'b') out += '\b';
      else if (n === 'f') out += '\f';
      else if (n === 'u' && i + 5 < text.length) {
        try { out += String.fromCharCode(parseInt(text.slice(i + 2, i + 6), 16)); i += 4; } catch { out += n; }
      } else out += n;
      i += 2;
    } else if (c === '"') {
      return out;
    } else {
      out += c;
      i++;
    }
  }
  // Unterminated — return what we got. Better partial code than nothing.
  return out || null;
}

// Best-effort extraction of the findings array from a possibly-truncated synthesis.
function csExtractFindingsArray(text) {
  const m = text.match(/"findings"\s*:\s*\[/);
  if (!m) return [];
  // Walk forward, collecting balanced { ... } objects until we hit ] or run out.
  let i = m.index + m[0].length;
  const out = [];
  while (i < text.length) {
    while (i < text.length && /\s|,/.test(text[i])) i++;
    if (text[i] === ']' || i >= text.length) break;
    if (text[i] !== '{') break;
    // Find matching closing brace, respecting strings + escapes.
    let depth = 0, j = i, inStr = false, escNext = false;
    for (; j < text.length; j++) {
      const c = text[j];
      if (escNext) { escNext = false; continue; }
      if (c === '\\') { escNext = true; continue; }
      if (c === '"') { inStr = !inStr; continue; }
      if (inStr) continue;
      if (c === '{') depth++;
      else if (c === '}') { depth--; if (depth === 0) { j++; break; } }
    }
    if (depth !== 0) break; // truncated — stop salvaging
    const raw = text.slice(i, j);
    try { out.push(JSON.parse(raw)); } catch { /* skip malformed finding */ }
    i = j;
  }
  return out;
}

const csRuns = new Map();
const CS_RUN_TTL_MS = 30 * 60 * 1000;
setInterval(() => {
  const now = Date.now();
  for (const [k, r] of csRuns) if (r.endedAt && now - r.endedAt > CS_RUN_TTL_MS) csRuns.delete(k);
}, 5 * 60 * 1000).unref?.();

function csBc(run, ev) {
  run.events.push(ev);
  const msg = `data: ${JSON.stringify(ev)}\n\n`;
  run.sseClients = run.sseClients.filter(c => { try { c.write(msg); return true; } catch { return false; } });
}

async function csOrchestrate(runId) {
  const run = csRuns.get(runId);
  if (!run) return;
  const keys = run.keys || {};
  const agents = csPickAgents(keys);
  run.agents = agents;

  csBc(run, { type: 'agents', agents });
  csBc(run, { type: 'phases', phases: CS_PHASES });
  csBc(run, { type: 'lineup', summary: agents.map(a => `${a.name}: ${CS_PROVIDERS[a.provider].label} (score ${a.score.toFixed(1)})`).join(' · ') });

  for (let i = 0; i < CS_PHASES.length; i++) {
    if (run.cancelled) { csBc(run, { type: 'cancelled' }); break; }
    const phase = CS_PHASES[i];
    const agent = agents.find(a => a.id === phase.agentId);
    const isFinalSynth = i === CS_PHASES.length - 1;
    csBc(run, { type: 'phase-start', phaseIndex: i, phaseId: phase.id, agentId: agent.id, label: agent.label, team: agent.team, step: phase.step, provider: agent.provider });

    const sys = csBuildSystem(agent, phase, isFinalSynth);
    const user = csBuildUser(run.code, run.filename, run.transcript, phase, isFinalSynth);

    let text = '', fallback = false, fbReason, errored = false;
    const t0 = Date.now();
    // The synthesis turn carries the full fixed source code + markdown report, so it
    // needs a much larger output budget than the analytical turns. 16k keeps us safe
    // for typical files (~2k LOC) without blowing past provider per-call caps.
    const maxTokens = isFinalSynth ? 16000 : 4000;
    try {
      const r = await csCallAgent(agent, sys, user, keys, maxTokens);
      text = r.text; fallback = r.fallback; fbReason = r.fallbackReason;
    } catch (err) {
      errored = true;
      // Penalise the provider that failed and abort the run
      csUpdateLeaderboard(agent.provider, csQualityDelta('', false, true), Date.now() - t0, 0);
      run.status = 'failed';
      run.error = `${agent.label} failed: ${err.message}`;
      run.endedAt = Date.now();
      csBc(run, { type: 'failed', error: run.error, agentId: agent.id });
      return;
    }
    const dt = Date.now() - t0;

    // Update leaderboard for whichever provider actually ran (claude on fallback, agent.provider otherwise)
    const realProvider = fallback ? 'claude' : agent.provider;
    csUpdateLeaderboard(realProvider, csQualityDelta(text, fallback, errored), dt, text.length);

    const turn = {
      phaseIndex: i, phaseId: phase.id, agentId: agent.id, label: agent.label, team: agent.team,
      step: phase.step, text, fallback, fallbackReason: fbReason, provider: agent.provider, realProvider,
      ms: dt, ts: Date.now(),
    };
    run.transcript.push(turn);
    csBc(run, { type: 'turn', ...turn });
  }

  const last = run.transcript[run.transcript.length - 1];
  let result = null;
  if (last) {
    result = csParseSynthesis(last.text);
    // Award a "win" to the provider that produced a fully parseable synthesis (not partial)
    if (result && !result.error && !result._partial) {
      csUpdateLeaderboard(last.realProvider || last.provider, 1.5, 0, 0, { win: true });
    }
  }

  run.result = result;
  run.status = 'complete';
  run.endedAt = Date.now();

  if (run.session?.isOwner) CS_OWNER_USAGE.used += 1;
  else if (run.session?.userId) csIncrementUserUsage(run.session.userId);

  csBc(run, { type: 'complete', result, agents });
}

app.post('/api/code-scan/multi/start', (req, res) => {
  const session = csSession(req);
  if (!session) return res.status(401).json({ ok: false, error: 'Subscription required.' });
  if (session.dailyLimit !== -1 && session.used >= session.dailyLimit) {
    return res.status(429).json({ ok: false, error: `Daily scan limit reached for the ${session.label} plan.` });
  }
  const { code, filename, keys: bodyKeys } = req.body || {};
  if (!code || typeof code !== 'string') return res.status(400).json({ ok: false, error: 'Provide source code.' });
  if (code.length > 1_000_000) return res.status(413).json({ ok: false, error: 'Code exceeds 1MB. Try splitting it into smaller files.' });

  // Browser-supplied keys are the source of truth. Server settings file & env are LEGACY fallbacks only.
  const legacy = loadSettings();
  const keys = {
    claude: bodyKeys?.claude || legacy.apiKey || process.env.ANTHROPIC_API_KEY || '',
    openai: bodyKeys?.openai || legacy.openaiKey || '',
    gemini: bodyKeys?.gemini || legacy.geminiKey || '',
    glm:    bodyKeys?.glm    || legacy.glmKey    || '',
  };
  if (!keys.claude) {
    return res.status(400).json({ ok: false, error: 'Anthropic key required. Add it in Settings → War-Room Provider Keys (stored only in your browser).' });
  }

  const runId = randomUUID().slice(0, 8);
  const sessForRun = session.isOwner ? { isOwner: true } : { isOwner: false, userId: session.userId };

  const run = {
    id: runId, code, filename: filename || null, keys,
    transcript: [], events: [], sseClients: [], agents: [],
    status: 'running', result: null, cancelled: false,
    startedAt: Date.now(), endedAt: null, session: sessForRun,
  };
  csRuns.set(runId, run);

  // Pre-pick agents synchronously so we can return the lineup with the start response.
  const lineup = csPickAgents(keys);
  run.agents = lineup;

  csOrchestrate(runId).catch(err => {
    run.status = 'failed';
    run.error = err.message;
    run.endedAt = Date.now();
    csBc(run, { type: 'failed', error: err.message });
  });

  res.json({ ok: true, runId, agents: lineup, phases: CS_PHASES });
});

app.get('/api/code-scan/multi/:id/events', (req, res) => {
  const run = csRuns.get(req.params.id);
  if (!run) return res.status(404).json({ ok: false, error: 'Run not found' });
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive' });
  for (const ev of run.events) res.write(`data: ${JSON.stringify(ev)}\n\n`);
  if (run.status === 'running') {
    run.sseClients.push(res);
    req.on('close', () => { run.sseClients = run.sseClients.filter(c => c !== res); });
  } else {
    res.end();
  }
});

app.get('/api/code-scan/multi/:id/result', (req, res) => {
  const run = csRuns.get(req.params.id);
  if (!run) return res.status(404).json({ ok: false, error: 'Run not found' });
  res.json({ ok: true, status: run.status, transcript: run.transcript, result: run.result, error: run.error, agents: run.agents || [], phases: CS_PHASES });
});

app.post('/api/code-scan/multi/:id/cancel', (req, res) => {
  const run = csRuns.get(req.params.id);
  if (!run) return res.status(404).json({ ok: false });
  run.cancelled = true;
  res.json({ ok: true });
});

// ============================================================
// Quick scan — single Claude pass per file, no war-room.
// Used by Project mode to scan many files cheaply.
// ============================================================
const QUICK_SYSTEM = `You are a dual-mode source-code security analyzer.

RED TEAM: enumerate every security flaw, bug, logic error, injection vector, authn/authz gap, data exposure, race condition, crypto misuse, or unsafe pattern. For each, provide severity, category, line numbers, a clear description, and a concrete proof-of-concept.

BLUE TEAM: produce a fully patched version of the SAME file that fixes every red-team finding while preserving public behavior. Tie each patch to finding IDs.

Respond with ONLY a single JSON object inside a \`\`\`json fence. Schema:
{
  "language": "string",
  "overallRisk": "critical"|"high"|"medium"|"low"|"clean",
  "redTeam": {
    "summary": "string",
    "findings": [ { "id":"F1","severity":"critical|high|medium|low|info","category":"string","title":"string","description":"string","lines":[int],"exploit":"string" } ]
  },
  "blueTeam": {
    "summary": "string",
    "fixedCode": "string (the COMPLETE corrected file content, not a diff)",
    "patches": [ { "findingIds":["F1"],"description":"string","rationale":"string" } ]
  }
}

Rules:
- fixedCode MUST be the complete file. If clean, return the original code unchanged with overallRisk "clean" and empty findings.
- Output ONLY the JSON code fence — no prose before or after.`;

function extractJsonFence(text) {
  if (!text) return null;
  const fence = text.match(/```(?:json)?\s*([\s\S]+?)\s*```/);
  const raw = fence ? fence[1] : text;
  try { return JSON.parse(raw); } catch { /* try first { ... last } */ }
  const start = raw.indexOf('{'), end = raw.lastIndexOf('}');
  if (start >= 0 && end > start) {
    try { return JSON.parse(raw.slice(start, end + 1)); } catch { return null; }
  }
  return null;
}

async function quickScanFile({ apiKey, code, filename }) {
  const client = new Anthropic({ apiKey });
  const safeFilename = filename || 'snippet.txt';
  const userPrompt = `File: ${safeFilename}\n\n\`\`\`\n${code}\n\`\`\``;
  const r = await client.messages.create({
    model: process.env.SHANNON_QUICK_MODEL || 'claude-sonnet-4-6',
    max_tokens: 8192,
    system: QUICK_SYSTEM,
    messages: [{ role: 'user', content: userPrompt }],
  });
  const text = (r.content || []).filter(b => b.type === 'text').map(b => b.text).join('\n');
  const parsed = extractJsonFence(text);
  if (!parsed) return { ok: false, error: 'Failed to parse model output', raw: text };
  return { ok: true, result: parsed };
}

app.post('/api/code-scan/quick', async (req, res) => {
  const session = csSession(req);
  if (!session) return res.status(401).json({ ok: false, error: 'Subscription required.' });
  if (session.dailyLimit !== -1 && session.used >= session.dailyLimit) {
    return res.status(429).json({ ok: false, error: `Daily scan limit reached for the ${session.label} plan.` });
  }
  const { code, filename, keys: bodyKeys } = req.body || {};
  if (!code || typeof code !== 'string') return res.status(400).json({ ok: false, error: 'Provide source code.' });
  if (code.length > 1_000_000) return res.status(413).json({ ok: false, error: 'File exceeds 1MB.' });

  const legacy = loadSettings();
  const apiKey = bodyKeys?.claude || legacy.apiKey || process.env.ANTHROPIC_API_KEY || '';
  if (!apiKey) return res.status(400).json({ ok: false, error: 'Anthropic key required.' });

  try {
    const out = await quickScanFile({ apiKey, code, filename });
    if (!session.isOwner && session.userId) csIncrementUserUsage(session.userId);
    res.json({ ok: true, ...out });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

// Provider performance leaderboard — drives the auto-pick and lets the user see who's winning.
app.get('/api/code-scan/leaderboard', (req, res) => {
  const lb = csLoadLeaderboard();
  const rows = Object.keys(CS_PROVIDERS).map(p => ({
    provider: p,
    label: CS_PROVIDERS[p].label,
    color: CS_PROVIDERS[p].color,
    short: CS_PROVIDERS[p].short,
    score: lb[p]?.score ?? CS_PROVIDERS[p].base,
    base: CS_PROVIDERS[p].base,
    runs: lb[p]?.runs ?? 0,
    wins: lb[p]?.wins ?? 0,
    avgMs: lb[p]?.runs ? Math.round(lb[p].totalMs / lb[p].runs) : 0,
    avgChars: lb[p]?.runs ? Math.round(lb[p].totalChars / lb[p].runs) : 0,
    lastRun: lb[p]?.lastRun ?? null,
  })).sort((a, b) => b.score - a.score);
  res.json({ ok: true, leaderboard: rows, totalRuns: rows.reduce((a, r) => a + r.runs, 0) });
});

app.post('/api/code-scan/leaderboard/reset', (req, res) => {
  csSaveLeaderboard({});
  res.json({ ok: true });
});

// ---- Settings persistence ----
function loadSettings() {
  if (existsSync(SETTINGS_PATH)) {
    try { return JSON.parse(readFileSync(SETTINGS_PATH, 'utf-8')); } catch { }
  }
  return { apiKey: process.env.ANTHROPIC_API_KEY || '', model: process.env.SHANNON_MODEL || 'claude-opus-4-7', provider: 'anthropic', baseUrl: '' };
}

// Sensitive provider keys MUST NOT be persisted on the server; the browser holds them.
// Strip them from any settings payload before writing to disk.
const KEY_FIELDS = ['apiKey', 'openaiKey', 'geminiKey', 'glmKey'];
function saveSettings(s) {
  const sanitized = { ...s };
  for (const f of KEY_FIELDS) delete sanitized[f];
  writeFileSync(SETTINGS_PATH, JSON.stringify(sanitized, null, 2));
  if (s.model) process.env.SHANNON_MODEL = s.model;
  if (s.baseUrl) process.env.SHANNON_LLM_BASE_URL = s.baseUrl;
}

// Initialize from saved settings
const initSettings = loadSettings();
if (initSettings.apiKey && !process.env.ANTHROPIC_API_KEY) process.env.ANTHROPIC_API_KEY = initSettings.apiKey;
if (initSettings.model) process.env.SHANNON_MODEL = initSettings.model;

// ---- API: Settings ----
// Provider keys are NOT returned here — they live only in the browser's localStorage.
app.get('/api/settings', (req, res) => {
  const s = loadSettings();
  res.json({
    keysStorage: 'browser',
    model: s.model || process.env.SHANNON_MODEL || 'claude-opus-4-7',
    provider: s.provider || 'anthropic',
    baseUrl: s.baseUrl || '',
  });
});

app.post('/api/settings', (req, res) => {
  const current = loadSettings();
  const updated = { ...current, ...req.body };
  saveSettings(updated);
  res.json({ ok: true });
});

// ---- API: List scans (no workspace paths exposed) ----
app.get('/api/scans', (req, res) => {
  if (!existsSync(WORKSPACES)) return res.json([]);
  const scans = readdirSync(WORKSPACES)
    .filter(d => { const p = join(WORKSPACES, d); return statSync(p).isDirectory() && existsSync(join(p, 'session.json')); })
    .map(d => {
      const session = JSON.parse(readFileSync(join(WORKSPACES, d, 'session.json'), 'utf-8'));
      return {
        id: d,
        target: session.target || d,
        status: session.status || 'unknown',
        startedAt: session.startedAt,
        completedAt: session.completedAt,
        agents: session.completedAgents?.length || 0,
        totalCost: Object.values(session.metrics || {}).reduce((s, m) => s + (m.cost || 0), 0),
        hasReport: existsSync(join(WORKSPACES, d, 'report.md')),
      };
    })
    .sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt));
  res.json(scans);
});

// ---- API: Scan details ----
app.get('/api/scans/:id', (req, res) => {
  const wsDir = join(WORKSPACES, req.params.id);
  if (!existsSync(wsDir)) return res.status(404).json({ error: 'Scan not found' });
  const session = existsSync(join(wsDir, 'session.json')) ? JSON.parse(readFileSync(join(wsDir, 'session.json'), 'utf-8')) : {};
  const rd = rel => { const p = join(wsDir, rel); return existsSync(p) ? readFileSync(p, 'utf-8') : null; };
  const files = {
    report: rd('report.md'), preRecon: rd('pre-recon/analysis.md'), recon: rd('recon/exploration.md'),
    httpProbe: rd('pre-recon/http-probe.txt'), chainAnalysis: rd('chain-analysis/analysis.md'),
    warRoom: rd('war-room/transcript.md'), forensicManifest: rd('forensic-package/manifest.json'),
    custody: rd('forensic-package/chain-of-custody.md'),
    redTeamSummary: rd('red-team/summary.md'),
    blueTeam: rd('blue-team/defense-assessment.md'),
    purpleTeam: rd('purple-team/transcript.md'),
    purpleConclusion: rd('purple-team/conclusion.md'),
    exploitVerify: rd('exploit-verify/verification.md'),
    securityHeaders: rd('pre-recon/security-headers.json'),
    vulns: {}, exploits: {},
  };
  for (const cat of ['sqli', 'xss', 'auth-bypass', 'authz-bypass', 'ssrf', 'business-logic', 'misconfig', 'info-disclosure']) {
    files.vulns[cat] = rd(`vuln/${cat}/analysis.md`);
    files.exploits[cat] = rd(`exploit/${cat}/exploit-report.md`);
  }
  res.json({ session, files });
});

// ---- API: Start scan ----
app.post('/api/scans', (req, res) => {
  const { targetUrl, authType, username, password, retryPreset, focusUrls, avoidUrls, apiKey: bodyKey, warRoom, providerKeys } = req.body;
  if (!targetUrl) return res.status(400).json({ error: 'Target URL is required' });
  const settings = loadSettings();
  // Browser-supplied key takes precedence; fall back to env or legacy file for backward compat.
  const apiKey = bodyKey || settings.apiKey || process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return res.status(400).json({ error: 'Anthropic API key required. Add it in Settings → API Keys (browser-only storage).' });

  const scanId = randomUUID().slice(0, 8);
  const config = { target: { url: targetUrl, urls: {} }, pipeline: { retryPreset: retryPreset || 'fast', maxConcurrentPipelines: 3 } };
  if (focusUrls) config.target.urls.focus = focusUrls.split(',').map(s => s.trim()).filter(Boolean);
  if (avoidUrls) config.target.urls.avoid = avoidUrls.split(',').map(s => s.trim()).filter(Boolean);
  if (authType && authType !== 'none') {
    config.authentication = { type: authType };
    if (username) config.authentication.username = username;
    if (password) config.authentication.password = password;
  }
  const configPath = join(ROOT, `scan-${scanId}.yaml`);
  writeFileSync(configPath, yamlDump(config, 0));

  const env = { ...process.env, ANTHROPIC_API_KEY: apiKey, SHANNON_MODEL: settings.model || 'claude-opus-4-7' };
  if (settings.baseUrl) env.SHANNON_LLM_BASE_URL = settings.baseUrl;
  // Multi-LLM war room — when enabled, pass extra provider keys + a flag through env so the scanner's
  // Red/Blue phases can route through the war-room orchestrator. run-scan.mjs reads these opportunistically.
  if (warRoom) {
    env.SHANNON_WAR_ROOM = '1';
    if (providerKeys?.openai) env.OPENAI_API_KEY = providerKeys.openai;
    if (providerKeys?.gemini) env.GOOGLE_API_KEY = providerKeys.gemini;
    if (providerKeys?.glm)    env.ZHIPU_API_KEY  = providerKeys.glm;
  }

  const child = spawn('node', [join(ROOT, 'run-scan.mjs'), '--config', configPath], { cwd: ROOT, env, stdio: ['ignore', 'pipe', 'pipe'] });

  const phasePatterns = [
    { re: /\[Phase 0\]/, id: 'http-recon', name: 'HTTP Recon' },
    { re: /\[Phase 1\]/, id: 'pre-recon', name: 'Pre-Recon' },
    { re: /\[Phase 2\]/, id: 'recon', name: 'Deep Recon' },
    { re: /\[Phase 3\]/, id: 'red-team', name: 'Red Team Attack' },
    { re: /\[Phase 4\]/, id: 'purple-team', name: 'Purple Team (2 Red + 2 Blue)' },
    { re: /\[Phase 5\]/, id: 'exploit-verify', name: 'Exploit Verify' },
    { re: /\[Phase 6\]/, id: 'chain', name: 'Attack Chains' },
    { re: /\[Phase 7\]/, id: 'war-room', name: 'War Room' },
    { re: /\[Phase 8\]/, id: 'report', name: 'Report' },
    { re: /\[Phase 9\]/, id: 'forensic', name: 'Forensic' },
  ];

  const scan = { child, output: '', startedAt: new Date().toISOString(), target: targetUrl, phases: [], currentPhase: null, sseClients: [] };
  runningScans.set(scanId, scan);

  function process_(chunk) {
    scan.output += chunk;
    const line = chunk.toString();
    for (const p of phasePatterns) {
      if (p.re.test(line)) {
        if (scan.currentPhase) { scan.currentPhase.status = 'done'; scan.currentPhase.endedAt = Date.now(); }
        scan.currentPhase = { id: p.id, name: p.name, status: 'running', startedAt: Date.now() };
        scan.phases.push(scan.currentPhase);
        bc(scan, { type: 'phase', phase: p.id, name: p.name, status: 'running' });
      }
    }
    if (/Done \(/.test(line) && scan.currentPhase?.status === 'running') {
      scan.currentPhase.status = 'done';
      scan.currentPhase.endedAt = Date.now();
      const cm = line.match(/\$([0-9.]+)/); if (cm) scan.currentPhase.cost = parseFloat(cm[1]);
      const tm = line.match(/(\d+\.?\d*)s/); if (tm) scan.currentPhase.duration = parseFloat(tm[1]);
      bc(scan, { type: 'phase-done', phase: scan.currentPhase.id, cost: scan.currentPhase.cost, duration: scan.currentPhase.duration });
    }
    if (/Scan Complete/.test(line)) bc(scan, { type: 'complete' });
    bc(scan, { type: 'output', line: line.trim() });
  }

  function bc(scan, data) {
    const msg = `data: ${JSON.stringify(data)}\n\n`;
    scan.sseClients = scan.sseClients.filter(c => { try { c.write(msg); return true; } catch { return false; } });
  }

  child.stdout.on('data', d => process_(d));
  child.stderr.on('data', d => process_(d));
  child.on('close', code => {
    scan.status = code === 0 ? 'completed' : 'failed';
    bc(scan, { type: code === 0 ? 'complete' : 'failed' });
  });

  res.json({ scanId, status: 'started' });
});

// ---- API: Stop scan ----
app.post('/api/scans/:id/stop', (req, res) => {
  const scan = runningScans.get(req.params.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found or already finished' });
  try {
    scan.child.kill('SIGTERM');
    setTimeout(() => { try { scan.child.kill('SIGKILL'); } catch {} }, 3000);
    scan.status = 'stopped';
    bc_ext(scan, { type: 'stopped' });
    res.json({ ok: true, message: 'Scan stopped' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---- API: Mark stale scan as failed ----
app.post('/api/scans/:id/mark-failed', (req, res) => {
  const wsDir = join(WORKSPACES, req.params.id);
  const sessionPath = join(wsDir, 'session.json');
  if (!existsSync(sessionPath)) return res.status(404).json({ error: 'Scan not found' });

  try {
    const session = JSON.parse(readFileSync(sessionPath, 'utf-8'));
    if (session.status === 'completed') return res.json({ ok: true, message: 'Already completed' });
    session.status = 'failed';
    session.completedAt = new Date().toISOString();
    session.failReason = 'Manually stopped — scan process was stale or crashed';
    writeFileSync(sessionPath, JSON.stringify(session, null, 2));
    // Also clean up from running scans map
    runningScans.delete(req.params.id);
    res.json({ ok: true, message: 'Scan marked as failed' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

function bc_ext(scan, data) {
  const msg = `data: ${JSON.stringify(data)}\n\n`;
  scan.sseClients = scan.sseClients.filter(c => { try { c.write(msg); return true; } catch { return false; } });
}

// ---- API: Live status ----
app.get('/api/scans/:id/live', (req, res) => {
  const scan = runningScans.get(req.params.id);
  if (scan) return res.json({ status: scan.status || 'running', output: scan.output, target: scan.target, phases: scan.phases });
  const wsDir = join(WORKSPACES, req.params.id);
  if (existsSync(join(wsDir, 'session.json'))) {
    const session = JSON.parse(readFileSync(join(wsDir, 'session.json'), 'utf-8'));
    return res.json({ status: session.status || 'completed' });
  }
  res.status(404).json({ error: 'Not found' });
});

// ---- SSE ----
app.get('/api/scans/:id/events', (req, res) => {
  const scan = runningScans.get(req.params.id);
  if (!scan) return res.status(404).json({ error: 'Not found' });
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
  for (const phase of scan.phases) {
    res.write(`data: ${JSON.stringify({ type: 'phase', phase: phase.id, name: phase.name, status: phase.status })}\n\n`);
    if (phase.status === 'done') res.write(`data: ${JSON.stringify({ type: 'phase-done', phase: phase.id, cost: phase.cost, duration: phase.duration })}\n\n`);
  }
  scan.sseClients.push(res);
  req.on('close', () => { scan.sseClients = scan.sseClients.filter(c => c !== res); });
});

// ---- API: Available models ----
app.get('/api/models', (req, res) => {
  // Latest available models as of May 2026.
  res.json([
    // Anthropic
    { id: 'claude-opus-4-7',         name: 'Claude Opus 4.7',     tier: 'flagship', desc: 'Most capable Anthropic model — best for deep red-team reasoning' },
    { id: 'claude-sonnet-4-6',       name: 'Claude Sonnet 4.6',   tier: 'large',    desc: 'Fast + capable — strong balance for either side' },
    { id: 'claude-haiku-4-5-20251001', name: 'Claude Haiku 4.5',  tier: 'small',    desc: 'Fastest, lowest cost — ideal for high-volume scans' },
    // OpenAI
    { id: 'gpt-5',                   name: 'GPT-5',               tier: 'flagship', desc: 'OpenAI flagship — broad knowledge, fast all-rounder' },
    { id: 'gpt-5-mini',              name: 'GPT-5 Mini',          tier: 'small',    desc: 'OpenAI cost-efficient tier' },
    { id: 'o3',                      name: 'OpenAI o3',           tier: 'reason',   desc: 'Deep reasoning model — best for chain analysis' },
    { id: 'gpt-4o',                  name: 'GPT-4o (legacy)',     tier: 'large',    desc: 'Previous-gen OpenAI flagship' },
    // Google
    { id: 'gemini-2.5-pro',          name: 'Gemini 2.5 Pro',      tier: 'flagship', desc: 'Huge context window — great for recon + chain analysis' },
    { id: 'gemini-2.5-flash',        name: 'Gemini 2.5 Flash',    tier: 'small',    desc: 'Fast Google tier' },
    // Zhipu
    { id: 'glm-4-plus',              name: 'GLM-4-Plus',          tier: 'large',    desc: 'Zhipu — cost-efficient blue-team workhorse' },
    // Custom
    { id: 'custom',                  name: 'Custom Model',        tier: 'custom',   desc: 'Any model via custom base URL' },
  ]);
});

function yamlDump(obj, indent = 0) {
  const pad = '  '.repeat(indent);
  let out = '';
  for (const [k, v] of Object.entries(obj)) {
    if (v == null) continue;
    if (typeof v === 'object' && !Array.isArray(v)) out += `${pad}${k}:\n${yamlDump(v, indent + 1)}`;
    else if (Array.isArray(v)) { out += `${pad}${k}:\n`; for (const i of v) out += `${pad}  - ${i}\n`; }
    else out += `${pad}${k}: ${v}\n`;
  }
  return out;
}

// Health-check endpoint — Railway will hit this to confirm the container is alive.
app.get('/healthz', (_req, res) => res.json({ ok: true, db: isSupabase() ? 'supabase' : 'fs', uptime: process.uptime() }));

(async () => {
  try {
    await initDb();
  } catch (e) {
    console.error('FATAL: db init failed.', e.message);
    process.exit(1);
  }
  app.listen(PORT, () => console.log(`\n  Securovix Dashboard running at http://localhost:${PORT}\n`));
})();
