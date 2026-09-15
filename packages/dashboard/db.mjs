/* db.mjs — persistence for users + leaderboard.
 *
 * Two backends, picked automatically by env vars:
 *   1. Supabase (production)  — set SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY
 *   2. Local JSON files (dev) — falls back to ~/.shannon/*.json
 *
 * The sync load/save API is preserved so nothing in server.mjs needs to change
 * its call style. On boot we hydrate from Supabase into memory once via
 * initDb(); subsequent reads are sync (in-memory), writes update the in-memory
 * cache AND fire-and-forget upsert to Supabase. This is fine for a single
 * Railway instance (typical for early production); add Redis pub/sub or
 * Postgres LISTEN if you ever scale horizontally.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import { join } from 'node:path';

// The engine loads the repo's .env itself (purple-engine.mjs), but the dashboard never did — so
// SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY were absent at runtime and this module silently fell
// back to the local JSON files. The visible symptom was that an already-verified domain looked
// unverified (its record lives in Supabase), so every Defender connect and scan launch was refused.
// This must run BEFORE the config constants below are evaluated; it does, because server.mjs
// imports this module, and an imported module's body is evaluated before the importer's.
// Platform-provided env (Railway) still wins: we never overwrite a variable that is already set.
try {
  for (const line of readFileSync(new URL('../../.env', import.meta.url), 'utf-8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2].trim().replace(/^["']|["']$/g, '');
  }
} catch {
  /* no .env file — env comes from the platform instead */
}

// ---- File-system fallback (and where we write secrets locally) ----
const SHANNON_HOME = join(os.homedir(), '.shannon');
const USERS_PATH = join(SHANNON_HOME, 'users.json');
const LEADERBOARD_PATH = join(SHANNON_HOME, 'leaderboard.json');
const VERIFIED_PATH = join(SHANNON_HOME, 'verified-domains.json');
const RUNS_PATH = join(SHANNON_HOME, 'agent-runs.json');
const MONITORS_PATH = join(SHANNON_HOME, 'monitors.json');
const MAX_RUNS_PER_USER = 50; // keep run history bounded in memory / storage

// ---- Supabase config (only used when both env vars are set) ----
const SUPABASE_URL = (process.env.SUPABASE_URL || '').replace(/\/$/, '');
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY || '';
const USE_SUPABASE = !!(SUPABASE_URL && SUPABASE_KEY);

// In-memory caches — loaded by initDb()
let _users = {};
let _lb = {};
let _verified = {}; // { [userId]: { [domain]: { verifiedAt, method } } }
let _runs = {}; // { [userId]: [ { id, target, createdAt, stats, findings, leads }, … newest first ] }
let _monitors = {}; // { [userId]: [ { id, target, intervalHours, webhookUrl, enabled, lastRunAt, createdAt } ] }
let _ready = false;

function ensureHome() {
  if (!existsSync(SHANNON_HOME)) mkdirSync(SHANNON_HOME, { recursive: true });
}

// ---- Tiny PostgREST helper. No third-party SDK required. ----
async function sb(path, opts = {}) {
  const r = await fetch(SUPABASE_URL + '/rest/v1' + path, {
    ...opts,
    headers: {
      apikey: SUPABASE_KEY,
      authorization: 'Bearer ' + SUPABASE_KEY,
      'content-type': 'application/json',
      prefer: opts.prefer || 'return=representation',
      ...(opts.headers || {}),
    },
  });
  if (!r.ok) {
    const txt = await r.text().catch(() => '');
    throw new Error(`Supabase ${opts.method || 'GET'} ${path} → ${r.status}: ${txt.slice(0, 240)}`);
  }
  if (r.status === 204) return null;
  return r.json().catch(() => null);
}

// ---- Row shape mapping (snake_case in DB ↔ camelCase in app) ----
function userFromRow(r) {
  if (!r) return null;
  return {
    id: r.id,
    email: r.email,
    name: r.name,
    passwordHash: r.password_hash || undefined,
    salt: r.salt || undefined,
    googleId: r.google_id || undefined,
    picture: r.picture || null,
    subscription: r.subscription || null,
    consent: r.consent || null,
    createdAt: r.created_at ? Number(r.created_at) : Date.now(),
  };
}
function userToRow(u) {
  return {
    id: u.id,
    email: u.email,
    name: u.name || null,
    password_hash: u.passwordHash || null,
    salt: u.salt || null,
    google_id: u.googleId || null,
    picture: u.picture || null,
    subscription: u.subscription || null,
    consent: u.consent || null,
    created_at: u.createdAt || Date.now(),
  };
}

// ---- Public API ----
export async function initDb() {
  if (USE_SUPABASE) {
    console.log('[db] Using Supabase →', SUPABASE_URL);
    try {
      const userRows = await sb('/shannon_users?select=*');
      _users = {};
      for (const r of userRows || []) _users[r.id] = userFromRow(r);
      const lbRows = await sb('/shannon_leaderboard?select=*');
      _lb = {};
      for (const r of lbRows || []) {
        _lb[r.provider] = {
          score: Number(r.score),
          runs: r.runs || 0,
          wins: r.wins || 0,
          totalMs: Number(r.total_ms) || 0,
          totalChars: Number(r.total_chars) || 0,
          lastRun: r.last_run ? Number(r.last_run) : null,
        };
      }
      // Non-fatal: if the table isn't created yet, start with empty verifications instead of
      // crashing the whole server (the table is created by the verified_domains migration).
      let vRows = [];
      try {
        vRows = await sb('/shannon_verified_domains?select=*');
      } catch (e) {
        console.warn('[db] verified_domains hydrate skipped (run the migration?):', e.message);
        vRows = [];
      }
      _verified = {};
      for (const r of vRows || []) {
        if (!_verified[r.user_id]) _verified[r.user_id] = {};
        _verified[r.user_id][r.domain] = { verifiedAt: r.verified_at || null, method: r.method || null };
      }
      // Non-fatal: agent-run history table may not exist yet.
      let runRows = [];
      try {
        runRows = await sb('/shannon_agent_runs?select=*&order=created_at.desc&limit=1000');
      } catch (e) {
        console.warn('[db] agent_runs hydrate skipped (run the migration?):', e.message);
        runRows = [];
      }
      _runs = {};
      for (const r of runRows || []) {
        (_runs[r.user_id] ||= []).push({
          id: r.id,
          target: r.target,
          createdAt: r.created_at ? Number(r.created_at) : Date.now(),
          stats: r.stats || {},
          findings: r.findings || [],
          leads: r.leads || [],
        });
      }
      // Non-fatal: monitors table may not exist yet.
      let monRows = [];
      try {
        monRows = await sb('/shannon_monitors?select=*');
      } catch (e) {
        console.warn('[db] monitors hydrate skipped (run the migration?):', e.message);
        monRows = [];
      }
      _monitors = {};
      for (const r of monRows || []) {
        (_monitors[r.user_id] ||= []).push({
          id: r.id,
          target: r.target,
          intervalHours: r.interval_hours ? Number(r.interval_hours) : 24,
          webhookUrl: r.webhook_url || null,
          enabled: r.enabled !== false,
          lastRunAt: r.last_run_at ? Number(r.last_run_at) : 0,
          createdAt: r.created_at ? Number(r.created_at) : Date.now(),
        });
      }
      console.log(
        `[db] Hydrated ${Object.keys(_users).length} users · ${Object.keys(_lb).length} providers · ${vRows?.length || 0} verified domains · ${runRows?.length || 0} agent runs · ${monRows?.length || 0} monitors from Supabase`,
      );
    } catch (e) {
      console.error('[db] Supabase hydration FAILED — server cannot start safely:', e.message);
      throw e;
    }
  } else {
    console.log('[db] Using local JSON files in', SHANNON_HOME);
    try {
      _users = JSON.parse(readFileSync(USERS_PATH, 'utf-8'));
    } catch {
      _users = {};
    }
    try {
      _lb = JSON.parse(readFileSync(LEADERBOARD_PATH, 'utf-8'));
    } catch {
      _lb = {};
    }
    try {
      _verified = JSON.parse(readFileSync(VERIFIED_PATH, 'utf-8'));
    } catch {
      _verified = {};
    }
    try {
      _runs = JSON.parse(readFileSync(RUNS_PATH, 'utf-8'));
    } catch {
      _runs = {};
    }
    try {
      _monitors = JSON.parse(readFileSync(MONITORS_PATH, 'utf-8'));
    } catch {
      _monitors = {};
    }
  }
  _ready = true;
}

// ---- Continuous-monitoring schedules ----
function persistMonitors() {
  if (USE_SUPABASE) return; // Supabase writes happen per-op below
  try {
    ensureHome();
    writeFileSync(MONITORS_PATH, JSON.stringify(_monitors, null, 2));
  } catch (e) {
    console.error('[db] monitors local write failed:', e.message);
  }
}
function monitorToRow(userId, m) {
  return {
    id: m.id,
    user_id: userId,
    target: m.target || null,
    interval_hours: m.intervalHours || 24,
    webhook_url: m.webhookUrl || null,
    enabled: m.enabled !== false,
    last_run_at: m.lastRunAt || 0,
    created_at: m.createdAt || Date.now(),
  };
}
export function saveMonitor(userId, m) {
  if (!userId || !m?.id) return;
  (_monitors[userId] ||= []).unshift(m);
  if (USE_SUPABASE) {
    sb('/shannon_monitors', {
      method: 'POST',
      headers: { prefer: 'resolution=merge-duplicates,return=minimal' },
      body: JSON.stringify([monitorToRow(userId, m)]),
    }).catch((e) => console.error('[db] monitor save failed:', e.message));
  } else persistMonitors();
}
export function listMonitors(userId) {
  return _monitors[userId] || [];
}
export function getMonitor(userId, id) {
  return (_monitors[userId] || []).find((m) => m.id === id) || null;
}
export function removeMonitor(userId, id) {
  if (_monitors[userId]) _monitors[userId] = _monitors[userId].filter((m) => m.id !== id);
  if (USE_SUPABASE) {
    sb(`/shannon_monitors?id=eq.${encodeURIComponent(id)}&user_id=eq.${encodeURIComponent(userId)}`, {
      method: 'DELETE',
      headers: { prefer: 'return=minimal' },
    }).catch((e) => console.error('[db] monitor delete failed:', e.message));
  } else persistMonitors();
}
export function touchMonitor(userId, id, lastRunAt) {
  const m = getMonitor(userId, id);
  if (!m) return;
  m.lastRunAt = lastRunAt;
  if (USE_SUPABASE) {
    sb(`/shannon_monitors?id=eq.${encodeURIComponent(id)}`, {
      method: 'PATCH',
      headers: { prefer: 'return=minimal' },
      body: JSON.stringify({ last_run_at: lastRunAt }),
    }).catch((e) => console.error('[db] monitor touch failed:', e.message));
  } else persistMonitors();
}
// Flat list of every monitor with its owner attached — for the scheduler.
export function allMonitors() {
  const out = [];
  for (const [userId, list] of Object.entries(_monitors)) for (const m of list) out.push({ ...m, userId });
  return out;
}

// ---- Agent run history (regression tracking) ----
// rec = { id, target, createdAt, stats, findings, leads }. Newest-first, capped per user.
export function saveAgentRun(userId, rec) {
  if (!userId || !rec?.id) return;
  const list = (_runs[userId] ||= []);
  list.unshift(rec);
  if (list.length > MAX_RUNS_PER_USER) list.length = MAX_RUNS_PER_USER;
  if (USE_SUPABASE) {
    sb('/shannon_agent_runs', {
      method: 'POST',
      headers: { prefer: 'return=minimal' },
      body: JSON.stringify([
        {
          id: rec.id,
          user_id: userId,
          target: rec.target || null,
          created_at: rec.createdAt || Date.now(),
          stats: rec.stats || {},
          findings: rec.findings || [],
          leads: rec.leads || [],
        },
      ]),
    }).catch((e) => console.error('[db] agent-run save failed:', e.message));
  } else {
    try {
      ensureHome();
      writeFileSync(RUNS_PATH, JSON.stringify(_runs, null, 2));
    } catch (e) {
      console.error('[db] agent-run local write failed:', e.message);
    }
  }
}

// Summaries (no findings payload) for a user, optionally filtered to one target, newest first.
export function listAgentRuns(userId, target) {
  const list = _runs[userId] || [];
  return list
    .filter((r) => !target || r.target === target)
    .map((r) => ({ id: r.id, target: r.target, createdAt: r.createdAt, stats: r.stats || {} }));
}

export function getAgentRun(userId, id) {
  return (_runs[userId] || []).find((r) => r.id === id) || null;
}

export function isReady() {
  return _ready;
}
export function isSupabase() {
  return USE_SUPABASE;
}

// ---- Users ----
export function loadUsers() {
  return _users;
}

export function saveUsers(u) {
  _users = u;
  if (USE_SUPABASE) {
    const rows = Object.values(u).map(userToRow);
    if (rows.length === 0) return;
    sb('/shannon_users', {
      method: 'POST',
      headers: { prefer: 'resolution=merge-duplicates,return=minimal' },
      body: JSON.stringify(rows),
    }).catch((e) => console.error('[db] users upsert failed:', e.message));
  } else {
    ensureHome();
    writeFileSync(USERS_PATH, JSON.stringify(u, null, 2));
  }
}

// ---- Leaderboard ----
export function loadLeaderboard() {
  return _lb;
}

export function saveLeaderboard(lb) {
  _lb = lb;
  if (USE_SUPABASE) {
    const rows = Object.entries(lb).map(([provider, s]) => ({
      provider,
      score: s.score,
      runs: s.runs || 0,
      wins: s.wins || 0,
      total_ms: s.totalMs || 0,
      total_chars: s.totalChars || 0,
      last_run: s.lastRun || null,
      updated_at: Date.now(),
    }));
    if (rows.length === 0) {
      // Reset case — wipe the table.
      sb('/shannon_leaderboard?provider=neq.__none__', {
        method: 'DELETE',
        headers: { prefer: 'return=minimal' },
      }).catch((e) => console.error('[db] leaderboard wipe failed:', e.message));
      return;
    }
    sb('/shannon_leaderboard', {
      method: 'POST',
      headers: { prefer: 'resolution=merge-duplicates,return=minimal' },
      body: JSON.stringify(rows),
    }).catch((e) => console.error('[db] leaderboard upsert failed:', e.message));
  } else {
    ensureHome();
    writeFileSync(LEADERBOARD_PATH, JSON.stringify(lb, null, 2));
  }
}

// ---- Verified domains (domain-ownership gate; must survive redeploys, unlike the old local file) ----
export function loadVerified() {
  return _verified;
}

export function addVerified(userId, domain, rec = {}) {
  if (!_verified[userId]) _verified[userId] = {};
  _verified[userId][domain] = { verifiedAt: rec.verifiedAt || null, method: rec.method || null };
  if (USE_SUPABASE) {
    sb('/shannon_verified_domains', {
      method: 'POST',
      headers: { prefer: 'resolution=merge-duplicates,return=minimal' },
      body: JSON.stringify([
        { user_id: userId, domain, method: rec.method || null, verified_at: rec.verifiedAt || null },
      ]),
    }).catch((e) => console.error('[db] verified-domain upsert failed:', e.message));
  } else {
    ensureHome();
    writeFileSync(VERIFIED_PATH, JSON.stringify(_verified, null, 2));
  }
}

export function removeVerified(userId, domain) {
  if (_verified[userId]) delete _verified[userId][domain];
  if (USE_SUPABASE) {
    sb(`/shannon_verified_domains?user_id=eq.${encodeURIComponent(userId)}&domain=eq.${encodeURIComponent(domain)}`, {
      method: 'DELETE',
      headers: { prefer: 'return=minimal' },
    }).catch((e) => console.error('[db] verified-domain delete failed:', e.message));
  } else {
    ensureHome();
    writeFileSync(VERIFIED_PATH, JSON.stringify(_verified, null, 2));
  }
}
