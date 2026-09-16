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
const SHANNON_HOME = process.env.SHANNON_DATA_DIR || join(os.homedir(), '.shannon');
const USERS_PATH = join(SHANNON_HOME, 'users.json');
const LEADERBOARD_PATH = join(SHANNON_HOME, 'leaderboard.json');
const VERIFIED_PATH = join(SHANNON_HOME, 'verified-domains.json');
const RUNS_PATH = join(SHANNON_HOME, 'agent-runs.json');
const MONITORS_PATH = join(SHANNON_HOME, 'monitors.json');
const TEAM_PATH = join(SHANNON_HOME, 'team-state.json');
const MAX_RUNS_PER_USER = 50; // keep run history bounded in memory / storage

// ---- Supabase config (only used when both env vars are set) ----
const SUPABASE_URL = (process.env.SUPABASE_URL || '').replace(/\/$/, '');
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY || '';
const USE_SUPABASE = process.env.SHANNON_FORCE_LOCAL_DB !== '1' && !!(SUPABASE_URL && SUPABASE_KEY);

// In-memory caches — loaded by initDb()
let _users = {};
let _lb = {};
let _verified = {}; // { [userId]: { [domain]: { verifiedAt, method } } }
let _runs = {}; // { [userId]: [ { id, target, createdAt, stats, findings, leads }, … newest first ] }
let _monitors = {}; // { [userId]: [ { id, target, intervalHours, webhookUrl, enabled, lastRunAt, createdAt } ] }
let _orgs = {}; // { [orgId]: Organization }
let _memberships = []; // Membership[]
let _projects = {}; // { [orgId]: Project[] }
let _findings = {}; // { [orgId]: Finding[] }
let _audit = {}; // { [orgId]: AuditEvent[] }
let _userSettings = {}; // { [userId]: settings }
let _scanOwners = {}; // { [scanId]: { scanId, orgId, userId, projectId, createdAt } }
let _edgeRoutes = {}; // { [host]: { host, orgId, userId, origin, mode, createdAt } }
let _defenseEvents = {}; // { [orgId]: DefenseEvent[] }
const _orgReady = new Map(); // serializes initial organization + owner membership before FK-dependent writes
let _userWriteReady = Promise.resolve();
let _ready = false;
let _hydratedAt = 0;
let _refreshPromise = null;

function ensureHome() {
  if (!existsSync(SHANNON_HOME)) mkdirSync(SHANNON_HOME, { recursive: true });
}

// ---- Tiny PostgREST helper. No third-party SDK required. ----
async function sb(path, opts = {}) {
  const r = await fetch(SUPABASE_URL + '/rest/v1' + path, {
    ...opts,
    signal: opts.signal || AbortSignal.timeout(Number(process.env.SHANNON_DB_TIMEOUT_MS || 15_000)),
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
    emailVerifiedAt: r.email_verified_at ? Number(r.email_verified_at) : null,
    disabledAt: r.disabled_at ? Number(r.disabled_at) : null,
    sessionInvalidBefore: r.session_invalid_before ? Number(r.session_invalid_before) : null,
    mfaEnabled: r.mfa_enabled === true,
    mfaSecretEnc: r.mfa_secret_enc || null,
    mfaRecoveryCodes: Array.isArray(r.mfa_recovery_codes) ? r.mfa_recovery_codes : [],
    defenderKeyVersion: Number(r.defender_key_version || 0),
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
    email_verified_at: u.emailVerifiedAt || null,
    disabled_at: u.disabledAt || null,
    session_invalid_before: u.sessionInvalidBefore || null,
    mfa_enabled: u.mfaEnabled === true,
    mfa_secret_enc: u.mfaSecretEnc || null,
    mfa_recovery_codes: u.mfaRecoveryCodes || [],
    defender_key_version: Number(u.defenderKeyVersion || 0),
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
      const teamTable = async (path, label) => {
        try {
          return await sb(path);
        } catch (e) {
          console.warn(`[db] ${label} hydrate skipped (run the team migration?):`, e.message);
          return [];
        }
      };
      const [orgRows, memberRows, projectRows, findingRows, auditRows, settingRows, ownerRows, edgeRows, defenseRows] = await Promise.all([
        teamTable('/shannon_organizations?select=*', 'organizations'),
        teamTable('/shannon_memberships?select=*', 'memberships'),
        teamTable('/shannon_projects?select=*', 'projects'),
        teamTable('/shannon_findings?select=*&order=updated_at.desc&limit=5000', 'findings'),
        teamTable('/shannon_audit_events?select=*&order=created_at.desc&limit=5000', 'audit_events'),
        teamTable('/shannon_user_settings?select=*', 'user_settings'),
        teamTable('/shannon_scan_owners?select=*', 'scan_owners'),
        teamTable('/shannon_edge_routes?select=*', 'edge_routes'),
        teamTable('/shannon_defense_events?select=*&order=created_at.desc&limit=5000', 'defense_events'),
      ]);
      _orgs = Object.fromEntries(
        orgRows.map((r) => [r.id, { id: r.id, name: r.name, slug: r.slug, createdBy: r.created_by, createdAt: Number(r.created_at) }]),
      );
      _memberships = memberRows.map((r) => ({
        orgId: r.org_id,
        userId: r.user_id,
        role: r.role,
        createdAt: Number(r.created_at),
      }));
      _projects = {};
      for (const r of projectRows) {
        (_projects[r.org_id] ||= []).push({
          id: r.id,
          orgId: r.org_id,
          name: r.name,
          description: r.description || '',
          environment: r.environment || 'production',
          criticality: r.criticality || 'medium',
          createdAt: Number(r.created_at),
        });
      }
      _findings = {};
      for (const r of findingRows) {
        (_findings[r.org_id] ||= []).push({
          id: r.id,
          orgId: r.org_id,
          projectId: r.project_id || null,
          fingerprint: r.fingerprint,
          title: r.title,
          severity: r.severity,
          status: r.status,
          assigneeUserId: r.assignee_user_id || null,
          source: r.source || 'manual',
          details: r.details || {},
          decision: r.decision || null,
          createdAt: Number(r.created_at),
          updatedAt: Number(r.updated_at),
        });
      }
      _audit = {};
      for (const r of auditRows) {
        (_audit[r.org_id] ||= []).push({
          id: r.id,
          orgId: r.org_id,
          actorUserId: r.actor_user_id || null,
          action: r.action,
          resourceType: r.resource_type,
          resourceId: r.resource_id || null,
          metadata: r.metadata || {},
          createdAt: Number(r.created_at),
        });
      }
      _userSettings = Object.fromEntries(settingRows.map((r) => [r.user_id, r.settings || {}]));
      _scanOwners = Object.fromEntries(
        ownerRows.map((r) => [r.scan_id, {
          scanId: r.scan_id,
          orgId: r.org_id,
          userId: r.user_id,
          projectId: r.project_id || null,
          createdAt: Number(r.created_at),
        }]),
      );
      _edgeRoutes = Object.fromEntries(
        edgeRows.map((r) => [r.host, { host: r.host, orgId: r.org_id, userId: r.user_id, origin: r.origin, mode: r.mode, createdAt: Number(r.created_at) }]),
      );
      _defenseEvents = {};
      for (const r of defenseRows) {
        (_defenseEvents[r.org_id] ||= []).push({
          id: r.id,
          orgId: r.org_id,
          userId: r.user_id,
          at: r.at,
          method: r.method,
          url: r.url,
          cls: r.cls,
          enforced: r.enforced === true,
          srcIp: r.src_ip || null,
          severity: r.severity || 'medium',
          source: r.source || 'sdk',
          status: r.status || 'open',
          metadata: r.metadata || {},
          createdAt: Number(r.created_at),
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
    try {
      const team = JSON.parse(readFileSync(TEAM_PATH, 'utf-8'));
      _orgs = team.organizations || {};
      _memberships = team.memberships || [];
      _projects = team.projects || {};
      _findings = team.findings || {};
      _audit = team.audit || {};
      _userSettings = team.userSettings || {};
      _scanOwners = team.scanOwners || {};
      _edgeRoutes = team.edgeRoutes || {};
      _defenseEvents = team.defenseEvents || {};
    } catch {
      _orgs = {};
      _memberships = [];
      _projects = {};
      _findings = {};
      _audit = {};
      _userSettings = {};
      _scanOwners = {};
      _edgeRoutes = {};
      _defenseEvents = {};
    }
  }
  _ready = true;
  _hydratedAt = Date.now();
}

export async function refreshDbIfStale(maxAgeMs = 5000) {
  if (!USE_SUPABASE || Date.now() - _hydratedAt < Math.max(250, maxAgeMs)) return;
  if (!_refreshPromise) {
    _refreshPromise = Promise.all([_userWriteReady, ..._orgReady.values()])
      .then(() => initDb())
      .finally(() => { _refreshPromise = null; });
  }
  await _refreshPromise;
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
    _userWriteReady = sb('/shannon_users', {
      method: 'POST',
      headers: { prefer: 'resolution=merge-duplicates,return=minimal' },
      body: JSON.stringify(rows),
    }).catch((e) => console.error('[db] users upsert failed:', e.message));
  } else {
    ensureHome();
    writeFileSync(USERS_PATH, JSON.stringify(u, null, 2));
  }
}

export function waitForUserWrites() {
  return _userWriteReady;
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

// ---- Team workspaces -------------------------------------------------------
// The dashboard keeps a synchronous in-memory view for its existing request
// handlers. Supabase remains the production system of record; local development
// stores the same shape in one JSON document.
function persistTeam() {
  if (USE_SUPABASE) return;
  ensureHome();
  writeFileSync(
    TEAM_PATH,
    JSON.stringify(
      {
        organizations: _orgs,
        memberships: _memberships,
        projects: _projects,
        findings: _findings,
        audit: _audit,
        userSettings: _userSettings,
        scanOwners: _scanOwners,
        edgeRoutes: _edgeRoutes,
        defenseEvents: _defenseEvents,
      },
      null,
      2,
    ),
  );
}

export function createOrganization(org, ownerMembership) {
  if (!org?.id || !ownerMembership?.userId) return null;
  _orgs[org.id] = org;
  _memberships = _memberships.filter((m) => !(m.orgId === org.id && m.userId === ownerMembership.userId));
  _memberships.push(ownerMembership);
  if (USE_SUPABASE) {
    const ready = _userWriteReady.then(() => sb('/shannon_organizations', {
      method: 'POST',
      headers: { prefer: 'resolution=merge-duplicates,return=minimal' },
      body: JSON.stringify([{
        id: org.id,
        name: org.name,
        slug: org.slug,
        created_by: org.createdBy,
        created_at: org.createdAt,
      }]),
    }))
      .then(() =>
        sb('/shannon_memberships', {
          method: 'POST',
          headers: { prefer: 'resolution=merge-duplicates,return=minimal' },
          body: JSON.stringify([{
            org_id: ownerMembership.orgId,
            user_id: ownerMembership.userId,
            role: ownerMembership.role,
            created_at: ownerMembership.createdAt || Date.now(),
          }]),
        }),
      )
      .catch((e) => console.error('[db] organization save failed:', e.message));
    _orgReady.set(org.id, ready);
  } else persistTeam();
  return org;
}

export function listOrganizations(userId) {
  return _memberships
    .filter((m) => m.userId === userId && _orgs[m.orgId])
    .map((m) => ({ ..._orgs[m.orgId], role: m.role }));
}

export function getOrganization(orgId) {
  return _orgs[orgId] || null;
}

export function getMembership(orgId, userId) {
  return _memberships.find((m) => m.orgId === orgId && m.userId === userId) || null;
}

export function listMembers(orgId) {
  return _memberships
    .filter((m) => m.orgId === orgId)
    .map((m) => ({
      ...m,
      name: _users[m.userId]?.name || null,
      email: _users[m.userId]?.email || null,
      picture: _users[m.userId]?.picture || null,
    }));
}

export function saveMembership(membership) {
  if (!membership?.orgId || !membership?.userId) return;
  _memberships = _memberships.filter((m) => !(m.orgId === membership.orgId && m.userId === membership.userId));
  _memberships.push(membership);
  if (USE_SUPABASE) {
    const ready = Promise.all([_userWriteReady, _orgReady.get(membership.orgId) || Promise.resolve()]).then(() => sb('/shannon_memberships', {
      method: 'POST',
      headers: { prefer: 'resolution=merge-duplicates,return=minimal' },
      body: JSON.stringify([{
        org_id: membership.orgId,
        user_id: membership.userId,
        role: membership.role,
        created_at: membership.createdAt || Date.now(),
      }]),
    })).catch((e) => console.error('[db] membership save failed:', e.message));
    _orgReady.set(membership.orgId, ready);
  } else persistTeam();
}

export function removeMembership(orgId, userId) {
  _memberships = _memberships.filter((m) => !(m.orgId === orgId && m.userId === userId));
  if (USE_SUPABASE) {
    sb(`/shannon_memberships?org_id=eq.${encodeURIComponent(orgId)}&user_id=eq.${encodeURIComponent(userId)}`, {
      method: 'DELETE',
      headers: { prefer: 'return=minimal' },
    }).catch((e) => console.error('[db] membership delete failed:', e.message));
  } else persistTeam();
}

export function listProjects(orgId) {
  return _projects[orgId] || [];
}

export function saveProject(project) {
  if (!project?.orgId || !project?.id) return;
  const list = (_projects[project.orgId] ||= []);
  const at = list.findIndex((p) => p.id === project.id);
  if (at >= 0) list[at] = project;
  else list.unshift(project);
  if (USE_SUPABASE) {
    sb('/shannon_projects', {
      method: 'POST',
      headers: { prefer: 'resolution=merge-duplicates,return=minimal' },
      body: JSON.stringify([{
        id: project.id,
        org_id: project.orgId,
        name: project.name,
        description: project.description || null,
        environment: project.environment || 'production',
        criticality: project.criticality || 'medium',
        created_at: project.createdAt || Date.now(),
      }]),
    }).catch((e) => console.error('[db] project save failed:', e.message));
  } else persistTeam();
}

export function listFindings(orgId, filters = {}) {
  return (_findings[orgId] || []).filter(
    (f) => (!filters.projectId || f.projectId === filters.projectId) && (!filters.status || f.status === filters.status),
  );
}

export function getFinding(orgId, findingId) {
  return (_findings[orgId] || []).find((f) => f.id === findingId) || null;
}

export function saveFinding(finding) {
  if (!finding?.orgId || !finding?.id) return null;
  const list = (_findings[finding.orgId] ||= []);
  const same = list.findIndex((f) => f.id === finding.id || (finding.fingerprint && f.fingerprint === finding.fingerprint));
  if (same >= 0) list[same] = { ...list[same], ...finding, id: list[same].id };
  else list.unshift(finding);
  const saved = same >= 0 ? list[same] : finding;
  if (USE_SUPABASE) {
    sb('/shannon_findings', {
      method: 'POST',
      headers: { prefer: 'resolution=merge-duplicates,return=minimal' },
      body: JSON.stringify([{
        id: saved.id,
        org_id: saved.orgId,
        project_id: saved.projectId || null,
        fingerprint: saved.fingerprint || saved.id,
        title: saved.title,
        severity: saved.severity || 'medium',
        status: saved.status || 'new',
        assignee_user_id: saved.assigneeUserId || null,
        source: saved.source || 'manual',
        details: saved.details || {},
        decision: saved.decision || null,
        created_at: saved.createdAt || Date.now(),
        updated_at: saved.updatedAt || Date.now(),
      }]),
    }).catch((e) => console.error('[db] finding save failed:', e.message));
  } else persistTeam();
  return saved;
}

export function appendAudit(event) {
  if (!event?.orgId || !event?.id) return;
  const list = (_audit[event.orgId] ||= []);
  list.unshift(event);
  if (list.length > 2000) list.length = 2000;
  if (USE_SUPABASE) {
    (_orgReady.get(event.orgId) || Promise.resolve())
      .then(() =>
        sb('/shannon_audit_events', {
          method: 'POST',
          headers: { prefer: 'return=minimal' },
          body: JSON.stringify([{
            id: event.id,
            org_id: event.orgId,
            actor_user_id: event.actorUserId || null,
            action: event.action,
            resource_type: event.resourceType,
            resource_id: event.resourceId || null,
            metadata: event.metadata || {},
            created_at: event.createdAt || Date.now(),
          }]),
        }),
      )
      .catch((e) => console.error('[db] audit save failed:', e.message));
  } else persistTeam();
}

export function listAudit(orgId, limit = 200) {
  return (_audit[orgId] || []).slice(0, Math.max(1, Math.min(500, limit)));
}

export function loadUserSettings(userId) {
  return _userSettings[userId] || {};
}

export function saveUserSettings(userId, settings) {
  _userSettings[userId] = settings || {};
  if (USE_SUPABASE) {
    sb('/shannon_user_settings', {
      method: 'POST',
      headers: { prefer: 'resolution=merge-duplicates,return=minimal' },
      body: JSON.stringify([{ user_id: userId, settings: settings || {}, updated_at: Date.now() }]),
    }).catch((e) => console.error('[db] user settings save failed:', e.message));
  } else persistTeam();
}

export function saveScanOwner(owner) {
  if (!owner?.scanId || !owner?.orgId || !owner?.userId) return;
  _scanOwners[owner.scanId] = owner;
  if (USE_SUPABASE) {
    sb('/shannon_scan_owners', {
      method: 'POST',
      headers: { prefer: 'resolution=merge-duplicates,return=minimal' },
      body: JSON.stringify([{
        scan_id: owner.scanId,
        org_id: owner.orgId,
        user_id: owner.userId,
        project_id: owner.projectId || null,
        created_at: owner.createdAt || Date.now(),
      }]),
    }).catch((e) => console.error('[db] scan owner save failed:', e.message));
  } else persistTeam();
}

export function getScanOwner(scanId) {
  return _scanOwners[scanId] || null;
}

export function saveEdgeRoute(route) {
  if (!route?.host || !route?.orgId || !route?.userId) return;
  _edgeRoutes[route.host] = route;
  if (USE_SUPABASE) {
    sb('/shannon_edge_routes', {
      method: 'POST',
      headers: { prefer: 'resolution=merge-duplicates,return=minimal' },
      body: JSON.stringify([{
        host: route.host,
        org_id: route.orgId,
        user_id: route.userId,
        origin: route.origin,
        mode: route.mode,
        created_at: route.createdAt || Date.now(),
      }]),
    }).catch((e) => console.error('[db] edge route save failed:', e.message));
  } else persistTeam();
}

export function listEdgeRoutes({ orgId, userId } = {}) {
  return Object.values(_edgeRoutes).filter((r) => (!orgId || r.orgId === orgId) && (!userId || r.userId === userId));
}

export function removeEdgeRoute(host, orgId) {
  const route = _edgeRoutes[host];
  if (!route || (orgId && route.orgId !== orgId)) return false;
  delete _edgeRoutes[host];
  if (USE_SUPABASE) {
    sb(`/shannon_edge_routes?host=eq.${encodeURIComponent(host)}&org_id=eq.${encodeURIComponent(route.orgId)}`, {
      method: 'DELETE',
      headers: { prefer: 'return=minimal' },
    }).catch((e) => console.error('[db] edge route delete failed:', e.message));
  } else persistTeam();
  return true;
}

export function appendDefenseEvent(event) {
  if (!event?.orgId || !event?.id) return;
  const list = (_defenseEvents[event.orgId] ||= []);
  list.unshift(event);
  if (list.length > 2000) list.length = 2000;
  if (USE_SUPABASE) {
    sb('/shannon_defense_events', {
      method: 'POST',
      headers: { prefer: 'return=minimal' },
      body: JSON.stringify([{
        id: event.id,
        org_id: event.orgId,
        user_id: event.userId,
        at: event.at,
        method: event.method,
        url: event.url,
        cls: event.cls,
        enforced: event.enforced === true,
        src_ip: event.srcIp || null,
        severity: event.severity || 'medium',
        source: event.source || 'sdk',
        status: event.status || 'open',
        metadata: event.metadata || {},
        created_at: event.createdAt || Date.now(),
      }]),
    }).catch((e) => console.error('[db] defense event save failed:', e.message));
  } else persistTeam();
}

export function listDefenseEvents(orgId, limit = 200) {
  return (_defenseEvents[orgId] || []).slice(0, Math.max(1, Math.min(500, limit)));
}

export function updateDefenseEvent(orgId, id, patch) {
  const event = (_defenseEvents[orgId] || []).find((item) => item.id === id);
  if (!event) return null;
  Object.assign(event, patch);
  if (USE_SUPABASE) {
    const body = {};
    if (patch.status !== undefined) body.status = patch.status;
    if (patch.severity !== undefined) body.severity = patch.severity;
    if (patch.metadata !== undefined) body.metadata = patch.metadata;
    sb(`/shannon_defense_events?id=eq.${encodeURIComponent(id)}&org_id=eq.${encodeURIComponent(orgId)}`, {
      method: 'PATCH',
      headers: { prefer: 'return=minimal' },
      body: JSON.stringify(body),
    }).catch((e) => console.error('[db] defense event update failed:', e.message));
  } else persistTeam();
  return event;
}
