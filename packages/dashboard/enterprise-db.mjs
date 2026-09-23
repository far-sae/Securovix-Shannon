import { createHash, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import { dirname, join } from 'node:path';

// Keep CLI, web, and worker startup behavior identical. Railway provides these
// values directly; local development may keep them in the repository .env.
try {
  for (const line of readFileSync(new URL('../../.env', import.meta.url), 'utf8').split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)$/);
    if (match && !process.env[match[1]]) process.env[match[1]] = match[2].trim().replace(/^["']|["']$/g, '');
  }
} catch {}

const SUPABASE_URL = String(process.env.SUPABASE_URL || '').replace(/\/$/, '');
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY || '';
const USE_SUPABASE = process.env.SHANNON_FORCE_LOCAL_DB !== '1' && !!(SUPABASE_URL && SUPABASE_KEY);
const DATA_DIR = process.env.SHANNON_DATA_DIR || join(os.homedir(), '.shannon');
const LOCAL_PATH = join(DATA_DIR, 'enterprise-state.json');

let local = {
  authTokens: [],
  identities: [],
  integrations: [],
  jobs: [],
  artifacts: [],
  deliveries: [],
  operations: [],
  orgSecrets: [],
  scanAuthGrants: [],
  entitlements: {},
  usageDaily: [],
  defensePrograms: [],
  defenseAssets: [],
  defenseCycles: [],
  softwareComponents: [],
  vulnerabilityMatches: [],
};

try {
  if (existsSync(LOCAL_PATH)) local = { ...local, ...JSON.parse(readFileSync(LOCAL_PATH, 'utf8')) };
} catch {}

function persist() {
  if (USE_SUPABASE) return;
  mkdirSync(dirname(LOCAL_PATH), { recursive: true });
  writeFileSync(LOCAL_PATH, JSON.stringify(local, null, 2));
}

function storagePath(path) {
  return String(path)
    .split('/')
    .map((part) => encodeURIComponent(part))
    .join('/');
}

async function rest(path, opts = {}) {
  if (!USE_SUPABASE) throw new Error('Supabase is not configured');
  const response = await fetch(`${SUPABASE_URL}/rest/v1${path}`, {
    ...opts,
    signal: opts.signal || AbortSignal.timeout(Number(process.env.SHANNON_DB_TIMEOUT_MS || 15_000)),
    headers: {
      apikey: SUPABASE_KEY,
      authorization: `Bearer ${SUPABASE_KEY}`,
      'content-type': 'application/json',
      prefer: opts.prefer || 'return=representation',
      ...(opts.headers || {}),
    },
  });
  if (!response.ok) {
    const detail = await response.text().catch(() => '');
    throw new Error(`Supabase ${opts.method || 'GET'} ${path} -> ${response.status}: ${detail.slice(0, 300)}`);
  }
  if (response.status === 204) return null;
  return response.json().catch(() => null);
}

function tokenFromRow(row) {
  return (
    row && {
      id: row.id,
      tokenHash: row.token_hash,
      kind: row.kind,
      userId: row.user_id || null,
      email: row.email,
      orgId: row.org_id || null,
      role: row.role || null,
      createdBy: row.created_by || null,
      expiresAt: Number(row.expires_at),
      usedAt: row.used_at ? Number(row.used_at) : null,
      createdAt: Number(row.created_at),
    }
  );
}

function integrationFromRow(row) {
  return (
    row && {
      id: row.id,
      orgId: row.org_id,
      type: row.type,
      name: row.name,
      config: row.config || {},
      secretEnc: row.secret_enc || null,
      enabled: row.enabled !== false,
      createdBy: row.created_by || null,
      createdAt: Number(row.created_at),
      updatedAt: Number(row.updated_at),
    }
  );
}

function orgSecretFromRow(row) {
  return row && { id: row.id, orgId: row.org_id, kind: row.kind, name: row.name, config: row.config || {}, secretEnc: row.secret_enc, createdBy: row.created_by || null, createdAt: Number(row.created_at), updatedAt: Number(row.updated_at) };
}

function scanAuthGrantFromRow(row) {
  return row && { id: row.id, userId: row.user_id, orgId: row.org_id, targetOrigin: row.target_origin, secretEnc: row.secret_enc, expiresAt: Number(row.expires_at), consumedAt: row.consumed_at ? Number(row.consumed_at) : null, createdAt: Number(row.created_at) };
}

function entitlementFromRow(row) {
  return row && { orgId: row.org_id, plan: row.plan, status: row.status, provider: row.provider || null, providerCustomerId: row.provider_customer_id || null, providerSubscriptionId: row.provider_subscription_id || null, currentPeriodEnd: row.current_period_end ? Number(row.current_period_end) : null, limits: row.limits || {}, updatedAt: Number(row.updated_at) };
}

function jobFromRow(row) {
  return (
    row && {
      id: row.id,
      orgId: row.org_id || null,
      userId: row.user_id || null,
      type: row.type,
      status: row.status,
      payload: row.payload || {},
      secretEnc: row.secret_enc || null,
      result: row.result || null,
      error: row.error || null,
      attempts: Number(row.attempts || 0),
      maxAttempts: Number(row.max_attempts || 5),
      runAt: Number(row.run_at),
      lockedBy: row.locked_by || null,
      lockedAt: row.locked_at ? Number(row.locked_at) : null,
      heartbeatAt: row.heartbeat_at ? Number(row.heartbeat_at) : null,
      idempotencyKey: row.idempotency_key || null,
      createdAt: Number(row.created_at),
      updatedAt: Number(row.updated_at),
    }
  );
}

function defenseProgramFromRow(row) {
  return row && {
    orgId: row.org_id, enabled: row.enabled === true, cadenceHours: Number(row.cadence_hours || 24),
    responseMode: row.response_mode || 'recommend', nextRunAt: row.next_run_at ? Number(row.next_run_at) : null,
    lastRunAt: row.last_run_at ? Number(row.last_run_at) : null, lastCycleId: row.last_cycle_id || null,
    createdBy: row.created_by || null, createdAt: Number(row.created_at), updatedAt: Number(row.updated_at),
  };
}

function defenseAssetFromRow(row) {
  return row && {
    id: row.id, orgId: row.org_id, projectId: row.project_id || null, type: row.type, name: row.name,
    locator: row.locator, criticality: row.criticality, status: row.status, coverage: row.coverage,
    config: row.config || {}, createdBy: row.created_by || null, createdAt: Number(row.created_at), updatedAt: Number(row.updated_at),
  };
}

function defenseCycleFromRow(row) {
  return row && {
    id: row.id, orgId: row.org_id, jobId: row.job_id || null, status: row.status,
    window: row.window || {}, snapshot: row.snapshot || {}, learning: row.learning || {}, actions: row.actions || {},
    error: row.error || null, startedAt: Number(row.started_at), completedAt: row.completed_at ? Number(row.completed_at) : null,
    createdAt: Number(row.created_at),
  };
}

function softwareComponentFromRow(row) {
  return row && {
    id: row.id, orgId: row.org_id, assetId: row.asset_id || null, projectId: row.project_id || null,
    fingerprint: row.fingerprint, source: row.source, sourceRef: row.source_ref, name: row.name,
    version: row.version || '', ecosystem: row.ecosystem || '', purl: row.purl || '', cpe: row.cpe || '',
    licenses: row.licenses || [], metadata: row.metadata || {}, firstSeenAt: Number(row.first_seen_at), lastSeenAt: Number(row.last_seen_at),
  };
}

function vulnerabilityMatchFromRow(row) {
  return row && {
    id: row.id, orgId: row.org_id, componentId: row.component_id, vulnerabilityId: row.vulnerability_id,
    aliases: row.aliases || [], source: row.source, severity: row.severity, summary: row.summary,
    details: row.details || {}, status: row.status, dueAt: row.due_at ? Number(row.due_at) : null,
    discoveredAt: Number(row.discovered_at), updatedAt: Number(row.updated_at), resolvedAt: row.resolved_at ? Number(row.resolved_at) : null,
  };
}

export function enterpriseUsesSupabase() {
  return USE_SUPABASE;
}

export async function enterpriseHealth() {
  if (!USE_SUPABASE) return { ok: true, backend: 'local' };
  await rest('/shannon_jobs?select=id&limit=1');
  return { ok: true, backend: 'supabase' };
}

export async function createAuthToken(record) {
  if (!USE_SUPABASE) {
    local.authTokens = local.authTokens.filter((item) => item.tokenHash !== record.tokenHash);
    local.authTokens.push(record);
    persist();
    return record;
  }
  const rows = await rest('/shannon_auth_tokens', {
    method: 'POST',
    body: JSON.stringify([
      {
        id: record.id,
        token_hash: record.tokenHash,
        kind: record.kind,
        user_id: record.userId || null,
        email: record.email,
        org_id: record.orgId || null,
        role: record.role || null,
        created_by: record.createdBy || null,
        expires_at: record.expiresAt,
        used_at: record.usedAt || null,
        created_at: record.createdAt,
      },
    ]),
  });
  return tokenFromRow(rows?.[0]);
}

export async function consumeAuthToken(tokenHash, kind) {
  const now = Date.now();
  if (!USE_SUPABASE) {
    const found = local.authTokens.find(
      (item) => item.tokenHash === tokenHash && item.kind === kind && !item.usedAt && item.expiresAt > now,
    );
    if (!found) return null;
    found.usedAt = now;
    persist();
    return found;
  }
  const rows = await rest('/rpc/shannon_consume_auth_token', {
    method: 'POST',
    body: JSON.stringify({ p_token_hash: tokenHash, p_kind: kind, p_now: now }),
  });
  return tokenFromRow(rows?.[0]);
}

export async function findAuthToken(tokenHash, kind) {
  const now = Date.now();
  if (!USE_SUPABASE) {
    return (
      local.authTokens.find(
        (item) => item.tokenHash === tokenHash && item.kind === kind && !item.usedAt && item.expiresAt > now,
      ) || null
    );
  }
  const rows = await rest(
    `/shannon_auth_tokens?token_hash=eq.${encodeURIComponent(tokenHash)}&kind=eq.${encodeURIComponent(kind)}&used_at=is.null&expires_at=gt.${now}&limit=1`,
  );
  return tokenFromRow(rows?.[0]);
}

export async function findSsoIdentity(provider, subject) {
  if (!USE_SUPABASE) {
    return local.identities.find((item) => item.provider === provider && item.subject === subject) || null;
  }
  const rows = await rest(
    `/shannon_sso_identities?provider=eq.${encodeURIComponent(provider)}&subject=eq.${encodeURIComponent(subject)}&limit=1`,
  );
  const row = rows?.[0];
  return row ? { provider: row.provider, subject: row.subject, userId: row.user_id, email: row.email || null } : null;
}

export async function saveSsoIdentity(identity) {
  if (!USE_SUPABASE) {
    local.identities = local.identities.filter(
      (item) => !(item.provider === identity.provider && item.subject === identity.subject),
    );
    local.identities.push(identity);
    persist();
    return identity;
  }
  await rest('/shannon_sso_identities', {
    method: 'POST',
    headers: { prefer: 'resolution=merge-duplicates,return=minimal' },
    body: JSON.stringify([
      {
        provider: identity.provider,
        subject: identity.subject,
        user_id: identity.userId,
        email: identity.email || null,
        created_at: identity.createdAt || Date.now(),
        last_login_at: identity.lastLoginAt || Date.now(),
      },
    ]),
  });
  return identity;
}

export async function listIntegrations(orgId, { includeSecrets = false } = {}) {
  const rows = USE_SUPABASE
    ? await rest(`/shannon_integrations?org_id=eq.${encodeURIComponent(orgId)}&order=created_at.desc`)
    : local.integrations.filter((item) => item.orgId === orgId);
  const mapped = USE_SUPABASE ? (rows || []).map(integrationFromRow) : rows;
  return mapped.map((item) => (includeSecrets ? item : { ...item, secretEnc: undefined, hasSecret: !!item.secretEnc }));
}

export async function getIntegration(orgId, id) {
  const rows = await listIntegrations(orgId, { includeSecrets: true });
  return rows.find((item) => item.id === id) || null;
}

export async function saveIntegration(integration) {
  if (!USE_SUPABASE) {
    local.integrations = local.integrations.filter((item) => item.id !== integration.id);
    local.integrations.push(integration);
    persist();
    return integration;
  }
  const rows = await rest('/shannon_integrations', {
    method: 'POST',
    headers: { prefer: 'resolution=merge-duplicates,return=representation' },
    body: JSON.stringify([
      {
        id: integration.id,
        org_id: integration.orgId,
        type: integration.type,
        name: integration.name,
        config: integration.config || {},
        secret_enc: integration.secretEnc || null,
        enabled: integration.enabled !== false,
        created_by: integration.createdBy || null,
        created_at: integration.createdAt,
        updated_at: integration.updatedAt,
      },
    ]),
  });
  return integrationFromRow(rows?.[0]);
}

export async function deleteIntegration(orgId, id) {
  if (!USE_SUPABASE) {
    const before = local.integrations.length;
    local.integrations = local.integrations.filter((item) => !(item.orgId === orgId && item.id === id));
    persist();
    return local.integrations.length !== before;
  }
  await rest(`/shannon_integrations?id=eq.${encodeURIComponent(id)}&org_id=eq.${encodeURIComponent(orgId)}`, {
    method: 'DELETE',
    headers: { prefer: 'return=minimal' },
  });
  return true;
}

export async function listOrgSecrets(orgId, kind, { includeSecrets = false } = {}) {
  const source = USE_SUPABASE
    ? await rest(`/shannon_org_secrets?org_id=eq.${encodeURIComponent(orgId)}${kind ? `&kind=eq.${encodeURIComponent(kind)}` : ''}&order=created_at.asc`)
    : local.orgSecrets.filter((item) => item.orgId === orgId && (!kind || item.kind === kind));
  const rows = USE_SUPABASE ? (source || []).map(orgSecretFromRow) : source;
  return rows.map((item) => includeSecrets ? item : { ...item, secretEnc: undefined, configured: !!item.secretEnc });
}

export async function getOrgSecret(orgId, kind, name) {
  const rows = await listOrgSecrets(orgId, kind, { includeSecrets: true });
  return rows.find((item) => item.name === name) || null;
}

export async function saveOrgSecret(record) {
  if (!USE_SUPABASE) {
    local.orgSecrets = local.orgSecrets.filter((item) => !(item.orgId === record.orgId && item.kind === record.kind && item.name === record.name));
    local.orgSecrets.push(record); persist(); return record;
  }
  const rows = await rest('/shannon_org_secrets', { method: 'POST', headers: { prefer: 'resolution=merge-duplicates,return=representation' }, body: JSON.stringify([{ id: record.id, org_id: record.orgId, kind: record.kind, name: record.name, config: record.config || {}, secret_enc: record.secretEnc, created_by: record.createdBy || null, created_at: record.createdAt, updated_at: record.updatedAt }]) });
  return orgSecretFromRow(rows?.[0]);
}

export async function deleteOrgSecret(orgId, kind, name) {
  if (!USE_SUPABASE) {
    local.orgSecrets = local.orgSecrets.filter((item) => !(item.orgId === orgId && item.kind === kind && item.name === name)); persist(); return true;
  }
  await rest(`/shannon_org_secrets?org_id=eq.${encodeURIComponent(orgId)}&kind=eq.${encodeURIComponent(kind)}&name=eq.${encodeURIComponent(name)}`, { method: 'DELETE', headers: { prefer: 'return=minimal' } });
  return true;
}

export async function createScanAuthGrant(record) {
  if (!USE_SUPABASE) {
    local.scanAuthGrants = local.scanAuthGrants.filter((item) => item.expiresAt > Date.now());
    local.scanAuthGrants.push(record);
    persist();
    return record;
  }
  await rest(`/shannon_scan_auth_grants?expires_at=lt.${Date.now()}`, { method: 'DELETE', headers: { prefer: 'return=minimal' } });
  const rows = await rest('/shannon_scan_auth_grants', { method: 'POST', body: JSON.stringify([{ id: record.id, user_id: record.userId, org_id: record.orgId, target_origin: record.targetOrigin, secret_enc: record.secretEnc, expires_at: record.expiresAt, consumed_at: null, created_at: record.createdAt }]) });
  return scanAuthGrantFromRow(rows?.[0]);
}

export async function consumeScanAuthGrant(id, userId, orgId, targetOrigin) {
  const now = Date.now();
  if (!USE_SUPABASE) {
    const index = local.scanAuthGrants.findIndex((item) => item.id === id && item.userId === userId && item.orgId === orgId && item.targetOrigin === targetOrigin && item.expiresAt > now);
    if (index < 0) return null;
    const [grant] = local.scanAuthGrants.splice(index, 1);
    persist();
    return grant;
  }
  const rows = await rest('/rpc/shannon_consume_scan_auth_grant', { method: 'POST', body: JSON.stringify({ p_id: id, p_user_id: userId, p_org_id: orgId, p_target_origin: targetOrigin, p_now: now }) });
  return scanAuthGrantFromRow(rows?.[0]);
}

export async function getEntitlement(orgId) {
  if (!USE_SUPABASE) return local.entitlements[orgId] || null;
  const rows = await rest(`/shannon_org_entitlements?org_id=eq.${encodeURIComponent(orgId)}&limit=1`);
  return entitlementFromRow(rows?.[0]);
}

export async function saveEntitlement(record) {
  if (!USE_SUPABASE) { local.entitlements[record.orgId] = record; persist(); return record; }
  const rows = await rest('/shannon_org_entitlements', { method: 'POST', headers: { prefer: 'resolution=merge-duplicates,return=representation' }, body: JSON.stringify([{ org_id: record.orgId, plan: record.plan, status: record.status, provider: record.provider || null, provider_customer_id: record.providerCustomerId || null, provider_subscription_id: record.providerSubscriptionId || null, current_period_end: record.currentPeriodEnd || null, limits: record.limits || {}, updated_at: record.updatedAt || Date.now() }]) });
  return entitlementFromRow(rows?.[0]);
}

export async function consumeUsage(orgId, metric, amount, limit, day = new Date().toISOString().slice(0, 10)) {
  const requested = Math.max(1, Number(amount || 1));
  const cap = Math.max(0, Number(limit || 0));
  if (!USE_SUPABASE) {
    const row = local.usageDaily.find((item) => item.orgId === orgId && item.day === day && item.metric === metric);
    const used = Number(row?.quantity || 0);
    if (used + requested > cap) return { allowed: false, used, limit: cap, day };
    if (row) { row.quantity = used + requested; row.updatedAt = Date.now(); }
    else local.usageDaily.push({ orgId, day, metric, quantity: requested, updatedAt: Date.now() });
    persist();
    return { allowed: true, used: used + requested, limit: cap, day };
  }
  const quantity = await rest('/rpc/shannon_consume_usage', { method: 'POST', body: JSON.stringify({ p_org_id: orgId, p_day: day, p_metric: metric, p_amount: requested, p_limit: cap, p_now: Date.now() }) });
  const used = Number(quantity || 0);
  return { allowed: used > 0, used, limit: cap, day };
}

export async function listUsage(orgId, day = new Date().toISOString().slice(0, 10)) {
  if (!USE_SUPABASE) return local.usageDaily.filter((item) => item.orgId === orgId && item.day === day);
  const rows = await rest(`/shannon_usage_daily?org_id=eq.${encodeURIComponent(orgId)}&day=eq.${encodeURIComponent(day)}&order=metric.asc`);
  return (rows || []).map((row) => ({ orgId: row.org_id, day: row.day, metric: row.metric, quantity: Number(row.quantity), updatedAt: Number(row.updated_at) }));
}

export async function enqueueJob(job) {
  const normalized = {
    id: job.id || randomUUID(),
    orgId: job.orgId || null,
    userId: job.userId || null,
    type: job.type,
    status: 'queued',
    payload: job.payload || {},
    secretEnc: job.secretEnc || null,
    result: null,
    error: null,
    attempts: 0,
    maxAttempts: Math.max(1, Math.min(20, Number(job.maxAttempts || 5))),
    runAt: Number(job.runAt || Date.now()),
    idempotencyKey: job.idempotencyKey || null,
    createdAt: Number(job.createdAt || Date.now()),
    updatedAt: Date.now(),
  };
  if (!USE_SUPABASE) {
    if (normalized.idempotencyKey) {
      const existing = local.jobs.find(
        (item) => item.orgId === normalized.orgId && item.idempotencyKey === normalized.idempotencyKey,
      );
      if (existing) return existing;
    }
    local.jobs.push(normalized);
    persist();
    return normalized;
  }
  const rows = await rest('/shannon_jobs', {
    method: 'POST',
    body: JSON.stringify([
      {
        id: normalized.id,
        org_id: normalized.orgId,
        user_id: normalized.userId,
        type: normalized.type,
        status: normalized.status,
        payload: normalized.payload,
        secret_enc: normalized.secretEnc,
        attempts: normalized.attempts,
        max_attempts: normalized.maxAttempts,
        run_at: normalized.runAt,
        idempotency_key: normalized.idempotencyKey,
        created_at: normalized.createdAt,
        updated_at: normalized.updatedAt,
      },
    ]),
  });
  return jobFromRow(rows?.[0]);
}

export async function claimJobs(workerId, limit = 1) {
  if (!USE_SUPABASE) {
    const now = Date.now();
    const jobs = local.jobs
      .filter((job) => job.status === 'queued' && job.runAt <= now)
      .sort((a, b) => a.runAt - b.runAt || a.createdAt - b.createdAt)
      .slice(0, Math.max(1, Math.min(20, limit)));
    for (const job of jobs) {
      job.status = 'running';
      job.lockedBy = workerId;
      job.lockedAt = now;
      job.heartbeatAt = now;
      job.attempts += 1;
      job.updatedAt = now;
    }
    persist();
    return jobs;
  }
  const rows = await rest('/rpc/shannon_claim_jobs', {
    method: 'POST',
    body: JSON.stringify({ p_worker_id: workerId, p_limit: limit, p_now: Date.now() }),
  });
  return (rows || []).map(jobFromRow);
}

export async function updateJob(id, patch) {
  const now = Date.now();
  if (!USE_SUPABASE) {
    const job = local.jobs.find((item) => item.id === id);
    if (!job) return null;
    Object.assign(job, patch, { updatedAt: now });
    persist();
    return job;
  }
  const body = { updated_at: now };
  const map = {
    status: 'status',
    result: 'result',
    error: 'error',
    runAt: 'run_at',
    lockedBy: 'locked_by',
    lockedAt: 'locked_at',
    heartbeatAt: 'heartbeat_at',
    payload: 'payload',
    secretEnc: 'secret_enc',
  };
  for (const [key, column] of Object.entries(map)) if (Object.hasOwn(patch, key)) body[column] = patch[key];
  const rows = await rest(`/shannon_jobs?id=eq.${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: JSON.stringify(body),
  });
  return jobFromRow(rows?.[0]);
}

export async function getJob(id) {
  if (!USE_SUPABASE) return local.jobs.find((item) => item.id === id) || null;
  const rows = await rest(`/shannon_jobs?id=eq.${encodeURIComponent(id)}&limit=1`);
  return jobFromRow(rows?.[0]);
}

export async function requeueStaleJobs(staleBefore = Date.now() - 2 * 60_000) {
  const now = Date.now();
  if (!USE_SUPABASE) {
    let count = 0;
    for (const job of local.jobs) {
      if (job.status === 'running' && Number(job.heartbeatAt || job.lockedAt || 0) < staleBefore) {
        job.status = job.attempts >= job.maxAttempts ? 'dead-letter' : 'queued';
        job.error = `${job.error ? `${job.error}\n` : ''}Worker lease expired; job recovered.`;
        job.runAt = now;
        job.lockedBy = null;
        job.lockedAt = null;
        job.updatedAt = now;
        count += 1;
      }
    }
    if (count) persist();
    return count;
  }
  const result = await rest('/rpc/shannon_requeue_stale_jobs', {
    method: 'POST',
    body: JSON.stringify({ p_stale_before: staleBefore, p_now: now }),
  });
  return Number(result || 0);
}

export async function listJobs(orgId, limit = 100) {
  if (!USE_SUPABASE) {
    return local.jobs
      .filter((item) => !orgId || item.orgId === orgId)
      .sort((a, b) => b.createdAt - a.createdAt)
      .slice(0, limit);
  }
  const filter = orgId ? `&org_id=eq.${encodeURIComponent(orgId)}` : '';
  const rows = await rest(`/shannon_jobs?select=*&order=created_at.desc&limit=${Math.min(500, limit)}${filter}`);
  return (rows || []).map(jobFromRow);
}

export async function appendDelivery(event) {
  if (!USE_SUPABASE) {
    local.deliveries.unshift(event);
    local.deliveries.length = Math.min(local.deliveries.length, 5000);
    persist();
    return event;
  }
  await rest('/shannon_delivery_events', {
    method: 'POST',
    headers: { prefer: 'return=minimal' },
    body: JSON.stringify([
      {
        id: event.id,
        org_id: event.orgId,
        integration_id: event.integrationId || null,
        event_type: event.eventType,
        status: event.status,
        attempt: event.attempt || 0,
        response_status: event.responseStatus || null,
        error: event.error || null,
        created_at: event.createdAt,
        completed_at: event.completedAt || null,
      },
    ]),
  });
  return event;
}

export async function listDeliveries(orgId, limit = 100) {
  if (!USE_SUPABASE) return local.deliveries.filter((item) => item.orgId === orgId).slice(0, limit);
  return rest(
    `/shannon_delivery_events?org_id=eq.${encodeURIComponent(orgId)}&order=created_at.desc&limit=${Math.min(500, limit)}`,
  );
}

export async function appendOperationalEvent(event) {
  if (!USE_SUPABASE) {
    local.operations.unshift(event);
    local.operations.length = Math.min(local.operations.length, 2000);
    persist();
    return event;
  }
  await rest('/shannon_operational_events', {
    method: 'POST',
    headers: { prefer: 'return=minimal' },
    body: JSON.stringify([
      {
        id: event.id || randomUUID(),
        service: event.service,
        instance_id: event.instanceId || null,
        level: event.level || 'info',
        event: event.event,
        org_id: event.orgId || null,
        metadata: event.metadata || {},
        created_at: event.createdAt || Date.now(),
      },
    ]),
  });
  return event;
}

export async function listOperationalEvents(service = null, limit = 100, orgId = null) {
  if (!USE_SUPABASE) {
    return local.operations
      .filter((item) => (!service || item.service === service) && (!orgId || item.orgId === orgId))
      .slice(0, Math.min(500, limit));
  }
  const serviceFilter = service ? `service=eq.${encodeURIComponent(service)}&` : '';
  const orgFilter = orgId ? `org_id=eq.${encodeURIComponent(orgId)}&` : '';
  const rows = await rest(
    `/shannon_operational_events?${serviceFilter}${orgFilter}order=created_at.desc&limit=${Math.min(500, limit)}`,
  );
  return (rows || []).map((row) => ({
    id: row.id,
    service: row.service,
    instanceId: row.instance_id || null,
    level: row.level,
    event: row.event,
    orgId: row.org_id || null,
    metadata: row.metadata || {},
    createdAt: Number(row.created_at),
  }));
}

export async function saveArtifact(record, content) {
  const bucket = record.bucket || 'shannon-artifacts';
  const objectPath = record.objectPath.replace(/^\/+/, '');
  if (!objectPath || objectPath.split('/').some((part) => part === '..' || part === '.')) {
    throw new Error('invalid artifact object path');
  }
  const body = Buffer.isBuffer(content) ? content : Buffer.from(content);
  const normalized = {
    ...record,
    id: record.id || randomUUID(),
    bucket,
    objectPath,
    sizeBytes: body.length,
    sha256: createHash('sha256').update(body).digest('hex'),
    createdAt: record.createdAt || Date.now(),
  };
  if (!USE_SUPABASE) {
    const target = join(DATA_DIR, 'artifacts', objectPath);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, body);
    local.artifacts.push(normalized);
    persist();
    return normalized;
  }
  const upload = await fetch(
    `${SUPABASE_URL}/storage/v1/object/${encodeURIComponent(bucket)}/${storagePath(objectPath)}`,
    {
      method: 'POST',
      headers: {
        apikey: SUPABASE_KEY,
        authorization: `Bearer ${SUPABASE_KEY}`,
        'content-type': record.contentType || 'application/octet-stream',
        'x-upsert': 'true',
      },
      body,
    },
  );
  if (!upload.ok) throw new Error(`artifact upload failed: ${upload.status} ${(await upload.text()).slice(0, 240)}`);
  await rest('/shannon_artifacts', {
    method: 'POST',
    headers: { prefer: 'resolution=merge-duplicates,return=minimal' },
    body: JSON.stringify([
      {
        id: normalized.id,
        org_id: normalized.orgId,
        scan_id: normalized.scanId || null,
        job_id: normalized.jobId || null,
        bucket,
        object_path: objectPath,
        content_type: normalized.contentType || null,
        size_bytes: normalized.sizeBytes,
        sha256: normalized.sha256,
        metadata: normalized.metadata || {},
        created_at: normalized.createdAt,
      },
    ]),
  });
  return normalized;
}

export async function listArtifacts(orgId, scanId) {
  if (!USE_SUPABASE)
    return local.artifacts.filter((item) => item.orgId === orgId && (!scanId || item.scanId === scanId));
  const scanFilter = scanId ? `&scan_id=eq.${encodeURIComponent(scanId)}` : '';
  const rows = await rest(
    `/shannon_artifacts?org_id=eq.${encodeURIComponent(orgId)}${scanFilter}&order=created_at.desc`,
  );
  return (rows || []).map((row) => ({
    id: row.id,
    orgId: row.org_id,
    scanId: row.scan_id,
    jobId: row.job_id,
    bucket: row.bucket,
    objectPath: row.object_path,
    contentType: row.content_type,
    sizeBytes: Number(row.size_bytes || 0),
    sha256: row.sha256,
    metadata: row.metadata || {},
    createdAt: Number(row.created_at),
  }));
}

export async function signedArtifactUrl(artifact, expiresIn = 300) {
  if (!USE_SUPABASE) return { signedUrl: null, localPath: join(DATA_DIR, 'artifacts', artifact.objectPath) };
  const response = await fetch(
    `${SUPABASE_URL}/storage/v1/object/sign/${encodeURIComponent(artifact.bucket)}/${storagePath(artifact.objectPath)}`,
    {
      method: 'POST',
      headers: {
        apikey: SUPABASE_KEY,
        authorization: `Bearer ${SUPABASE_KEY}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ expiresIn: Math.max(60, Math.min(3600, expiresIn)) }),
    },
  );
  if (!response.ok) throw new Error(`artifact signing failed: ${response.status}`);
  const data = await response.json();
  const relative = data.signedURL || data.signedUrl;
  return { signedUrl: relative?.startsWith('http') ? relative : `${SUPABASE_URL}/storage/v1${relative}` };
}

export async function readArtifact(artifact) {
  if (!artifact?.objectPath || artifact.objectPath.split('/').some((part) => part === '..' || part === '.')) {
    throw new Error('invalid artifact object path');
  }
  if (!USE_SUPABASE) return readFileSync(join(DATA_DIR, 'artifacts', artifact.objectPath));
  const response = await fetch(
    `${SUPABASE_URL}/storage/v1/object/${encodeURIComponent(artifact.bucket)}/${storagePath(artifact.objectPath)}`,
    {
      headers: { apikey: SUPABASE_KEY, authorization: `Bearer ${SUPABASE_KEY}` },
      signal: AbortSignal.timeout(20_000),
    },
  );
  if (!response.ok) throw new Error(`artifact download failed: ${response.status}`);
  return Buffer.from(await response.arrayBuffer());
}

export async function upsertScanFindings({ orgId, userId, projectId = null, scanId, findings }) {
  const now = Date.now();
  const rows = (findings || []).map((raw) => {
    const title = String(raw.title || raw.detail || raw.cls || raw.tool || 'Security finding')
      .split('')
      .map((character) => (character.charCodeAt(0) < 32 ? ' ' : character))
      .join('')
      .trim()
      .slice(0, 180);
    const target = String(raw.target || '');
    const cls = String(raw.cls || raw.tool || 'unknown');
    const fingerprint = createHash('sha256')
      .update(`${orgId}|${projectId || ''}|${cls}|${target}|${title}`)
      .digest('hex');
    return {
      id: `fnd_${fingerprint.slice(0, 16)}`,
      org_id: orgId,
      project_id: projectId,
      fingerprint,
      title,
      severity: ['info', 'low', 'medium', 'high', 'critical'].includes(raw.severity) ? raw.severity : 'medium',
      status: 'new',
      assignee_user_id: null,
      source: 'pentest-scan',
      details: { ...raw, scanId },
      decision: null,
      created_at: now,
      updated_at: now,
    };
  });
  if (!rows.length) return 0;
  if (USE_SUPABASE) {
    await rest('/shannon_findings?on_conflict=org_id,fingerprint', {
      method: 'POST',
      headers: { prefer: 'resolution=merge-duplicates,return=minimal' },
      body: JSON.stringify(rows),
    });
    await rest('/shannon_audit_events', {
      method: 'POST',
      headers: { prefer: 'return=minimal' },
      body: JSON.stringify([
        {
          id: randomUUID(),
          org_id: orgId,
          actor_user_id: userId || null,
          action: 'findings.imported',
          resource_type: 'scan',
          resource_id: scanId,
          metadata: { count: rows.length, source: 'pentest-scan', projectId },
          created_at: now,
        },
      ]),
    });
    return rows.length;
  }
  // The normal dashboard cache owns local finding persistence. Durable workers
  // are a Supabase production feature, so local mode only reports the count.
  return rows.length;
}

export async function upsertSoftwareComponents({ orgId, assetId = null, projectId = null, components }) {
  const now = Date.now();
  const input = (components || []).slice(0, 5000);
  if (!input.length) return [];
  if (!USE_SUPABASE) {
    const output = [];
    for (const component of input) {
      const existing = local.softwareComponents.find((item) => item.orgId === orgId && item.fingerprint === component.fingerprint);
      const normalized = {
        ...(existing || {}), ...component, id: existing?.id || `cmp_${component.fingerprint.slice(0, 20)}`,
        orgId, assetId, projectId, firstSeenAt: existing?.firstSeenAt || now, lastSeenAt: now,
      };
      if (existing) Object.assign(existing, normalized);
      else local.softwareComponents.push(normalized);
      output.push(normalized);
    }
    persist();
    return output;
  }
  const prior = new Map((await listSoftwareComponents(orgId)).map((item) => [item.fingerprint, item]));
  const rows = input.map((component) => ({
    id: `cmp_${component.fingerprint.slice(0, 20)}`, org_id: orgId, asset_id: assetId, project_id: projectId,
    fingerprint: component.fingerprint, source: component.source, source_ref: component.sourceRef,
    name: component.name, version: component.version || '', ecosystem: component.ecosystem || '',
    purl: component.purl || '', cpe: component.cpe || '', licenses: component.licenses || [], metadata: component.metadata || {},
    first_seen_at: prior.get(component.fingerprint)?.firstSeenAt || now, last_seen_at: now,
  }));
  const saved = await rest('/shannon_software_components?on_conflict=org_id,fingerprint', {
    method: 'POST', headers: { prefer: 'resolution=merge-duplicates,return=representation' }, body: JSON.stringify(rows),
  });
  return (saved || []).map(softwareComponentFromRow);
}

export async function listSoftwareComponents(orgId) {
  if (!USE_SUPABASE) return local.softwareComponents.filter((item) => item.orgId === orgId).sort((a, b) => b.lastSeenAt - a.lastSeenAt);
  const rows = await rest(`/shannon_software_components?org_id=eq.${encodeURIComponent(orgId)}&order=last_seen_at.desc&limit=5000`);
  return (rows || []).map(softwareComponentFromRow);
}

export async function listInventoryOrganizations() {
  if (!USE_SUPABASE) return [...new Set(local.softwareComponents.map((item) => item.orgId))];
  const rows = await rest('/shannon_software_components?select=org_id&limit=10000');
  return [...new Set((rows || []).map((row) => row.org_id).filter(Boolean))];
}

export async function upsertVulnerabilityMatches(orgId, matches) {
  const input = (matches || []).slice(0, 20_000);
  if (!input.length) return { matches: [], created: [], newKev: [] };
  const existing = await listVulnerabilityMatches(orgId);
  const byKey = new Map(existing.map((item) => [`${item.componentId}|${item.vulnerabilityId}`, item]));
  const created = [];
  const newKev = [];
  const normalized = input.map((match) => {
    const current = byKey.get(`${match.componentId}|${match.vulnerabilityId}`);
    const item = {
      ...match, id: current?.id || `vul_${createHash('sha256').update(`${orgId}|${match.componentId}|${match.vulnerabilityId}`).digest('hex').slice(0, 20)}`,
      orgId, status: current?.status || 'new', dueAt: current?.dueAt || match.dueAt,
      discoveredAt: current?.discoveredAt || match.discoveredAt || Date.now(), resolvedAt: current?.resolvedAt || null,
    };
    if (!current) created.push(item);
    else if (!current.details?.kev && item.details?.kev) newKev.push(item);
    return item;
  });
  if (!USE_SUPABASE) {
    for (const item of normalized) {
      const current = local.vulnerabilityMatches.find((row) => row.id === item.id);
      if (current) Object.assign(current, item);
      else local.vulnerabilityMatches.push(item);
    }
    persist();
    return { matches: normalized, created, newKev };
  }
  const rows = normalized.map((item) => ({
    id: item.id, org_id: orgId, component_id: item.componentId, vulnerability_id: item.vulnerabilityId,
    aliases: item.aliases || [], source: item.source, severity: item.severity, summary: item.summary,
    details: item.details || {}, status: item.status, due_at: item.dueAt, discovered_at: item.discoveredAt,
    updated_at: item.updatedAt || Date.now(), resolved_at: item.resolvedAt,
  }));
  const saved = await rest('/shannon_vulnerability_matches?on_conflict=org_id,component_id,vulnerability_id', {
    method: 'POST', headers: { prefer: 'resolution=merge-duplicates,return=representation' }, body: JSON.stringify(rows),
  });
  return { matches: (saved || []).map(vulnerabilityMatchFromRow), created, newKev };
}

export async function listVulnerabilityMatches(orgId) {
  if (!USE_SUPABASE) return local.vulnerabilityMatches.filter((item) => item.orgId === orgId).sort((a, b) => b.updatedAt - a.updatedAt);
  const rows = await rest(`/shannon_vulnerability_matches?org_id=eq.${encodeURIComponent(orgId)}&order=updated_at.desc&limit=10000`);
  return (rows || []).map(vulnerabilityMatchFromRow);
}

export async function updateVulnerabilityMatch(orgId, id, patch) {
  const allowed = new Set(['new', 'acknowledged', 'patching', 'resolved', 'accepted']);
  if (patch.status !== undefined && !allowed.has(patch.status)) throw new Error('Invalid vulnerability status.');
  const now = Date.now();
  if (!USE_SUPABASE) {
    const item = local.vulnerabilityMatches.find((row) => row.orgId === orgId && row.id === id);
    if (!item) return null;
    if (patch.status !== undefined) item.status = patch.status;
    if (patch.dueAt !== undefined) item.dueAt = patch.dueAt;
    item.resolvedAt = item.status === 'resolved' ? (item.resolvedAt || now) : null;
    item.updatedAt = now;
    persist();
    return item;
  }
  const body = { updated_at: now };
  if (patch.status !== undefined) { body.status = patch.status; body.resolved_at = patch.status === 'resolved' ? now : null; }
  if (patch.dueAt !== undefined) body.due_at = patch.dueAt;
  const rows = await rest(`/shannon_vulnerability_matches?org_id=eq.${encodeURIComponent(orgId)}&id=eq.${encodeURIComponent(id)}`, {
    method: 'PATCH', body: JSON.stringify(body),
  });
  return vulnerabilityMatchFromRow(rows?.[0]);
}

export async function getDefenseProgram(orgId) {
  if (!USE_SUPABASE) return local.defensePrograms.find((item) => item.orgId === orgId) || null;
  const rows = await rest(`/shannon_defense_programs?org_id=eq.${encodeURIComponent(orgId)}&limit=1`);
  return defenseProgramFromRow(rows?.[0]);
}

export async function saveDefenseProgram(record) {
  const now = Date.now();
  const existing = await getDefenseProgram(record.orgId);
  const normalized = {
    orgId: record.orgId,
    enabled: record.enabled === true,
    cadenceHours: Math.max(1, Math.min(168, Number(record.cadenceHours || 24))),
    responseMode: record.responseMode === 'bounded-auto' ? 'bounded-auto' : 'recommend',
    nextRunAt: record.enabled === true ? Number(record.nextRunAt || existing?.nextRunAt || now) : null,
    lastRunAt: record.lastRunAt ?? existing?.lastRunAt ?? null,
    lastCycleId: record.lastCycleId ?? existing?.lastCycleId ?? null,
    createdBy: record.createdBy || existing?.createdBy || null,
    createdAt: existing?.createdAt || record.createdAt || now,
    updatedAt: now,
  };
  if (!USE_SUPABASE) {
    local.defensePrograms = local.defensePrograms.filter((item) => item.orgId !== record.orgId);
    local.defensePrograms.push(normalized);
    persist();
    return normalized;
  }
  const rows = await rest('/shannon_defense_programs', {
    method: 'POST',
    headers: { prefer: 'resolution=merge-duplicates,return=representation' },
    body: JSON.stringify([{
      org_id: normalized.orgId, enabled: normalized.enabled, cadence_hours: normalized.cadenceHours,
      response_mode: normalized.responseMode, next_run_at: normalized.nextRunAt, last_run_at: normalized.lastRunAt,
      last_cycle_id: normalized.lastCycleId, created_by: normalized.createdBy, created_at: normalized.createdAt,
      updated_at: normalized.updatedAt,
    }]),
  });
  return defenseProgramFromRow(rows?.[0]);
}

export async function claimDueDefensePrograms(limit = 20, now = Date.now()) {
  if (!USE_SUPABASE) {
    const due = local.defensePrograms
      .filter((item) => item.enabled && Number(item.nextRunAt || 0) <= now)
      .sort((a, b) => Number(a.nextRunAt || 0) - Number(b.nextRunAt || 0))
      .slice(0, Math.max(1, Math.min(100, limit)));
    for (const item of due) {
      item.lastRunAt = now;
      item.nextRunAt = now + item.cadenceHours * 3_600_000;
      item.updatedAt = now;
    }
    if (due.length) persist();
    return due;
  }
  const rows = await rest('/rpc/shannon_claim_due_defense_programs', {
    method: 'POST', body: JSON.stringify({ p_limit: limit, p_now: now }),
  });
  return (rows || []).map(defenseProgramFromRow);
}

export async function listDefenseAssets(orgId) {
  if (!USE_SUPABASE) return local.defenseAssets.filter((item) => item.orgId === orgId).sort((a, b) => b.createdAt - a.createdAt);
  const rows = await rest(`/shannon_defense_assets?org_id=eq.${encodeURIComponent(orgId)}&order=created_at.desc`);
  return (rows || []).map(defenseAssetFromRow);
}

export async function saveDefenseAsset(record) {
  const now = Date.now();
  const existing = (await listDefenseAssets(record.orgId)).find((item) => item.type === record.type && item.locator === record.locator);
  const normalized = {
    id: existing?.id || record.id || randomUUID(), orgId: record.orgId, projectId: record.projectId || null,
    type: record.type, name: record.name, locator: record.locator, criticality: record.criticality || 'medium',
    status: record.status === 'paused' ? 'paused' : 'active', coverage: record.coverage === 'online' ? 'online' : 'inventory',
    config: record.config || {}, createdBy: record.createdBy || existing?.createdBy || null, createdAt: existing?.createdAt || record.createdAt || now, updatedAt: now,
  };
  if (!USE_SUPABASE) {
    const duplicate = local.defenseAssets.find((item) => item.orgId === normalized.orgId && item.type === normalized.type && item.locator === normalized.locator);
    if (duplicate) Object.assign(duplicate, normalized, { id: duplicate.id, createdAt: duplicate.createdAt });
    else local.defenseAssets.unshift(normalized);
    persist();
    return duplicate || normalized;
  }
  const rows = await rest('/shannon_defense_assets?on_conflict=org_id,type,locator', {
    method: 'POST', headers: { prefer: 'resolution=merge-duplicates,return=representation' },
    body: JSON.stringify([{
      id: normalized.id, org_id: normalized.orgId, project_id: normalized.projectId, type: normalized.type,
      name: normalized.name, locator: normalized.locator, criticality: normalized.criticality, status: normalized.status,
      coverage: normalized.coverage, config: normalized.config, created_by: normalized.createdBy,
      created_at: normalized.createdAt, updated_at: normalized.updatedAt,
    }]),
  });
  return defenseAssetFromRow(rows?.[0]);
}

export async function updateDefenseAsset(orgId, id, patch) {
  const now = Date.now();
  if (!USE_SUPABASE) {
    const asset = local.defenseAssets.find((item) => item.orgId === orgId && item.id === id);
    if (!asset) return null;
    if (patch.status !== undefined) asset.status = patch.status;
    if (patch.coverage !== undefined) asset.coverage = patch.coverage;
    if (patch.config !== undefined) asset.config = patch.config;
    asset.updatedAt = now;
    persist();
    return asset;
  }
  const body = { updated_at: now };
  if (patch.status !== undefined) body.status = patch.status;
  if (patch.coverage !== undefined) body.coverage = patch.coverage;
  if (patch.config !== undefined) body.config = patch.config;
  const rows = await rest(`/shannon_defense_assets?id=eq.${encodeURIComponent(id)}&org_id=eq.${encodeURIComponent(orgId)}`, {
    method: 'PATCH', body: JSON.stringify(body),
  });
  return defenseAssetFromRow(rows?.[0]);
}

export async function deleteDefenseAsset(orgId, id) {
  if (!USE_SUPABASE) {
    const before = local.defenseAssets.length;
    local.defenseAssets = local.defenseAssets.filter((item) => !(item.orgId === orgId && item.id === id));
    if (local.defenseAssets.length !== before) persist();
    return local.defenseAssets.length !== before;
  }
  const rows = await rest(`/shannon_defense_assets?id=eq.${encodeURIComponent(id)}&org_id=eq.${encodeURIComponent(orgId)}`, { method: 'DELETE' });
  return Array.isArray(rows) && rows.length > 0;
}

export async function listDefenseCycles(orgId, limit = 30) {
  if (!USE_SUPABASE) return local.defenseCycles.filter((item) => item.orgId === orgId).sort((a, b) => b.createdAt - a.createdAt).slice(0, limit);
  const rows = await rest(`/shannon_defense_cycles?org_id=eq.${encodeURIComponent(orgId)}&order=created_at.desc&limit=${Math.min(100, limit)}`);
  return (rows || []).map(defenseCycleFromRow);
}

export async function saveDefenseCycle(record) {
  const normalized = {
    id: record.id || randomUUID(), orgId: record.orgId, jobId: record.jobId || null, status: record.status,
    window: record.window || {}, snapshot: record.snapshot || {}, learning: record.learning || {}, actions: record.actions || {},
    error: record.error || null, startedAt: record.startedAt || Date.now(), completedAt: record.completedAt || null,
    createdAt: record.createdAt || Date.now(),
  };
  if (!USE_SUPABASE) {
    local.defenseCycles = local.defenseCycles.filter((item) => item.id !== normalized.id);
    local.defenseCycles.unshift(normalized);
    if (local.defenseCycles.length > 500) local.defenseCycles.length = 500;
    const program = local.defensePrograms.find((item) => item.orgId === normalized.orgId);
    if (program && normalized.status === 'completed') program.lastCycleId = normalized.id;
    persist();
    return normalized;
  }
  const rows = await rest('/shannon_defense_cycles', {
    method: 'POST', headers: { prefer: 'resolution=merge-duplicates,return=representation' },
    body: JSON.stringify([{
      id: normalized.id, org_id: normalized.orgId, job_id: normalized.jobId, status: normalized.status,
      window: normalized.window, snapshot: normalized.snapshot, learning: normalized.learning, actions: normalized.actions,
      error: normalized.error, started_at: normalized.startedAt, completed_at: normalized.completedAt, created_at: normalized.createdAt,
    }]),
  });
  if (normalized.status === 'completed') {
    await rest(`/shannon_defense_programs?org_id=eq.${encodeURIComponent(normalized.orgId)}`, {
      method: 'PATCH', body: JSON.stringify({ last_cycle_id: normalized.id, updated_at: Date.now() }),
    });
  }
  return defenseCycleFromRow(rows?.[0]);
}

export async function getDefenseTelemetry(orgId, since = Date.now() - 86_400_000) {
  if (!USE_SUPABASE) return { routes: [], events: [], findings: [], jobs: await listJobs(orgId, 200) };
  const [routeRows, eventRows, findingRows, jobs] = await Promise.all([
    rest(`/shannon_edge_routes?org_id=eq.${encodeURIComponent(orgId)}`),
    rest(`/shannon_defense_events?org_id=eq.${encodeURIComponent(orgId)}&created_at=gte.${since}&order=created_at.desc&limit=1000`),
    rest(`/shannon_findings?org_id=eq.${encodeURIComponent(orgId)}&order=updated_at.desc&limit=1000`),
    listJobs(orgId, 200),
  ]);
  return {
    routes: (routeRows || []).map((row) => ({ host: row.host, origin: row.origin, mode: row.mode, createdAt: Number(row.created_at) })),
    events: (eventRows || []).map((row) => ({ id: row.id, cls: row.cls, severity: row.severity, status: row.status, enforced: row.enforced === true, at: row.at, createdAt: Number(row.created_at) })),
    findings: (findingRows || []).map((row) => ({ id: row.id, severity: row.severity, status: row.status, updatedAt: Number(row.updated_at) })),
    jobs,
  };
}

export async function purgeExpiredEnterpriseData({
  authTokenDays = 7,
  deliveryDays = 90,
  operationalDays = 30,
  completedJobDays = 30,
  artifactDays = 90,
} = {}) {
  const now = Date.now();
  const cutoffs = {
    auth: now - authTokenDays * 86_400_000,
    deliveries: now - deliveryDays * 86_400_000,
    operations: now - operationalDays * 86_400_000,
    jobs: now - completedJobDays * 86_400_000,
    artifacts: now - artifactDays * 86_400_000,
  };
  if (!USE_SUPABASE) {
    local.authTokens = local.authTokens.filter((x) => x.expiresAt >= cutoffs.auth);
    local.deliveries = local.deliveries.filter((x) => x.createdAt >= cutoffs.deliveries);
    local.operations = local.operations.filter((x) => x.createdAt >= cutoffs.operations);
    local.jobs = local.jobs.filter(
      (x) => !['succeeded', 'cancelled', 'dead-letter'].includes(x.status) || x.updatedAt >= cutoffs.jobs,
    );
    persist();
    return { ok: true, backend: 'local' };
  }
  const oldArtifacts = await rest(
    `/shannon_artifacts?created_at=lt.${cutoffs.artifacts}&select=id,bucket,object_path&limit=1000`,
  );
  for (const artifact of oldArtifacts || []) {
    const response = await fetch(
      `${SUPABASE_URL}/storage/v1/object/${encodeURIComponent(artifact.bucket)}/${storagePath(artifact.object_path)}`,
      {
        method: 'DELETE',
        headers: { apikey: SUPABASE_KEY, authorization: `Bearer ${SUPABASE_KEY}` },
      },
    );
    if (!response.ok && response.status !== 404) throw new Error(`artifact delete failed: ${response.status}`);
  }
  if (oldArtifacts?.length) {
    await rest(`/shannon_artifacts?id=in.(${oldArtifacts.map((x) => encodeURIComponent(x.id)).join(',')})`, {
      method: 'DELETE',
      headers: { prefer: 'return=minimal' },
    });
  }
  await Promise.all([
    rest(`/shannon_auth_tokens?expires_at=lt.${cutoffs.auth}`, {
      method: 'DELETE',
      headers: { prefer: 'return=minimal' },
    }),
    rest(`/shannon_delivery_events?created_at=lt.${cutoffs.deliveries}`, {
      method: 'DELETE',
      headers: { prefer: 'return=minimal' },
    }),
    rest(`/shannon_operational_events?created_at=lt.${cutoffs.operations}`, {
      method: 'DELETE',
      headers: { prefer: 'return=minimal' },
    }),
    rest(`/shannon_jobs?status=in.(succeeded,cancelled,dead-letter)&updated_at=lt.${cutoffs.jobs}`, {
      method: 'DELETE',
      headers: { prefer: 'return=minimal' },
    }),
  ]);
  return { ok: true, backend: 'supabase', artifactsDeleted: oldArtifacts?.length || 0 };
}
