import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import _crypto from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import Anthropic from '@anthropic-ai/sdk';
import express from 'express';
import QRCode from 'qrcode';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import { crawl } from '../../crawler.mjs';
import { runDefender } from '../../defender/agent.mjs';
import { httpProxyConnector } from '../../defender/connectors.mjs';
import { createSelfDefense } from '../../defender/middleware.mjs';
import { cmdContext, sqliExtract, ssrfMetadata } from '../../impact.mjs';
import { checkIpControl, ipInCidr, ipVerifyToken, parseCidr, verificationInstructions } from '../../ip-ownership.mjs';
import { sendMonitorAlert } from '../../monitor.mjs';
import {
  COMPLIANCE,
  PROBERS,
  detectionRule,
  fetchT,
  injReq,
  login,
  setScanOrigin,
  setSessionHeaders,
  setTestMark,
} from '../../purple-engine.mjs';
import { diffRuns } from './agent-history.mjs';
import { runAgentCampaign, runAgentLoop } from './agent-loop.mjs';
import { toJson, toMarkdown, toSarif } from './agent-report.mjs';
import { runSecurityTeam } from './agent-team.mjs';
import { analyzeSurface } from './agent-understand.mjs';
import { describeAiError, runChat, runResearch } from './assistant-ai.mjs';
import {
  API_SCOPES,
  ASSISTANT_INSTRUCTIONS,
  CHAT_LIMITS,
  RESEARCH_INSTRUCTIONS,
  SHARE_TYPES,
  buildOrgContext,
  cleanUserText,
  conversationTitle,
  domainMatches,
  newApiKey,
  newShareToken,
  normalizeMemoryText,
  normalizeScopes,
  parseApiKey,
  parseRememberCommand,
  parseShareToken,
  researchMaterial,
  secretMatches,
  shareExpiry,
  shareUsable,
  toApiMessages,
  v1RouteScope,
} from './assistant.mjs';
import { clientAddress } from './client-address.mjs';
import { locateFinding } from './code-locate.mjs';
import {
  CODE_SCAN_MAX_CHARS,
  FILE_IS_DATA_RULE,
  checkScanResult,
  fileBlock,
  outputBudget,
  parseModelJson,
  safeFilename,
} from './code-scan.mjs';
import {
  cancelOrder,
  catalogItem,
  commerceEnabled,
  creditBalance,
  creditGrantFor,
  markCardPaid,
  newOrder,
  paymentInstructions,
  paymentMethods,
  publicCatalog,
  reviewOrder,
  submitEvidence,
} from './commerce.mjs';
import { evaluateMatcher, sanitizeCheck } from './custom-check.mjs';
import {
  addVerified,
  allMonitors,
  appendAudit,
  appendDefenseEvent,
  createOrganization,
  getAgentRun,
  getFinding,
  getMembership,
  getOrganization,
  getScanOwner,
  initDb,
  isSupabase,
  listAgentRuns,
  listAudit,
  listDefenseEventOrgIds,
  listDefenseEvents,
  listDefenseEventsSince,
  listEdgeRoutes,
  listFindings,
  listMembers,
  listMonitors,
  listOrganizations,
  listProjects,
  loadLeaderboard,
  loadUserSettings,
  loadUsers,
  loadVerified,
  refreshDbIfStale,
  removeEdgeRoute,
  removeMembership,
  removeMonitor,
  removeVerified,
  saveAgentRun,
  saveEdgeRoute,
  saveFinding,
  saveLeaderboard,
  saveMembership,
  saveMonitor,
  saveProject,
  saveScanOwner,
  saveUserSettings,
  saveUsers,
  touchMonitor,
  updateDefenseEvent,
  waitForUserWrites,
} from './db.mjs';
import { DAY, buildDefenseDigest, lastCompleteWeek } from './defender-digest.mjs';
import { cleanDetection, createIntakeGate } from './defender-intake.mjs';
import {
  OWN_TEST_SCAN_TTL_MS,
  createOwnTestLedger,
  isOwnTest,
  signOwnTest,
  siteName,
  verifyOwnTest,
} from './defender-own-test.mjs';
import { DEFENDER_RULES, normalizePolicy, policyFor, sdkBundle } from './defender-policy.mjs';
import {
  addCreditGrant,
  apiKeys,
  appendOperationalEvent,
  assistantConversations,
  assistantMemory,
  consumeAuthToken,
  consumeCredits,
  consumeScanAuthGrant,
  consumeUsage,
  createAuthToken,
  createScanAuthGrant,
  defenderBans,
  deleteDefenseAsset,
  deleteIntegration,
  deleteOrgSecret,
  enqueueJob,
  enterpriseHealth,
  findAuthToken,
  findSsoIdentity,
  getCommerceOrder,
  getDefenseProgram,
  getEntitlement,
  getIntegration,
  getJob,
  getOrgSecret,
  guardActions,
  guardAgents,
  guardCommands,
  guardConnections,
  guardEndpoint,
  guardHashes,
  guardIncidents,
  guardSamples,
  guardSettings,
  guardState,
  listArtifacts,
  listCommerceOrders,
  listCreditGrants,
  listDefenseAssets,
  listDefenseCycles,
  listDeliveries,
  listIntegrations,
  listJobs,
  listOperationalEvents,
  listOrgSecrets,
  listSoftwareComponents,
  listUsage,
  listVulnerabilityMatches,
  readArtifact,
  researchReports,
  saveCommerceOrder,
  saveDefenseAsset,
  saveDefenseProgram,
  saveEntitlement,
  saveIntegration,
  saveOrgSecret,
  saveSsoIdentity,
  shareLinks,
  signedArtifactUrl,
  updateDefenseAsset,
  updateJob,
  updateVulnerabilityMatch,
  upsertSoftwareComponents,
} from './enterprise-db.mjs';
import { queueIntegrationEvent, sendEmail } from './enterprise-integrations.mjs';
import {
  consumeRecoveryCode,
  createRecoveryCodes,
  decryptSecret,
  encryptSecret,
  hashRecoveryCodes,
  hashToken,
  newTotpSecret,
  publicBaseUrl,
  randomToken,
  signChallenge,
  totpUri,
  verifyChallenge,
  verifyTotp,
} from './enterprise-security.mjs';
import { openPullRequest } from './github-pr.mjs';
import { registerEndpointRoutes } from './guard/endpoint-routes.mjs';
import { createEndpointService } from './guard/endpoint.mjs';
import { createGuardEngine } from './guard/engine.mjs';
import { createGoogleProvider } from './guard/google.mjs';
import { loadBadIps } from './guard/intel.mjs';
import { createMicrosoftProvider } from './guard/microsoft.mjs';
import { registerGuardRoutes } from './guard/routes.mjs';
import { createCapeClient } from './guard/sandbox.mjs';
import { createSimulationProvider } from './guard/simulate.mjs';
import { gatherLeads } from './leads.mjs';
import { createLoginGuard } from './login-guard.mjs';
import { diffToDelta, dueMonitors } from './monitor-schedule.mjs';
import { applyLineFix, generatePatch } from './patch.mjs';
import { analyzePersonalThreat } from './personal-shield.mjs';
import { renderPricingPage } from './pricing-page.mjs';
import { isLocalHost, isPrivateAddress, publicOriginAllowed } from './public-address.mjs';
import { runInSandbox, sandboxAvailable } from './sandbox.mjs';
import { SCAN_PHASES, createSeen, progressSince } from './scan-progress.mjs';
import { renderSecurityArea, renderSecurityIndex, renderSitemap, securityArea } from './security-pages.mjs';
import { renderMarkdown, renderShareGone, renderSharedConversation, renderSharedResearch } from './share-page.mjs';
import { refusedBy } from './site-firewall.mjs';
import { ROLES, can, canChangeMember, sanitizeLabel, slugifyOrg, validateFindingTransition } from './team-access.mjs';
import { fetchGithubSbom, manualSoftwareComponent, parseSbom } from './vulnerability-management.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const ROOT = join(__dirname, '..', '..');
const WORKSPACES = join(ROOT, 'workspaces');
const SHANNON_HOME = process.env.SHANNON_DATA_DIR || join(os.homedir(), '.shannon');
const LEADERBOARD_PATH = join(SHANNON_HOME, 'leaderboard.json');
const SETTINGS_PATH = join(ROOT, '.shannon-settings.json');
const PORT = process.env.PORT || 3000;

const app = express();
// Railway / Vercel / any reverse proxy: trust the X-Forwarded-* headers so
// req.protocol correctly reports "https" (not "http"). Without this the
// Google OAuth redirect URI is built with http://, which Google rejects.
app.set('trust proxy', 1);
app.disable('x-powered-by');
// First of all: req.ip is the visitor's own address (see client-address.mjs). Everything below that
// counts, limits, bans or compares by address depends on it.
app.use(clientAddress());
app.use(
  express.json({
    limit: '2mb',
    verify(req, _res, buffer) {
      if (req.originalUrl === '/api/billing/webhook') req.rawBody = Buffer.from(buffer);
    },
  }),
);
app.use((req, res, next) => {
  res.setHeader('x-content-type-options', 'nosniff');
  res.setHeader('x-frame-options', 'DENY');
  res.setHeader('referrer-policy', 'strict-origin-when-cross-origin');
  res.setHeader('permissions-policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('cross-origin-opener-policy', 'same-origin');
  // API answers carry account data. Neither a browser nor a proxy keeps a copy. (Event streams and
  // downloads set their own value afterwards.)
  if (req.path.startsWith('/api/')) res.setHeader('cache-control', 'no-store');
  // HTTPS only (trust proxy makes req.secure reflect the edge). Never sent over plain local http.
  if (req.secure) res.setHeader('strict-transport-security', 'max-age=31536000; includeSubDomains');
  res.setHeader(
    'content-security-policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
  );
  next();
});

// Browser requests with an Origin header must be same-origin. SameSite cookies are useful defense in
// depth, but this explicit check protects every mutating JSON route, including future routes.
app.use((req, res, next) => {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();
  const origin = req.headers.origin;
  if (!origin) return next(); // CLI/service clients generally omit Origin and authenticate separately.
  let expected;
  try {
    expected = `${req.protocol}://${req.get('host')}`;
  } catch {
    return res.status(403).json({ error: 'Invalid request origin.' });
  }
  if (origin !== expected) return res.status(403).json({ error: 'Cross-origin request rejected.' });
  next();
});

const RATE_BUCKETS = new Map();
function rateLimit(key, { limit, windowMs }) {
  const now = Date.now();
  const rec = RATE_BUCKETS.get(key);
  if (!rec || now >= rec.resetAt) {
    // Finished windows are dropped once the table grows, so many distinct addresses cannot fill memory.
    if (RATE_BUCKETS.size >= 20_000) {
      for (const [k, v] of RATE_BUCKETS) if (now >= v.resetAt) RATE_BUCKETS.delete(k);
      while (RATE_BUCKETS.size >= 20_000) RATE_BUCKETS.delete(RATE_BUCKETS.keys().next().value);
    }
    RATE_BUCKETS.set(key, { count: 1, resetAt: now + windowMs });
    return { ok: true };
  }
  rec.count += 1;
  return rec.count <= limit ? { ok: true } : { ok: false, retryAfter: Math.ceil((rec.resetAt - now) / 1000) };
}
function limited(req, res, bucket, limit, windowMs) {
  const ip = req.ip || req.socket?.remoteAddress || 'unknown';
  const hit = rateLimit(`${bucket}:${ip}`, { limit, windowMs });
  if (hit.ok) return false;
  res.setHeader('retry-after', String(hit.retryAfter));
  res.status(429).json({ error: 'Too many requests. Try again later.' });
  return true;
}

// ── Self-defense (opt-in) ───────────────────────────────────────────────────────────────────────
// Run the Defender inside the app it protects. The inline proxy assumes Shannon sits in front of a
// SEPARATE app reached over a port; when the app to protect is this dashboard, that proxy can only
// bind loopback in its own container and no request can ever reach it. As middleware the defender
// sits on the real request path — no port, no DNS or TLS work, nothing to reconnect after a deploy.
// Mounted after express.json() so a JSON body is already parsed and can be inspected, and before
// the routes so a confirmed attack is stopped before it reaches any of them.
// Off unless SHANNON_DEFEND_SELF=1, and monitor-only unless SHANNON_DEFEND_SELF_MODE=enforce.
// Repeat-offender ban. Off unless SHANNON_DEFEND_SELF_BAN=1, and report-only ("would have banned")
// unless SHANNON_DEFEND_SELF_BAN_MODE=enforce — so an operator sees the policy's decisions before it
// is allowed to refuse anyone. Only confirmed ENFORCEABLE classes ever count (see middleware.mjs).
const SELF_BAN = {
  enabled: process.env.SHANNON_DEFEND_SELF_BAN === '1',
  enforce: process.env.SHANNON_DEFEND_SELF_BAN_MODE === 'enforce',
  threshold: Number(process.env.SHANNON_DEFEND_SELF_BAN_THRESHOLD || 5),
  windowMs: Number(process.env.SHANNON_DEFEND_SELF_BAN_WINDOW_MS || 60_000),
  ttlMs: Number(process.env.SHANNON_DEFEND_SELF_BAN_TTL_MS || 15 * 60_000),
};
// Bans are persisted so a redeploy does not forgive a scanner, and so every instance shares them.
const DEFENDER_BAN_STORE = {
  async load() {
    const now = Date.now();
    const rows = await defenderBans.list({}, { orderBy: 'until', limit: 500 });
    for (const row of rows) if (!(row.until > now)) defenderBans.remove(row.id).catch(() => {});
    return rows.filter((row) => row.until > now);
  },
  save: ({ ip, until, reason }) =>
    defenderBans.save({ id: ip, ip, until, reason: reason || null, createdAt: Date.now() }),
  remove: (ip) => defenderBans.remove(ip),
};
const SELF_DEFENSE =
  process.env.SHANNON_DEFEND_SELF === '1'
    ? createSelfDefense({
        mode: process.env.SHANNON_DEFEND_SELF_MODE === 'enforce' ? 'enforce' : 'monitor',
        ban: SELF_BAN,
        banStore: DEFENDER_BAN_STORE,
        honeypot: process.env.SHANNON_DEFEND_SELF_HONEYPOT === '0' ? false : undefined,
        scanners: process.env.SHANNON_DEFEND_SELF_SCANNERS === '0' ? false : undefined,
      })
    : null;
// Live subscribers of /api/defender/self/events (platform operators watching the Defender page).
const SELF_SSE = new Set();
function selfSseBroadcast(payload) {
  const line = `data: ${JSON.stringify(payload)}\n\n`;
  for (const client of SELF_SSE) {
    try {
      client.write(line);
    } catch {}
  }
}
if (SELF_DEFENSE) {
  app.use(SELF_DEFENSE.middleware);
  console.log(
    `[defender] self-defense active in ${SELF_DEFENSE.getMode()} mode; repeat-offender ban ${SELF_BAN.enabled ? (SELF_BAN.enforce ? 'ENFORCING' : 'report-only') : 'off'}`,
  );
  // Every detection and ban decision: stream it live; and when a platform organization is
  // configured, persist it and fan it out to that organization's alert integrations exactly as
  // SDK and edge detections already are. Detect-only classes (an apostrophe, an HTML tag) are
  // streamed for visibility but never alerted — they would page someone for every signup.
  SELF_DEFENSE.subscribe((payload) => {
    selfSseBroadcast(payload);
    const orgId = process.env.SHANNON_PLATFORM_ORG_ID || '';
    if (!orgId) return;
    const isBan = payload.type === 'ban';
    const confirmed = payload.type === 'detection' && payload.recommendedAction === 'block-inline';
    if (!isBan && !confirmed) return;
    const enforced = isBan ? payload.enforce === true : payload.enforced === true;
    const event = {
      id: randomUUID(),
      orgId,
      userId: null,
      at: payload.at,
      method: isBan ? 'BAN' : String(payload.method || '').slice(0, 10),
      url: isBan
        ? `repeat offender ${payload.ip} (${payload.count} confirmed attacks)`
        : String(payload.url || '').slice(0, 300),
      cls: isBan ? 'repeat-offender' : String(payload.cls || '').slice(0, 60),
      // eventText() in enterprise-integrations titles a message as data.title || event.type; without
      // this a Slack alert would read "[HIGH] defender.detection (open)".
      title: isBan
        ? payload.reason === 'honeypot'
          ? `Scanner ${payload.ip} ${payload.enforce ? 'banned' : 'would be banned'} after requesting a honeypot path on the dashboard`
          : payload.reason === 'scanner-tool'
            ? `Attack tool at ${payload.ip} ${payload.enforce ? 'banned' : 'would be banned'} after identifying itself to the dashboard`
            : `Repeat offender ${payload.ip} ${payload.enforce ? 'banned' : 'would be banned'} after ${payload.count} confirmed attacks on the dashboard`
        : `${String(payload.cls || 'attack')} ${enforced ? 'blocked' : 'detected'} on the dashboard: ${String(payload.method || '')} ${String(payload.url || '').slice(0, 120)}`,
      enforced,
      srcIp: payload.srcIp || payload.ip || null,
      severity: isBan ? 'high' : defenderSeverity(payload.cls),
      source: 'self',
      status: enforced ? 'contained' : 'open',
      metadata: { platform: true, ...(isBan ? { until: payload.until, count: payload.count } : {}) },
      createdAt: Date.now(),
    };
    appendDefenseEvent(event);
    sendDefenseAlert(orgId, event, null, 'self');
  });
  if (!process.env.SHANNON_PLATFORM_ORG_ID) {
    console.warn(
      '[defender] SHANNON_PLATFORM_ORG_ID is not set — self-defense detections stream live to operators but are not persisted or sent to alert integrations',
    );
  }
}

// Public, server-rendered landing pages for each security-testing area (see security-pages.mjs).
app.get('/security-testing', (req, res) => {
  res.setHeader('cache-control', 'public, max-age=300');
  res.type('html').send(renderSecurityIndex({ baseUrl: publicBaseUrl(req) }));
});
app.get('/security-testing/:slug', (req, res) => {
  const area = securityArea(String(req.params.slug || ''));
  if (!area)
    return res
      .status(404)
      .type('html')
      .send(renderSecurityIndex({ baseUrl: publicBaseUrl(req) }));
  res.setHeader('cache-control', 'public, max-age=300');
  res.type('html').send(renderSecurityArea(area, { baseUrl: publicBaseUrl(req), compliance: COMPLIANCE }));
});
app.get('/pricing', (req, res) => {
  res.setHeader('cache-control', 'public, max-age=60');
  res.type('html').send(renderPricingPage(commerceCatalog(), { baseUrl: publicBaseUrl(req) }));
});
app.get('/sitemap.xml', (req, res) => {
  res.type('application/xml').send(renderSitemap(publicBaseUrl(req)));
});
app.get('/robots.txt', (req, res) => {
  res.type('text/plain').send(`User-agent: *
Allow: /
Disallow: /api/
Sitemap: ${publicBaseUrl(req)}/sitemap.xml
`);
});

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
  } catch {
    return _crypto.randomBytes(32).toString('hex');
  }
}
const SESSION_SECRET = process.env.SHANNON_SESSION_SECRET || ensureSessionSecret();
const SESSION_TTL_DAYS = 30;
const COOKIE_SECURE = process.env.NODE_ENV === 'production';

// This failure is silent and expensive, so say it loudly at boot. ensureSessionSecret() persists the
// signing key to ~/.shannon/.session-secret — fine locally, useless on a platform with an ephemeral
// filesystem (Railway, Fly, Heroku, any container rebuild): the key is regenerated on EVERY deploy,
// which invalidates every session already issued. Users keep their cookie and still look signed in,
// but verifySession() fails, getUser() returns null, and every authenticated route answers 401 —
// so the whole app appears broken with no error that points at the cause.
if (!process.env.SHANNON_SESSION_SECRET) {
  if (process.env.NODE_ENV === 'production') {
    throw new Error(
      'SHANNON_SESSION_SECRET is required in production; use an independent random value of at least 32 bytes',
    );
  }
  console.warn(
    '[auth] WARNING: SHANNON_SESSION_SECRET is not set — using a key stored on local disk.\n' +
      '       On an ephemeral filesystem this key changes on every deploy and silently logs out\n' +
      '       every user (their requests start returning 401 while they still appear signed in).\n' +
      '       Set SHANNON_SESSION_SECRET to a fixed random value to keep sessions across deploys:\n' +
      '         openssl rand -hex 32',
  );
}

const FREE_LIMITS = { scans: 5, codeFiles: 25, agentRuns: 10 };
const PRO_LIMITS = { scans: 100, codeFiles: 1000, agentRuns: 500 };
const FREE_PLAN = {
  plan: 'free',
  label: 'Free',
  pricing: { monthly: 0, yearly: 0, currency: 'GBP' },
  features: ['Dashboard', 'Web pentest', 'AI Agent', 'Code Scan', 'Defender', 'Team Workspace'],
  limits: FREE_LIMITS,
};
const PRO_PLAN = {
  plan: 'pro',
  label: 'Pro',
  pricing: {
    monthly: Number(process.env.SHANNON_PRO_MONTHLY_GBP || 99),
    yearly: Number(process.env.SHANNON_PRO_YEARLY_GBP || 990),
    currency: 'GBP',
  },
  features: ['Everything in Free', 'Higher organization limits', 'SSO and SCIM', 'Priority operations support'],
  limits: PRO_LIMITS,
};

function stripeCardReady() {
  return !!(process.env.STRIPE_SECRET_KEY && process.env.STRIPE_WEBHOOK_SECRET);
}

function billingEnabled() {
  return !!(
    process.env.STRIPE_SECRET_KEY &&
    process.env.STRIPE_WEBHOOK_SECRET &&
    process.env.STRIPE_PRO_MONTHLY_PRICE_ID
  );
}

async function organizationPlan(orgId) {
  const entitlement = await getEntitlement(orgId);
  const paid =
    entitlement?.plan === 'pro' &&
    ['active', 'trialing'].includes(entitlement.status) &&
    (!entitlement.currentPeriodEnd || entitlement.currentPeriodEnd > Date.now());
  return {
    plan: paid ? 'pro' : 'free',
    limits: paid ? { ...PRO_LIMITS, ...(entitlement.limits || {}) } : FREE_LIMITS,
    entitlement,
  };
}

// Daily plan allowance first; once it is spent, fall back to prepaid credits (soonest-expiring first).
export async function consumeOrgAllowance(orgId, metric, amount = 1) {
  const current = await organizationPlan(orgId);
  const limit = Number(current.limits[metric] || 0);
  const usage = await consumeUsage(orgId, metric, amount, limit);
  if (usage.allowed) return { allowed: true, source: 'daily', used: usage.used, limit, plan: current.plan };
  const credit = await consumeCredits(orgId, metric, amount);
  if (credit.allowed)
    return {
      allowed: true,
      source: 'credits',
      used: usage.used,
      limit,
      plan: current.plan,
      creditsRemaining: credit.remaining,
    };
  return { allowed: false, source: null, used: usage.used, limit, plan: current.plan };
}

async function consumeOrgQuota(ctx, res, metric, amount = 1) {
  const quota = await consumeOrgAllowance(ctx.org.id, metric, amount);
  res.setHeader('x-shannon-limit', String(quota.limit));
  res.setHeader('x-shannon-remaining', String(Math.max(0, quota.limit - quota.used)));
  if (quota.source === 'credits') res.setHeader('x-shannon-credits-remaining', String(quota.creditsRemaining));
  if (quota.allowed) return true;
  const buyable = billingEnabled() || commerceEnabled();
  res.status(429).json({
    error: `Daily organization limit reached for ${metric}.`,
    code: 'ORG_USAGE_LIMIT',
    metric,
    used: quota.used,
    limit: quota.limit,
    plan: quota.plan,
    upgradeAvailable: buyable,
    creditsAvailable: commerceEnabled(),
  });
  return false;
}

// loadUsers / saveUsers now provided by db.mjs (Supabase or JSON-file backend).
function findUserByEmail(email) {
  const users = loadUsers();
  return Object.values(users).find((u) => u.email === String(email || '').toLowerCase()) || null;
}
function hashPassword(pwd, salt) {
  const s = salt || _crypto.randomBytes(16).toString('hex');
  const h = _crypto.pbkdf2Sync(pwd, s, 120000, 32, 'sha256').toString('hex');
  return { hash: h, salt: s };
}
function verifyPassword(pwd, hash, salt) {
  const { hash: h } = hashPassword(pwd, salt);
  try {
    return _crypto.timingSafeEqual(Buffer.from(h, 'hex'), Buffer.from(hash, 'hex'));
  } catch {
    return false;
  }
}
function signSession(userId) {
  const payload = JSON.stringify({ uid: userId, sid: _crypto.randomBytes(16).toString('hex'), iat: Date.now() });
  const b64 = Buffer.from(payload).toString('base64url');
  const sig = _crypto.createHmac('sha256', SESSION_SECRET).update(b64).digest('base64url');
  return `${b64}.${sig}`;
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
  } catch {
    return null;
  }
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
  res.setHeader(
    'Set-Cookie',
    `shannon_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL_DAYS * 86400}${COOKIE_SECURE ? '; Secure' : ''}`,
  );
}
if (
  process.env.NODE_ENV === 'production' &&
  (String(process.env.SHANNON_SESSION_SECRET).length < 32 ||
    /replace-me|change-me/i.test(process.env.SHANNON_SESSION_SECRET))
) {
  throw new Error('SHANNON_SESSION_SECRET must be a non-placeholder value of at least 32 characters');
}
// A request sent by another website's page (browsers label these). Used on the few GET routes that
// start work, which the Origin check on POST/PUT/PATCH/DELETE does not cover.
const fromAnotherSite = (req) => String(req.headers['sec-fetch-site'] || '').toLowerCase() === 'cross-site';
// Tokens are handed back in an API answer only for automated tests, or when a developer asks for it
// on a machine that is not production. A deployment that merely forgot NODE_ENV gets nothing.
export function devTokensAllowed(env = process.env) {
  if (env.NODE_ENV === 'production') return false;
  return env.NODE_ENV === 'test' || env.SHANNON_DEV_TOKENS === '1';
}
const DEV_TOKENS = devTokensAllowed();
// What a member sees of a queued job. An email's text can hold a one-time link (invitation,
// password reset) meant for its recipient only, so the text never leaves the server.
export function publicJob({ secretEnc: _secret, ...job }) {
  // A scan's own-test mark is for the scan's process, not for the job list.
  if (job.payload?.testMark) return { ...job, payload: { ...job.payload, testMark: undefined } };
  if (job.type !== 'email') return job;
  return { ...job, payload: { to: job.payload?.to, subject: job.payload?.subject }, result: null };
}
// The one way a sign-in is completed for an account that already exists. With two-step sign-in on,
// a password or a link from the mailbox is only the first step: the answer is the code challenge,
// never a session.
function finishSignIn(res, user, extra = {}) {
  if (user.mfaEnabled) {
    return res.json({ ok: true, mfaRequired: true, challenge: signChallenge({ uid: user.id }, 'mfa-login') });
  }
  setSessionCookie(res, user.id);
  return res.json({ ok: true, user: publicUser(user), ...extra });
}
function clearSessionCookie(res) {
  res.append(
    'Set-Cookie',
    `shannon_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${COOKIE_SECURE ? '; Secure' : ''}`,
  );
}
function getUser(req) {
  const session = verifySession(parseCookies(req).shannon_session);
  if (!session) return null;
  const users = loadUsers();
  const user = users[session.uid] || null;
  return user && !user.disabledAt && Number(user.sessionInvalidBefore || 0) <= Number(session.iat || 0) ? user : null;
}
function publicUser(u) {
  if (!u) return null;
  return {
    id: u.id,
    email: u.email,
    name: u.name,
    picture: u.picture || null,
    googleLinked: !!u.googleId,
    emailVerified: !!u.emailVerifiedAt,
    mfaEnabled: u.mfaEnabled === true,
    subscription: u.subscription || null,
    createdAt: u.createdAt,
  };
}

function ensurePersonalOrg(user) {
  const existing = listOrganizations(user.id);
  if (existing.length) return existing[0];
  const id = `org_${user.id}`;
  const name = `${user.name || user.email.split('@')[0]}'s Security Team`;
  const org = {
    id,
    name,
    slug: `${slugifyOrg(name) || 'security-team'}-${user.id.slice(0, 6)}`,
    createdBy: user.id,
    createdAt: Date.now(),
  };
  createOrganization(org, { orgId: id, userId: user.id, role: 'owner', createdAt: Date.now() });
  appendAudit({
    id: randomUUID(),
    orgId: id,
    actorUserId: user.id,
    action: 'organization.created',
    resourceType: 'organization',
    resourceId: id,
    metadata: { automatic: true },
    createdAt: Date.now(),
  });
  return { ...org, role: 'owner' };
}

function requestContext(req) {
  const user = req.shannonUser || getUser(req);
  if (!user) return null;
  const orgs = listOrganizations(user.id);
  const requested = String(
    req.headers['x-shannon-org'] || req.query?.orgId || req.body?.orgId || parseCookies(req).shannon_org || '',
  );
  let org = orgs.find((o) => o.id === requested) || orgs[0];
  if (!org) org = ensurePersonalOrg(user);
  const membership = getMembership(org.id, user.id);
  return membership ? { user, org, membership } : null;
}

function requirePermission(req, res, permission) {
  const ctx = requestContext(req);
  if (!ctx) {
    res.status(401).json({ error: 'Authentication required.' });
    return null;
  }
  if (!can(ctx.membership.role, permission)) {
    res.status(403).json({ error: `Your ${ctx.membership.role} role cannot perform this action.` });
    return null;
  }
  return ctx;
}

function orgContext(req, res, permission) {
  const user = req.shannonUser || getUser(req);
  const orgId = String(req.params?.orgId || req.headers['x-shannon-org'] || '');
  const org = getOrganization(orgId);
  const membership = user && org ? getMembership(orgId, user.id) : null;
  if (!user || !org || !membership) {
    res.status(404).json({ error: 'Organization not found.' });
    return null;
  }
  if (!can(membership.role, permission)) {
    res.status(403).json({ error: `Your ${membership.role} role cannot perform this action.` });
    return null;
  }
  return { user, org, membership };
}

function audit(ctx, action, resourceType, resourceId, metadata = {}) {
  appendAudit({
    id: randomUUID(),
    orgId: ctx.org.id,
    actorUserId: ctx.user.id,
    action,
    resourceType,
    resourceId: resourceId || null,
    metadata,
    createdAt: Date.now(),
  });
}

function scanContext(req, res, scanId, permission = 'scans.read') {
  const ctx = requirePermission(req, res, permission);
  if (!ctx) return null;
  const owner = getScanOwner(scanId);
  if (!owner || owner.orgId !== ctx.org.id) {
    res.status(404).json({ error: 'Scan not found.' });
    return null;
  }
  return { ...ctx, scanOwner: owner };
}

function requirePlatformOperator(req, res) {
  const user = req.shannonUser || getUser(req);
  const allowed = String(process.env.SHANNON_PLATFORM_ADMINS || '')
    .split(',')
    .map((x) => x.trim().toLowerCase())
    .filter(Boolean);
  if (!user || (!allowed.includes(user.email.toLowerCase()) && !(LOCAL_OPERATOR && csIsLocalhost(req)))) {
    res.status(403).json({ error: 'Platform operator permission required.' });
    return null;
  }
  return user;
}
// On a developer's own machine the person at the keyboard is the operator. That shortcut is on for
// automated tests and by explicit choice, never in production, and never merely because NODE_ENV
// was left unset behind a proxy on the same host (where every visitor looks local).
const LOCAL_OPERATOR =
  process.env.NODE_ENV !== 'production' &&
  (process.env.NODE_ENV === 'test' || process.env.SHANNON_LOCAL_OPERATOR === '1');
function isPlatformOperator(req, user) {
  const allowed = String(process.env.SHANNON_PLATFORM_ADMINS || '')
    .split(',')
    .map((x) => x.trim().toLowerCase())
    .filter(Boolean);
  return !!user && (allowed.includes(String(user.email || '').toLowerCase()) || (LOCAL_OPERATOR && csIsLocalhost(req)));
}

// Must a new account prove its email address before it can use the product?
// Yes on a production service that is able to send email, unless switched off with
// SHANNON_REQUIRE_EMAIL_VERIFICATION=0. Setting it to 1 forces it on anywhere. (A service that
// cannot send email cannot ask for this: nobody could ever get in.)
export function emailVerificationRequired(env = process.env) {
  if (env.SHANNON_REQUIRE_EMAIL_VERIFICATION === '1') return true;
  if (env.SHANNON_REQUIRE_EMAIL_VERIFICATION === '0') return false;
  return env.NODE_ENV === 'production' && !!(env.RESEND_API_KEY || env.SHANNON_EMAIL_WEBHOOK_URL);
}

const PUBLIC_API = new Set([
  '/auth/me',
  '/auth/signup',
  '/auth/login',
  '/auth/mfa/login',
  '/auth/email/verify',
  '/auth/email/resend',
  '/auth/password/request',
  '/auth/password/reset',
  '/auth/invitations/accept',
  '/auth/plans',
  '/billing/webhook',
  '/commerce/catalog',
]);
app.use('/api', async (req, res, next) => {
  try {
    await refreshDbIfStale(Number(process.env.SHANNON_CACHE_REFRESH_MS || 5000));
  } catch (error) {
    return res.status(503).json({ error: `Database refresh failed: ${error.message}` });
  }
  const relative = req.path;
  if (relative.startsWith('/v1/') || relative === '/v1') {
    const route = v1RouteScope(req.method, relative);
    if (!route.known) return res.status(404).json({ error: 'Unknown API route.' });
    const parsed = parseApiKey(String(req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
    if (!parsed) return res.status(401).json({ error: 'Send a Securovix API key: Authorization: Bearer svx_...' });
    const key = await apiKeys.get(parsed.id).catch(() => null);
    if (!key || key.revokedAt || !secretMatches(parsed.secret, key.secretHash))
      return res.status(401).json({ error: 'Invalid or revoked API key.' });
    const keyUser = loadUsers()[key.createdBy];
    if (!keyUser || keyUser.disabledAt || !getMembership(key.orgId, keyUser.id))
      return res.status(401).json({ error: 'The user who created this key no longer has access to the organization.' });
    if (route.scope && !(key.scopes || []).includes(route.scope))
      return res.status(403).json({ error: `This API key does not have the ${route.scope} scope.` });
    if (limited(req, res, `apikey:${key.id}`, 300, 5 * 60 * 1000)) return;
    req.shannonUser = keyUser;
    req.apiKey = key;
    req.headers['x-shannon-org'] = key.orgId;
    if (!key.lastUsedAt || Date.now() - key.lastUsedAt > 60_000)
      apiKeys.save({ ...key, lastUsedAt: Date.now() }).catch(() => {});
    return next();
  }
  const bearerRoute =
    req.headers.authorization &&
    (relative === '/defender/report' ||
      (relative === '/defender/sdk/policy' && req.method === 'GET') ||
      relative === '/defender/sensors/heartbeat' ||
      (relative === '/defender/edge/routes' && req.method === 'GET') ||
      relative === '/platform/defender/edge/routes' ||
      relative === '/platform/defender/edge/report');
  // The Guard endpoint agent authenticates with its own token inside its routes.
  if (relative.startsWith('/endpoint-agent/v1/')) return next();
  if (PUBLIC_API.has(relative) || bearerRoute) return next();
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'Authentication required.' });
  // An account whose email address is not proven gets as far as its own sign-in routes (to ask for
  // the link again, or sign out) and no further: no tests, no invitations, no keys.
  if (emailVerificationRequired() && !user.emailVerifiedAt && !relative.startsWith('/auth/')) {
    return res.status(403).json({
      error: 'Verify your email address to continue. Open the link we sent you, or ask for a new one.',
      code: 'EMAIL_NOT_VERIFIED',
      emailVerificationRequired: true,
    });
  }
  req.shannonUser = user;
  ensurePersonalOrg(user);
  if (limited(req, res, `api:${user.id}`, 600, 5 * 60 * 1000)) return;
  next();
});

async function dispatchEmail(payload, { orgId = null, userId = null } = {}) {
  if (isSupabase() && process.env.SHANNON_DURABLE_JOBS !== '0') {
    return enqueueJob({ orgId, userId, type: 'email', payload, maxAttempts: 5 });
  }
  return sendEmail(payload);
}

async function issueAuthToken(
  req,
  { kind, email, userId = null, orgId = null, role = null, createdBy = null, ttlMs, linkPath, subject, message },
) {
  const token = randomToken();
  await createAuthToken({
    id: randomUUID(),
    tokenHash: hashToken(token),
    kind,
    userId,
    email,
    orgId,
    role,
    createdBy,
    expiresAt: Date.now() + ttlMs,
    usedAt: null,
    createdAt: Date.now(),
  });
  const link = `${publicBaseUrl(req)}${linkPath}${encodeURIComponent(token)}`;
  await dispatchEmail(
    { to: email, subject, text: `${message}\n\n${link}\n\nIf you did not request this, ignore this message.` },
    { orgId, userId },
  );
  return { token, link };
}

// --- Routes
app.get('/api/auth/me', (req, res) => {
  const u = getUser(req);
  // Always send googleConfigured — the login screen (401 path) needs it to
  // decide whether to enable the "Continue with Google" button.
  const googleConfigured = !!process.env.GOOGLE_CLIENT_ID;
  const ssoConfigured = !!(process.env.OIDC_ISSUER && process.env.OIDC_CLIENT_ID && process.env.OIDC_CLIENT_SECRET);
  if (!u)
    return res.status(401).json({
      ok: false,
      googleConfigured,
      ssoConfigured,
      ssoName: process.env.OIDC_NAME || 'Company SSO',
    });
  ensurePersonalOrg(u);
  res.json({
    ok: true,
    user: publicUser(u),
    organizations: listOrganizations(u.id),
    googleConfigured,
    ssoConfigured,
    ssoName: process.env.OIDC_NAME || 'Company SSO',
  });
});

app.post('/api/auth/signup', async (req, res) => {
  if (limited(req, res, 'signup', Number(process.env.SHANNON_SIGNUP_RATE_LIMIT || 5), 60 * 60 * 1000)) return;
  const email = String(req.body?.email || '')
    .trim()
    .toLowerCase();
  const password = String(req.body?.password || '');
  const name = String(req.body?.name || '').trim() || email.split('@')[0];
  // Terms + Privacy consent — required for legal record.
  if (!req.body?.acceptedTerms)
    return res.status(400).json({ error: 'You must accept the Terms of Service and Privacy Policy.' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (password.length < 12) return res.status(400).json({ error: 'Password must be at least 12 characters.' });
  if (findUserByEmail(email)) return res.status(409).json({ error: 'An account with that email already exists.' });
  const users = loadUsers();
  const id = _crypto.randomBytes(8).toString('hex');
  const { hash, salt } = hashPassword(password);
  const acceptedAt = Number(req.body?.acceptedAt) || Date.now();
  users[id] = {
    id,
    email,
    name,
    passwordHash: hash,
    salt,
    createdAt: Date.now(),
    emailVerifiedAt: null,
    disabledAt: null,
    mfaEnabled: false,
    mfaSecretEnc: null,
    mfaRecoveryCodes: [],
    subscription: null,
    // Legal consent record — captured at signup time per UK GDPR Art. 7(1).
    consent: {
      termsVersion: '2026-05-04',
      privacyVersion: '2026-05-04',
      acceptedAt,
      ip: String(req.ip || req.socket?.remoteAddress || ''),
      userAgent: String(req.headers['user-agent'] || '').slice(0, 240),
    },
  };
  saveUsers(users);
  await waitForUserWrites();
  ensurePersonalOrg(users[id]);
  let verification = null;
  try {
    verification = await issueAuthToken(req, {
      kind: 'email-verification',
      email,
      ttlMs: 24 * 60 * 60_000,
      linkPath: '/?verify=',
      subject: 'Verify your Securovix Shannon email',
      message: 'Verify your email address to activate your security workspace.',
    });
  } catch (error) {
    console.error('[auth] verification email failed:', error.message);
  }
  const verificationRequired = emailVerificationRequired();
  if (!verificationRequired) setSessionCookie(res, id);
  res.status(verificationRequired ? 202 : 200).json({
    ok: true,
    verificationRequired,
    user: publicUser(users[id]),
    organizations: listOrganizations(id),
    ...(DEV_TOKENS && verification ? { developmentToken: verification.token } : {}),
  });
});

// Per-ACCOUNT lockout, on top of the per-address limits below. `limited()` stops one address
// guessing; this stops a guesser that rotates addresses against one account (see login-guard.mjs).
const LOGIN_GUARD = createLoginGuard({
  limit: Math.max(3, Number(process.env.SHANNON_LOGIN_LOCK_THRESHOLD || 10)),
  lockMs: Math.max(1, Number(process.env.SHANNON_LOGIN_LOCK_MINUTES || 15)) * 60_000,
});
function accountLocked(res, state) {
  res.setHeader('retry-after', String(state.retryAfter));
  const minutes = Math.ceil(state.retryAfter / 60);
  res.status(429).json({
    error: `Too many failed sign-in attempts for this account. Try again in ${minutes} minute${minutes === 1 ? '' : 's'}, or reset your password.`,
    code: 'ACCOUNT_LOCKED',
  });
}
function noteAccountLock(req, scope) {
  appendOperationalEvent({
    service: 'dashboard',
    level: 'warning',
    event: 'auth.account_locked',
    metadata: { scope, ip: req.ip || null },
    createdAt: Date.now(),
  }).catch(() => {});
}

app.post('/api/auth/login', (req, res) => {
  if (limited(req, res, 'login', 10, 15 * 60 * 1000)) return;
  const email = String(req.body?.email || '')
    .trim()
    .toLowerCase();
  const password = String(req.body?.password || '');
  // Checked before the password, and for unknown emails too, so a locked account answers the same
  // whether the guess was right, wrong, or aimed at an account that does not exist.
  const lock = email ? LOGIN_GUARD.check('password', email) : { locked: false };
  if (lock.locked) return accountLocked(res, lock);
  const u = findUserByEmail(email);
  if (!u || !u.passwordHash || !verifyPassword(password, u.passwordHash, u.salt)) {
    if (email && LOGIN_GUARD.fail('password', email).justLocked) noteAccountLock(req, 'password');
    return res.status(401).json({ error: 'Wrong email or password.' });
  }
  LOGIN_GUARD.succeed('password', email);
  if (u.disabledAt) return res.status(403).json({ error: 'This account is disabled.' });
  if (emailVerificationRequired() && !u.emailVerifiedAt) {
    return res.status(403).json({ error: 'Verify your email before signing in.', emailVerificationRequired: true });
  }
  finishSignIn(res, u);
});

app.post('/api/auth/mfa/login', async (req, res) => {
  if (limited(req, res, 'mfa-login', 10, 15 * 60 * 1000)) return;
  const challenge = verifyChallenge(req.body?.challenge, 'mfa-login');
  const user = challenge ? loadUsers()[challenge.uid] : null;
  if (!user || !user.mfaEnabled || user.disabledAt) return res.status(401).json({ error: 'Invalid MFA challenge.' });
  // A six-digit code has a million values; without a per-account cap, rotating addresses could
  // walk through them.
  const lock = LOGIN_GUARD.check('mfa', user.id);
  if (lock.locked) return accountLocked(res, lock);
  let verified = false;
  try {
    verified = verifyTotp(decryptSecret(user.mfaSecretEnc)?.secret, req.body?.code);
  } catch {}
  if (!verified) {
    const remaining = consumeRecoveryCode(req.body?.code, user.mfaRecoveryCodes || []);
    if (remaining) {
      user.mfaRecoveryCodes = remaining;
      saveUsers(loadUsers());
      await waitForUserWrites();
      verified = true;
    }
  }
  if (!verified) {
    if (LOGIN_GUARD.fail('mfa', user.id).justLocked) noteAccountLock(req, 'mfa');
    return res.status(401).json({ error: 'Invalid authentication code.' });
  }
  LOGIN_GUARD.succeed('mfa', user.id);
  setSessionCookie(res, user.id);
  res.json({ ok: true, user: publicUser(user) });
});

app.post('/api/auth/email/verify', async (req, res) => {
  const record = await consumeAuthToken(hashToken(req.body?.token), 'email-verification');
  if (!record) return res.status(400).json({ error: 'This verification link is invalid or expired.' });
  const user = findUserByEmail(record.email);
  if (!user) return res.status(404).json({ error: 'Account not found.' });
  user.emailVerifiedAt = Date.now();
  saveUsers(loadUsers());
  finishSignIn(res, user);
});

app.post('/api/auth/email/resend', async (req, res) => {
  if (limited(req, res, 'email-resend', 5, 60 * 60_000)) return;
  const email = String(req.body?.email || '')
    .trim()
    .toLowerCase();
  const user = findUserByEmail(email);
  let verification = null;
  // Capped per mailbox as well as per sender, so rotating addresses cannot flood one inbox.
  if (
    user &&
    !user.emailVerifiedAt &&
    !user.disabledAt &&
    rateLimit(`mail-verify:${email}`, { limit: 3, windowMs: 60 * 60_000 }).ok
  ) {
    try {
      verification = await issueAuthToken(req, {
        kind: 'email-verification',
        email,
        ttlMs: 24 * 60 * 60_000,
        linkPath: '/?verify=',
        subject: 'Verify your Securovix Shannon email',
        message: 'Verify your email address to activate your security workspace.',
      });
    } catch (error) {
      console.error('[auth] verification email failed:', error.message);
    }
  }
  res.json({
    ok: true,
    message: 'If that account requires verification, a new link has been sent.',
    ...(DEV_TOKENS && verification ? { developmentToken: verification.token } : {}),
  });
});

app.post('/api/auth/password/request', async (req, res) => {
  if (limited(req, res, 'password-reset', 5, 60 * 60_000)) return;
  // In production sendEmail() throws when no provider is configured. That throw used to be caught
  // below and the route still answered "a reset link has been sent" — so on a deployment without
  // RESEND_API_KEY / SHANNON_EMAIL_WEBHOOK_URL, password reset was 100% broken and reported success.
  // Say so instead. This is a deployment-level fact, identical for every email address, so it leaks
  // nothing about whether an account exists.
  if (process.env.NODE_ENV === 'production' && !process.env.RESEND_API_KEY && !process.env.SHANNON_EMAIL_WEBHOOK_URL) {
    return res.status(503).json({
      error:
        'Password reset by email is not available on this deployment: no email provider is configured. Contact your administrator.',
      code: 'EMAIL_NOT_CONFIGURED',
    });
  }
  const email = String(req.body?.email || '')
    .trim()
    .toLowerCase();
  const user = findUserByEmail(email);
  let reset = null;
  // Capped per mailbox as well as per sender, so rotating addresses cannot flood one inbox. Over the
  // cap the answer is the same as always; no link is sent.
  if (user && !user.disabledAt && rateLimit(`mail-reset:${email}`, { limit: 3, windowMs: 60 * 60_000 }).ok) {
    try {
      reset = await issueAuthToken(req, {
        kind: 'password-reset',
        email,
        userId: user.id,
        ttlMs: 30 * 60_000,
        linkPath: '/?reset=',
        subject: 'Reset your Securovix Shannon password',
        message: 'Use this one-time link to reset your password. It expires in 30 minutes.',
      });
    } catch (error) {
      console.error('[auth] password reset email failed:', error.message);
    }
  }
  res.json({
    ok: true,
    message: 'If an account exists for that email, a reset link has been sent.',
    ...(DEV_TOKENS && reset ? { developmentToken: reset.token } : {}),
  });
});

app.post('/api/auth/password/reset', async (req, res) => {
  const password = String(req.body?.password || '');
  if (password.length < 12) return res.status(400).json({ error: 'Password must be at least 12 characters.' });
  const record = await consumeAuthToken(hashToken(req.body?.token), 'password-reset');
  if (!record) return res.status(400).json({ error: 'This reset link is invalid or expired.' });
  const user = (record.userId && loadUsers()[record.userId]) || findUserByEmail(record.email);
  if (!user || user.disabledAt) return res.status(400).json({ error: 'This reset link is invalid or expired.' });
  const next = hashPassword(password);
  user.passwordHash = next.hash;
  user.salt = next.salt;
  user.sessionInvalidBefore = Date.now();
  saveUsers(loadUsers());
  // The owner of the mailbox has proved who they are, so a lock caused by someone else's guesses ends.
  LOGIN_GUARD.succeed('password', user.email);
  // The mailbox proves the first step only: an account with two-step sign-in is asked for its code.
  finishSignIn(res, user);
});

app.post('/api/auth/invitations/accept', async (req, res) => {
  const password = String(req.body?.password || '');
  const tokenHash = hashToken(req.body?.token);
  const preview = await findAuthToken(tokenHash, 'invitation');
  // An invitation adds a member; it is never a way in to an account. For an address that already
  // has an account, the invited person signs in to it first (password, and code if they use one),
  // and only that account may accept. Refusing here leaves the invitation unused.
  const signInFirst = () =>
    res.status(401).json({
      error: 'This email address already has an account. Sign in to it and the invitation will be accepted.',
      signInRequired: true,
    });
  const invited = preview ? findUserByEmail(preview.email) : null;
  if (invited && getUser(req)?.id !== invited.id) return signInFirst();
  if (preview && !invited) {
    if (password.length < 12) return res.status(400).json({ error: 'Choose a password with at least 12 characters.' });
    if (!req.body?.acceptedTerms)
      return res.status(400).json({ error: 'You must accept the Terms and Privacy Policy.' });
  }
  const record = await consumeAuthToken(tokenHash, 'invitation');
  if (!record || !record.orgId || !ROLES.includes(record.role) || record.role === 'owner') {
    return res.status(400).json({ error: 'This invitation is invalid or expired.' });
  }
  let user = findUserByEmail(record.email);
  // The account may have been created between the two lookups above: same rule.
  if (user && getUser(req)?.id !== user.id) return signInFirst();
  const created = !user;
  if (!user) {
    const id = _crypto.randomBytes(8).toString('hex');
    const passwordRecord = hashPassword(password);
    user = {
      id,
      email: record.email,
      name: sanitizeLabel(req.body?.name || record.email.split('@')[0], 100),
      passwordHash: passwordRecord.hash,
      salt: passwordRecord.salt,
      emailVerifiedAt: Date.now(),
      disabledAt: null,
      mfaEnabled: false,
      mfaSecretEnc: null,
      mfaRecoveryCodes: [],
      createdAt: Date.now(),
      subscription: null,
      consent: { termsVersion: '2026-05-04', privacyVersion: '2026-05-04', acceptedAt: Date.now() },
    };
    loadUsers()[id] = user;
    saveUsers(loadUsers());
    await waitForUserWrites();
  }
  if (!getMembership(record.orgId, user.id)) {
    saveMembership({ orgId: record.orgId, userId: user.id, role: record.role, createdAt: Date.now() });
  }
  appendAudit({
    id: randomUUID(),
    orgId: record.orgId,
    actorUserId: user.id,
    action: 'invitation.accepted',
    resourceType: 'membership',
    resourceId: user.id,
    metadata: { role: record.role },
    createdAt: Date.now(),
  });
  // A session is issued only for the account this request created; an existing one is already signed in.
  if (created) setSessionCookie(res, user.id);
  res.json({ ok: true, user: publicUser(user), organization: getOrganization(record.orgId) });
});

app.get('/api/auth/mfa/status', (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'Authentication required.' });
  let enrollment = null;
  try {
    enrollment = decryptSecret(user.mfaSecretEnc);
  } catch {}
  const pending = !!(
    !user.mfaEnabled &&
    enrollment?.pending &&
    Date.now() - Number(enrollment.createdAt || 0) < 15 * 60_000
  );
  res.json({
    enabled: user.mfaEnabled === true,
    pending,
    recoveryCodesRemaining: user.mfaEnabled ? (user.mfaRecoveryCodes || []).length : 0,
    enabledAt: user.mfaEnabled ? Number(enrollment?.enabledAt || 0) || null : null,
    passwordReauthenticationRequired: !!user.passwordHash,
  });
});

app.post('/api/auth/mfa/setup', async (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'Authentication required.' });
  if (limited(req, res, `mfa-manage:${user.id}`, 10, 15 * 60 * 1000)) return;
  if (user.mfaEnabled) return res.status(409).json({ error: 'MFA is already enabled.' });
  if (user.passwordHash && !verifyPassword(String(req.body?.password || ''), user.passwordHash, user.salt)) {
    return res.status(401).json({ error: 'Enter your current password to start MFA enrollment.' });
  }
  const secret = newTotpSecret();
  user.mfaSecretEnc = encryptSecret({ secret, pending: true, createdAt: Date.now() });
  user.mfaEnabled = false;
  user.mfaRecoveryCodes = [];
  saveUsers(loadUsers());
  await waitForUserWrites();
  const uri = totpUri({ secret, email: user.email });
  const qrDataUrl = await QRCode.toDataURL(uri, {
    errorCorrectionLevel: 'M',
    margin: 2,
    width: 260,
    color: { dark: '#111710', light: '#ffffff' },
  });
  res.json({ secret, uri, qrDataUrl, expiresInSeconds: 900 });
});

app.delete('/api/auth/mfa/setup', async (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'Authentication required.' });
  if (user.mfaEnabled) return res.status(409).json({ error: 'MFA is already enabled.' });
  user.mfaSecretEnc = null;
  user.mfaRecoveryCodes = [];
  saveUsers(loadUsers());
  await waitForUserWrites();
  res.json({ ok: true });
});

app.post('/api/auth/mfa/enable', async (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'Authentication required.' });
  if (limited(req, res, `mfa-enable:${user.id}`, 10, 15 * 60 * 1000)) return;
  let enrollment;
  try {
    enrollment = decryptSecret(user.mfaSecretEnc);
  } catch {}
  if (!enrollment?.pending || Date.now() - Number(enrollment.createdAt || 0) >= 15 * 60_000) {
    user.mfaSecretEnc = null;
    saveUsers(loadUsers());
    await waitForUserWrites();
    return res.status(400).json({ error: 'MFA enrollment expired. Start again to create a new QR code.' });
  }
  const secret = enrollment.secret;
  if (!secret || !verifyTotp(secret, req.body?.code))
    return res.status(400).json({ error: 'Invalid authentication code.' });
  const recoveryCodes = createRecoveryCodes();
  user.mfaSecretEnc = encryptSecret({ secret, pending: false, enabledAt: Date.now() });
  user.mfaEnabled = true;
  user.mfaRecoveryCodes = hashRecoveryCodes(recoveryCodes);
  user.sessionInvalidBefore = Date.now();
  saveUsers(loadUsers());
  await waitForUserWrites();
  setSessionCookie(res, user.id);
  const ctx = requestContext(req);
  if (ctx) audit(ctx, 'authentication.mfa_enabled', 'user', user.id, { recoveryCodes: recoveryCodes.length });
  res.json({ ok: true, recoveryCodes, recoveryCodesRemaining: recoveryCodes.length });
});

app.post('/api/auth/mfa/recovery-codes', async (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'Authentication required.' });
  if (limited(req, res, `mfa-recovery:${user.id}`, 6, 15 * 60 * 1000)) return;
  if (!user.mfaEnabled) return res.status(409).json({ error: 'Enable MFA before generating recovery codes.' });
  let secret;
  try {
    secret = decryptSecret(user.mfaSecretEnc)?.secret;
  } catch {}
  if (!secret || !verifyTotp(secret, req.body?.code))
    return res.status(400).json({ error: 'Invalid authentication code.' });
  const recoveryCodes = createRecoveryCodes();
  user.mfaRecoveryCodes = hashRecoveryCodes(recoveryCodes);
  user.sessionInvalidBefore = Date.now();
  saveUsers(loadUsers());
  await waitForUserWrites();
  setSessionCookie(res, user.id);
  const ctx = requestContext(req);
  if (ctx)
    audit(ctx, 'authentication.mfa_recovery_codes_regenerated', 'user', user.id, {
      recoveryCodes: recoveryCodes.length,
    });
  res.json({ ok: true, recoveryCodes, recoveryCodesRemaining: recoveryCodes.length });
});

app.delete('/api/auth/mfa', async (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'Authentication required.' });
  if (limited(req, res, `mfa-disable:${user.id}`, 6, 15 * 60 * 1000)) return;
  if (!user.mfaEnabled) return res.status(409).json({ error: 'MFA is not enabled.' });
  let secret;
  try {
    secret = decryptSecret(user.mfaSecretEnc)?.secret;
  } catch {}
  let verified = !!secret && verifyTotp(secret, req.body?.code);
  if (!verified) verified = consumeRecoveryCode(req.body?.code, user.mfaRecoveryCodes || []) !== null;
  if (!verified) return res.status(400).json({ error: 'Invalid authentication or recovery code.' });
  user.mfaEnabled = false;
  user.mfaSecretEnc = null;
  user.mfaRecoveryCodes = [];
  user.sessionInvalidBefore = Date.now();
  saveUsers(loadUsers());
  await waitForUserWrites();
  setSessionCookie(res, user.id);
  const ctx = requestContext(req);
  if (ctx) audit(ctx, 'authentication.mfa_disabled', 'user', user.id);
  res.json({ ok: true });
});

app.post('/api/auth/logout', (req, res) => {
  // The cookie is a signed token, so clearing it in this browser is not enough: a copy would keep
  // working until it expired. Signing out ends every session of the account.
  const user = getUser(req);
  if (user) {
    user.sessionInvalidBefore = Date.now();
    saveUsers(loadUsers());
  }
  clearSessionCookie(res);
  res.json({ ok: true });
});

// Google OAuth — requires GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET env vars
app.get('/auth/google', (req, res) => {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  if (!clientId)
    return res
      .status(500)
      .send(
        'Google OAuth not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET env vars before restarting the server.',
      );
  const redirectUri = `${req.protocol}://${req.get('host')}/auth/google/callback`;
  const state = _crypto.randomBytes(24).toString('base64url');
  res.append(
    'Set-Cookie',
    `shannon_oauth_state=${state}; HttpOnly; SameSite=Lax; Path=/auth/google/callback; Max-Age=600${COOKIE_SECURE ? '; Secure' : ''}`,
  );
  const url = `https://accounts.google.com/o/oauth2/v2/auth?${new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid email profile',
    access_type: 'online',
    prompt: 'select_account',
    state,
  })}`;
  res.redirect(url);
});

app.get('/auth/google/callback', async (req, res) => {
  const { code, state } = req.query;
  if (!code) return res.status(400).send('Missing code.');
  const expectedState = parseCookies(req).shannon_oauth_state || '';
  const stateOk =
    expectedState.length === String(state || '').length &&
    expectedState.length > 0 &&
    _crypto.timingSafeEqual(Buffer.from(expectedState), Buffer.from(String(state || '')));
  if (!stateOk) return res.status(400).send('Invalid OAuth state. Start sign-in again.');
  res.setHeader(
    'Set-Cookie',
    `shannon_oauth_state=; HttpOnly; SameSite=Lax; Path=/auth/google/callback; Max-Age=0${COOKIE_SECURE ? '; Secure' : ''}`,
  );
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  if (!clientId || !clientSecret) return res.status(500).send('Google OAuth not configured.');
  const redirectUri = `${req.protocol}://${req.get('host')}/auth/google/callback`;
  try {
    const tokenResp = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code: String(code),
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code',
      }),
    });
    const td = await tokenResp.json();
    if (!tokenResp.ok) throw new Error(td.error_description || td.error || 'token exchange failed');
    const userResp = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { authorization: `Bearer ${td.access_token}` },
    });
    const profile = await userResp.json();
    if (!userResp.ok || !profile.email) throw new Error('userinfo failed');
    if (profile.email_verified === false || profile.email_verified === 'false')
      throw new Error('this Google account has not verified its email address');
    const users = loadUsers();
    let user = Object.values(users).find((u) => u.googleId === profile.sub) || findUserByEmail(profile.email);
    if (!user) {
      const id = _crypto.randomBytes(8).toString('hex');
      user = {
        id,
        email: profile.email.toLowerCase(),
        name: profile.name || profile.email,
        picture: profile.picture || null,
        googleId: profile.sub,
        emailVerifiedAt: Date.now(),
        disabledAt: null,
        mfaEnabled: false,
        mfaSecretEnc: null,
        mfaRecoveryCodes: [],
        createdAt: Date.now(),
        subscription: null,
      };
      users[id] = user;
    } else {
      if (!user.googleId) user.googleId = profile.sub;
      if (!user.picture && profile.picture) user.picture = profile.picture;
      if (!user.emailVerifiedAt) user.emailVerifiedAt = Date.now();
    }
    saveUsers(users);
    ensurePersonalOrg(user);
    setSessionCookie(res, user.id);
    res.redirect('/');
  } catch (e) {
    res.status(500).type('text/plain').send(`Google sign-in failed: ${e.message}`);
  }
});

// OIDC discovery is shared by the legacy platform provider and encrypted organization providers.
const OIDC_DISCOVERY_CACHE = new Map();
async function oidcDiscovery(configuredIssuer = process.env.OIDC_ISSUER) {
  const issuer = String(configuredIssuer || '').replace(/\/$/, '');
  if (!issuer) throw new Error('OIDC_ISSUER is not configured');
  if (!issuer.startsWith('https://') || !(await publicOriginAllowed(issuer)))
    throw new Error('OIDC issuer must be a public HTTPS origin');
  const cached = OIDC_DISCOVERY_CACHE.get(issuer);
  if (cached?.expiresAt > Date.now()) return cached.value;
  const response = await fetch(`${issuer}/.well-known/openid-configuration`, {
    signal: AbortSignal.timeout(10_000),
    redirect: 'error',
  });
  if (!response.ok) throw new Error(`OIDC discovery returned ${response.status}`);
  const value = await response.json();
  if (!value.authorization_endpoint || !value.token_endpoint || !value.userinfo_endpoint) {
    throw new Error('OIDC provider discovery is incomplete');
  }
  const endpointsArePublic = await Promise.all(
    [value.authorization_endpoint, value.token_endpoint, value.userinfo_endpoint].map(
      async (endpoint) => String(endpoint).startsWith('https://') && (await publicOriginAllowed(endpoint)),
    ),
  );
  if (endpointsArePublic.some((allowed) => !allowed)) throw new Error('OIDC endpoints must use public HTTPS origins');
  OIDC_DISCOVERY_CACHE.set(issuer, { expiresAt: Date.now() + 60 * 60_000, value });
  return value;
}

async function organizationIdentityConfig(orgId, kind) {
  const row = await getOrgSecret(orgId, kind, 'default');
  if (!row) return null;
  let secret = {};
  try {
    secret = decryptSecret(row.secretEnc) || {};
  } catch {}
  return { ...row.config, ...secret, updatedAt: row.updatedAt };
}

app.get('/api/team/:orgId/identity', async (req, res) => {
  const ctx = orgContext(req, res, 'settings.manage');
  if (!ctx) return;
  const [oidc, scim] = await Promise.all([
    getOrgSecret(ctx.org.id, 'oidc', 'default'),
    getOrgSecret(ctx.org.id, 'scim', 'default'),
  ]);
  res.json({
    ok: true,
    oidc: oidc
      ? {
          configured: true,
          ...oidc.config,
          updatedAt: oidc.updatedAt,
          startUrl: `${publicBaseUrl(req)}/auth/sso/org/${encodeURIComponent(ctx.org.id)}/start`,
        }
      : { configured: false },
    scim: scim
      ? {
          configured: true,
          updatedAt: scim.updatedAt,
          baseUrl: `${publicBaseUrl(req)}/scim/v2/orgs/${encodeURIComponent(ctx.org.id)}`,
        }
      : { configured: false },
  });
});

app.put('/api/team/:orgId/identity/oidc', async (req, res) => {
  const ctx = orgContext(req, res, 'settings.manage');
  if (!ctx) return;
  const issuer = String(req.body?.issuer || '').replace(/\/$/, '');
  const clientId = String(req.body?.clientId || '').trim();
  const clientSecret = String(req.body?.clientSecret || '');
  if (!/^https:\/\//i.test(issuer) || !clientId || clientSecret.length < 8)
    return res.status(400).json({ error: 'Issuer, client ID, and client secret are required; issuer must use HTTPS.' });
  try {
    await oidcDiscovery(issuer);
  } catch (error) {
    return res.status(400).json({ error: `OIDC discovery failed: ${error.message}` });
  }
  const previous = await getOrgSecret(ctx.org.id, 'oidc', 'default');
  const now = Date.now();
  const requestedDomains = String(req.body?.allowedDomains || '')
    .split(',')
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
  if (!requestedDomains.length)
    return res.status(400).json({ error: 'At least one verified email domain is required.' });
  const allowedDomains = [];
  for (const value of requestedDomains) {
    let domain;
    try {
      domain = registrable(hostOf(value));
    } catch {
      return res.status(400).json({ error: `Invalid email domain: ${value}` });
    }
    if (!domain.includes('.') || !isVerified(ctx.user.id, domain)) {
      return res.status(403).json({ error: `Verify ownership of ${domain} in Domains before enabling it for SSO.` });
    }
    if (!allowedDomains.includes(domain)) allowedDomains.push(domain);
  }
  await saveOrgSecret({
    id: previous?.id || `osec_${randomUUID().replaceAll('-', '')}`,
    orgId: ctx.org.id,
    kind: 'oidc',
    name: 'default',
    config: {
      issuer,
      clientId,
      scopes: String(req.body?.scopes || 'openid email profile'),
      name: sanitizeLabel(req.body?.name || 'Company SSO', 80),
      allowedDomains,
    },
    secretEnc: encryptSecret({ clientSecret }),
    createdBy: previous?.createdBy || ctx.user.id,
    createdAt: previous?.createdAt || now,
    updatedAt: now,
  });
  audit(ctx, previous ? 'identity.oidc_rotated' : 'identity.oidc_created', 'organization', ctx.org.id);
  res.json({ ok: true, startUrl: `${publicBaseUrl(req)}/auth/sso/org/${encodeURIComponent(ctx.org.id)}/start` });
});

app.delete('/api/team/:orgId/identity/oidc', async (req, res) => {
  const ctx = orgContext(req, res, 'settings.manage');
  if (!ctx) return;
  await deleteOrgSecret(ctx.org.id, 'oidc', 'default');
  audit(ctx, 'identity.oidc_deleted', 'organization', ctx.org.id);
  res.json({ ok: true });
});

app.put('/api/team/:orgId/identity/scim', async (req, res) => {
  const ctx = orgContext(req, res, 'settings.manage');
  if (!ctx) return;
  const token = String(req.body?.token || randomToken(36));
  if (token.length < 24) return res.status(400).json({ error: 'SCIM token must be at least 24 characters.' });
  const previous = await getOrgSecret(ctx.org.id, 'scim', 'default');
  const now = Date.now();
  await saveOrgSecret({
    id: previous?.id || `osec_${randomUUID().replaceAll('-', '')}`,
    orgId: ctx.org.id,
    kind: 'scim',
    name: 'default',
    config: {},
    secretEnc: encryptSecret({ token }),
    createdBy: previous?.createdBy || ctx.user.id,
    createdAt: previous?.createdAt || now,
    updatedAt: now,
  });
  audit(ctx, previous ? 'identity.scim_rotated' : 'identity.scim_created', 'organization', ctx.org.id);
  res.json({ ok: true, token, baseUrl: `${publicBaseUrl(req)}/scim/v2/orgs/${encodeURIComponent(ctx.org.id)}` });
});

app.delete('/api/team/:orgId/identity/scim', async (req, res) => {
  const ctx = orgContext(req, res, 'settings.manage');
  if (!ctx) return;
  await deleteOrgSecret(ctx.org.id, 'scim', 'default');
  audit(ctx, 'identity.scim_deleted', 'organization', ctx.org.id);
  res.json({ ok: true });
});

app.get('/auth/sso/org/:orgId/start', async (req, res) => {
  const org = getOrganization(String(req.params.orgId || ''));
  const config = org && (await organizationIdentityConfig(org.id, 'oidc'));
  if (!org || !config?.issuer || !config?.clientId || !config?.clientSecret)
    return res.status(404).send('Organization SSO is not configured.');
  try {
    const discovery = await oidcDiscovery(config.issuer);
    const state = randomToken(24);
    const verifier = randomToken(48);
    const flow = signChallenge({ state, verifier, orgId: org.id }, 'org-oidc-flow', 10 * 60_000);
    const challenge = _crypto.createHash('sha256').update(verifier).digest('base64url');
    res.append(
      'Set-Cookie',
      `shannon_org_oidc_state=${flow}; HttpOnly; SameSite=Lax; Path=/auth/sso/org/callback; Max-Age=600${COOKIE_SECURE ? '; Secure' : ''}`,
    );
    const redirectUri = `${publicBaseUrl(req)}/auth/sso/org/callback`;
    const target = new URL(discovery.authorization_endpoint);
    target.search = new URLSearchParams({
      client_id: config.clientId,
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: config.scopes || 'openid email profile',
      state,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });
    res.redirect(target.toString());
  } catch (error) {
    res.status(502).type('text/plain').send(`SSO initialization failed: ${error.message}`);
  }
});

app.get('/auth/sso/org/callback', async (req, res) => {
  const flow = verifyChallenge(parseCookies(req).shannon_org_oidc_state || '', 'org-oidc-flow');
  const expected = String(flow?.state || '');
  const actual = String(req.query?.state || '');
  const stateOk =
    expected.length > 0 &&
    expected.length === actual.length &&
    _crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(actual));
  if (!stateOk || !req.query?.code || !flow?.orgId)
    return res.status(400).send('Invalid SSO callback. Start sign-in again.');
  res.append(
    'Set-Cookie',
    `shannon_org_oidc_state=; HttpOnly; SameSite=Lax; Path=/auth/sso/org/callback; Max-Age=0${COOKIE_SECURE ? '; Secure' : ''}`,
  );
  try {
    const config = await organizationIdentityConfig(flow.orgId, 'oidc');
    if (!config) throw new Error('Organization SSO configuration was removed');
    const discovery = await oidcDiscovery(config.issuer);
    const redirectUri = `${publicBaseUrl(req)}/auth/sso/org/callback`;
    const tokenResponse = await fetch(discovery.token_endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: String(req.query.code),
        redirect_uri: redirectUri,
        client_id: config.clientId,
        client_secret: config.clientSecret,
        code_verifier: String(flow.verifier),
      }),
      signal: AbortSignal.timeout(10_000),
    });
    const tokens = await tokenResponse.json();
    if (!tokenResponse.ok || !tokens.access_token)
      throw new Error(tokens.error_description || tokens.error || 'token exchange failed');
    const profileResponse = await fetch(discovery.userinfo_endpoint, {
      headers: { authorization: `Bearer ${tokens.access_token}` },
      signal: AbortSignal.timeout(10_000),
    });
    const profile = await profileResponse.json();
    if (!profileResponse.ok || !profile.sub || !profile.email || profile.email_verified === false)
      throw new Error('SSO user profile is incomplete or unverified');
    const email = String(profile.email).toLowerCase();
    const emailDomain = registrable(email.split('@')[1] || '');
    if (!config.allowedDomains?.includes(emailDomain))
      throw new Error('Your email domain is not allowed for this workspace');
    const providerKey = `${config.issuer}#org=${flow.orgId}`;
    const identity = await findSsoIdentity(providerKey, String(profile.sub));
    const users = loadUsers();
    let user = (identity && users[identity.userId]) || findUserByEmail(email);
    if (!user) {
      const id = _crypto.randomBytes(8).toString('hex');
      user = {
        id,
        email,
        name: profile.name || email,
        picture: profile.picture || null,
        emailVerifiedAt: Date.now(),
        disabledAt: null,
        mfaEnabled: false,
        mfaSecretEnc: null,
        mfaRecoveryCodes: [],
        createdAt: Date.now(),
        subscription: null,
      };
      users[id] = user;
    }
    if (user.disabledAt) return res.status(403).send('This account is disabled.');
    user.emailVerifiedAt ||= Date.now();
    saveUsers(users);
    await waitForUserWrites();
    await saveSsoIdentity({
      provider: providerKey,
      subject: String(profile.sub),
      userId: user.id,
      email,
      createdAt: Date.now(),
      lastLoginAt: Date.now(),
    });
    if (!getMembership(flow.orgId, user.id))
      saveMembership({ orgId: flow.orgId, userId: user.id, role: 'viewer', createdAt: Date.now() });
    setSessionCookie(res, user.id);
    res.append(
      'Set-Cookie',
      `shannon_org=${encodeURIComponent(flow.orgId)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL_DAYS * 86400}${COOKIE_SECURE ? '; Secure' : ''}`,
    );
    res.redirect('/');
  } catch (error) {
    res.status(502).type('text/plain').send(`SSO sign-in failed: ${error.message}`);
  }
});

app.get('/auth/sso', async (req, res) => {
  const clientId = process.env.OIDC_CLIENT_ID;
  if (!clientId || !process.env.OIDC_CLIENT_SECRET) return res.status(503).send('Company SSO is not configured.');
  try {
    const discovery = await oidcDiscovery();
    const state = randomToken(24);
    const verifier = randomToken(48);
    const flow = signChallenge({ state, verifier }, 'oidc-flow', 10 * 60_000);
    const challenge = _crypto.createHash('sha256').update(verifier).digest('base64url');
    res.append(
      'Set-Cookie',
      `shannon_oidc_state=${flow}; HttpOnly; SameSite=Lax; Path=/auth/sso/callback; Max-Age=600${COOKIE_SECURE ? '; Secure' : ''}`,
    );
    const redirectUri = `${publicBaseUrl(req)}/auth/sso/callback`;
    const target = new URL(discovery.authorization_endpoint);
    target.search = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: process.env.OIDC_SCOPES || 'openid email profile',
      state,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });
    res.redirect(target.toString());
  } catch (error) {
    res.status(502).type('text/plain').send(`SSO initialization failed: ${error.message}`);
  }
});

app.get('/auth/sso/callback', async (req, res) => {
  const flow = verifyChallenge(parseCookies(req).shannon_oidc_state || '', 'oidc-flow');
  const expected = String(flow?.state || '');
  const actual = String(req.query?.state || '');
  const stateOk =
    expected.length > 0 &&
    expected.length === actual.length &&
    _crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(actual));
  if (!stateOk || !req.query?.code) return res.status(400).send('Invalid SSO callback. Start sign-in again.');
  res.append(
    'Set-Cookie',
    `shannon_oidc_state=; HttpOnly; SameSite=Lax; Path=/auth/sso/callback; Max-Age=0${COOKIE_SECURE ? '; Secure' : ''}`,
  );
  try {
    const discovery = await oidcDiscovery();
    const redirectUri = `${publicBaseUrl(req)}/auth/sso/callback`;
    const tokenResponse = await fetch(discovery.token_endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: String(req.query.code),
        redirect_uri: redirectUri,
        client_id: process.env.OIDC_CLIENT_ID,
        client_secret: process.env.OIDC_CLIENT_SECRET,
        code_verifier: String(flow.verifier),
      }),
      signal: AbortSignal.timeout(10_000),
    });
    const tokens = await tokenResponse.json();
    if (!tokenResponse.ok || !tokens.access_token)
      throw new Error(tokens.error_description || tokens.error || 'token exchange failed');
    const profileResponse = await fetch(discovery.userinfo_endpoint, {
      headers: { authorization: `Bearer ${tokens.access_token}` },
      signal: AbortSignal.timeout(10_000),
    });
    const profile = await profileResponse.json();
    if (!profileResponse.ok || !profile.sub || !profile.email) throw new Error('SSO user profile is incomplete');
    if (profile.email_verified === false) throw new Error('SSO provider has not verified this email address');
    const email = String(profile.email).toLowerCase();
    const allowedDomains = String(process.env.SHANNON_SSO_ALLOWED_DOMAINS || '')
      .split(',')
      .map((item) => item.trim().toLowerCase())
      .filter(Boolean);
    if (allowedDomains.length && !allowedDomains.includes(email.split('@')[1]))
      throw new Error('Your email domain is not allowed for this workspace');
    const provider = String(process.env.OIDC_ISSUER).replace(/\/$/, '');
    const identity = await findSsoIdentity(provider, String(profile.sub));
    const users = loadUsers();
    let user = (identity && users[identity.userId]) || findUserByEmail(email);
    if (!user) {
      const id = _crypto.randomBytes(8).toString('hex');
      user = {
        id,
        email,
        name: profile.name || email,
        picture: profile.picture || null,
        emailVerifiedAt: Date.now(),
        disabledAt: null,
        mfaEnabled: false,
        mfaSecretEnc: null,
        mfaRecoveryCodes: [],
        createdAt: Date.now(),
        subscription: null,
      };
      users[id] = user;
    } else if (user.disabledAt) {
      return res.status(403).send('This account is disabled.');
    }
    user.emailVerifiedAt ||= Date.now();
    if (!user.picture && profile.picture) user.picture = profile.picture;
    saveUsers(users);
    await waitForUserWrites();
    await saveSsoIdentity({
      provider,
      subject: String(profile.sub),
      userId: user.id,
      email,
      createdAt: Date.now(),
      lastLoginAt: Date.now(),
    });
    ensurePersonalOrg(user);
    setSessionCookie(res, user.id);
    res.redirect('/');
  } catch (error) {
    res.status(502).type('text/plain').send(`SSO sign-in failed: ${error.message}`);
  }
});

function requireScim(req, res, next) {
  const configured = String(process.env.SHANNON_SCIM_TOKEN || '');
  const supplied = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const valid =
    configured.length >= 24 &&
    configured.length === supplied.length &&
    _crypto.timingSafeEqual(Buffer.from(configured), Buffer.from(supplied));
  if (!valid)
    return res
      .status(401)
      .set('www-authenticate', 'Bearer')
      .json({ schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], status: '401', detail: 'Unauthorized' });
  const orgId = process.env.SHANNON_SCIM_ORG_ID;
  if (!orgId || !getOrganization(orgId))
    return res.status(503).json({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
      status: '503',
      detail: 'SCIM organization is not configured',
    });
  req.scimOrgId = orgId;
  req.scimTenantScoped = false;
  next();
}

function scimUser(user, active = !user.disabledAt) {
  return {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
    id: user.id,
    userName: user.email,
    active,
    displayName: user.name || user.email,
    name: { formatted: user.name || user.email },
    emails: [{ value: user.email, primary: true }],
    meta: { resourceType: 'User', created: new Date(user.createdAt || Date.now()).toISOString() },
  };
}

async function requireOrgScim(req, res, next) {
  const orgId = String(req.params.orgId || '');
  const config = getOrganization(orgId) && (await organizationIdentityConfig(orgId, 'scim'));
  const configured = String(config?.token || '');
  const supplied = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const valid =
    configured.length >= 24 &&
    configured.length === supplied.length &&
    _crypto.timingSafeEqual(Buffer.from(configured), Buffer.from(supplied));
  if (!valid)
    return res
      .status(401)
      .set('www-authenticate', 'Bearer')
      .json({ schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], status: '401', detail: 'Unauthorized' });
  req.scimOrgId = orgId;
  req.scimTenantScoped = true;
  next();
}

const scimRouter = express.Router();
scimRouter.get('/ServiceProviderConfig', (_req, res) =>
  res.json({
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
    patch: { supported: true },
    bulk: { supported: false },
    filter: { supported: true, maxResults: 200 },
    changePassword: { supported: false },
    sort: { supported: false },
    etag: { supported: false },
  }),
);
scimRouter.get('/Users', (req, res) => {
  let users = listMembers(req.scimOrgId)
    .map((member) => loadUsers()[member.userId])
    .filter(Boolean);
  const match = /^userName\s+eq\s+"([^"]+)"$/i.exec(String(req.query.filter || ''));
  if (match) users = users.filter((user) => user.email === match[1].toLowerCase());
  const resources = users.map(scimUser);
  res.json({
    schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
    totalResults: resources.length,
    startIndex: 1,
    itemsPerPage: resources.length,
    Resources: resources,
  });
});
scimRouter.get('/Users/:id', (req, res) => {
  const membership = getMembership(req.scimOrgId, req.params.id);
  const user = membership && loadUsers()[req.params.id];
  if (!user)
    return res
      .status(404)
      .json({ schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], status: '404', detail: 'User not found' });
  res.json(scimUser(user));
});
scimRouter.post('/Users', async (req, res) => {
  const email = String(req.body?.userName || req.body?.emails?.[0]?.value || '')
    .trim()
    .toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
      status: '400',
      detail: 'A valid userName is required',
    });
  const users = loadUsers();
  let user = findUserByEmail(email);
  if (!user) {
    const id = _crypto.randomBytes(8).toString('hex');
    user = {
      id,
      email,
      name: sanitizeLabel(req.body?.displayName || req.body?.name?.formatted || email, 100),
      emailVerifiedAt: Date.now(),
      disabledAt: !req.scimTenantScoped && req.body?.active === false ? Date.now() : null,
      mfaEnabled: false,
      mfaSecretEnc: null,
      mfaRecoveryCodes: [],
      createdAt: Date.now(),
      subscription: null,
    };
    users[id] = user;
    saveUsers(users);
    await waitForUserWrites();
  }
  if (req.body?.active !== false && !getMembership(req.scimOrgId, user.id))
    saveMembership({ orgId: req.scimOrgId, userId: user.id, role: 'viewer', createdAt: Date.now() });
  res.status(201).json(scimUser(user, req.body?.active !== false && !user.disabledAt));
});
scimRouter.patch('/Users/:id', (req, res) => {
  const membership = getMembership(req.scimOrgId, req.params.id);
  const user = membership && loadUsers()[req.params.id];
  if (!user)
    return res
      .status(404)
      .json({ schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], status: '404', detail: 'User not found' });
  for (const operation of req.body?.Operations || []) {
    const path = String(operation.path || '').toLowerCase();
    if (path === 'active' || (!path && Object.hasOwn(operation.value || {}, 'active'))) {
      const active = path === 'active' ? operation.value : operation.value.active;
      if (req.scimTenantScoped) {
        // The dashboard never lets an owner be removed this way; neither does provisioning.
        if (active === false && membership.role === 'owner') {
          return res.status(403).json({
            schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
            status: '403',
            detail: 'The organization owner cannot be deactivated through provisioning.',
          });
        }
        if (active === false) removeMembership(req.scimOrgId, user.id);
        else if (!getMembership(req.scimOrgId, user.id))
          saveMembership({ orgId: req.scimOrgId, userId: user.id, role: 'viewer', createdAt: Date.now() });
      } else user.disabledAt = active === false ? Date.now() : null;
    }
    if (path === 'displayname') user.name = sanitizeLabel(operation.value, 100);
  }
  saveUsers(loadUsers());
  res.json(scimUser(user, req.scimTenantScoped ? !!getMembership(req.scimOrgId, user.id) : !user.disabledAt));
});
scimRouter.delete('/Users/:id', (req, res) => {
  const membership = getMembership(req.scimOrgId, req.params.id);
  const user = membership && loadUsers()[req.params.id];
  if (!user) return res.status(404).end();
  if (req.scimTenantScoped && membership.role === 'owner') {
    return res.status(403).json({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
      status: '403',
      detail: 'The organization owner cannot be removed through provisioning.',
    });
  }
  if (req.scimTenantScoped) removeMembership(req.scimOrgId, user.id);
  else {
    user.disabledAt = Date.now();
    saveUsers(loadUsers());
  }
  res.status(204).end();
});

app.use('/scim/v2/orgs/:orgId', requireOrgScim, scimRouter);
app.use('/scim/v2', requireScim, scimRouter);

async function stripeRequest(path, params) {
  const response = await fetch(`https://api.stripe.com/v1/${path}`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${process.env.STRIPE_SECRET_KEY}`,
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams(params),
    signal: AbortSignal.timeout(15_000),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data?.error?.message || `Stripe returned ${response.status}`);
  return data;
}

export function verifyStripeWebhook(raw, signatureHeader, secret, now = Date.now()) {
  const header = String(signatureHeader || '');
  const timestamp = header
    .split(',')
    .find((item) => item.startsWith('t='))
    ?.slice(2);
  const signatures = header
    .split(',')
    .filter((item) => item.startsWith('v1='))
    .map((item) => item.slice(3));
  if (!raw || !timestamp || !secret || Math.abs(now / 1000 - Number(timestamp)) > 300) return null;
  const expected = _crypto
    .createHmac('sha256', secret)
    .update(`${timestamp}.${raw.toString('utf8')}`)
    .digest('hex');
  const valid = signatures.some(
    (value) => value.length === expected.length && _crypto.timingSafeEqual(Buffer.from(value), Buffer.from(expected)),
  );
  if (!valid) return null;
  try {
    return JSON.parse(raw.toString('utf8'));
  } catch {
    return null;
  }
}

function verifiedStripeEvent(req) {
  return verifyStripeWebhook(req.rawBody, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET || '');
}

app.post('/api/auth/subscribe', async (req, res) => {
  const ctx = requirePermission(req, res, 'settings.manage');
  if (!ctx) return;
  if (!billingEnabled()) return res.status(503).json({ error: 'Billing is not configured.' });
  const cycle = req.body?.cycle === 'yearly' ? 'yearly' : 'monthly';
  const price = cycle === 'yearly' ? process.env.STRIPE_PRO_YEARLY_PRICE_ID : process.env.STRIPE_PRO_MONTHLY_PRICE_ID;
  if (!price) return res.status(503).json({ error: `${cycle} billing is not configured.` });
  try {
    const base = publicBaseUrl(req);
    const session = await stripeRequest('checkout/sessions', {
      mode: 'subscription',
      'line_items[0][price]': price,
      'line_items[0][quantity]': '1',
      customer_email: ctx.user.email,
      client_reference_id: ctx.org.id,
      'metadata[orgId]': ctx.org.id,
      'subscription_data[metadata][orgId]': ctx.org.id,
      success_url: `${base}/?billing=success`,
      cancel_url: `${base}/?billing=cancelled`,
      allow_promotion_codes: 'true',
    });
    audit(ctx, 'billing.checkout_created', 'organization', ctx.org.id, { cycle, sessionId: session.id });
    res.json({ ok: true, url: session.url });
  } catch (error) {
    res.status(502).json({ error: `Could not create checkout: ${error.message}` });
  }
});

app.post('/api/billing/webhook', async (req, res) => {
  if (!stripeCardReady()) return res.status(503).json({ error: 'Billing is not configured.' });
  const event = verifiedStripeEvent(req);
  if (!event) return res.status(400).json({ error: 'Invalid Stripe signature.' });
  const object = event.data?.object || {};
  if (object.metadata?.kind === 'commerce') {
    try {
      const outcome = await applyCommerceWebhook(event, object);
      return res.json({ received: true, ...outcome });
    } catch (error) {
      console.error('[commerce] webhook failed:', error.message);
      return res.status(500).json({ error: 'Could not apply payment.' });
    }
  }
  if (!billingEnabled()) return res.json({ received: true, ignored: 'subscription billing is not configured' });
  const orgId = String(object.metadata?.orgId || object.client_reference_id || '');
  if (orgId && getOrganization(orgId)) {
    const eventAt = Number(event.created || 0) * 1000 || Date.now();
    const current = await getEntitlement(orgId);
    if (current?.updatedAt && current.updatedAt >= eventAt) return res.json({ received: true, duplicateOrStale: true });
    if (event.type === 'checkout.session.completed') {
      const paid = object.payment_status === 'paid' || object.payment_status === 'no_payment_required';
      await saveEntitlement({
        orgId,
        plan: 'pro',
        status: paid ? 'active' : 'incomplete',
        provider: 'stripe',
        providerCustomerId: String(object.customer || ''),
        providerSubscriptionId: String(object.subscription || ''),
        currentPeriodEnd: null,
        limits: PRO_LIMITS,
        updatedAt: eventAt,
      });
    } else if (
      event.type === 'customer.subscription.updated' ||
      event.type === 'customer.subscription.created' ||
      event.type === 'customer.subscription.deleted'
    ) {
      await saveEntitlement({
        orgId,
        plan: 'pro',
        status: event.type.endsWith('.deleted') ? 'canceled' : String(object.status || 'incomplete'),
        provider: 'stripe',
        providerCustomerId: String(object.customer || ''),
        providerSubscriptionId: String(object.id || ''),
        currentPeriodEnd: object.current_period_end ? Number(object.current_period_end) * 1000 : null,
        limits: PRO_LIMITS,
        updatedAt: eventAt,
      });
    }
  }
  res.json({ received: true });
});

app.get('/api/auth/plans', (_req, res) => {
  res.json({ plans: billingEnabled() ? [FREE_PLAN, PRO_PLAN] : [FREE_PLAN], billingEnabled: billingEnabled() });
});

app.post('/api/auth/cancel', async (req, res) => {
  const ctx = requirePermission(req, res, 'settings.manage');
  if (!ctx) return;
  const entitlement = await getEntitlement(ctx.org.id);
  if (!billingEnabled() || !entitlement?.providerCustomerId)
    return res.status(409).json({ error: 'This organization has no Stripe subscription.' });
  try {
    const portal = await stripeRequest('billing_portal/sessions', {
      customer: entitlement.providerCustomerId,
      return_url: `${publicBaseUrl(req)}/`,
    });
    res.json({ ok: true, url: portal.url });
  } catch (error) {
    res.status(502).json({ error: `Could not open billing portal: ${error.message}` });
  }
});

// ===== Security assistant, memory, research reports, developer API keys, share links =====
// The assistant runs on the organization's own Anthropic key. Org context sent to the model is
// wrapped as data; see assistant.mjs for the prompts and limits.

const MEMORY_MAX_NOTES = 50;
const newId = (prefix) => `${prefix}_${randomUUID().replaceAll('-', '').slice(0, 20)}`;

async function readScanText(orgId, scanId, paths) {
  for (const rel of paths) {
    const local = join(WORKSPACES, scanId, rel);
    if (existsSync(local)) return readFileSync(local, 'utf-8');
  }
  const artifacts = await listArtifacts(orgId, scanId).catch(() => []);
  for (const rel of paths) {
    const artifact = artifacts.find((item) => item.metadata?.relativePath === rel);
    if (artifact) {
      try {
        return (await readArtifact(artifact)).toString('utf8');
      } catch {}
    }
  }
  return null;
}

// Assistant and research text is rendered server-side with raw HTML escaped (share-page.mjs).
const withHtml = (message) => ({ ...message, html: renderMarkdown(message.content) });
const conversationSummary = (c) => ({
  id: c.id,
  title: c.title,
  createdAt: c.createdAt,
  updatedAt: c.updatedAt,
  messageCount: (c.messages || []).length,
});

async function ownConversation(req, res) {
  const ctx = requirePermission(req, res, 'findings.read');
  if (!ctx) return null;
  const conversation = await assistantConversations.get(String(req.params.id || ''));
  if (!conversation || conversation.orgId !== ctx.org.id || conversation.userId !== ctx.user.id) {
    res.status(404).json({ error: 'Conversation not found.' });
    return null;
  }
  return { ctx, conversation };
}

app.get('/api/assistant/conversations', async (req, res) => {
  const ctx = requirePermission(req, res, 'findings.read');
  if (!ctx) return;
  const list = await assistantConversations.list(
    { orgId: ctx.org.id, userId: ctx.user.id },
    { orderBy: 'updatedAt', limit: 100 },
  );
  res.json({ ok: true, conversations: list.map(conversationSummary) });
});

app.get('/api/assistant/conversations/:id', async (req, res) => {
  const found = await ownConversation(req, res);
  if (found)
    res.json({
      ok: true,
      conversation: { ...found.conversation, messages: (found.conversation.messages || []).map(withHtml) },
    });
});

app.delete('/api/assistant/conversations/:id', async (req, res) => {
  const found = await ownConversation(req, res);
  if (!found) return;
  await assistantConversations.remove(found.conversation.id);
  res.json({ ok: true });
});

async function saveMemoryNote(ctx, rawText) {
  const normalized = normalizeMemoryText(rawText);
  if (!normalized.ok) return { ok: false, status: 400, error: normalized.error };
  const existing = await assistantMemory.list({ orgId: ctx.org.id }, { limit: 500 });
  if (existing.length >= MEMORY_MAX_NOTES)
    return { ok: false, status: 409, error: `Memory is full (${MEMORY_MAX_NOTES} notes). Delete one first.` };
  const note = {
    id: newId('mem'),
    orgId: ctx.org.id,
    text: normalized.text,
    createdBy: ctx.user.id,
    createdAt: Date.now(),
  };
  await assistantMemory.save(note);
  audit(ctx, 'assistant.memory_added', 'assistant_memory', note.id, {});
  return { ok: true, note };
}

app.post('/api/assistant/chat', async (req, res) => {
  const ctx = requirePermission(req, res, 'findings.read');
  if (!ctx) return;
  if (limited(req, res, `assistant:${ctx.user.id}`, 60, 60 * 60 * 1000)) return;
  const text = cleanUserText(req.body?.message);
  if (!text) return res.status(400).json({ error: 'Type a message.' });
  const requestedId = req.body?.conversationId ? String(req.body.conversationId) : '';
  let conversation = requestedId ? await assistantConversations.get(requestedId) : null;
  if (requestedId && (!conversation || conversation.orgId !== ctx.org.id || conversation.userId !== ctx.user.id)) {
    return res.status(404).json({ error: 'Conversation not found.' });
  }
  const now = Date.now();
  conversation ||= {
    id: newId('cnv'),
    orgId: ctx.org.id,
    userId: ctx.user.id,
    title: conversationTitle(text),
    messages: [],
    createdAt: now,
    updatedAt: now,
  };
  const history = [...(conversation.messages || []), { role: 'user', content: text, at: now }];

  const remember = parseRememberCommand(text);
  let reply;
  if (remember !== null) {
    if (!can(ctx.membership.role, 'findings.triage'))
      reply = {
        role: 'assistant',
        content: 'Your role cannot add organization memory. Ask an analyst, engineer, admin or owner.',
        at: Date.now(),
        local: true,
      };
    else {
      const saved = await saveMemoryNote(ctx, remember);
      reply = {
        role: 'assistant',
        content: saved.ok ? `Saved to organization memory: "${saved.note.text}"` : saved.error,
        at: Date.now(),
        local: true,
      };
    }
  } else {
    const apiKey = (await aiKeysForRequest(req)).claude;
    if (!apiKey)
      return res
        .status(400)
        .json({ error: 'Anthropic key required. An organization owner or admin can add it in Settings.' });
    const [memory, scans] = await Promise.all([
      assistantMemory.list({ orgId: ctx.org.id }, { limit: MEMORY_MAX_NOTES }),
      listOrgScans(ctx.org.id),
    ]);
    const system = [
      { type: 'text', text: ASSISTANT_INSTRUCTIONS, cache_control: { type: 'ephemeral' } },
      {
        type: 'text',
        text: buildOrgContext({ orgName: ctx.org.name, memory, findings: listFindings(ctx.org.id), scans }),
      },
    ];
    let result;
    try {
      result = await runChat({ apiKey, system, messages: toApiMessages(history) });
    } catch (error) {
      const described = describeAiError(error);
      return res.status(described.status).json({ error: described.message });
    }
    reply = result.ok
      ? {
          role: 'assistant',
          content: result.text || '(The assistant returned no text.)',
          at: Date.now(),
          model: result.model,
          truncated: result.truncated || undefined,
        }
      : {
          role: 'assistant',
          content:
            "I can't help with that request. I can help you understand, prioritize and fix findings in systems your organization owns.",
          at: Date.now(),
          model: result.model,
          refusal: true,
        };
  }
  conversation = {
    ...conversation,
    messages: [...history, reply].slice(-CHAT_LIMITS.storedMessages),
    updatedAt: Date.now(),
  };
  await assistantConversations.save(conversation);
  res.json({ ok: true, conversation: conversationSummary(conversation), reply: withHtml(reply) });
});

app.get('/api/assistant/memory', async (req, res) => {
  const ctx = requirePermission(req, res, 'findings.read');
  if (!ctx) return;
  res.json({
    ok: true,
    notes: await assistantMemory.list({ orgId: ctx.org.id }, { limit: MEMORY_MAX_NOTES }),
    canEdit: can(ctx.membership.role, 'findings.triage'),
  });
});

app.post('/api/assistant/memory', async (req, res) => {
  const ctx = requirePermission(req, res, 'findings.triage');
  if (!ctx) return;
  const saved = await saveMemoryNote(ctx, req.body?.text);
  if (!saved.ok) return res.status(saved.status).json({ error: saved.error });
  res.status(201).json({ ok: true, note: saved.note });
});

app.delete('/api/assistant/memory/:id', async (req, res) => {
  const ctx = requirePermission(req, res, 'findings.triage');
  if (!ctx) return;
  const note = await assistantMemory.get(String(req.params.id || ''));
  if (!note || note.orgId !== ctx.org.id) return res.status(404).json({ error: 'Note not found.' });
  await assistantMemory.remove(note.id);
  audit(ctx, 'assistant.memory_deleted', 'assistant_memory', note.id, {});
  res.json({ ok: true });
});

const RESEARCH_STALE_MS = 20 * 60 * 1000;
const researchSummary = ({ markdown, ...rest }) => ({ ...rest, hasReport: !!markdown });

async function settleStaleResearch(report) {
  if (report?.status === 'running' && Date.now() - report.updatedAt > RESEARCH_STALE_MS) {
    const failed = {
      ...report,
      status: 'failed',
      error: 'The report did not finish (the server may have restarted). Start a new one.',
      updatedAt: Date.now(),
    };
    await researchReports.save(failed);
    return failed;
  }
  return report;
}

async function generateResearch(report, { apiKey, orgId }) {
  try {
    const findings = listFindings(orgId).filter(
      (f) =>
        domainMatches(f.details?.target || f.details?.url || f.details?.host || '', report.domain) ||
        JSON.stringify(f.details || {})
          .toLowerCase()
          .includes(report.domain),
    );
    const scans = (await listOrgScans(orgId)).filter((scan) => domainMatches(scan.target, report.domain));
    const reports = [];
    for (const scan of scans) {
      if (reports.length >= 5) break;
      const text = await readScanText(orgId, scan.id, ['purple/certification-report.md', 'report.md']);
      if (text)
        reports.push({ scanId: scan.id, target: scan.target, status: scan.status, startedAt: scan.startedAt, text });
    }
    const result = await runResearch({
      apiKey,
      system: RESEARCH_INSTRUCTIONS,
      prompt: researchMaterial({ domain: report.domain, findings, reports }),
    });
    const sources = { findings: findings.length, scans: scans.length, reportsUsed: reports.map((r) => r.scanId) };
    if (!result.ok) {
      await researchReports.save({
        ...report,
        status: 'failed',
        error: 'The model declined to write this report.',
        model: result.model,
        sources,
        updatedAt: Date.now(),
      });
      return;
    }
    await researchReports.save({
      ...report,
      status: 'completed',
      markdown: result.truncated ? `${result.text}\n\n> Report truncated at the output limit.` : result.text,
      model: result.model,
      sources,
      updatedAt: Date.now(),
    });
  } catch (error) {
    await researchReports
      .save({ ...report, status: 'failed', error: describeAiError(error).message, updatedAt: Date.now() })
      .catch(() => {});
  }
}

app.post('/api/assistant/research', async (req, res) => {
  const ctx = requirePermission(req, res, 'scans.run');
  if (!ctx) return;
  const domain = registrable(hostOf(String(req.body?.domain || '')));
  if (!domain || !domain.includes('.'))
    return res.status(400).json({ error: 'Enter a domain, for example example.com.' });
  if (!isVerified(ctx.user.id, domain))
    return res
      .status(403)
      .json({ error: `Verify ownership of ${domain} first (Domains page).`, needsVerification: domain });
  const running = (await researchReports.list({ orgId: ctx.org.id, status: 'running' }, { limit: 10 })).map((r) => r);
  for (const item of running) await settleStaleResearch(item);
  if ((await researchReports.list({ orgId: ctx.org.id, status: 'running' }, { limit: 1 })).length)
    return res.status(409).json({ error: 'A research report is already being written for this organization.' });
  const apiKey = (await aiKeysForRequest(req)).claude;
  if (!apiKey)
    return res
      .status(400)
      .json({ error: 'Anthropic key required. An organization owner or admin can add it in Settings.' });
  if (!(await consumeOrgQuota(ctx, res, 'agentRuns'))) return;
  const now = Date.now();
  const report = {
    id: newId('rsr'),
    orgId: ctx.org.id,
    userId: ctx.user.id,
    domain,
    status: 'running',
    markdown: null,
    model: null,
    error: null,
    sources: null,
    createdAt: now,
    updatedAt: now,
  };
  await researchReports.save(report);
  audit(ctx, 'assistant.research_started', 'research_report', report.id, { domain });
  generateResearch(report, { apiKey, orgId: ctx.org.id });
  res.status(202).json({ ok: true, report: researchSummary(report) });
});

app.get('/api/assistant/research', async (req, res) => {
  const ctx = requirePermission(req, res, 'findings.read');
  if (!ctx) return;
  const list = await researchReports.list({ orgId: ctx.org.id }, { limit: 50 });
  const settled = [];
  for (const item of list) settled.push(await settleStaleResearch(item));
  res.json({ ok: true, reports: settled.map(researchSummary) });
});

app.get('/api/assistant/research/:id', async (req, res) => {
  const ctx = requirePermission(req, res, 'findings.read');
  if (!ctx) return;
  const report = await settleStaleResearch(await researchReports.get(String(req.params.id || '')));
  if (!report || report.orgId !== ctx.org.id) return res.status(404).json({ error: 'Report not found.' });
  res.json({ ok: true, report: { ...report, html: report.markdown ? renderMarkdown(report.markdown) : null } });
});

app.delete('/api/assistant/research/:id', async (req, res) => {
  const ctx = requirePermission(req, res, 'scans.run');
  if (!ctx) return;
  const report = await researchReports.get(String(req.params.id || ''));
  if (!report || report.orgId !== ctx.org.id) return res.status(404).json({ error: 'Report not found.' });
  await researchReports.remove(report.id);
  res.json({ ok: true });
});

// --- Developer API keys (used as Authorization: Bearer svx_... on /api/v1/*) ---
const MAX_ACTIVE_KEYS = 20;
const keyView = ({ secretHash, ...rest }) => rest;

app.get('/api/developer/keys', async (req, res) => {
  const ctx = requirePermission(req, res, 'settings.manage');
  if (!ctx) return;
  res.json({
    ok: true,
    keys: (await apiKeys.list({ orgId: ctx.org.id }, { limit: 200 })).map(keyView),
    scopes: API_SCOPES,
  });
});

app.post('/api/developer/keys', async (req, res) => {
  const ctx = requirePermission(req, res, 'settings.manage');
  if (!ctx) return;
  const name = sanitizeLabel(req.body?.name || '', 80);
  if (!name) return res.status(400).json({ error: 'Give the key a name, for example "GitHub Actions".' });
  const active = (await apiKeys.list({ orgId: ctx.org.id }, { limit: 200 })).filter((key) => !key.revokedAt);
  if (active.length >= MAX_ACTIVE_KEYS)
    return res.status(409).json({ error: `An organization can have at most ${MAX_ACTIVE_KEYS} active keys.` });
  const generated = newApiKey();
  const key = {
    id: generated.id,
    orgId: ctx.org.id,
    name,
    hint: generated.hint,
    secretHash: generated.secretHash,
    scopes: normalizeScopes(req.body?.scopes),
    createdBy: ctx.user.id,
    createdAt: Date.now(),
    lastUsedAt: null,
    revokedAt: null,
  };
  await apiKeys.save(key);
  audit(ctx, 'developer.key_created', 'api_key', key.id, { scopes: key.scopes });
  res.status(201).json({ ok: true, key: keyView(key), token: generated.token });
});

app.delete('/api/developer/keys/:id', async (req, res) => {
  const ctx = requirePermission(req, res, 'settings.manage');
  if (!ctx) return;
  const key = await apiKeys.get(String(req.params.id || ''));
  if (!key || key.orgId !== ctx.org.id) return res.status(404).json({ error: 'Key not found.' });
  if (!key.revokedAt) await apiKeys.save({ ...key, revokedAt: Date.now() });
  audit(ctx, 'developer.key_revoked', 'api_key', key.id, {});
  res.json({ ok: true });
});

app.get('/api/v1/me', (req, res) => {
  const ctx = requirePermission(req, res, 'scans.read');
  if (!ctx) return;
  res.json({ organization: { id: ctx.org.id, name: ctx.org.name }, key: req.apiKey ? keyView(req.apiKey) : null });
});

app.get('/api/v1/findings', (req, res) => {
  const ctx = requirePermission(req, res, 'findings.read');
  if (!ctx) return;
  const status = req.query.status ? String(req.query.status) : undefined;
  res.json({ findings: listFindings(ctx.org.id, { status }) });
});

// --- Share links: expiring, revocable, read-only public pages ---
const shareView = ({ secretHash, ...rest }) => rest;

async function shareResource(ctx, type, id) {
  if (type === 'research') {
    const report = await researchReports.get(id);
    return report && report.orgId === ctx.org.id && report.status === 'completed'
      ? { title: `Security assessment: ${report.domain}` }
      : null;
  }
  if (type === 'conversation') {
    const conversation = await assistantConversations.get(id);
    return conversation && conversation.orgId === ctx.org.id && conversation.userId === ctx.user.id
      ? { title: conversation.title }
      : null;
  }
  if (type === 'scan-report') {
    if (getScanOwner(id)?.orgId !== ctx.org.id) return null;
    const html = await readScanText(ctx.org.id, id, ['purple/certification-report.html']);
    return html ? { title: `Scan report ${id}` } : null;
  }
  return null;
}

app.post('/api/share-links', async (req, res) => {
  const ctx = requirePermission(req, res, 'findings.triage');
  if (!ctx) return;
  const type = String(req.body?.resourceType || '');
  const resourceId = String(req.body?.resourceId || '');
  if (!SHARE_TYPES.includes(type) || !resourceId) return res.status(400).json({ error: 'Choose what to share.' });
  const resource = await shareResource(ctx, type, resourceId);
  if (!resource)
    return res.status(404).json({ error: 'Nothing to share: it does not exist, is not finished, or is not yours.' });
  const token = newShareToken();
  const link = {
    id: token.id,
    orgId: ctx.org.id,
    resourceType: type,
    resourceId,
    title: resource.title,
    secretHash: token.secretHash,
    createdBy: ctx.user.id,
    createdAt: Date.now(),
    expiresAt: shareExpiry(req.body?.days),
    revokedAt: null,
    views: 0,
  };
  await shareLinks.save(link);
  audit(ctx, 'share.created', 'share_link', link.id, { resourceType: type, resourceId, expiresAt: link.expiresAt });
  res.status(201).json({ ok: true, link: shareView(link), url: `${publicBaseUrl(req)}/share/${token.token}` });
});

app.get('/api/share-links', async (req, res) => {
  const ctx = requirePermission(req, res, 'findings.read');
  if (!ctx) return;
  const links = await shareLinks.list({ orgId: ctx.org.id }, { limit: 200 });
  res.json({ ok: true, links: links.map((link) => ({ ...shareView(link), active: shareUsable(link) })) });
});

app.delete('/api/share-links/:id', async (req, res) => {
  const ctx = requirePermission(req, res, 'findings.triage');
  if (!ctx) return;
  const link = await shareLinks.get(String(req.params.id || ''));
  if (!link || link.orgId !== ctx.org.id) return res.status(404).json({ error: 'Link not found.' });
  if (link.createdBy !== ctx.user.id && !can(ctx.membership.role, 'settings.manage'))
    return res.status(403).json({ error: 'Only the person who shared it or an admin can revoke this link.' });
  if (!link.revokedAt) await shareLinks.save({ ...link, revokedAt: Date.now() });
  audit(ctx, 'share.revoked', 'share_link', link.id, {});
  res.json({ ok: true });
});

app.get('/share/:token', async (req, res) => {
  if (limited(req, res, 'share-view', 120, 5 * 60 * 1000)) return;
  res.setHeader('cache-control', 'no-store');
  res.setHeader('x-robots-tag', 'noindex, nofollow');
  res.setHeader('referrer-policy', 'no-referrer');
  const parsed = parseShareToken(req.params.token);
  const link = parsed ? await shareLinks.get(parsed.id).catch(() => null) : null;
  if (!link || !secretMatches(parsed.secret, link.secretHash) || !shareUsable(link))
    return res.status(404).type('html').send(renderShareGone());
  let html = null;
  if (link.resourceType === 'research') {
    const report = await researchReports.get(link.resourceId);
    if (report?.orgId === link.orgId && report.status === 'completed') html = renderSharedResearch(report, link);
  } else if (link.resourceType === 'conversation') {
    const conversation = await assistantConversations.get(link.resourceId);
    if (conversation?.orgId === link.orgId) html = renderSharedConversation(conversation, link);
  } else if (link.resourceType === 'scan-report' && getScanOwner(link.resourceId)?.orgId === link.orgId) {
    html = await readScanText(link.orgId, link.resourceId, ['purple/certification-report.html']);
    // Engine-generated HTML: render it sandboxed so no script can run on our origin.
    if (html) res.setHeader('content-security-policy', REPORT_SANDBOX);
  }
  if (!html) return res.status(404).type('html').send(renderShareGone());
  shareLinks.save({ ...link, views: Number(link.views || 0) + 1 }).catch(() => {});
  res.type('html').send(html);
});

// ===== Commerce: fixed-price scan offers, credit packs, card + manual payments =====
// Everything answers "free during beta" until SHANNON_COMMERCE_ENABLED=1. Prices come only from
// commerce.mjs; the client never sends an amount.

function commerceCatalog() {
  return publicCatalog(process.env, {
    cardReady: stripeCardReady(),
    plans: billingEnabled() ? [FREE_PLAN, PRO_PLAN] : [FREE_PLAN],
    freeLimits: FREE_LIMITS,
  });
}

async function grantCreditsForOrder(order) {
  const grant = creditGrantFor(order);
  if (!grant) return null;
  const { created } = await addCreditGrant(grant);
  return { grantId: grant.id, created };
}

async function applyCommerceWebhook(event, object) {
  const paidEvent =
    event.type === 'checkout.session.completed' || event.type === 'checkout.session.async_payment_succeeded';
  if (!paidEvent) return { ignored: event.type };
  if (object.payment_status !== 'paid') return { pending: true };
  const order = await getCommerceOrder(String(object.metadata?.orderId || ''));
  if (!order || order.orgId !== String(object.metadata?.orgId || '')) return { ignored: 'unknown order' };
  const expected = Math.round(order.amount * 100);
  if (Number(object.amount_total) !== expected || String(object.currency || '').toUpperCase() !== order.currency) {
    console.error(`[commerce] amount mismatch for order ${order.id}: got ${object.amount_total} ${object.currency}`);
    return { ignored: 'amount mismatch' };
  }
  const result = markCardPaid(order, { providerRef: object.payment_intent || object.id });
  if (!result.ok) return { ignored: result.code };
  if (!result.alreadyApplied) await saveCommerceOrder(result.order);
  const grant = await grantCreditsForOrder(result.order);
  return { orderId: order.id, applied: !result.alreadyApplied, grant };
}

function commerceClosed(res) {
  res
    .status(503)
    .json({ error: 'Securovix is free during beta, so purchases are not open yet.', code: 'COMMERCE_DISABLED' });
}

function orderView(order) {
  const { history, ...rest } = order;
  return { ...rest, history: (history || []).map(({ status, at }) => ({ status, at })) };
}

app.get('/api/commerce/catalog', (_req, res) => {
  res.setHeader('cache-control', 'public, max-age=60');
  res.json(commerceCatalog());
});

app.get('/api/commerce/account', async (req, res) => {
  const ctx = requirePermission(req, res, 'audit.read');
  if (!ctx) return;
  const [orders, grants] = await Promise.all([
    listCommerceOrders({ orgId: ctx.org.id, limit: 50 }),
    listCreditGrants(ctx.org.id),
  ]);
  const now = Date.now();
  res.json({
    ok: true,
    catalog: commerceCatalog(),
    credits: creditBalance(grants, now),
    grants: grants
      .filter((grant) => grant.expiresAt > now)
      .map(({ id, orderId, remaining, expiresAt }) => ({ id, orderId, remaining, expiresAt })),
    orders: orders.map(orderView),
    canPurchase: can(ctx.membership.role, 'settings.manage'),
  });
});

app.post('/api/commerce/orders', async (req, res) => {
  const ctx = requirePermission(req, res, 'settings.manage');
  if (!ctx) return;
  if (!commerceEnabled()) return commerceClosed(res);
  if (limited(req, res, `commerce:order:${ctx.user.id}`, 20, 60 * 60 * 1000)) return;
  const item = catalogItem(req.body?.itemId);
  const method = String(req.body?.method || '');
  const created = newOrder({
    id: randomUUID(),
    orgId: ctx.org.id,
    userId: ctx.user.id,
    itemId: item?.id,
    method,
    methods: paymentMethods(process.env, { cardReady: stripeCardReady() }),
  });
  if (!created.ok) return res.status(400).json({ error: created.error, code: created.code });
  const order = created.order;
  if (method === 'card') {
    try {
      const base = publicBaseUrl(req);
      const session = await stripeRequest('checkout/sessions', {
        mode: 'payment',
        customer_email: ctx.user.email,
        client_reference_id: ctx.org.id,
        'line_items[0][quantity]': '1',
        'line_items[0][price_data][currency]': order.currency.toLowerCase(),
        'line_items[0][price_data][unit_amount]': String(Math.round(order.amount * 100)),
        'line_items[0][price_data][product_data][name]': `Securovix — ${order.itemName}`,
        'metadata[kind]': 'commerce',
        'metadata[orderId]': order.id,
        'metadata[orgId]': ctx.org.id,
        'payment_intent_data[metadata][orderId]': order.id,
        success_url: `${base}/?purchase=success#billing`,
        cancel_url: `${base}/?purchase=cancelled#billing`,
      });
      await saveCommerceOrder({ ...order, providerRef: session.id });
      audit(ctx, 'commerce.order_created', 'commerce_order', order.id, { itemId: order.itemId, method });
      return res.status(201).json({ ok: true, order: orderView(order), checkoutUrl: session.url });
    } catch (error) {
      return res.status(502).json({ error: `Could not start card checkout: ${error.message}` });
    }
  }
  await saveCommerceOrder(order);
  audit(ctx, 'commerce.order_created', 'commerce_order', order.id, { itemId: order.itemId, method });
  res.status(201).json({ ok: true, order: orderView(order), instructions: paymentInstructions(order) });
});

async function ownedOrder(req, res, permission) {
  const ctx = requirePermission(req, res, permission);
  if (!ctx) return null;
  const order = await getCommerceOrder(String(req.params.id || ''));
  if (!order || order.orgId !== ctx.org.id) {
    res.status(404).json({ error: 'Order not found.' });
    return null;
  }
  return { ctx, order };
}

app.get('/api/commerce/orders/:id/instructions', async (req, res) => {
  const found = await ownedOrder(req, res, 'settings.manage');
  if (!found) return;
  if (found.order.status !== 'pending_evidence')
    return res.status(409).json({ error: `Order is ${found.order.status}.` });
  res.json({ ok: true, instructions: paymentInstructions(found.order) });
});

app.post('/api/commerce/orders/:id/evidence', async (req, res) => {
  const found = await ownedOrder(req, res, 'settings.manage');
  if (!found) return;
  const result = submitEvidence(found.order, {
    reference: req.body?.reference,
    note: req.body?.note,
    userId: found.ctx.user.id,
  });
  if (!result.ok)
    return res.status(result.code === 'INVALID_STATE' ? 409 : 400).json({ error: result.error, code: result.code });
  await saveCommerceOrder(result.order);
  audit(found.ctx, 'commerce.evidence_submitted', 'commerce_order', result.order.id, { method: result.order.method });
  res.json({ ok: true, order: orderView(result.order) });
});

app.post('/api/commerce/orders/:id/cancel', async (req, res) => {
  const found = await ownedOrder(req, res, 'settings.manage');
  if (!found) return;
  const result = cancelOrder(found.order, { userId: found.ctx.user.id });
  if (!result.ok) return res.status(409).json({ error: result.error, code: result.code });
  await saveCommerceOrder(result.order);
  audit(found.ctx, 'commerce.order_cancelled', 'commerce_order', result.order.id, {});
  res.json({ ok: true, order: orderView(result.order) });
});

app.get('/api/platform/commerce/orders', async (req, res) => {
  if (!requirePlatformOperator(req, res)) return;
  const status = [
    'pending_review',
    'pending_evidence',
    'pending_payment',
    'approved',
    'rejected',
    'cancelled',
  ].includes(String(req.query.status))
    ? String(req.query.status)
    : 'pending_review';
  const orders = await listCommerceOrders({ status, limit: 200 });
  res.json({
    ok: true,
    status,
    orders: orders.map((order) => ({ ...orderView(order), orgName: getOrganization(order.orgId)?.name || null })),
  });
});

app.post('/api/platform/commerce/orders/:id/review', async (req, res) => {
  const operator = requirePlatformOperator(req, res);
  if (!operator) return;
  const order = await getCommerceOrder(String(req.params.id || ''));
  if (!order) return res.status(404).json({ error: 'Order not found.' });
  const result = reviewOrder(order, {
    decision: req.body?.decision,
    reviewer: operator.email,
    reason: req.body?.reason,
  });
  if (!result.ok)
    return res.status(result.code === 'INVALID_STATE' ? 409 : 400).json({ error: result.error, code: result.code });
  await saveCommerceOrder(result.order);
  const grant = result.order.status === 'approved' ? await grantCreditsForOrder(result.order) : null;
  const org = getOrganization(order.orgId);
  if (org)
    audit({ org, user: operator }, `commerce.order_${result.order.status}`, 'commerce_order', order.id, {
      reviewer: operator.email,
    });
  res.json({ ok: true, order: orderView(result.order), grant });
});

app.get('/api/team/:orgId/usage', async (req, res) => {
  const ctx = orgContext(req, res, 'audit.read');
  if (!ctx) return;
  const current = await organizationPlan(ctx.org.id);
  const [usage, grants] = await Promise.all([listUsage(ctx.org.id), listCreditGrants(ctx.org.id)]);
  res.json({
    ok: true,
    plan: current.plan,
    limits: current.limits,
    usage,
    credits: creditBalance(grants),
    billingEnabled: billingEnabled(),
    commerceEnabled: commerceEnabled(),
  });
});

// Personal Security Shield — deterministic, read-only triage for suspicious messages and links.
// Submitted content is processed in memory, is not persisted, is never fetched, and never becomes
// an instruction to an AI model or external tool.
app.post('/api/personal-shield/analyze', (req, res) => {
  const ctx = requirePermission(req, res, 'scans.read');
  if (!ctx) return;
  if (limited(req, res, `personal-shield:${ctx.user.id}`, 60, 60 * 60 * 1000)) return;
  const message = String(req.body?.message || '');
  const link = String(req.body?.link || '');
  if (!message.trim() && !link.trim()) return res.status(400).json({ error: 'Paste a suspicious message or link.' });
  if (message.length > 20_000 || link.length > 2_048)
    return res.status(413).json({ error: 'Submitted content is too large.' });
  const result = analyzePersonalThreat({ message, link });
  audit(ctx, 'personal_shield.analyzed', 'personal-threat', null, {
    risk: result.risk,
    score: result.score,
    findingTypes: result.findings.map((finding) => finding.id),
    analyzedLinks: result.analyzedLinks,
  });
  res.json({ ok: true, result });
});

// ============================================================
// Code Scan (Red Team vs Blue Team) — authenticated and free for workspace members.
// ============================================================
const CS_OWNER_DISABLED = process.env.SHANNON_OWNER_BYPASS === '0';

function csIsLocalhost(req) {
  if (CS_OWNER_DISABLED) return false;
  const a = req.socket?.remoteAddress || '';
  return a === '::1' || a === '127.0.0.1' || a === '::ffff:127.0.0.1';
}

// Code Scan access is authenticated and organization-scoped.
// Every caller must have a workspace session. The handlers consume durable organization quotas;
// this helper only resolves the user and active organization context.
function csSession(req) {
  const u = getUser(req);
  if (!u) return null;
  const ctx = requestContext(req);
  return {
    isOwner: ctx?.membership?.role === 'owner',
    userId: u.id,
    orgId: ctx?.org?.id || null,
    user: u,
    plan: 'free',
    label: 'Free',
    dailyLimit: -1,
    used: 0,
  };
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

app.get('/api/code-scan/me', async (req, res) => {
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
  const ctx = requestContext(req);
  const current = await organizationPlan(ctx.org.id);
  const usage = await listUsage(ctx.org.id);
  const used = Number(usage.find((item) => item.metric === 'codeFiles')?.quantity || 0);
  return res.json({
    subscribed: true,
    authed: !!u,
    user: publicUser(u),
    isOwner: s.isOwner,
    plan: current.plan,
    label: current.plan === 'pro' ? 'Pro' : 'Free',
    used,
    dailyLimit: current.limits.codeFiles,
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
  claude: { label: 'Claude Opus 4.7', short: 'C', color: '#e26847', model: 'claude-opus-4-7', base: 96 },
  openai: { label: 'GPT-5', short: 'G', color: '#10a37f', model: 'gpt-5', base: 94 },
  gemini: { label: 'Gemini 2.5 Pro', short: 'g', color: '#5b94c4', model: 'gemini-2.5-pro', base: 90 },
  glm: { label: 'GLM-4-Plus', short: 'Z', color: '#88b3a8', model: 'glm-4-plus', base: 80 },
};
const CS_ROLES = [
  { id: 'r1', team: 'red', name: 'Red Lead' },
  { id: 'r2', team: 'red', name: 'Red Operator' },
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
  if (fallback) return -4; // didn't run on the agent's native provider
  const len = (text || '').length;
  let q = 0.4; // base credit for completing the turn
  if (len > 200) q += 0.4;
  if (len > 800) q += 0.6;
  if (len > 2000) q += 0.6;
  return Math.min(2.0, q); // cap per-turn delta
}

// Auto-pick agents from the provider keys the user supplied, ranked by leaderboard score.
// Top score → Red Lead, then Red Operator, Blue Architect, Blue Engineer.
function csPickAgents(keys) {
  // Provider is "available" if it has its own key, OR is claude (which is always the fallback).
  const eligible = Object.keys(CS_PROVIDERS).filter((p) => (p === 'claude' ? !!keys?.claude : !!keys?.[p]));
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
  { id: 'red-recon', agentId: 'r1', step: 'Red Lead surveys the attack surface' },
  { id: 'red-cross', agentId: 'r2', step: 'Red Operator cross-checks findings, adds new vectors' },
  { id: 'blue-defend', agentId: 'b1', step: 'Blue Architect drafts patches' },
  { id: 'blue-harden', agentId: 'b2', step: 'Blue Engineer hardens patches' },
  { id: 'red-bypass', agentId: 'r1', step: 'Red Lead probes for patch bypasses' },
  { id: 'blue-final', agentId: 'b1', step: 'Blue Architect addresses bypasses' },
  { id: 'synth', agentId: 'b2', step: 'Synthesize fixed code & full report' },
];

// The Claude client Code Scan uses. Tests replace it with a fake so no real request is made.
let csClientFactory = (apiKey) => new Anthropic({ apiKey, timeout: 15 * 60 * 1000, maxRetries: 2 });
export function setCodeScanClientFactory(factory) {
  csClientFactory = factory;
}

// One model reply: its text, and whether the provider cut it off at the output limit. A reply
// that was cut off is never treated as a finished one.
async function csCallProvider(provider, model, system, user, keys, maxTokens, signal) {
  // The synthesis turn must hold the full fixed source code + markdown report, so the caller
  // gives it a larger budget. Earlier turns stay lean.
  const mt = maxTokens || 4000;
  if (provider === 'claude') {
    const apiKey = keys?.claude;
    if (!apiKey) throw new Error('No Anthropic API key supplied');
    // Streamed: a reply that carries a whole corrected file is too long for one plain response.
    const message = await csClientFactory(apiKey)
      .messages.stream(
        { model: model || 'claude-opus-4-7', max_tokens: mt, system, messages: [{ role: 'user', content: user }] },
        { signal },
      )
      .finalMessage();
    if (message.stop_reason === 'refusal') throw new Error('The AI declined to review this file.');
    return {
      text: (message.content || [])
        .filter((b) => b.type === 'text')
        .map((b) => b.text)
        .join('\n'),
      truncated: message.stop_reason === 'max_tokens',
    };
  }
  if (provider === 'openai') {
    if (!keys?.openai) throw new Error('No OpenAI key supplied');
    const r = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      signal,
      headers: { authorization: `Bearer ${keys.openai}`, 'content-type': 'application/json' },
      // GPT-5 models take max_completion_tokens and only the default temperature.
      body: JSON.stringify({
        model: model || 'gpt-5',
        messages: [
          { role: 'system', content: system },
          { role: 'user', content: user },
        ],
        max_completion_tokens: mt,
      }),
    });
    const j = await r.json();
    if (!r.ok) throw new Error(j.error?.message || `OpenAI HTTP ${r.status}`);
    return { text: j.choices?.[0]?.message?.content || '', truncated: j.choices?.[0]?.finish_reason === 'length' };
  }
  if (provider === 'gemini') {
    if (!keys?.gemini) throw new Error('No Gemini key supplied');
    const m = model || 'gemini-2.5-pro';
    const r = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(m)}:generateContent?key=${encodeURIComponent(keys.gemini)}`,
      {
        method: 'POST',
        signal,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          systemInstruction: { parts: [{ text: system }] },
          contents: [{ role: 'user', parts: [{ text: user }] }],
          generationConfig: { maxOutputTokens: mt, temperature: 0.4 },
        }),
      },
    );
    const j = await r.json();
    if (!r.ok) throw new Error(j.error?.message || `Gemini HTTP ${r.status}`);
    return {
      text: j.candidates?.[0]?.content?.parts?.map((p) => p.text || '').join('') || '',
      truncated: j.candidates?.[0]?.finishReason === 'MAX_TOKENS',
    };
  }
  if (provider === 'glm') {
    if (!keys?.glm) throw new Error('No GLM key supplied');
    const r = await fetch('https://open.bigmodel.cn/api/paas/v4/chat/completions', {
      method: 'POST',
      signal,
      headers: { authorization: `Bearer ${keys.glm}`, 'content-type': 'application/json' },
      body: JSON.stringify({
        model: model || 'glm-4-plus',
        messages: [
          { role: 'system', content: system },
          { role: 'user', content: user },
        ],
        max_tokens: mt,
        temperature: 0.4,
      }),
    });
    const j = await r.json();
    if (!r.ok) throw new Error(j.error?.message || `GLM HTTP ${r.status}`);
    return { text: j.choices?.[0]?.message?.content || '', truncated: j.choices?.[0]?.finish_reason === 'length' };
  }
  throw new Error(`Unknown provider: ${provider}`);
}

// Runs one agent's turn. A provider that fails is replaced by Claude for that turn and for the
// rest of the run (`failed` remembers it), so one broken key costs one failed call, not one per turn.
async function csCallAgent(agent, system, user, keys, maxTokens, signal, failed) {
  const standIn = async (reason) => {
    const fbSystem = `${system}\n\n[FALLBACK ROLEPLAY: The "${agent.label}" provider failed (${reason}). Continue in-character as ${agent.label} but execute on Anthropic.]`;
    const out = await csCallProvider('claude', null, fbSystem, user, keys, maxTokens, signal);
    return { ...out, fallback: true, fallbackReason: reason };
  };
  if (agent.provider !== 'claude' && failed.has(agent.provider)) return standIn(failed.get(agent.provider));
  try {
    const out = await csCallProvider(agent.provider, agent.model, system, user, keys, maxTokens, signal);
    return { ...out, fallback: false };
  } catch (err) {
    if (agent.provider === 'claude' || signal?.aborted) throw err;
    failed.set(agent.provider, err.message);
    return { ...(await standIn(err.message)), providerFailed: true };
  }
}

function csBuildSystem(agent, phase, isFinalSynth) {
  const role = agent.team === 'red' ? 'OFFENSIVE security researcher' : 'DEFENSIVE security engineer';
  const teamGoal =
    agent.team === 'red'
      ? 'Red Team — find every flaw and produce concrete exploits'
      : 'Blue Team — patch every flaw without breaking original behavior';
  let txt = `You are ${agent.label}, an ${role} in a multi-agent code-security war room. Your team: ${teamGoal}.

You will see a running transcript of every other agent's contribution. Address peers by name. Build on or critique their work — DO NOT repeat what others have said.

${FILE_IS_DATA_RULE}

Be concrete: name lines, name attack vectors, name patches.`;
  if (!isFinalSynth) txt += '\n\nKeep your turn under ~600 words.';
  if (isFinalSynth) {
    txt += `

THIS IS THE FINAL SYNTHESIS TURN. Produce a single JSON object inside a \`\`\`json fence with this schema:
{
  "language": "string",
  "overallRisk": "critical"|"high"|"medium"|"low"|"clean",
  "redTeam": {
    "summary": "string",
    "findings": [ {"id":"F1","severity":"critical|high|medium|low|info","category":"string","title":"string","description":"string","lines":[int],"snippet":"the vulnerable line(s) copied exactly from the file, without the line-number prefix","exploit":"string"} ]
  },
  "blueTeam": {
    "summary": "string",
    "fixedCode": "FULL corrected source code (complete file, not a diff, no line-number prefixes)",
    "patches": [ {"findingIds":["F1"],"description":"string","rationale":"string"} ]
  },
  "report": "Markdown executive report covering: ## Summary, ## Findings (per finding with severity & PoC), ## Patch Strategy, ## Risk Assessment, ## Recommendations, ## Agent Collaboration Notes."
}

Consolidate everything from the transcript. Every finding must quote the vulnerable code in "snippet" exactly as it stands in the file: a finding whose quote is not in the file is discarded, so do not include a finding you cannot point to. Output ONLY the JSON fence — no prose outside it.`;
  }
  return txt;
}

function csBuildUser(code, filename, transcript, phase, isFinalSynth, nonce) {
  let u = `=== Source code under review ===\n${fileBlock(code, filename, nonce)}\n\n`;
  if (transcript.length > 0) {
    u += '=== War-room transcript so far ===\n';
    for (const t of transcript) {
      // A turn may be up to 4,000 tokens long; it is passed on whole so nothing a reviewer found is lost.
      const trim = t.text.length > 20_000 ? `${t.text.slice(0, 20_000)}\n…(truncated)` : t.text;
      u += `\n--- [${t.label} · ${t.step}] ---\n${trim}\n`;
    }
  }
  u += `\n\n=== YOUR TURN ===\nStep: ${phase.step}\n`;
  u += isFinalSynth
    ? 'Produce the final JSON deliverable per the system prompt schema. Consolidate all prior turns into definitive findings, patches, fixedCode, and a markdown report.'
    : 'Contribute NEW analysis specific to this step. Reference peers by name. Be concrete.';
  return u;
}

const csRuns = new Map();
const CS_RUN_TTL_MS = 30 * 60 * 1000;
setInterval(
  () => {
    const now = Date.now();
    for (const [k, r] of csRuns) if (r.endedAt && now - r.endedAt > CS_RUN_TTL_MS) csRuns.delete(k);
  },
  5 * 60 * 1000,
).unref?.();

function csBc(run, ev) {
  // Each event is numbered, so a browser that reconnects can ask for what came after the last one
  // it saw instead of being sent the whole run again.
  const id = run.events.push(ev) - 1;
  const msg = `id: ${id}\ndata: ${JSON.stringify(ev)}\n\n`;
  run.sseClients = run.sseClients.filter((c) => {
    try {
      c.write(msg);
      return true;
    } catch {
      return false;
    }
  });
}

// Ends a run. The submitted code and the provider keys are dropped: nothing needs them any more.
function csEnd(run, status, error = null) {
  run.status = status;
  run.error = error;
  run.endedAt = Date.now();
  run.code = null;
  run.keys = null;
}

async function csOrchestrate(runId) {
  const run = csRuns.get(runId);
  if (!run) return;
  const keys = run.keys || {};
  const code = run.code;
  const agents = run.agents?.length ? run.agents : csPickAgents(keys);
  run.agents = agents;
  const signal = run.abort?.signal;
  // Providers that failed in this run, with the reason. They are not tried again.
  const failed = new Map();
  // The file is fenced with a code the file itself cannot contain or predict.
  const nonce = randomUUID().replaceAll('-', '').slice(0, 16);

  csBc(run, { type: 'agents', agents });
  csBc(run, { type: 'phases', phases: CS_PHASES });
  csBc(run, {
    type: 'lineup',
    summary: agents
      .map((a) => `${a.name}: ${CS_PROVIDERS[a.provider].label} (score ${a.score.toFixed(1)})`)
      .join(' · '),
  });

  for (let i = 0; i < CS_PHASES.length && !run.cancelled; i++) {
    const phase = CS_PHASES[i];
    const agent = agents.find((a) => a.id === phase.agentId);
    const isFinalSynth = i === CS_PHASES.length - 1;
    csBc(run, {
      type: 'phase-start',
      phaseIndex: i,
      phaseId: phase.id,
      agentId: agent.id,
      label: agent.label,
      team: agent.team,
      step: phase.step,
      provider: agent.provider,
    });

    const sys = csBuildSystem(agent, phase, isFinalSynth);
    const user = csBuildUser(code, run.filename, run.transcript, phase, isFinalSynth, nonce);
    const t0 = Date.now();
    // The synthesis turn carries the whole corrected file and the report, so its budget grows
    // with the file. The other turns are short.
    const maxTokens = isFinalSynth ? outputBudget(code, { min: 16_000, max: 64_000, extra: 8_000 }) : 4000;
    let turnResult;
    try {
      turnResult = await csCallAgent(agent, sys, user, keys, maxTokens, signal, failed);
    } catch (err) {
      if (run.cancelled) break;
      csUpdateLeaderboard(agent.provider, csQualityDelta('', false, true), Date.now() - t0, 0);
      csEnd(run, 'failed', `${agent.label} failed: ${err.message}`);
      csBc(run, { type: 'failed', error: run.error, agentId: agent.id });
      return;
    }
    if (run.cancelled) break;
    const { text, truncated, fallback, fallbackReason } = turnResult;
    const dt = Date.now() - t0;

    // The provider that broke is marked down once, when it breaks. The one that did the work
    // (Claude, when it stood in) is credited for the work.
    if (turnResult.providerFailed) csUpdateLeaderboard(agent.provider, csQualityDelta('', false, true), dt, 0);
    const realProvider = fallback ? 'claude' : agent.provider;
    csUpdateLeaderboard(realProvider, csQualityDelta(text, false, false), dt, text.length);

    const turn = {
      phaseIndex: i,
      phaseId: phase.id,
      agentId: agent.id,
      label: agent.label,
      team: agent.team,
      step: phase.step,
      text,
      truncated,
      fallback,
      fallbackReason,
      provider: agent.provider,
      realProvider,
      ms: dt,
      ts: Date.now(),
    };
    run.transcript.push(turn);
    csBc(run, { type: 'turn', ...turn });
  }

  if (run.cancelled) {
    csEnd(run, 'cancelled');
    csBc(run, { type: 'cancelled' });
    return;
  }

  // Nothing the last turn says is passed on unchecked: it must be in the agreed shape, and each
  // finding must be found in the submitted file.
  const last = run.transcript.at(-1);
  const parsed = parseModelJson(last?.text);
  const checked = checkScanResult(parsed?.value ?? null, code, {
    truncated: !!last?.truncated,
    complete: parsed?.complete ?? false,
  });
  if (!checked.ok) {
    csEnd(run, 'failed', checked.error);
    csBc(run, { type: 'failed', error: checked.error });
    return;
  }
  if (!checked.result.incomplete) csUpdateLeaderboard(last.realProvider || last.provider, 1.5, 0, 0, { win: true });
  run.result = checked.result;
  csEnd(run, 'complete');
  csBc(run, { type: 'complete', result: checked.result, agents });
}

app.post('/api/code-scan/multi/start', async (req, res) => {
  const ctx = requirePermission(req, res, 'scans.run');
  if (!ctx) return;
  if (limited(req, res, `code-scan:${ctx.user.id}`, 20, 60 * 60 * 1000)) return;
  const session = csSession(req);
  if (!session) return res.status(401).json({ ok: false, error: 'Authentication required.' });
  const { code } = req.body || {};
  const filename = safeFilename(req.body?.filename);
  if (!code || typeof code !== 'string') return res.status(400).json({ ok: false, error: 'Provide source code.' });
  if (code.length > CODE_SCAN_MAX_CHARS)
    return res.status(413).json({
      ok: false,
      code: 'FILE_TOO_LARGE',
      limit: CODE_SCAN_MAX_CHARS,
      error: `This file is too large for Code Scan (${code.length.toLocaleString('en')} characters; the limit is ${CODE_SCAN_MAX_CHARS.toLocaleString('en')}). A larger file could not be returned whole as a corrected copy. Split it into smaller files.`,
    });

  const keys = await aiKeysForRequest(req);
  if (!keys.claude) {
    return res.status(400).json({
      ok: false,
      error: 'Anthropic key required. An organization owner or admin can add it in Settings.',
    });
  }
  if (!(await consumeOrgQuota(ctx, res, 'codeFiles'))) return;

  const runId = randomUUID().slice(0, 8);
  const sessForRun = { isOwner: session.isOwner, userId: session.userId, orgId: ctx.org.id };

  const run = {
    id: runId,
    code,
    filename,
    keys,
    transcript: [],
    events: [],
    sseClients: [],
    agents: [],
    status: 'running',
    result: null,
    cancelled: false,
    abort: new AbortController(),
    startedAt: Date.now(),
    endedAt: null,
    session: sessForRun,
  };
  csRuns.set(runId, run);

  // Pre-pick agents synchronously so we can return the lineup with the start response.
  const lineup = csPickAgents(keys);
  run.agents = lineup;

  csOrchestrate(runId).catch((err) => {
    csEnd(run, 'failed', err.message);
    csBc(run, { type: 'failed', error: err.message });
  });

  res.json({ ok: true, runId, agents: lineup, phases: CS_PHASES });
});

app.get('/api/code-scan/multi/:id/events', (req, res) => {
  const run = csRuns.get(req.params.id);
  const ctx = requestContext(req);
  if (!run || !ctx || run.session?.userId !== ctx.user.id || run.session?.orgId !== ctx.org.id)
    return res.status(404).json({ ok: false, error: 'Run not found' });
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  // A browser that reconnects says which event it saw last and is sent only what came after.
  const seen = Number.parseInt(req.headers['last-event-id'] ?? req.query.after ?? '', 10);
  const from = Number.isInteger(seen) && seen >= 0 ? seen + 1 : 0;
  for (let i = from; i < run.events.length; i++) res.write(`id: ${i}\ndata: ${JSON.stringify(run.events[i])}\n\n`);
  if (run.status !== 'running') return res.end();
  run.sseClients.push(res);
  // A model call can be silent for minutes; without this a proxy closes the idle connection.
  const beat = setInterval(() => {
    try {
      res.write(': keep-alive\n\n');
    } catch {}
  }, 15_000);
  beat.unref?.();
  req.on('close', () => {
    clearInterval(beat);
    run.sseClients = run.sseClients.filter((c) => c !== res);
  });
});

app.get('/api/code-scan/multi/:id/result', (req, res) => {
  const run = csRuns.get(req.params.id);
  const ctx = requestContext(req);
  if (!run || !ctx || run.session?.userId !== ctx.user.id || run.session?.orgId !== ctx.org.id)
    return res.status(404).json({ ok: false, error: 'Run not found' });
  res.json({
    ok: true,
    status: run.status,
    transcript: run.transcript,
    result: run.result,
    error: run.error,
    agents: run.agents || [],
    phases: CS_PHASES,
  });
});

app.post('/api/code-scan/multi/:id/cancel', (req, res) => {
  const run = csRuns.get(req.params.id);
  const ctx = requirePermission(req, res, 'scans.stop');
  if (!ctx) return;
  if (!run || run.session?.userId !== ctx.user.id || run.session?.orgId !== ctx.org.id)
    return res.status(404).json({ ok: false });
  run.cancelled = true;
  // Stops the model call that is in flight, not only the ones after it.
  run.abort?.abort();
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
    "findings": [ { "id":"F1","severity":"critical|high|medium|low|info","category":"string","title":"string","description":"string","lines":[int],"snippet":"the vulnerable line(s) copied exactly from the file, without the line-number prefix","exploit":"string" } ]
  },
  "blueTeam": {
    "summary": "string",
    "fixedCode": "string (the COMPLETE corrected file content, not a diff, no line-number prefixes)",
    "patches": [ { "findingIds":["F1"],"description":"string","rationale":"string" } ]
  }
}

Rules:
- fixedCode MUST be the complete file. If clean, return the original code unchanged with overallRisk "clean" and empty findings.
- Every finding must quote the vulnerable code in "snippet" exactly as it stands in the file. A finding whose quote is not in the file is discarded, so do not include a finding you cannot point to.
- Output ONLY the JSON code fence — no prose before or after.

${FILE_IS_DATA_RULE}`;

async function quickScanFile({ apiKey, code, filename, signal }) {
  const nonce = randomUUID().replaceAll('-', '').slice(0, 16);
  const { text, truncated } = await csCallProvider(
    'claude',
    process.env.SHANNON_QUICK_MODEL || 'claude-sonnet-4-6',
    QUICK_SYSTEM,
    fileBlock(code, filename, nonce),
    { claude: apiKey },
    outputBudget(code, { min: 8192, max: 64_000, extra: 4000 }),
    signal,
  );
  const parsed = parseModelJson(text);
  const checked = checkScanResult(parsed?.value ?? null, code, { truncated, complete: parsed?.complete ?? false });
  return checked.ok ? { ok: true, result: checked.result } : { ok: false, error: checked.error };
}

app.post('/api/code-scan/quick', async (req, res) => {
  const ctx = requirePermission(req, res, 'scans.run');
  if (!ctx) return;
  if (limited(req, res, `quick-scan:${ctx.user.id}`, 60, 60 * 60 * 1000)) return;
  const session = csSession(req);
  if (!session) return res.status(401).json({ ok: false, error: 'Authentication required.' });
  const { code } = req.body || {};
  const filename = safeFilename(req.body?.filename);
  if (!code || typeof code !== 'string') return res.status(400).json({ ok: false, error: 'Provide source code.' });
  if (code.length > CODE_SCAN_MAX_CHARS)
    return res.status(413).json({
      ok: false,
      code: 'FILE_TOO_LARGE',
      limit: CODE_SCAN_MAX_CHARS,
      error: `File too large for Code Scan (${code.length.toLocaleString('en')} characters; the limit is ${CODE_SCAN_MAX_CHARS.toLocaleString('en')}).`,
    });

  const apiKey = (await aiKeysForRequest(req)).claude;
  if (!apiKey) return res.status(400).json({ ok: false, error: 'Anthropic key required.' });
  if (!(await consumeOrgQuota(ctx, res, 'codeFiles'))) return;

  try {
    const out = await quickScanFile({ apiKey, code, filename });
    // A reply that could not be used is a failed scan of this file, never an empty result.
    res.status(out.ok ? 200 : 502).json(out);
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message || String(err) });
  }
});

// Provider performance leaderboard — drives the auto-pick and lets the user see who's winning.
app.get('/api/code-scan/leaderboard', (req, res) => {
  const lb = csLoadLeaderboard();
  const rows = Object.keys(CS_PROVIDERS)
    .map((p) => ({
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
    }))
    .sort((a, b) => b.score - a.score);
  res.json({ ok: true, leaderboard: rows, totalRuns: rows.reduce((a, r) => a + r.runs, 0) });
});

app.post('/api/code-scan/leaderboard/reset', (req, res) => {
  if (!requirePlatformOperator(req, res)) return;
  const ctx = requestContext(req);
  csSaveLeaderboard({});
  audit(ctx, 'leaderboard.reset', 'leaderboard', null);
  res.json({ ok: true });
});

// ---- Settings persistence ----
function loadSettings() {
  if (existsSync(SETTINGS_PATH)) {
    try {
      return JSON.parse(readFileSync(SETTINGS_PATH, 'utf-8'));
    } catch {}
  }
  return {
    apiKey: process.env.ANTHROPIC_API_KEY || '',
    model: process.env.SHANNON_MODEL || 'claude-opus-4-7',
    provider: 'anthropic',
    baseUrl: '',
  };
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

function settingsFor(req) {
  const user = getUser(req);
  return user ? { ...loadSettings(), ...loadUserSettings(user.id) } : loadSettings();
}

const AI_PROVIDER_NAMES = new Set(['claude', 'openai', 'gemini', 'glm']);

async function organizationAiKeys(orgId) {
  const keys = { claude: '', openai: '', gemini: '', glm: '' };
  if (!orgId) return keys;
  for (const row of await listOrgSecrets(orgId, 'ai-provider', { includeSecrets: true })) {
    if (!AI_PROVIDER_NAMES.has(row.name)) continue;
    try {
      keys[row.name] = String(decryptSecret(row.secretEnc)?.apiKey || '');
    } catch {}
  }
  return keys;
}

async function aiKeysForRequest(req) {
  const ctx = requestContext(req);
  const keys = await organizationAiKeys(ctx?.org?.id);
  if (Object.values(keys).some(Boolean)) return keys;
  const allowPlatform = process.env.SHANNON_ALLOW_PLATFORM_AI_KEYS === '1' || process.env.NODE_ENV !== 'production';
  if (!allowPlatform) return keys;
  const legacy = settingsFor(req);
  return {
    claude: legacy.apiKey || process.env.ANTHROPIC_API_KEY || '',
    openai: legacy.openaiKey || process.env.OPENAI_API_KEY || '',
    gemini: legacy.geminiKey || process.env.GOOGLE_API_KEY || '',
    glm: legacy.glmKey || process.env.ZHIPU_API_KEY || '',
  };
}

// Initialize from saved settings
const initSettings = loadSettings();
if (initSettings.apiKey && !process.env.ANTHROPIC_API_KEY) process.env.ANTHROPIC_API_KEY = initSettings.apiKey;
if (initSettings.model) process.env.SHANNON_MODEL = initSettings.model;

// ---- API: Settings ----
// Provider key values are never returned; only organization-scoped configuration status is exposed.
app.get('/api/settings', (req, res) => {
  const s = settingsFor(req);
  res.json({
    keysStorage: 'encrypted-organization-store',
    model: s.model || process.env.SHANNON_MODEL || 'claude-opus-4-7',
    provider: s.provider || 'anthropic',
    baseUrl: s.baseUrl || '',
  });
});

app.post('/api/settings', async (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in first.' });
  const current = settingsFor(req);
  const updated = { ...current, ...req.body };
  const baseUrl = typeof updated.baseUrl === 'string' ? updated.baseUrl.trim().slice(0, 2048) : '';
  // Scans send the organization's AI key to this address, so it is never an internal one.
  if (baseUrl && (!/^https?:\/\//i.test(baseUrl) || (await privateTarget(baseUrl)))) {
    return res.status(400).json({ error: 'The AI base address must be a public http(s) address.' });
  }
  const sanitized = {
    provider: String(updated.provider || '').slice(0, 40),
    model: String(updated.model || '').slice(0, 120),
    baseUrl,
  };
  // Only these three fields change; anything else stored for the account (such as the weekly
  // summary choice) is kept.
  saveUserSettings(user.id, { ...loadUserSettings(user.id), ...sanitized });
  res.json({ ok: true });
});

app.get('/api/team/:orgId/ai-providers', async (req, res) => {
  const ctx = orgContext(req, res, 'scans.read');
  if (!ctx) return;
  const rows = await listOrgSecrets(ctx.org.id, 'ai-provider');
  res.json({
    ok: true,
    providers: [...AI_PROVIDER_NAMES].map((provider) => {
      const row = rows.find((item) => item.name === provider);
      return { provider, configured: !!row?.configured, updatedAt: row?.updatedAt || null };
    }),
  });
});

app.put('/api/team/:orgId/ai-providers/:provider', async (req, res) => {
  const ctx = orgContext(req, res, 'integrations.manage');
  if (!ctx) return;
  const provider = String(req.params.provider || '').toLowerCase();
  if (!AI_PROVIDER_NAMES.has(provider)) return res.status(400).json({ error: 'Unsupported AI provider.' });
  const apiKey = String(req.body?.apiKey || '').trim();
  if (apiKey.length < 10 || apiKey.length > 8_192) return res.status(400).json({ error: 'API key is invalid.' });
  const previous = await getOrgSecret(ctx.org.id, 'ai-provider', provider);
  const now = Date.now();
  await saveOrgSecret({
    id: previous?.id || `osec_${randomUUID().replaceAll('-', '')}`,
    orgId: ctx.org.id,
    kind: 'ai-provider',
    name: provider,
    config: {},
    secretEnc: encryptSecret({ apiKey }),
    createdBy: previous?.createdBy || ctx.user.id,
    createdAt: previous?.createdAt || now,
    updatedAt: now,
  });
  audit(ctx, previous ? 'ai_provider.rotated' : 'ai_provider.created', 'ai-provider', provider);
  res.json({ ok: true, provider, configured: true, updatedAt: now });
});

app.delete('/api/team/:orgId/ai-providers/:provider', async (req, res) => {
  const ctx = orgContext(req, res, 'integrations.manage');
  if (!ctx) return;
  const provider = String(req.params.provider || '').toLowerCase();
  if (!AI_PROVIDER_NAMES.has(provider)) return res.status(400).json({ error: 'Unsupported AI provider.' });
  await deleteOrgSecret(ctx.org.id, 'ai-provider', provider);
  audit(ctx, 'ai_provider.deleted', 'ai-provider', provider);
  res.json({ ok: true });
});

// Repository automation credentials are organization-scoped and encrypted with the same
// envelope used for AI, OIDC, SCIM, and connector secrets. The token is never returned.
app.get('/api/team/:orgId/repository-provider', async (req, res) => {
  const ctx = orgContext(req, res, 'scans.read');
  if (!ctx) return;
  const row = await getOrgSecret(ctx.org.id, 'repository-provider', 'github');
  res.json({
    ok: true,
    provider: 'github',
    configured: !!row?.secretEnc,
    repo: String(row?.config?.repo || ''),
    updatedAt: row?.updatedAt || null,
  });
});

app.put('/api/team/:orgId/repository-provider', async (req, res) => {
  const ctx = orgContext(req, res, 'integrations.manage');
  if (!ctx) return;
  const token = String(req.body?.token || '').trim();
  const repo = String(req.body?.repo || '').trim();
  if (repo && (!/^[^\s/]+\/[^\s/]+$/.test(repo) || repo.length > 240)) {
    return res.status(400).json({ error: 'Default repository must use owner/repository format.' });
  }
  const previous = await getOrgSecret(ctx.org.id, 'repository-provider', 'github');
  let previousSecret = {};
  try {
    previousSecret = previous ? decryptSecret(previous.secretEnc) || {} : {};
  } catch {}
  const selectedToken = token || String(previousSecret.token || '');
  if (selectedToken.length < 20 || selectedToken.length > 8_192) {
    return res.status(400).json({ error: 'A valid GitHub token is required.' });
  }
  const now = Date.now();
  await saveOrgSecret({
    id: previous?.id || `osec_${randomUUID().replaceAll('-', '')}`,
    orgId: ctx.org.id,
    kind: 'repository-provider',
    name: 'github',
    config: { repo },
    secretEnc: encryptSecret({ token: selectedToken }),
    createdBy: previous?.createdBy || ctx.user.id,
    createdAt: previous?.createdAt || now,
    updatedAt: now,
  });
  audit(
    ctx,
    previous ? 'repository_provider.rotated' : 'repository_provider.created',
    'repository-provider',
    'github',
    { repo },
  );
  res.json({ ok: true, provider: 'github', configured: true, repo, updatedAt: now });
});

app.delete('/api/team/:orgId/repository-provider', async (req, res) => {
  const ctx = orgContext(req, res, 'integrations.manage');
  if (!ctx) return;
  await deleteOrgSecret(ctx.org.id, 'repository-provider', 'github');
  audit(ctx, 'repository_provider.deleted', 'repository-provider', 'github');
  res.json({ ok: true });
});

// ---- API: Vulnerability management ---------------------------------------
app.get('/api/team/:orgId/vulnerabilities', async (req, res) => {
  const ctx = orgContext(req, res, 'findings.read');
  if (!ctx) return;
  try {
    const [components, matches, provider] = await Promise.all([
      listSoftwareComponents(ctx.org.id),
      listVulnerabilityMatches(ctx.org.id),
      getOrgSecret(ctx.org.id, 'repository-provider', 'github'),
    ]);
    const componentById = new Map(components.map((item) => [item.id, item]));
    const enriched = matches.map((item) => ({ ...item, component: componentById.get(item.componentId) || null }));
    const open = enriched.filter((item) => !['resolved', 'accepted'].includes(item.status));
    res.json({
      ok: true,
      components,
      matches: enriched,
      github: { configured: !!provider?.secretEnc, repo: String(provider?.config?.repo || '') },
      stats: {
        components: components.length,
        open: open.length,
        critical: open.filter((item) => item.severity === 'critical').length,
        kev: open.filter((item) => item.details?.kev).length,
        overdue: open.filter((item) => item.dueAt && item.dueAt < Date.now()).length,
      },
    });
  } catch (error) {
    const migration = /shannon_(software_components|vulnerability_matches)/i.test(error.message || '');
    res
      .status(migration ? 503 : 500)
      .json({ error: migration ? 'Vulnerability database migration is not applied yet.' : error.message });
  }
});

app.post('/api/team/:orgId/vulnerabilities/sbom', async (req, res) => {
  const ctx = orgContext(req, res, 'defender.manage');
  if (!ctx) return;
  try {
    const projectId = req.body?.projectId || null;
    const assetId = req.body?.assetId || null;
    if (projectId && !listProjects(ctx.org.id).some((item) => item.id === projectId))
      return res.status(400).json({ error: 'Project is not part of this organization.' });
    if (assetId && !(await listDefenseAssets(ctx.org.id)).some((item) => item.id === assetId))
      return res.status(400).json({ error: 'Asset is not part of this organization.' });
    const sourceRef = sanitizeLabel(req.body?.sourceRef || `upload-${new Date().toISOString().slice(0, 10)}`, 500);
    const parsed = parseSbom(req.body?.document, { source: 'sbom', sourceRef });
    const components = await upsertSoftwareComponents({
      orgId: ctx.org.id,
      projectId,
      assetId,
      components: parsed.components,
    });
    const job = await enqueueJob({
      orgId: ctx.org.id,
      userId: ctx.user.id,
      type: 'vulnerability-refresh',
      payload: { trigger: 'sbom-upload', sourceRef },
      idempotencyKey: `vulnerability-refresh:${ctx.org.id}:sbom:${Date.now()}`,
      maxAttempts: 4,
    });
    audit(ctx, 'sbom.imported', 'software-inventory', sourceRef, { format: parsed.format, count: components.length });
    res
      .status(202)
      .json({ ok: true, format: parsed.format, imported: components.length, job: { id: job.id, status: job.status } });
  } catch (error) {
    res
      .status(/Unsupported|No software|exceeds|must be/.test(error.message) ? 400 : 500)
      .json({ error: error.message });
  }
});

app.post('/api/team/:orgId/vulnerabilities/github', async (req, res) => {
  const ctx = orgContext(req, res, 'defender.manage');
  if (!ctx) return;
  try {
    const provider = await getOrgSecret(ctx.org.id, 'repository-provider', 'github');
    if (!provider?.secretEnc)
      return res.status(409).json({ error: 'Configure a GitHub repository token in Settings first.' });
    const projectId = req.body?.projectId || null;
    if (projectId && !listProjects(ctx.org.id).some((item) => item.id === projectId))
      return res.status(400).json({ error: 'Project is not part of this organization.' });
    const secret = decryptSecret(provider.secretEnc) || {};
    const repository = String(req.body?.repo || provider.config?.repo || '').trim();
    const sbom = await fetchGithubSbom(repository, secret.token);
    const parsed = parseSbom(sbom, { source: 'github', sourceRef: repository });
    const components = await upsertSoftwareComponents({ orgId: ctx.org.id, projectId, components: parsed.components });
    const job = await enqueueJob({
      orgId: ctx.org.id,
      userId: ctx.user.id,
      type: 'vulnerability-refresh',
      payload: { trigger: 'github', sourceRef: repository },
      idempotencyKey: `vulnerability-refresh:${ctx.org.id}:github:${Date.now()}`,
      maxAttempts: 4,
    });
    audit(ctx, 'github.dependencies.discovered', 'repository', repository, { count: components.length });
    res
      .status(202)
      .json({ ok: true, repository, imported: components.length, job: { id: job.id, status: job.status } });
  } catch (error) {
    res.status(/must use|not configured|Configure/.test(error.message) ? 400 : 502).json({ error: error.message });
  }
});

app.post('/api/team/:orgId/vulnerabilities/components', async (req, res) => {
  const ctx = orgContext(req, res, 'defender.manage');
  if (!ctx) return;
  try {
    const component = manualSoftwareComponent(req.body, sanitizeLabel(req.body?.sourceRef || 'manual inventory', 500));
    const saved = await upsertSoftwareComponents({ orgId: ctx.org.id, components: [component] });
    const job = await enqueueJob({
      orgId: ctx.org.id,
      userId: ctx.user.id,
      type: 'vulnerability-refresh',
      payload: { trigger: 'manual-inventory' },
      idempotencyKey: `vulnerability-refresh:${ctx.org.id}:manual-inventory:${Date.now()}`,
      maxAttempts: 4,
    });
    audit(ctx, 'software.component.created', 'software-component', saved[0].id, {
      name: saved[0].name,
      version: saved[0].version,
    });
    res.status(202).json({ ok: true, component: saved[0], job: { id: job.id, status: job.status } });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/team/:orgId/vulnerabilities/refresh', async (req, res) => {
  const ctx = orgContext(req, res, 'defender.manage');
  if (!ctx) return;
  const job = await enqueueJob({
    orgId: ctx.org.id,
    userId: ctx.user.id,
    type: 'vulnerability-refresh',
    payload: { trigger: 'manual' },
    idempotencyKey: `vulnerability-refresh:${ctx.org.id}:manual:${Date.now()}`,
    maxAttempts: 4,
  });
  audit(ctx, 'vulnerabilities.refresh.queued', 'job', job.id);
  res.status(202).json({ ok: true, job: { id: job.id, status: job.status } });
});

app.patch('/api/team/:orgId/vulnerabilities/:id', async (req, res) => {
  const ctx = orgContext(req, res, 'findings.triage');
  if (!ctx) return;
  let dueAt;
  if (Object.hasOwn(req.body || {}, 'dueAt')) {
    dueAt = req.body.dueAt ? Date.parse(req.body.dueAt) : null;
    if (req.body.dueAt && !Number.isFinite(dueAt))
      return res.status(400).json({ error: 'Remediation deadline is invalid.' });
  }
  try {
    const match = await updateVulnerabilityMatch(ctx.org.id, req.params.id, {
      status: req.body?.status,
      ...(dueAt !== undefined ? { dueAt } : {}),
    });
    if (!match) return res.status(404).json({ error: 'Vulnerability match not found.' });
    audit(ctx, 'vulnerability.updated', 'vulnerability-match', match.id, { status: match.status, dueAt: match.dueAt });
    res.json({ ok: true, match });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ---- API: Team workspaces --------------------------------------------------
app.get('/api/team/context', (req, res) => {
  const user = getUser(req);
  const organizations = listOrganizations(user.id);
  const active = requestContext(req);
  res.json({
    ok: true,
    organizations,
    active: active ? { organization: active.org, role: active.membership.role } : null,
    roles: ROLES,
  });
});

app.post('/api/team/active', (req, res) => {
  const user = getUser(req);
  const orgId = String(req.body?.orgId || '');
  const membership = getMembership(orgId, user.id);
  if (!membership) return res.status(404).json({ error: 'Organization not found.' });
  res.append(
    'Set-Cookie',
    `shannon_org=${encodeURIComponent(orgId)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL_DAYS * 86400}${COOKIE_SECURE ? '; Secure' : ''}`,
  );
  res.json({ ok: true, organization: getOrganization(orgId), role: membership.role });
});

app.post('/api/team/organizations', (req, res) => {
  const user = getUser(req);
  const name = sanitizeLabel(req.body?.name, 80);
  if (name.length < 2) return res.status(400).json({ error: 'Organization name must be at least 2 characters.' });
  const id = `org_${randomUUID().replaceAll('-', '').slice(0, 16)}`;
  const org = {
    id,
    name,
    slug: `${slugifyOrg(name) || 'security-team'}-${id.slice(-6)}`,
    createdBy: user.id,
    createdAt: Date.now(),
  };
  createOrganization(org, { orgId: id, userId: user.id, role: 'owner', createdAt: Date.now() });
  const ctx = { user, org, membership: getMembership(id, user.id) };
  audit(ctx, 'organization.created', 'organization', id);
  res.status(201).json({ ok: true, organization: { ...org, role: 'owner' } });
});

app.get('/api/team/:orgId/members', (req, res) => {
  const ctx = orgContext(req, res, 'scans.read');
  if (!ctx) return;
  res.json({ ok: true, members: listMembers(ctx.org.id) });
});

app.post('/api/team/:orgId/invitations', async (req, res) => {
  const ctx = orgContext(req, res, 'members.manage');
  if (!ctx) return;
  const email = String(req.body?.email || '')
    .trim()
    .toLowerCase();
  const role = String(req.body?.role || 'viewer');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (!ROLES.includes(role) || role === 'owner')
    return res.status(400).json({ error: 'Choose a valid non-owner role.' });
  const existing = findUserByEmail(email);
  if (existing && getMembership(ctx.org.id, existing.id))
    return res.status(409).json({ error: 'That user is already a member.' });
  try {
    const invitation = await issueAuthToken(req, {
      kind: 'invitation',
      email,
      userId: existing?.id || null,
      orgId: ctx.org.id,
      role,
      createdBy: ctx.user.id,
      ttlMs: 7 * 24 * 60 * 60_000,
      linkPath: '/?invite=',
      subject: `You were invited to ${ctx.org.name}`,
      message: `${ctx.user.name || ctx.user.email} invited you to join ${ctx.org.name} as ${role}. This invitation expires in 7 days.`,
    });
    audit(ctx, 'invitation.created', 'invitation', email, { role });
    res.status(201).json({
      ok: true,
      email,
      role,
      expiresInDays: 7,
      ...(DEV_TOKENS ? { developmentToken: invitation.token } : {}),
    });
  } catch (error) {
    res.status(502).json({ error: `Unable to send invitation: ${error.message}` });
  }
});

app.post('/api/team/:orgId/members', (req, res) => {
  const ctx = orgContext(req, res, 'members.manage');
  if (!ctx) return;
  const email = String(req.body?.email || '')
    .trim()
    .toLowerCase();
  const role = String(req.body?.role || 'viewer');
  const user = findUserByEmail(email);
  if (!user) return res.status(404).json({ error: 'That user must create a Securovix account before being added.' });
  if (!ROLES.includes(role) || role === 'owner')
    return res.status(400).json({ error: 'Choose a valid non-owner role.' });
  if (getMembership(ctx.org.id, user.id)) return res.status(409).json({ error: 'That user is already a member.' });
  const membership = { orgId: ctx.org.id, userId: user.id, role, createdAt: Date.now() };
  saveMembership(membership);
  audit(ctx, 'membership.created', 'membership', user.id, { role });
  res.status(201).json({ ok: true, member: listMembers(ctx.org.id).find((m) => m.userId === user.id) });
});

app.patch('/api/team/:orgId/members/:userId', (req, res) => {
  const ctx = orgContext(req, res, 'members.manage');
  if (!ctx) return;
  const target = getMembership(ctx.org.id, req.params.userId);
  const role = String(req.body?.role || '');
  if (!target) return res.status(404).json({ error: 'Member not found.' });
  if (!canChangeMember(ctx.membership, target, role))
    return res.status(403).json({ error: 'Role change not permitted.' });
  if (
    target.role === 'owner' &&
    role !== 'owner' &&
    listMembers(ctx.org.id).filter((m) => m.role === 'owner').length === 1
  )
    return res.status(409).json({ error: 'An organization must always have an owner.' });
  saveMembership({ ...target, role });
  audit(ctx, 'membership.role_changed', 'membership', target.userId, { from: target.role, to: role });
  res.json({ ok: true, member: listMembers(ctx.org.id).find((m) => m.userId === target.userId) });
});

app.delete('/api/team/:orgId/members/:userId', (req, res) => {
  const ctx = orgContext(req, res, 'members.manage');
  if (!ctx) return;
  const target = getMembership(ctx.org.id, req.params.userId);
  if (!target) return res.status(404).json({ error: 'Member not found.' });
  if (target.role === 'owner') return res.status(409).json({ error: 'Transfer ownership before removing the owner.' });
  if (!canChangeMember(ctx.membership, target, 'viewer'))
    return res.status(403).json({ error: 'Member removal not permitted.' });
  removeMembership(ctx.org.id, target.userId);
  audit(ctx, 'membership.removed', 'membership', target.userId, { role: target.role });
  res.json({ ok: true });
});

app.get('/api/team/:orgId/projects', (req, res) => {
  const ctx = orgContext(req, res, 'scans.read');
  if (!ctx) return;
  res.json({ ok: true, projects: listProjects(ctx.org.id) });
});

app.post('/api/team/:orgId/projects', (req, res) => {
  const ctx = orgContext(req, res, 'projects.manage');
  if (!ctx) return;
  const name = sanitizeLabel(req.body?.name, 100);
  if (name.length < 2) return res.status(400).json({ error: 'Project name must be at least 2 characters.' });
  const criticality = ['low', 'medium', 'high', 'critical'].includes(req.body?.criticality)
    ? req.body.criticality
    : 'medium';
  const project = {
    id: `prj_${randomUUID().replaceAll('-', '').slice(0, 16)}`,
    orgId: ctx.org.id,
    name,
    description: sanitizeLabel(req.body?.description, 500),
    environment: sanitizeLabel(req.body?.environment || 'production', 40),
    criticality,
    createdAt: Date.now(),
  };
  saveProject(project);
  audit(ctx, 'project.created', 'project', project.id, { criticality });
  res.status(201).json({ ok: true, project });
});

app.get('/api/team/:orgId/findings', (req, res) => {
  const ctx = orgContext(req, res, 'findings.read');
  if (!ctx) return;
  res.json({
    ok: true,
    findings: listFindings(ctx.org.id, {
      projectId: req.query.projectId || undefined,
      status: req.query.status || undefined,
    }),
  });
});

app.post('/api/team/:orgId/findings', (req, res) => {
  const ctx = orgContext(req, res, 'findings.triage');
  if (!ctx) return;
  const title = sanitizeLabel(req.body?.title, 180);
  if (!title) return res.status(400).json({ error: 'Finding title is required.' });
  const severity = ['info', 'low', 'medium', 'high', 'critical'].includes(req.body?.severity)
    ? req.body.severity
    : 'medium';
  const basis = `${ctx.org.id}|${req.body?.projectId || ''}|${req.body?.source || 'manual'}|${title.toLowerCase()}|${req.body?.target || ''}`;
  const fingerprint = _crypto.createHash('sha256').update(basis).digest('hex');
  const now = Date.now();
  const finding = saveFinding({
    id: `fnd_${randomUUID().replaceAll('-', '').slice(0, 16)}`,
    orgId: ctx.org.id,
    projectId: req.body?.projectId || null,
    fingerprint,
    title,
    severity,
    status: 'new',
    assigneeUserId: null,
    source: sanitizeLabel(req.body?.source || 'manual', 60),
    details: typeof req.body?.details === 'object' && req.body.details ? req.body.details : {},
    decision: null,
    createdAt: now,
    updatedAt: now,
  });
  audit(ctx, 'finding.created', 'finding', finding.id, { severity, source: finding.source });
  queueIntegrationEvent(
    ctx.org.id,
    {
      id: `finding-created:${finding.id}`,
      type: 'finding.created',
      at: new Date().toISOString(),
      data: finding,
    },
    ctx.user.id,
  ).catch((error) => console.error('[integrations] finding event enqueue failed:', error.message));
  res.status(201).json({ ok: true, finding });
});

app.patch('/api/team/:orgId/findings/:findingId', (req, res) => {
  const ctx = orgContext(req, res, 'findings.read');
  if (!ctx) return;
  if (!can(ctx.membership.role, 'findings.triage') && !can(ctx.membership.role, 'findings.remediate')) {
    return res.status(403).json({ error: `Your ${ctx.membership.role} role cannot change findings.` });
  }
  const finding = getFinding(ctx.org.id, req.params.findingId);
  if (!finding) return res.status(404).json({ error: 'Finding not found.' });
  const next = { ...finding, updatedAt: Date.now() };
  if (req.body?.status && req.body.status !== finding.status) {
    const check = validateFindingTransition({
      role: ctx.membership.role,
      currentStatus: finding.status,
      nextStatus: req.body.status,
      reason: req.body.reason,
      expiresAt: req.body.expiresAt,
    });
    if (!check.ok) return res.status(403).json({ error: check.error });
    next.status = req.body.status;
    next.decision = ['risk-accepted', 'false-positive'].includes(next.status)
      ? {
          reason: sanitizeLabel(req.body.reason, 1000),
          expiresAt: req.body.expiresAt || null,
          by: ctx.user.id,
          at: Date.now(),
        }
      : null;
  }
  if (Object.hasOwn(req.body || {}, 'assigneeUserId')) {
    if (!can(ctx.membership.role, 'findings.triage'))
      return res.status(403).json({ error: 'Assignment not permitted.' });
    const assignee = req.body.assigneeUserId ? getMembership(ctx.org.id, req.body.assigneeUserId) : null;
    if (req.body.assigneeUserId && !assignee)
      return res.status(400).json({ error: 'Assignee must be an organization member.' });
    next.assigneeUserId = req.body.assigneeUserId || null;
    if (next.assigneeUserId && next.status === 'new') next.status = 'assigned';
  }
  saveFinding(next);
  audit(ctx, 'finding.updated', 'finding', next.id, {
    fromStatus: finding.status,
    toStatus: next.status,
    assigneeUserId: next.assigneeUserId,
  });
  queueIntegrationEvent(
    ctx.org.id,
    {
      id: `finding-updated:${next.id}:${next.updatedAt}`,
      type: 'finding.updated',
      at: new Date().toISOString(),
      data: next,
    },
    ctx.user.id,
  ).catch((error) => console.error('[integrations] finding event enqueue failed:', error.message));
  res.json({ ok: true, finding: next });
});

app.get('/api/team/:orgId/audit', (req, res) => {
  const ctx = orgContext(req, res, 'audit.read');
  if (!ctx) return;
  res.json({ ok: true, events: listAudit(ctx.org.id, Number(req.query.limit) || 200) });
});

const INTEGRATION_TYPES = new Set(['webhook', 'slack', 'teams', 'jira', 'linear', 'siem-http']);

const INTEGRATION_FIELDS = {
  webhook: { config: ['url'], secret: ['token', 'headers'] },
  'siem-http': { config: ['url'], secret: ['token', 'headers'] },
  slack: { config: [], secret: ['webhookUrl'] },
  teams: { config: [], secret: ['webhookUrl'] },
  jira: { config: ['baseUrl', 'projectKey', 'issueType'], secret: ['email', 'apiToken'] },
  linear: { config: ['teamId'], secret: ['apiKey'] },
};

function integrationInput(type, rawConfig, rawSecret, existingHasSecret = false) {
  const fields = INTEGRATION_FIELDS[type];
  if (!fields) throw new Error('Unsupported integration type.');
  const config = {};
  const secret = {};
  for (const key of fields.config) {
    if (rawConfig?.[key] !== undefined) config[key] = String(rawConfig[key]).trim().slice(0, 2048);
  }
  for (const key of fields.secret) {
    if (rawSecret?.[key] === undefined) continue;
    if (key === 'headers') {
      if (!rawSecret.headers || typeof rawSecret.headers !== 'object' || Array.isArray(rawSecret.headers))
        throw new Error('headers must be an object.');
      secret.headers = Object.fromEntries(
        Object.entries(rawSecret.headers)
          .slice(0, 20)
          .map(([name, value]) => {
            const headerName = String(name).slice(0, 100);
            const headerValue = String(value).slice(0, 2000);
            if (!/^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/.test(headerName) || /[\r\n]/.test(headerValue))
              throw new Error('headers contain an invalid name or value.');
            if (['host', 'content-length', 'transfer-encoding', 'connection'].includes(headerName.toLowerCase()))
              throw new Error(`${headerName} cannot be overridden.`);
            return [headerName, headerValue];
          }),
      );
    } else secret[key] = String(rawSecret[key]).trim().slice(0, 4096);
  }
  const required =
    {
      webhook: ['config.url'],
      'siem-http': ['config.url'],
      slack: ['secret.webhookUrl'],
      teams: ['secret.webhookUrl'],
      jira: ['config.baseUrl', 'config.projectKey', 'secret.email', 'secret.apiToken'],
      linear: ['config.teamId', 'secret.apiKey'],
    }[type] || [];
  for (const path of required) {
    const [group, key] = path.split('.');
    if (group === 'secret' && existingHasSecret && rawSecret === undefined) continue;
    if (!(group === 'config' ? config : secret)[key]) throw new Error(`${path} is required.`);
  }
  for (const [label, value] of [
    ['config.url', config.url],
    ['config.baseUrl', config.baseUrl],
    ['secret.webhookUrl', secret.webhookUrl],
  ]) {
    if (!value) continue;
    let parsed;
    try {
      parsed = new URL(value);
    } catch {
      throw new Error(`${label} must be a valid HTTPS URL.`);
    }
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password)
      throw new Error(`${label} must be an HTTPS URL without embedded credentials.`);
  }
  return { config, secret };
}

app.get('/api/team/:orgId/integrations', async (req, res) => {
  const ctx = orgContext(req, res, 'integrations.read');
  if (!ctx) return;
  res.json({ ok: true, integrations: await listIntegrations(ctx.org.id) });
});

app.post('/api/team/:orgId/integrations', async (req, res) => {
  const ctx = orgContext(req, res, 'integrations.manage');
  if (!ctx) return;
  const type = String(req.body?.type || '');
  const name = sanitizeLabel(req.body?.name, 100);
  if (!INTEGRATION_TYPES.has(type) || !name)
    return res.status(400).json({ error: 'A valid integration type and name are required.' });
  let input;
  try {
    input = integrationInput(type, req.body?.config, req.body?.secret);
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
  const now = Date.now();
  const integration = await saveIntegration({
    id: `int_${randomUUID().replaceAll('-', '').slice(0, 16)}`,
    orgId: ctx.org.id,
    type,
    name,
    config: input.config,
    secretEnc: encryptSecret(input.secret),
    enabled: req.body?.enabled !== false,
    createdBy: ctx.user.id,
    createdAt: now,
    updatedAt: now,
  });
  audit(ctx, 'integration.created', 'integration', integration.id, { type });
  res
    .status(201)
    .json({ ok: true, integration: { ...integration, secretEnc: undefined, hasSecret: !!integration.secretEnc } });
});

app.patch('/api/team/:orgId/integrations/:id', async (req, res) => {
  const ctx = orgContext(req, res, 'integrations.manage');
  if (!ctx) return;
  const current = await getIntegration(ctx.org.id, req.params.id);
  if (!current) return res.status(404).json({ error: 'Integration not found.' });
  let input = { config: current.config, secretEnc: current.secretEnc };
  if (req.body?.config !== undefined || req.body?.secret !== undefined) {
    try {
      const parsed = integrationInput(
        current.type,
        req.body?.config ?? current.config,
        req.body?.secret,
        !!current.secretEnc,
      );
      input = {
        config: parsed.config,
        secretEnc: req.body?.secret === undefined ? current.secretEnc : encryptSecret(parsed.secret),
      };
    } catch (error) {
      return res.status(400).json({ error: error.message });
    }
  }
  const integration = await saveIntegration({
    ...current,
    name: req.body?.name === undefined ? current.name : sanitizeLabel(req.body.name, 100),
    config: input.config,
    secretEnc: input.secretEnc,
    enabled: req.body?.enabled === undefined ? current.enabled : req.body.enabled === true,
    updatedAt: Date.now(),
  });
  audit(ctx, 'integration.updated', 'integration', integration.id, {
    type: integration.type,
    enabled: integration.enabled,
  });
  res.json({ ok: true, integration: { ...integration, secretEnc: undefined, hasSecret: !!integration.secretEnc } });
});

app.delete('/api/team/:orgId/integrations/:id', async (req, res) => {
  const ctx = orgContext(req, res, 'integrations.manage');
  if (!ctx) return;
  if (!(await getIntegration(ctx.org.id, req.params.id)))
    return res.status(404).json({ error: 'Integration not found.' });
  await deleteIntegration(ctx.org.id, req.params.id);
  audit(ctx, 'integration.deleted', 'integration', req.params.id);
  res.json({ ok: true });
});

app.post('/api/team/:orgId/integrations/:id/test', async (req, res) => {
  const ctx = orgContext(req, res, 'integrations.manage');
  if (!ctx) return;
  const integration = await getIntegration(ctx.org.id, req.params.id);
  if (!integration) return res.status(404).json({ error: 'Integration not found.' });
  const jobs = await queueIntegrationEvent(
    ctx.org.id,
    {
      id: `integration-test:${randomUUID()}`,
      type: 'integration.test',
      at: new Date().toISOString(),
      data: { title: `Test event for ${integration.name}`, severity: 'info' },
    },
    ctx.user.id,
    integration.id,
  );
  audit(ctx, 'integration.test_queued', 'integration', integration.id);
  res.status(202).json({ ok: true, jobs: jobs.map((job) => ({ id: job.id, status: job.status })) });
});

app.get('/api/team/:orgId/deliveries', async (req, res) => {
  const ctx = orgContext(req, res, 'integrations.read');
  if (!ctx) return;
  res.json({ ok: true, deliveries: await listDeliveries(ctx.org.id, Number(req.query.limit) || 100) });
});

app.get('/api/team/:orgId/jobs', async (req, res) => {
  const ctx = orgContext(req, res, 'jobs.read');
  if (!ctx) return;
  const jobs = await listJobs(ctx.org.id, Number(req.query.limit) || 100);
  res.json({
    ok: true,
    jobs: jobs.map(publicJob),
  });
});

app.post('/api/team/:orgId/jobs/:id/cancel', async (req, res) => {
  const ctx = orgContext(req, res, 'scans.stop');
  if (!ctx) return;
  const job = (await listJobs(ctx.org.id, 500)).find((item) => item.id === req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found.' });
  if (job.type !== 'scan' && !can(ctx.membership.role, 'settings.manage')) {
    return res.status(403).json({ error: `Your ${ctx.membership.role} role can cancel scans only.` });
  }
  if (!['queued', 'running'].includes(job.status))
    return res.status(409).json({ error: `Cannot cancel a ${job.status} job.` });
  await updateJob(job.id, { status: 'cancelled', error: 'Cancelled by user', lockedBy: null, lockedAt: null });
  audit(ctx, 'job.cancelled', 'job', job.id, { type: job.type });
  res.json({ ok: true });
});

app.get('/api/team/:orgId/artifacts', async (req, res) => {
  const ctx = orgContext(req, res, 'scans.read');
  if (!ctx) return;
  res.json({ ok: true, artifacts: await listArtifacts(ctx.org.id, req.query.scanId || null) });
});

app.post('/api/team/:orgId/artifacts/:id/url', async (req, res) => {
  const ctx = orgContext(req, res, 'scans.read');
  if (!ctx) return;
  const artifact = (await listArtifacts(ctx.org.id, req.body?.scanId || null)).find(
    (item) => item.id === req.params.id,
  );
  if (!artifact) return res.status(404).json({ error: 'Artifact not found.' });
  res.json({ ok: true, ...(await signedArtifactUrl(artifact, 300)) });
});

// How a worker job reads as a scan. The page knows completed, running, queued, failed and stopped.
function scanStatusOfJob(job) {
  if (job.status === 'succeeded') return job.result?.status || 'completed';
  if (job.status === 'dead-letter' || job.status === 'failed') return 'failed';
  if (job.status === 'cancelled') return 'stopped';
  return job.status;
}

// Where a scan's result files are: the working folder when this process ran the scan, storage when
// the worker did. Only the verified-results folders are listed.
async function scanResultStore(orgId, scanId) {
  const dir = join(WORKSPACES, scanId);
  if (existsSync(dir)) {
    const paths = [];
    const visit = (sub) => {
      for (const entry of readdirSync(join(dir, sub), { withFileTypes: true })) {
        const rel = `${sub}/${entry.name}`;
        if (entry.isDirectory()) visit(rel);
        else if (entry.isFile()) paths.push(rel);
      }
    };
    for (const top of ['broker', 'defense']) if (existsSync(join(dir, top))) visit(top);
    return {
      paths,
      read: async (rel) => {
        try {
          return readFileSync(join(dir, rel), 'utf-8');
        } catch {
          return null;
        }
      },
    };
  }
  const byPath = new Map();
  for (const artifact of await listArtifacts(orgId, scanId).catch(() => []))
    if (artifact.metadata?.relativePath) byPath.set(artifact.metadata.relativePath, artifact);
  return {
    paths: [...byPath.keys()],
    read: async (rel) => {
      const artifact = byPath.get(rel);
      if (!artifact) return null;
      try {
        return (await readArtifact(artifact)).toString('utf8');
      } catch {
        return null;
      }
    },
  };
}

// ---- API: List scans (no workspace paths exposed) ----
async function listOrgScans(orgId) {
  const scans = (existsSync(WORKSPACES) ? readdirSync(WORKSPACES) : [])
    .filter((d) => {
      const p = join(WORKSPACES, d);
      const owner = getScanOwner(d);
      return owner?.orgId === orgId && statSync(p).isDirectory() && existsSync(join(p, 'session.json'));
    })
    .map((d) => {
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
  const known = new Set(scans.map((scan) => scan.id));
  for (const job of await listJobs(orgId, 500)) {
    if (job.type !== 'scan' || !job.payload?.scanId || known.has(job.payload.scanId)) continue;
    scans.push({
      id: job.payload.scanId,
      jobId: job.id,
      target: job.result?.target || job.payload.targetUrl,
      status: scanStatusOfJob(job),
      startedAt: job.result?.startedAt || new Date(job.createdAt).toISOString(),
      completedAt: job.result?.completedAt || null,
      agents: 0,
      totalCost: 0,
      // A scan that stopped part-way still has what it found up to then.
      hasReport: Number(job.result?.artifactCount || 0) > 0,
      attempts: job.attempts,
      error: job.error || null,
    });
  }
  scans.sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt));
  return scans;
}

app.get(['/api/scans', '/api/v1/scans'], async (req, res) => {
  const ctx = requirePermission(req, res, 'scans.read');
  if (!ctx) return;
  res.json(await listOrgScans(ctx.org.id));
});

// ---- API: Scan details ----
app.get(['/api/scans/:id', '/api/v1/scans/:id'], async (req, res) => {
  const ctx = scanContext(req, res, req.params.id);
  if (!ctx) return;
  const wsDir = join(WORKSPACES, req.params.id);
  if (!existsSync(wsDir)) {
    const jobs = await listJobs(ctx.org.id, 500);
    const job = jobs.find((item) => item.type === 'scan' && item.payload?.scanId === req.params.id);
    if (!job) return res.status(404).json({ error: 'Scan not found' });
    const artifacts = await listArtifacts(ctx.org.id, req.params.id);
    const byPath = new Map(artifacts.map((artifact) => [artifact.metadata?.relativePath, artifact]));
    const readText = async (path) => {
      const artifact = byPath.get(path);
      if (!artifact) return null;
      try {
        return (await readArtifact(artifact)).toString('utf8');
      } catch {
        return null;
      }
    };
    let session = job.result || {
      status: job.status,
      target: job.payload?.targetUrl,
      startedAt: new Date(job.createdAt).toISOString(),
    };
    const sessionRaw = await readText('session.json');
    if (sessionRaw) {
      try {
        session = JSON.parse(sessionRaw);
      } catch {}
    }
    // A scanner that was stopped never marks its own session as ended; the job knows how it ended.
    if (!['queued', 'running', 'succeeded'].includes(job.status)) {
      session = {
        ...session,
        status: scanStatusOfJob(job),
        failReason: job.error || session.failReason || null,
        completedAt:
          session.completedAt || job.result?.completedAt || new Date(job.updatedAt || Date.now()).toISOString(),
      };
    }
    const files = {
      report: await readText('report.md'),
      preRecon: await readText('pre-recon/analysis.md'),
      recon: await readText('recon/exploration.md'),
      httpProbe: await readText('pre-recon/http-probe.txt'),
      chainAnalysis: await readText('chain-analysis/analysis.md'),
      warRoom: await readText('war-room/transcript.md'),
      forensicManifest: await readText('forensic-package/manifest.json'),
      custody: await readText('forensic-package/chain-of-custody.md'),
      redTeamSummary: await readText('red-team/summary.md'),
      blueTeam: await readText('blue-team/defense-assessment.md'),
      purpleTeam: await readText('purple-team/transcript.md'),
      purpleConclusion: await readText('purple-team/conclusion.md'),
      exploitVerify: await readText('exploit-verify/verification.md'),
      securityHeaders: await readText('pre-recon/security-headers.json'),
      vulns: {},
      exploits: {},
      queues: {},
    };
    for (const category of [
      'sqli',
      'xss',
      'auth-bypass',
      'authz-bypass',
      'ssrf',
      'business-logic',
      'misconfig',
      'info-disclosure',
    ]) {
      files.vulns[category] = await readText(`vuln/${category}/analysis.md`);
      files.exploits[category] = await readText(`exploit/${category}/exploit-report.md`);
      const queue = await readText(`vuln/${category}/exploitation-queue.json`);
      try {
        files.queues[category] = queue ? JSON.parse(queue) : null;
      } catch {
        files.queues[category] = null;
      }
    }
    return res.json({
      session,
      files,
      durable: true,
      job: { id: job.id, status: job.status, attempts: job.attempts, error: job.error },
    });
  }
  const session = existsSync(join(wsDir, 'session.json'))
    ? JSON.parse(readFileSync(join(wsDir, 'session.json'), 'utf-8'))
    : {};
  const rd = (rel) => {
    const p = join(wsDir, rel);
    return existsSync(p) ? readFileSync(p, 'utf-8') : null;
  };
  const files = {
    report: rd('report.md'),
    preRecon: rd('pre-recon/analysis.md'),
    recon: rd('recon/exploration.md'),
    httpProbe: rd('pre-recon/http-probe.txt'),
    chainAnalysis: rd('chain-analysis/analysis.md'),
    warRoom: rd('war-room/transcript.md'),
    forensicManifest: rd('forensic-package/manifest.json'),
    custody: rd('forensic-package/chain-of-custody.md'),
    redTeamSummary: rd('red-team/summary.md'),
    blueTeam: rd('blue-team/defense-assessment.md'),
    purpleTeam: rd('purple-team/transcript.md'),
    purpleConclusion: rd('purple-team/conclusion.md'),
    exploitVerify: rd('exploit-verify/verification.md'),
    securityHeaders: rd('pre-recon/security-headers.json'),
    vulns: {},
    exploits: {},
    queues: {},
  };
  const rj = (rel) => {
    const raw = rd(rel);
    if (!raw) return null;
    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  };
  for (const cat of [
    'sqli',
    'xss',
    'auth-bypass',
    'authz-bypass',
    'ssrf',
    'business-logic',
    'misconfig',
    'info-disclosure',
  ]) {
    files.vulns[cat] = rd(`vuln/${cat}/analysis.md`);
    files.exploits[cat] = rd(`exploit/${cat}/exploit-report.md`);
    // Structured findings (each tagged CONFIRMED/LIKELY/THEORETICAL) are the source of truth
    // for scoring. The prose analysis.md embeds the severity rubric ("Critical / High / ...")
    // verbatim, so keyword-scanning it falsely flags every category that ran as critical.
    files.queues[cat] = rj(`vuln/${cat}/exploitation-queue.json`);
  }
  res.json({ session, files });
});

// ---- API: Broker-verified findings + compliance (Track B/C) ----
// The broker exploitation phase writes structured artifacts per vuln class:
//   workspaces/<id>/broker/<category>/findings.json   (NormalizedToolFinding[])
//   workspaces/<id>/broker/<category>/compliance.json (ComplianceReport)
// We aggregate them across whatever classes ran into one verified-findings view +
// a merged OWASP/CWE coverage roll-up. Tool-confirmed only → these are real, not noise.
// Automated evidence report (CVSS 3.1 + OWASP WSTG/ASVS + framework mappings + sign-off).
// Open the HTML in a browser and Print → Save as PDF for a deliverable. ?format=md for Markdown.
app.get(['/api/scans/:id/report', '/api/v1/scans/:id/report'], async (req, res) => {
  const ctx = scanContext(req, res, req.params.id);
  if (!ctx) return;
  // SARIF export for CI/CD & GitHub code scanning.
  if (req.query.format === 'sarif') {
    const sp = join(WORKSPACES, req.params.id, 'purple', 'report.sarif');
    if (!existsSync(sp)) {
      const artifact = (await listArtifacts(ctx.org.id, req.params.id)).find(
        (item) => item.metadata?.relativePath === 'purple/report.sarif',
      );
      if (!artifact) return res.status(404).json({ error: 'No SARIF report for this scan yet.' });
      res.setHeader('content-type', 'application/sarif+json; charset=utf-8');
      res.setHeader('content-disposition', `attachment; filename="shannon-${req.params.id}.sarif"`);
      return res.end(await readArtifact(artifact));
    }
    res.setHeader('content-type', 'application/sarif+json; charset=utf-8');
    res.setHeader('content-disposition', `attachment; filename="shannon-${req.params.id}.sarif"`);
    return res.end(readFileSync(sp, 'utf-8'));
  }
  const fmt = req.query.format === 'md' ? 'md' : 'html';
  const p = join(WORKSPACES, req.params.id, 'purple', `certification-report.${fmt}`);
  if (!existsSync(p)) {
    const artifact = (await listArtifacts(ctx.org.id, req.params.id)).find(
      (item) => item.metadata?.relativePath === `purple/certification-report.${fmt}`,
    );
    if (!artifact) return res.status(404).json({ error: 'No evidence report for this scan yet.' });
    res.setHeader('content-type', fmt === 'md' ? 'text/markdown; charset=utf-8' : 'text/html; charset=utf-8');
    res.setHeader('content-disposition', `inline; filename="shannon-pentest-${req.params.id}.${fmt}"`);
    res.setHeader('content-security-policy', REPORT_SANDBOX);
    return res.end(await readArtifact(artifact));
  }
  res.setHeader('content-security-policy', REPORT_SANDBOX);
  res.setHeader('content-type', fmt === 'md' ? 'text/markdown; charset=utf-8' : 'text/html; charset=utf-8');
  res.setHeader('content-disposition', `inline; filename="shannon-pentest-${req.params.id}.${fmt}"`);
  res.end(readFileSync(p, 'utf-8'));
});

app.get('/api/scans/:id/broker', async (req, res) => {
  const ctx = scanContext(req, res, req.params.id);
  if (!ctx) return;
  const store = await scanResultStore(ctx.org.id, req.params.id);
  const json = async (rel) => {
    const raw = await store.read(rel);
    if (!raw) return null;
    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  };
  // <top>/<category>/<file>: the categories that have this file.
  const categories = (top, file) =>
    store.paths
      .map((path) => path.split('/'))
      .filter((parts) => parts.length === 3 && parts[0] === top && parts[2] === file)
      .map((parts) => parts[1])
      .sort();

  const findings = [];
  const rows = [];
  const owaspCoverage = {};
  const cweCoverage = {};

  for (const category of categories('broker', 'findings.json')) {
    const parsed = await json(`broker/${category}/findings.json`);
    const list = Array.isArray(parsed) ? parsed : Array.isArray(parsed?.findings) ? parsed.findings : [];
    for (const f of list) findings.push({ category, ...f });
  }
  for (const category of categories('broker', 'compliance.json')) {
    const compliance = await json(`broker/${category}/compliance.json`);
    if (!compliance) continue;
    for (const r of compliance.rows || []) rows.push(r);
    for (const [k, n] of Object.entries(compliance.owaspCoverage || {})) owaspCoverage[k] = (owaspCoverage[k] || 0) + n;
    for (const [k, n] of Object.entries(compliance.cweCoverage || {})) cweCoverage[k] = (cweCoverage[k] || 0) + n;
  }

  // Paired defenses from the Purple Engine: per confirmed exploit, a detection rule,
  // an inline-block proof, and LLM remediation (defense/<category>/defense.json).
  const defenses = [];
  for (const category of categories('defense', 'defense.json')) {
    const d = await json(`defense/${category}/defense.json`);
    if (d) defenses.push(d);
  }

  // Advanced layers surfaced to the client: attack chains + impact are already in `findings`
  // (their own classes); the monitoring delta and AI leads are separate report artifacts.
  const monitoring = await json('broker/monitoring.json');
  const leads = await json('broker/ai-leads.json');
  const aiLeads = Array.isArray(leads) ? leads : [];
  const chains = findings.filter((f) => f.category === 'attack-chain');
  const impact = findings.filter((f) => f.category === 'impact');

  res.json({ findings, rows, owaspCoverage, cweCoverage, defenses, monitoring, aiLeads, chains, impact });
});

// ============================================================
//  Domain-ownership authorization — clients may only scan
//  targets whose domain they have PROVEN they control.
// ============================================================
// loadVerified / addVerified / removeVerified now provided by db.mjs (Supabase-backed, so domain
// verifications survive Railway redeploys instead of dying with the container's local file).
// Canonical hostname. Do not guess eTLD+1 by taking the last two labels: that turns
// app.example.co.uk into co.uk and is both incorrect and unsafe. A verified parent
// explicitly covers its subdomains in isVerified().
function registrable(host) {
  return String(host || '')
    .toLowerCase()
    .replace(/\.$/, '');
}
function hostOf(u) {
  try {
    return new URL(/^https?:\/\//.test(u) ? u : `https://${u}`).hostname.toLowerCase();
  } catch {
    return '';
  }
}
// A target on this machine (localhost, 127.*, *.local) needs no proof of ownership when the
// dashboard runs on someone's own computer. On the hosted service "this machine" is the service
// itself, so there a local target is treated like any other: unproven, and refused.
export function localTargetsAllowed(env = process.env) {
  return env.NODE_ENV !== 'production' || env.SHANNON_ALLOW_LOCAL_TARGETS === '1';
}
const LOCAL_TARGETS = localTargetsAllowed();
const localExempt = (h) => LOCAL_TARGETS && isLocalHost(h);
// Engine-generated report HTML quotes what the scanned site answered. It is always shown sandboxed,
// so nothing in it can run as script on this origin.
const REPORT_SANDBOX = "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:";
// On the hosted service a test target must be on the public internet. Owning a domain name does not
// make the address it points to yours: a name can be pointed at this server's own network, and the
// checks would then be sent there. (Checked when a test is requested. The engine also refuses
// internal addresses written out as such.)
const PRIVATE_TARGET = 'This address points to a private or internal network, which the hosted service does not test.';
export async function privateTarget(hostOrUrl, allowLocal = LOCAL_TARGETS) {
  if (allowLocal) return false;
  const given = String(hostOrUrl);
  const url = given.startsWith('http://') || given.startsWith('https://') ? given : `https://${given}`;
  try {
    return !(await publicOriginAllowed(url));
  } catch {
    return true;
  }
}
// Deterministic per-(user,domain) token — recomputable, so we don't need to store the token itself.
function domainToken(userId, domain) {
  return _crypto.createHmac('sha256', SESSION_SECRET).update(`verify:${userId}:${domain}`).digest('hex').slice(0, 40);
}
function isVerified(userId, host) {
  if (!userId) return false;
  const v = loadVerified()[userId] || {};
  const candidate = registrable(host);
  return Object.keys(v).some((domain) => candidate === domain || candidate.endsWith(`.${domain}`));
}

// Step 1: get the token + instructions for proving ownership of a domain.
app.post('/api/verify/request', (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'Log in first.' });
  const domain = registrable(hostOf(req.body?.domain || ''));
  if (!domain || !domain.includes('.')) return res.status(400).json({ error: 'Provide a valid domain.' });
  const token = domainToken(user.id, domain);
  res.json({
    ok: true,
    domain,
    token,
    methods: {
      dns: { record: `_shannon.${domain}`, type: 'TXT', value: `shannon-site-verification=${token}` },
      file: { url: `https://${domain}/.well-known/shannon-verify.txt`, content: token },
      meta: { tag: `<meta name="shannon-site-verification" content="${token}">` },
    },
    instructions: 'Add ANY one of the above to the domain, then call /api/verify/check.',
  });
});

// Step 2: verify ownership via DNS TXT, a well-known file, or a homepage meta tag.
app.post('/api/verify/check', async (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'Log in first.' });
  const domain = registrable(hostOf(req.body?.domain || ''));
  if (!domain || !domain.includes('.')) return res.status(400).json({ error: 'Provide a valid domain.' });
  const token = domainToken(user.id, domain);
  const tryFetch = async (url) => {
    try {
      const c = new AbortController();
      const t = setTimeout(() => c.abort(), 8000);
      let at = url;
      let r;
      // Followed by hand, at most four steps, each one checked: a site's own redirect (to "www",
      // to https) is normal, a redirect into a private network is not.
      for (let hop = 0; hop < 5; hop++) {
        if (!(await publicOriginAllowed(at))) return '';
        r = await fetch(at, { redirect: 'manual', signal: c.signal });
        const next = r.status >= 300 && r.status < 400 ? r.headers.get('location') : null;
        if (!next) break;
        at = new URL(next, at).toString();
        r = null;
      }
      if (!r) return '';
      const body = await r.text().catch(() => '');
      clearTimeout(t);
      return r.status === 200 ? body : '';
    } catch {
      return '';
    }
  };
  let method = null;
  // (a) DNS TXT on _shannon.<domain> or the apex.
  try {
    const { resolveTxt } = await import('node:dns/promises');
    for (const name of [`_shannon.${domain}`, domain]) {
      try {
        const recs = (await resolveTxt(name)).map((r) => r.join(''));
        if (recs.some((v) => v.includes(token))) {
          method = 'dns';
          break;
        }
      } catch {}
    }
  } catch {}
  // (b) Well-known file.
  if (!method) {
    for (const u of [
      `https://${domain}/.well-known/shannon-verify.txt`,
      `http://${domain}/.well-known/shannon-verify.txt`,
    ]) {
      if ((await tryFetch(u)).includes(token)) {
        method = 'file';
        break;
      }
    }
  }
  // (c) Homepage meta tag.
  if (!method) {
    const html = (await tryFetch(`https://${domain}/`)) || (await tryFetch(`http://${domain}/`));
    if (html.includes('shannon-site-verification') && html.includes(token)) method = 'meta';
  }
  if (!method)
    return res.json({
      ok: false,
      verified: false,
      error: 'Token not found yet. Add it and retry (DNS can take a few minutes).',
    });
  addVerified(user.id, domain, { verifiedAt: new Date().toISOString(), method });
  res.json({ ok: true, verified: true, domain, method });
});

// List the caller's verified domains.
app.get('/api/verify/list', (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'Log in first.' });
  res.json({ ok: true, domains: loadVerified()[user.id] || {} });
});

// Remove (revoke) a verified domain.
app.post('/api/verify/remove', (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'Log in first.' });
  const domain = registrable(hostOf(req.body?.domain || ''));
  removeVerified(user.id, domain);
  res.json({ ok: true, domains: loadVerified()[user.id] || {} });
});

// ---- IP / range ownership verification (authorizes network-level scanning of a CIDR) ----
const listCidrs = (userId) =>
  Object.fromEntries(Object.entries(loadVerified()[userId] || {}).filter(([, v]) => v?.method === 'ip-range'));

app.post('/api/verify/ip/request', (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'Log in first.' });
  const cidr = String(req.body?.cidr || '').trim();
  if (!parseCidr(cidr))
    return res.status(400).json({ error: 'Provide a valid IPv4 CIDR range (e.g. 203.0.113.0/24).' });
  const token = ipVerifyToken(SESSION_SECRET, user.id, cidr);
  res.json({ ok: true, cidr, token, instructions: verificationInstructions(cidr, token) });
});

app.post('/api/verify/ip/check', async (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'Log in first.' });
  const cidr = String(req.body?.cidr || '').trim();
  const ip = String(req.body?.ip || '').trim();
  if (!parseCidr(cidr)) return res.status(400).json({ error: 'Invalid CIDR.' });
  if (!ipInCidr(ip, cidr)) return res.status(400).json({ error: 'The proof IP must be inside the range.' });
  if (await privateTarget(ip)) return res.status(400).json({ error: PRIVATE_TARGET });
  const token = ipVerifyToken(SESSION_SECRET, user.id, cidr);
  const controlled = await checkIpControl(ip, token);
  if (!controlled)
    return res.json({
      ok: false,
      verified: false,
      error: `Token not found at http://${ip}/.well-known/shannon-verify.txt yet.`,
    });
  addVerified(user.id, cidr, { method: 'ip-range', verifiedAt: new Date().toISOString() });
  res.json({ ok: true, verified: true, cidr });
});

app.get('/api/verify/ip/list', (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'Log in first.' });
  res.json({ ok: true, ranges: listCidrs(user.id) });
});

app.post('/api/verify/ip/remove', (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'Log in first.' });
  removeVerified(user.id, String(req.body?.cidr || '').trim());
  res.json({ ok: true, ranges: listCidrs(user.id) });
});

// ---- API: Start scan ----
// ============================================================
//  AI AGENT — "understand a target" (the recon/planning agent, step 1 of the autonomous engine)
//  Crawls a target you OWN and builds a deterministic understanding (analyzeSurface, in its own
//  unit-tested module): what it appears to be, where the risk concentrates, and a prioritized plan
//  mapping the discovered surface to Shannon's proof classes. Deterministic (needs no API key — matches
//  the engine-is-truth model); an LLM narrative is layered on top when a key is present.
// ============================================================
async function aiNarrative(understanding, key) {
  if (!key) return null;
  try {
    const client = new Anthropic({ apiKey: key });
    const model = process.env.SHANNON_QUICK_MODEL || process.env.SHANNON_MODEL || 'claude-haiku-4-5-20251001';
    const msg = await client.messages.create({
      model,
      max_tokens: 300,
      messages: [
        {
          role: 'user',
          content: `You are a penetration-test lead. In 2-3 sentences, say what this web app appears to be and where its risk concentrates, based ONLY on this reconnaissance JSON. Be concrete; do NOT invent findings or claim anything is exploitable.\n\n${JSON.stringify(understanding).slice(0, 4000)}`,
        },
      ],
    });
    return (
      (msg.content || [])
        .map((c) => c.text || '')
        .join('')
        .trim() || null
    );
  } catch {
    return null; // no credits / bad key / network → deterministic understanding still stands alone
  }
}

// Build the agent's escalation + re-crawl closures for a given resolved target. escalate chains a
// confirmed finding into a benign, read-only impact demonstrator; recrawl deepens the surface (or
// re-crawls as a newly-obtained identity) each round.
function agentDeps(target, headers = {}) {
  const origin = new URL(target).origin;
  setScanOrigin(origin); // host-gate the probers' fetcher to this target only
  setSessionHeaders(headers || {}); // authenticated probing when a session was supplied ({} resets it)
  const probe = (key, t) => (PROBERS[key] ? PROBERS[key].probe(t) : []);
  const escalate = async (cls, t) => {
    const url = typeof t === 'string' ? t : t.url;
    try {
      if (cls === 'sqli' || cls === 'sqli-auth-bypass') return await sqliExtract(url, { fetchT, injReq });
      if (cls === 'ssrf') return await ssrfMetadata(url, { fetchT });
      if (cls === 'cmd-injection') return await cmdContext(url, { fetchT, injReq });
    } catch {}
    return null;
  };
  const recrawl = async ({ round, identity }) => {
    const h = identity?.headers ? { ...headers, ...identity.headers } : headers;
    return crawl({ target, maxPages: 25 * round, timeoutMs: 7000, maxRequests: 120 + 60 * round, headers: h });
  };
  const fetchText = async (url) => (await fetchT(url)).body || ''; // host-gated to the target origin
  const fetchStatus = async (url) => (await fetchT(url)).status || 0;
  // The status of a plain request, and which protection sent it when it is a refusal.
  const fetchAnswer = async (url) => {
    const reply = await fetchT(url);
    return { status: reply.status || 0, by: refusedBy(reply.headers, reply.body) };
  };
  return { probe, escalate, recrawl, fetchText, fetchStatus, fetchAnswer };
}

// The checking engine keeps the site it is aimed at, and that site's login session, in one shared
// place. Two runs at once would switch each other's target and session mid-run, and each would
// quietly test less than it reports. So runs take turns: one uses the engine, the others wait.
let engineQueue = Promise.resolve();
let engineWaiting = 0;
// The signed mark one run sends to the site it tests, so that site's Defender files the run's
// requests as the organization's own test instead of as attacks (see defender-own-test.mjs).
function ownTestMark(orgId, target, kind) {
  const signed = signOwnTest(SESSION_SECRET, { orgId, target, kind });
  return signed
    ? { header: signed.header, value: signed.value, applies: (url) => siteName(url) === signed.site }
    : null;
}
// `mark` is a function so the mark is signed when the run's turn comes, not while it waits in line.
function withEngine(work, { onWait, mark } = {}) {
  if (engineWaiting > 0) {
    try {
      onWait?.(engineWaiting);
    } catch {}
  }
  engineWaiting += 1;
  const turn = engineQueue.then(async () => {
    try {
      setTestMark(typeof mark === 'function' ? mark() : null);
      return await work();
    } finally {
      engineWaiting -= 1;
      // A login session never outlives the run it was given for, and neither does its test mark.
      setSessionHeaders({});
      setScanOrigin(null);
      setTestMark(null);
    }
  });
  engineQueue = turn.catch(() => {});
  return turn;
}

// How far a run goes. More pages and more checks take longer and send more requests to the site.
const AGENT_DEPTHS = {
  quick: { maxPages: 25, maxRequests: 120, maxTasks: 30, maxPer: 6 },
  standard: { maxPages: 75, maxRequests: 320, maxTasks: 90, maxPer: 15 },
  deep: { maxPages: 200, maxRequests: 800, maxTasks: 240, maxPer: 40 },
};
const agentDepth = (value) => (Object.hasOwn(AGENT_DEPTHS, value) ? value : 'quick');
// What a site's firewall answers when it has decided to refuse an automated visitor.
const REFUSED = new Set([401, 403, 406, 429, 503]);

// One complete run: the campaign, the unproven leads, and an honest account of what was covered.
async function agentCampaign(target, surface, headers, { depth = 'quick', onStep } = {}) {
  const limits = AGENT_DEPTHS[agentDepth(depth)];
  const deps = agentDeps(target, headers);
  const origin = new URL(target).origin;
  // The address the run was given must answer before anything is checked. A site that refuses it
  // (a firewall, a rate limit, a login wall with no login supplied) cannot be tested, and saying
  // "nothing found" about it would be false.
  const status = await deps.fetchStatus(target).catch(() => 0);
  if (!(surface.pages || []).length || REFUSED.has(status)) {
    const reason = REFUSED.has(status)
      ? `it answered ${status}, which usually means a firewall is refusing automated visitors`
      : status
        ? `it answered ${status}`
        : 'it did not answer';
    const error = new Error(
      `No page of ${origin} could be read (${reason}), so nothing was checked.${status === 401 || status === 403 ? ' If the site needs a login, add it under "Login / session" and run again.' : ''}`,
    );
    error.status = 502;
    throw error;
  }
  const recrawl = async ({ round, identity }) => {
    const h = identity?.headers ? { ...headers, ...identity.headers } : headers;
    return crawl({
      target,
      maxPages: limits.maxPages * round,
      timeoutMs: 7000,
      maxRequests: limits.maxRequests + (limits.maxRequests / 2) * round,
      headers: h,
    });
  };
  const run = annotateFixes(
    await runAgentCampaign({
      surface,
      probe: deps.probe,
      escalate: deps.escalate,
      recrawl,
      maxTasks: limits.maxTasks,
      maxPer: limits.maxPer,
      onStep,
    }),
  );
  const mapped = run.surface || surface;
  run.surface = undefined;
  // Did the site start refusing the requests while it was being checked?
  const answer = await deps.fetchAnswer(target).catch(() => ({ status: 0, by: null }));
  const after = answer.status;
  const blocked = REFUSED.has(after) || after === 0;
  run.coverage = {
    depth: agentDepth(depth),
    pages: (mapped.pages || []).length,
    forms: (mapped.forms || []).length,
    checksRun: run.stats.tested || 0,
    checksPossible: Math.max(run.stats.possible || 0, run.stats.tested || 0),
    checksFailed: run.stats.errors || 0,
    blocked,
    siteStatus: after,
    // Whose firewall refused, when the refusal says: the owner needs to know where to allow the test.
    refusedBy: blocked ? answer.by : null,
  };
  const note = (detail) => {
    const step = { phase: 'warning', detail, t: run.steps.length };
    run.steps.push(step);
    onStep?.(step);
  };
  if (blocked)
    note(
      `By the end the site answered ${after || 'nothing'} to a plain request. ${answer.by ? `The refusal came from ${answer.by}, which` : 'A firewall or rate limit'} was refusing these checks, so the result is incomplete: "nothing confirmed" here does not mean the site is clean.`,
    );
  if (run.coverage.checksPossible > run.coverage.checksRun)
    note(
      `${run.coverage.checksRun} of ${run.coverage.checksPossible} possible checks were run at "${run.coverage.depth}" depth. Choose a deeper run to cover the rest.`,
    );
  run.leads = await gatherLeads(mapped, {
    fetchText: deps.fetchText,
    confirmedTargets: run.findings.map((f) => f.target).filter(Boolean),
  });
  return run;
}

// Keeps an event stream open while a long step is silent, so a proxy does not close it.
function keepAlive(res) {
  const beat = setInterval(() => {
    try {
      res.write(': keep-alive\n\n');
    } catch {}
  }, 15_000);
  beat.unref?.();
  return () => clearInterval(beat);
}

// Resolve an optional authenticated session from the request: a session Cookie, or a form login (which
// we perform server-side → session cookie). The login URL must share the target's registrable domain
// (or be localhost) so the server can't be used to POST credentials to an unrelated host.
async function resolveAuthHeaders(req, target) {
  const b = req.body || {};
  const q = req.query || {};
  const ctx = requestContext(req);
  const grantId = String(b.authGrantId || q.authGrantId || '').trim();
  let credentials = b;
  if (grantId) {
    if (!ctx) throw Object.assign(new Error('Authentication required.'), { status: 401 });
    const targetOrigin = new URL(target).origin;
    const grant = await consumeScanAuthGrant(grantId, ctx.user.id, ctx.org.id, targetOrigin);
    if (!grant)
      throw Object.assign(new Error('The authenticated-session grant is invalid, expired, or already used.'), {
        status: 401,
      });
    credentials = decryptSecret(grant.secretEnc) || {};
  }
  const cookie = String(credentials.cookie || '').trim();
  if (cookie) return { Cookie: cookie };
  const loginUrl = String(credentials.loginUrl || '').trim();
  const username = String(credentials.username || '').trim();
  const password = String(credentials.password || '');
  if (!loginUrl || !username) return {};
  try {
    const lh = hostOf(loginUrl);
    const th = hostOf(target);
    if (!localExempt(lh) && registrable(lh) !== registrable(th)) return {}; // cross-domain login → refuse
    if (await privateTarget(lh)) return {};
    const sess = await login({ loginUrl, username, password });
    return sess?.Cookie ? sess : {};
  } catch (error) {
    if (error?.status) throw error;
    return {};
  }
}

// Make each primary finding actionable (Strix-style remediation) using the engine's deterministic
// per-class fix map — no LLM/credits needed. Impact findings inherit their parent vuln's fix.
function annotateFixes(run) {
  for (const f of run.findings || []) if (!f.impact && f.cls) f.fix = detectionRule(f.cls);
  return run;
}

// Shared for the AI Agent endpoints: apply the same ownership gate as scanning (crawling is active HTTP
// against the target), then crawl. `rawTarget` lets the SSE GET stream pass ?target=… (POSTs use body).
// Returns { target, surface } or { status, error } to send back.
async function agentGateAndCrawl(req, rawTarget = req.body?.target) {
  const ctx = requestContext(req);
  if (!ctx) return { status: 401, error: 'Sign in first.' };
  if (!can(ctx.membership.role, 'scans.run'))
    return { status: 403, error: 'Your role cannot run active security tests.' };
  const raw = (rawTarget || '').trim();
  if (!raw) return { status: 400, error: 'Provide a target URL.' };
  const target = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  let host;
  try {
    host = hostOf(target);
  } catch {
    return { status: 400, error: 'That does not look like a valid URL.' };
  }
  if (!localExempt(host)) {
    if (!isVerified(ctx.user.id, host))
      return {
        status: 403,
        error: `Verify ownership of ${registrable(host)} first (Domains page).`,
        needsVerification: registrable(host),
      };
  }
  if (await privateTarget(host)) return { status: 400, error: PRIVATE_TARGET };
  try {
    const headers = await resolveAuthHeaders(req, target);
    const quota = await consumeOrgAllowance(ctx.org.id, 'agentRuns', 1);
    if (!quota.allowed)
      return {
        status: 429,
        error: `Daily organization limit reached for agent runs (${quota.used}/${quota.limit}) and no prepaid credits remain.`,
      };
    const depth = agentDepth(String(req.body?.depth || req.query?.depth || ''));
    const { maxPages, maxRequests } = AGENT_DEPTHS[depth];
    const surface = await crawl({ target, maxPages, timeoutMs: 7000, maxRequests, headers });
    return { target, surface, headers, ctx, depth };
  } catch (e) {
    return e?.status
      ? { status: e.status, error: e.message }
      : { status: 502, error: `Could not reach the target: ${e.message}` };
  }
}

// EventSource can only issue GET requests. Never place target credentials in its URL: exchange
// them over a protected POST for an encrypted, exact-origin-bound, single-use grant instead.
app.post('/api/agent/auth-grant', async (req, res) => {
  const ctx = requirePermission(req, res, 'scans.run');
  if (!ctx) return;
  const raw = String(req.body?.target || '').trim();
  if (!raw) return res.status(400).json({ error: 'Provide a target URL.' });
  let target;
  try {
    target = new URL(/^https?:\/\//i.test(raw) ? raw : `https://${raw}`);
  } catch {
    return res.status(400).json({ error: 'That does not look like a valid URL.' });
  }
  const host = target.hostname.toLowerCase();
  if (!localExempt(host) && !isVerified(ctx.user.id, host)) {
    return res
      .status(403)
      .json({ error: `Verify ownership of ${registrable(host)} first.`, needsVerification: registrable(host) });
  }
  const cookie = String(req.body?.cookie || '').trim();
  const loginUrl = String(req.body?.loginUrl || '').trim();
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '');
  if (!cookie && !(loginUrl && username)) return res.json({ ok: true, authGrantId: null });
  if (cookie.length > 16_384 || loginUrl.length > 2_048 || username.length > 512 || password.length > 4_096) {
    return res.status(400).json({ error: 'Authentication data is too large.' });
  }
  if (loginUrl) {
    let loginHost;
    try {
      loginHost = hostOf(loginUrl);
    } catch {
      return res.status(400).json({ error: 'Login URL is invalid.' });
    }
    if (!localExempt(loginHost) && registrable(loginHost) !== registrable(host)) {
      return res.status(400).json({ error: 'The login URL must use the same registrable domain as the scan target.' });
    }
    if (await privateTarget(loginHost)) return res.status(400).json({ error: PRIVATE_TARGET });
  }
  const now = Date.now();
  const id = `sag_${randomToken(32)}`;
  await createScanAuthGrant({
    id,
    userId: ctx.user.id,
    orgId: ctx.org.id,
    targetOrigin: target.origin,
    secretEnc: encryptSecret(cookie ? { cookie } : { loginUrl, username, password }),
    expiresAt: now + 5 * 60_000,
    createdAt: now,
  });
  audit(ctx, 'agent.auth_grant_created', 'scan-auth-grant', id, {
    targetOrigin: target.origin,
    expiresAt: now + 5 * 60_000,
  });
  res.status(201).json({ ok: true, authGrantId: id, expiresInSeconds: 300 });
});

app.post('/api/agent/understand', async (req, res) => {
  const r = await agentGateAndCrawl(req);
  if (r.error) return res.status(r.status).json({ error: r.error, needsVerification: r.needsVerification });
  const understanding = analyzeSurface(r.surface);
  const key = (await aiKeysForRequest(req)).claude;
  understanding.aiAvailable = !!key;
  understanding.narrative = await aiNarrative(understanding, key);
  res.json({ ok: true, understanding });
});

// The AUTONOMOUS agent (non-streaming fallback): understand → decide → RUN the real proof-based
// probers → ESCALATE each hit into an impact demonstrator → report, across adaptive rounds. Every
// finding is still gated by the engine's benign proof — the agent chooses what to run, the engine
// decides what is REAL.
app.post('/api/agent/run', async (req, res) => {
  const r = await agentGateAndCrawl(req);
  if (r.error) return res.status(r.status).json({ error: r.error, needsVerification: r.needsVerification });
  try {
    const run = await withEngine(() => agentCampaign(r.target, r.surface, r.headers, { depth: r.depth }), {
      mark: () => ownTestMark(r.ctx.org.id, r.target, 'agent'),
    });
    run.savedId = persistRun(req, r.target, run);
    res.json({ ok: true, run });
  } catch (e) {
    res.status(e.status || 500).json({ error: e.status ? e.message : `Agent run failed: ${e.message}` });
  }
});

// Same autonomous campaign, STREAMED live over Server-Sent Events so the UI watches the agent work
// step-by-step. EventSource is GET-only and same-origin (cookies carry auth); the target is a query
// param. Gate/crawl errors are delivered as an SSE `error` event (the stream itself is always 200).
app.get('/api/agent/run/stream', async (req, res) => {
  if (fromAnotherSite(req)) return res.status(403).json({ error: 'Cross-site request rejected.' });
  res.writeHead(200, {
    'content-type': 'text/event-stream',
    'cache-control': 'no-cache, no-transform',
    connection: 'keep-alive',
    'x-accel-buffering': 'no',
  });
  const send = (obj, event) => {
    if (event) res.write(`event: ${event}\n`);
    res.write(`data: ${JSON.stringify(obj)}\n\n`);
  };
  const r = await agentGateAndCrawl(req, req.query.target);
  if (r.error) {
    send({ message: r.error, needsVerification: r.needsVerification }, 'error');
    return res.end();
  }
  const stop = keepAlive(res);
  try {
    const run = await withEngine(
      () => agentCampaign(r.target, r.surface, r.headers, { depth: r.depth, onStep: (s) => send(s) }),
      {
        onWait: (ahead) =>
          send({ phase: 'wait', detail: `Waiting for ${ahead} other check${ahead === 1 ? '' : 's'} to finish first…` }),
        mark: () => ownTestMark(r.ctx.org.id, r.target, 'agent'),
      },
    );
    run.savedId = persistRun(req, r.target, run);
    send({
      phase: 'leads',
      detail: `Gathered ${run.leads.length} potential lead(s) for manual review — UNPROVEN, kept separate from the ${run.stats.confirmed} confirmed finding(s).`,
    });
    send({ run }, 'done');
  } catch (e) {
    send({ message: e.status ? e.message : `Agent run failed: ${e.message}` }, 'error');
  } finally {
    stop();
  }
  res.end();
});

// MULTI-AGENT SECURITY TEAM: a blackboard-coordinated team of role agents (recon · exploit pool ·
// remediation · report) that run the whole engagement hands-off. Reuses the same ownership gate,
// crawl, and zero-FP probers; remediation is guidance-level (black-box scan → no source tree), so
// fixes are labeled suggested. Returns findings + suggested fixes + report + a handoff graph.
function teamDeps(target, headers) {
  const base = agentDeps(target, headers); // probe, escalate, recrawl, fetchText
  return {
    ...base,
    locate: async () => null, // black-box: no source tree to point at (Code Scan takes pasted source)
    patch: async (finding) => generatePatch({ finding, guidance: detectionRule(finding.cls) }),
    report: async (run, meta) => ({ markdown: toMarkdown({ findings: run.findings || [], leads: [] }, meta || {}) }),
    files: [],
  };
}

app.post('/api/agent/team', async (req, res) => {
  const r = await agentGateAndCrawl(req);
  if (r.error) return res.status(r.status).json({ error: r.error, needsVerification: r.needsVerification });
  try {
    const out = await withEngine(
      () => runSecurityTeam({ surface: r.surface, deps: teamDeps(r.target, r.headers), roster: { exploitAgents: 4 } }),
      { mark: () => ownTestMark(r.ctx.org.id, r.target, 'team') },
    );
    out.savedId = persistRun(req, r.target, { stats: out.stats, findings: out.findings, leads: [] });
    res.json({ ok: true, team: out });
  } catch (e) {
    res.status(500).json({ error: `Security team run failed: ${e.message}` });
  }
});

// Streamed live over SSE so the dashboard watches the team coordinate step by step (same transport
// contract as /api/agent/run/stream: GET, same-origin cookie auth, target as a query param).
app.get('/api/agent/team/stream', async (req, res) => {
  if (fromAnotherSite(req)) return res.status(403).json({ error: 'Cross-site request rejected.' });
  res.writeHead(200, {
    'content-type': 'text/event-stream',
    'cache-control': 'no-cache, no-transform',
    connection: 'keep-alive',
    'x-accel-buffering': 'no',
  });
  const send = (obj, event) => {
    if (event) res.write(`event: ${event}\n`);
    res.write(`data: ${JSON.stringify(obj)}\n\n`);
  };
  const r = await agentGateAndCrawl(req, req.query.target);
  if (r.error) {
    send({ message: r.error, needsVerification: r.needsVerification }, 'error');
    return res.end();
  }
  const stopTeamBeat = keepAlive(res);
  res.on('close', stopTeamBeat);
  try {
    const out = await withEngine(
      () =>
        runSecurityTeam({
          surface: r.surface,
          deps: teamDeps(r.target, r.headers),
          roster: { exploitAgents: 4 },
          onEvent: (e) => send(e),
        }),
      { mark: () => ownTestMark(r.ctx.org.id, r.target, 'team') },
    );
    out.savedId = persistRun(req, r.target, { stats: out.stats, findings: out.findings, leads: [] });
    send({ team: out }, 'done');
  } catch (e) {
    send({ message: `Security team run failed: ${e.message}` }, 'error');
  }
  res.end();
});

function persistConfirmedFindings(ctx, findings, { source, projectId = null, scanId = null } = {}) {
  let saved = 0;
  for (const raw of findings || []) {
    const title = sanitizeLabel(raw.title || raw.detail || raw.cls || raw.tool || 'Security finding', 180);
    const target = String(raw.target || '');
    const cls = String(raw.cls || raw.tool || 'unknown');
    const fingerprint = _crypto
      .createHash('sha256')
      .update(`${ctx.org.id}|${projectId || ''}|${cls}|${target}|${title}`)
      .digest('hex');
    const now = Date.now();
    saveFinding({
      id: `fnd_${fingerprint.slice(0, 16)}`,
      orgId: ctx.org.id,
      projectId,
      fingerprint,
      title,
      severity: ['info', 'low', 'medium', 'high', 'critical'].includes(raw.severity) ? raw.severity : 'medium',
      status: 'new',
      assigneeUserId: null,
      source: source || 'scan',
      details: { ...raw, scanId },
      decision: null,
      createdAt: now,
      updatedAt: now,
    });
    saved += 1;
  }
  if (saved) audit(ctx, 'findings.imported', 'scan', scanId, { count: saved, source, projectId });
  return saved;
}

// Persist a completed run for regression tracking and the active team's shared finding queue.
function persistRun(req, target, run) {
  try {
    const ctx = requestContext(req);
    if (!ctx) return null;
    const id = randomUUID().slice(0, 12);
    saveAgentRun(ctx.user.id, {
      id,
      target,
      createdAt: Date.now(),
      stats: { ...(run.stats || {}), coverage: run.coverage || null },
      findings: run.findings || [],
      leads: run.leads || [],
    });
    persistConfirmedFindings(ctx, run.findings || [], {
      source: 'agent-run',
      projectId: req.body?.projectId || req.query?.projectId || null,
      scanId: id,
    });
    return id;
  } catch {
    return null;
  }
}

// Run history + regression diff (per user).
app.get('/api/agent/runs', (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in to see run history.' });
  res.json({ ok: true, runs: listAgentRuns(user.id, req.query.target || undefined) });
});
app.get('/api/agent/runs/:id', (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in first.' });
  const run = getAgentRun(user.id, req.params.id);
  if (!run) return res.status(404).json({ error: 'Run not found.' });
  res.json({ ok: true, run });
});
app.get('/api/agent/runs/:id/diff/:prevId', (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in first.' });
  const curr = getAgentRun(user.id, req.params.id);
  const prev = getAgentRun(user.id, req.params.prevId);
  if (!curr || !prev) return res.status(404).json({ error: 'Run not found.' });
  res.json({
    ok: true,
    diff: diffRuns(prev, curr),
    curr: { id: curr.id, createdAt: curr.createdAt },
    prev: { id: prev.id, createdAt: prev.createdAt },
  });
});

// ── Continuous monitoring — a scheduled agent run + auto-diff + webhook alert on NEW findings ──
// Reusable: crawl + run the campaign + gather leads (no HTTP req — used by the scheduler).
async function executeAgentRun(target, orgId = null) {
  const surface = await crawl({ target, maxPages: 25, timeoutMs: 7000, maxRequests: 120 });
  return withEngine(() => agentCampaign(target, surface, {}, { depth: 'quick' }), {
    mark: orgId ? () => ownTestMark(orgId, target, 'monitor') : null,
  });
}

let _monitorBusy = false;
async function runDueMonitors() {
  if (_monitorBusy) return;
  _monitorBusy = true;
  try {
    const due = dueMonitors(allMonitors(), Date.now());
    for (const m of due) {
      try {
        const prevSummary = listAgentRuns(m.userId, m.target)[0];
        const prev = prevSummary ? getAgentRun(m.userId, prevSummary.id) : null;
        const creator = loadUsers()[m.userId];
        const org = creator && !creator.disabledAt ? listOrganizations(m.userId)[0] : null;
        const role = org ? getMembership(org.id, m.userId)?.role : null;
        let monitored = '';
        try {
          monitored = hostOf(m.target);
        } catch {}
        // The schedule outlives the click that made it. Each time, the person who made it must still
        // be allowed to run tests, and must still hold the proof that the site is theirs.
        if (
          !role ||
          !can(role, 'scans.run') ||
          !monitored ||
          (!localExempt(monitored) && !isVerified(m.userId, monitored)) ||
          (await privateTarget(monitored))
        ) {
          console.warn(`[monitor] skipped ${m.target}: its creator may no longer test this site`);
          touchMonitor(m.userId, m.id, Date.now());
          continue;
        }
        const run = await executeAgentRun(m.target, org?.id);
        const runId = randomUUID().slice(0, 12);
        saveAgentRun(m.userId, {
          id: runId,
          target: m.target,
          createdAt: Date.now(),
          stats: { ...(run.stats || {}), coverage: run.coverage || null },
          findings: run.findings || [],
          leads: run.leads || [],
        });
        touchMonitor(m.userId, m.id, Date.now());
        // What a scheduled check finds goes where a manual run's findings go: the organization's
        // finding queue, and its alert destinations when something is new. Before this a monitor
        // with no webhook of its own found things every hour and told nobody.
        const fresh = prev ? diffRuns(prev, run).added : run.findings || [];
        if (org && fresh.length) {
          try {
            persistConfirmedFindings({ org, user: { id: m.userId } }, fresh, {
              source: 'agent-monitor',
              scanId: runId,
            });
            queueIntegrationEvent(
              org.id,
              {
                id: `agent-monitor:${m.id}:${runId}`,
                type: 'agent.monitor.new_findings',
                at: new Date().toISOString(),
                data: {
                  target: m.target,
                  new: fresh.length,
                  findings: fresh.slice(0, 20).map((f) => ({
                    cls: f.cls || f.tool || 'finding',
                    severity: f.severity || 'medium',
                    target: String(f.target || '').slice(0, 300),
                    detail: String(f.detail || '').slice(0, 300),
                  })),
                },
              },
              m.userId,
            ).catch((error) => console.error('[monitor] alert failed:', error.message));
          } catch (error) {
            console.error('[monitor] could not record findings:', error.message);
          }
        }
        if (run.coverage?.blocked)
          console.warn(
            `[monitor] ${m.target} refused the checks (answered ${run.coverage.siteStatus}${run.coverage.refusedBy ? `, from ${run.coverage.refusedBy}` : ''}); this run is incomplete`,
          );
        // The alert address was typed by a user: it is only ever a public one.
        if (m.webhookUrl && prev && (await publicOriginAllowed(m.webhookUrl).catch(() => false))) {
          const diff = diffRuns(prev, run);
          if (diff.summary.new > 0) {
            const previousScanAt = prev.createdAt ? new Date(prev.createdAt).toISOString().slice(0, 16) : null;
            await sendMonitorAlert(
              m.target,
              diffToDelta(diff, { firstRun: false, previousScanAt }),
              m.webhookUrl,
            ).catch(() => {});
          }
        }
        console.log(`[monitor] ran ${m.target} → ${run.stats?.confirmed || 0} proven`);
      } catch (e) {
        console.error('[monitor] run failed for', m.target, '—', e.message);
      }
    }
  } finally {
    _monitorBusy = false;
  }
}

app.post('/api/agent/monitors', async (req, res) => {
  const ctx = requirePermission(req, res, 'scans.run');
  if (!ctx) return;
  const user = ctx.user;
  const raw = (req.body?.target || '').trim();
  if (!raw) return res.status(400).json({ error: 'Provide a target URL.' });
  const target = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  let host;
  try {
    host = hostOf(target);
  } catch {
    return res.status(400).json({ error: 'Invalid URL.' });
  }
  if (!localExempt(host) && !isVerified(user.id, host))
    return res.status(403).json({
      error: `Verify ownership of ${registrable(host)} first (Domains page).`,
      needsVerification: registrable(host),
    });
  if (await privateTarget(host)) return res.status(400).json({ error: PRIVATE_TARGET });
  const intervalHours = Math.max(1, Math.min(168, Number(req.body?.intervalHours) || 24));
  const webhookUrl = (typeof req.body?.webhookUrl === 'string' ? req.body.webhookUrl : '').trim() || null;
  if (webhookUrl && !(await publicOriginAllowed(webhookUrl).catch(() => false))) {
    return res.status(400).json({ error: 'The alert address must be a public http(s) address.' });
  }
  const monitor = {
    id: randomUUID().slice(0, 12),
    target,
    intervalHours,
    webhookUrl,
    enabled: true,
    lastRunAt: 0,
    createdAt: Date.now(),
  };
  saveMonitor(user.id, monitor);
  res.json({ ok: true, monitor });
});
app.get('/api/agent/monitors', (req, res) => {
  const ctx = requirePermission(req, res, 'scans.read');
  if (!ctx) return;
  const user = ctx.user;
  res.json({ ok: true, monitors: listMonitors(user.id) });
});
app.delete('/api/agent/monitors/:id', (req, res) => {
  const ctx = requirePermission(req, res, 'scans.run');
  if (!ctx) return;
  const user = ctx.user;
  removeMonitor(user.id, req.params.id);
  res.json({ ok: true });
});

// AGENT REPORT — format a completed run as a shareable Markdown or JSON report. Pure formatting of
// data the caller already has; touches no target.
app.post('/api/agent/report', (req, res) => {
  const { run, target, format } = req.body || {};
  if (!run || typeof run !== 'object') return res.status(400).json({ error: 'No run to report.' });
  const meta = { target: target || null, date: new Date().toISOString().slice(0, 10) };
  if (format === 'json') return res.type('application/json').send(toJson(run, meta));
  if (format === 'sarif') return res.type('application/json').send(JSON.stringify(toSarif(run, meta), null, 2));
  return res.type('text/markdown').send(toMarkdown(run, meta));
});

// REPEATER — craft & replay a single request to a target you own and see the raw response (manual
// verification, à la Burp/Caido Repeater). Same ownership gate as scans; the engine's fetchT blocks
// internal/metadata hosts (SSRF guard) and follows redirects safely. Only the supplied headers are sent.
const REPLAY_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
app.post('/api/agent/replay', async (req, res) => {
  const active = requirePermission(req, res, 'scans.run');
  if (!active) return;
  const { method = 'GET', url, headers = {}, body } = req.body || {};
  if (!url || typeof url !== 'string') return res.status(400).json({ error: 'Provide a URL.' });
  let host;
  try {
    host = hostOf(url);
  } catch {
    return res.status(400).json({ error: 'Invalid URL.' });
  }
  if (await privateTarget(host)) return res.status(400).json({ error: PRIVATE_TARGET });
  if (!localExempt(host)) {
    const user = getUser(req);
    if (!user) return res.status(401).json({ error: 'Sign in first.' });
    if (!isVerified(user.id, host))
      return res.status(403).json({
        error: `Verify ownership of ${registrable(host)} first (Domains page).`,
        needsVerification: registrable(host),
      });
  }
  const m = String(method).toUpperCase();
  if (!REPLAY_METHODS.has(m)) return res.status(400).json({ error: 'Unsupported method.' });
  try {
    // It takes its turn with the checking engine, as a run does (they share the engine's target and
    // session), and carries the organization's own-test mark, so Defender on that site files it as
    // a test of yours rather than an attack.
    const { r, timeMs } = await withEngine(
      async () => {
        setSessionHeaders({}); // send ONLY the headers the user supplied (don't leak a prior run's session)
        setScanOrigin(new URL(url).origin);
        const t0 = Date.now();
        const reply = await fetchT(url, { method: m, headers: headers || {}, body: body || undefined }, 12000);
        return { r: reply, timeMs: Date.now() - t0 };
      },
      { mark: () => ownTestMark(active.org.id, url, 'tool') },
    );
    const hdrs = {};
    try {
      if (r.headers?.forEach)
        r.headers.forEach((v, k) => {
          hdrs[k] = v;
        });
    } catch {}
    res.json({ ok: true, status: r.status, timeMs, headers: hdrs, body: String(r.body || '').slice(0, 200_000) });
  } catch (e) {
    res.status(502).json({ error: `Request failed: ${e.message}` });
  }
});

// AI CUSTOM CHECK — the LLM AUTHORS a bounded HTTP check; Shannon runs it deterministically (SSRF-
// guarded, path forced relative to the authorized origin). A match is a labeled POTENTIAL lead, never
// a confirmed finding — and NO code executes on the host (the safe alternative to a code sandbox).
async function llmProposeCheck(instruction, key) {
  try {
    const client = new Anthropic({ apiKey: key });
    const model = process.env.SHANNON_QUICK_MODEL || process.env.SHANNON_MODEL || 'claude-haiku-4-5-20251001';
    const msg = await client.messages.create({
      model,
      max_tokens: 300,
      messages: [
        {
          role: 'user',
          content: `Propose ONE bounded HTTP check to test for: ${instruction}\nRespond with JSON ONLY (no prose): {"method":"GET","path":"/relative/path","matcher":{"status":200,"contains":"text","regex":"...","condition":"and|or"},"why":"..."}. The path MUST be relative (start with /). Include only the matcher fields you need.`,
        },
      ],
    });
    const text = (msg.content || []).map((c) => c.text || '').join('');
    const m = text.match(/\{[\s\S]*\}/);
    return m ? JSON.parse(m[0]) : null;
  } catch {
    return null;
  }
}

app.post('/api/agent/custom-check', async (req, res) => {
  const active = requirePermission(req, res, 'scans.run');
  if (!active) return;
  const { target, check, instruction } = req.body || {};
  if (!target) return res.status(400).json({ error: 'Provide a target.' });
  let host;
  try {
    host = hostOf(target);
  } catch {
    return res.status(400).json({ error: 'Invalid URL.' });
  }
  if (await privateTarget(host)) return res.status(400).json({ error: PRIVATE_TARGET });
  if (!localExempt(host)) {
    const user = getUser(req);
    if (!user) return res.status(401).json({ error: 'Sign in first.' });
    if (!isVerified(user.id, host))
      return res.status(403).json({
        error: `Verify ownership of ${registrable(host)} first (Domains page).`,
        needsVerification: registrable(host),
      });
  }
  let proposed = check;
  if (!proposed && instruction) {
    const key = (await aiKeysForRequest(req)).claude;
    if (!key)
      return res
        .status(400)
        .json({ error: 'Add an Anthropic key to have the AI author a check, or specify one manually.' });
    proposed = await llmProposeCheck(instruction, key);
    if (!proposed) return res.status(502).json({ error: 'The AI could not author a check — try a manual one.' });
  }
  if (!proposed) return res.status(400).json({ error: 'Provide an instruction (AI) or a manual check.' });
  const c = sanitizeCheck(proposed);
  if (!Object.keys(c.matcher).length)
    return res.status(400).json({ error: 'The check needs at least one matcher (status / contains / regex).' });
  try {
    const origin = new URL(target).origin;
    const r = await withEngine(
      async () => {
        setSessionHeaders({});
        setScanOrigin(origin);
        return fetchT(origin + c.path, { method: c.method, body: c.body }, 12000);
      },
      { mark: () => ownTestMark(active.org.id, origin, 'tool') },
    );
    const matched = evaluateMatcher(r, c.matcher);
    const lead = matched
      ? {
          kind: 'ai-custom-check',
          tier: 'potential',
          severity: 'info',
          target: origin + c.path,
          note: `Custom check MATCHED (POTENTIAL — unproven): ${c.why || `matcher ${Object.keys(c.matcher).join(', ')}`}. Verify manually.`,
        }
      : null;
    res.json({ ok: true, check: c, matched, status: r.status, snippet: String(r.body || '').slice(0, 400), lead });
  } catch (e) {
    res.status(502).json({ error: `Check failed: ${e.message}` });
  }
});

// EXPLOIT SANDBOX — run LLM-authored (or pasted) analysis code inside a HARDENED, network-isolated
// Docker container (see sandbox.mjs). The code gets the target response Shannon safely fetched (no
// network of its own); a matched result is a labeled POTENTIAL lead, never confirmed. Docker-gated.
async function llmWriteCode(instruction, lang, key) {
  try {
    const client = new Anthropic({ apiKey: key });
    const model = process.env.SHANNON_QUICK_MODEL || process.env.SHANNON_MODEL || 'claude-haiku-4-5-20251001';
    const runtime = lang === 'node' ? 'JavaScript (Node 20)' : 'Python 3';
    const readIn =
      lang === 'node'
        ? "Buffer.from(process.env.SX_INPUT||'','base64').toString()"
        : "base64.b64decode(os.environ.get('SX_INPUT','')).decode('utf-8','ignore')";
    const msg = await client.messages.create({
      model,
      max_tokens: 500,
      messages: [
        {
          role: 'user',
          content: `Write a short ${runtime} program (there is NO network — do not attempt requests) that reads the base64-encoded HTTP response from SX_INPUT (${readIn}) and checks for: ${instruction}. Print exactly ONE line of JSON to stdout: {"matched": true|false, "detail": "..."}. Output ONLY the code — no code fences, no prose.`,
        },
      ],
    });
    let code = (msg.content || [])
      .map((c) => c.text || '')
      .join('')
      .trim();
    code = code
      .replace(/^```[a-z]*\n?/gim, '')
      .replace(/```$/gm, '')
      .trim();
    return code || null;
  } catch {
    return null;
  }
}

app.post('/api/agent/sandbox', async (req, res) => {
  const active = requirePermission(req, res, 'scans.run');
  if (!active) return;
  if (limited(req, res, `sandbox:${active.user.id}`, 10, 60 * 60 * 1000)) return;
  const { target, code, lang = 'python', instruction } = req.body || {};
  if (!target) return res.status(400).json({ error: 'Provide a target.' });
  let host;
  try {
    host = hostOf(target);
  } catch {
    return res.status(400).json({ error: 'Invalid URL.' });
  }
  if (await privateTarget(host)) return res.status(400).json({ error: PRIVATE_TARGET });
  if (!localExempt(host)) {
    const user = getUser(req);
    if (!user) return res.status(401).json({ error: 'Sign in first.' });
    if (!isVerified(user.id, host))
      return res.status(403).json({
        error: `Verify ownership of ${registrable(host)} first (Domains page).`,
        needsVerification: registrable(host),
      });
  }
  if (!(await sandboxAvailable()))
    return res.status(400).json({
      error:
        'The code sandbox needs Docker on the host (for isolation). It is unavailable here — deploy where Docker is present, or use the AI custom check instead.',
      unavailable: true,
    });
  let src = code;
  if (!src && instruction) {
    const key = (await aiKeysForRequest(req)).claude;
    if (!key)
      return res
        .status(400)
        .json({ error: 'Add an Anthropic key to have the AI write the code, or paste code yourself.' });
    src = await llmWriteCode(instruction, lang === 'node' ? 'node' : 'python', key);
    if (!src) return res.status(502).json({ error: 'The AI could not write the code — try pasting it.' });
  }
  if (!src) return res.status(400).json({ error: 'Provide an instruction (AI) or paste code.' });
  if (!(await consumeOrgQuota(active, res, 'agentRuns'))) return;
  let input = '';
  try {
    setSessionHeaders({});
    setScanOrigin(new URL(target).origin);
    const r = await fetchT(target, {}, 12000);
    input = `HTTP ${r.status}\n${String(r.body || '').slice(0, 100_000)}`;
  } catch {}
  const result = await runInSandbox({ code: src, lang: lang === 'node' ? 'node' : 'python', input });
  let parsed = null;
  const mm = (result.stdout || '').match(/\{[\s\S]*"matched"[\s\S]*?\}/);
  if (mm) {
    try {
      parsed = JSON.parse(mm[0]);
    } catch {}
  }
  const lead = parsed?.matched
    ? {
        kind: 'ai-sandbox',
        tier: 'potential',
        severity: 'info',
        target,
        note: `Sandbox check MATCHED (POTENTIAL — unproven): ${String(parsed.detail || '').slice(0, 200)}. Verify manually.`,
      }
    : null;
  res.json({
    ok: true,
    code: src,
    image: result.image || null,
    unavailable: !!result.unavailable,
    timedOut: !!result.timedOut,
    stdout: String(result.stdout || '').slice(0, 8000),
    stderr: String(result.stderr || '').slice(0, 2000),
    matched: !!parsed?.matched,
    lead,
  });
});

// CODE LOCATOR — bridge a proven finding to the likely vulnerable line in pasted source (first step
// toward a fix/patch). Pure local analysis of code the caller provides; touches no target.
app.post('/api/agent/locate', (req, res) => {
  const { finding, code, filename } = req.body || {};
  if (!finding || !code) return res.status(400).json({ error: 'Provide a finding and source code.' });
  if (typeof code !== 'string' || code.length > 1_000_000)
    return res.status(413).json({ error: 'Code exceeds 1MB — paste the specific route/handler file.' });
  const locations = locateFinding({ finding, files: [{ path: filename || 'pasted-source', content: code }] });
  res.json({ ok: true, locations });
});

// PATCH GENERATOR — suggest a fix for a located line. Deterministic rewrite for the clean cases +
// a targeted note otherwise; an LLM diff is layered on when a key is present. Always a SUGGESTION.
async function llmPatch({ snippet, cls, key }) {
  try {
    const client = new Anthropic({ apiKey: key });
    const model = process.env.SHANNON_QUICK_MODEL || process.env.SHANNON_MODEL || 'claude-haiku-4-5-20251001';
    const msg = await client.messages.create({
      model,
      max_tokens: 300,
      messages: [
        {
          role: 'user',
          content: `Rewrite ONLY this code to fix a ${cls} vulnerability. Output just the corrected code (no prose, no fences):\n\n${snippet}`,
        },
      ],
    });
    return (
      (msg.content || [])
        .map((c) => c.text || '')
        .join('')
        .trim() || null
    );
  } catch {
    return null;
  }
}

app.post('/api/agent/patch', async (req, res) => {
  if (!requirePermission(req, res, 'findings.remediate')) return;
  const { finding, snippet } = req.body || {};
  if (!finding || !snippet) return res.status(400).json({ error: 'Provide a finding and the code snippet.' });
  const cls = String(finding.cls || finding.tool || '')
    .replace(/^impact[-:]/, '')
    .replace(/-extract$|-context$|-metadata$/, '');
  const patch = generatePatch({ finding, snippet, guidance: detectionRule(cls) });
  if (!patch) return res.json({ ok: true, patch: null });
  const key = (await aiKeysForRequest(req)).claude;
  if (key) patch.llm = await llmPatch({ snippet, cls, key });
  // If we have a confident rewrite AND the caller passed the full file + line, apply it so they can
  // copy the corrected file back (the usable step before an actual PR).
  if (patch.applicable && patch.after && typeof req.body.code === 'string' && Number.isInteger(req.body.line)) {
    const patchedFile = applyLineFix(req.body.code, req.body.line, patch.after);
    if (patchedFile) patch.patchedFile = patchedFile;
  }
  res.json({ ok: true, patch });
});

// OPEN A PULL REQUEST with a fix. Production credentials come from the encrypted organization
// secret store. A per-request token remains accepted only for backward-compatible API clients.
app.post('/api/agent/pr', async (req, res) => {
  const ctx = requirePermission(req, res, 'findings.remediate');
  if (!ctx) return;
  const { repo, path: filePath, content, token, finding } = req.body || {};
  const provider = await getOrgSecret(ctx.org.id, 'repository-provider', 'github');
  let providerSecret = {};
  try {
    providerSecret = provider ? decryptSecret(provider.secretEnc) || {} : {};
  } catch {}
  // The server's own GITHUB_TOKEN belongs to whoever runs the service. Another organization uses
  // the credential it saved, or one sent with the request, never the operator's.
  const platformToken =
    process.env.NODE_ENV !== 'production' || ctx.org.id === process.env.SHANNON_PLATFORM_ORG_ID
      ? process.env.GITHUB_TOKEN
      : '';
  const tok = String(token || providerSecret.token || platformToken || '').trim();
  const selectedRepo = String(repo || provider?.config?.repo || '').trim();
  if (!tok)
    return res
      .status(400)
      .json({ error: 'Configure the organization GitHub credential in Settings before opening PRs.' });
  if (!selectedRepo || !filePath || !content)
    return res.status(400).json({ error: 'Provide the repo, file path, and the fixed content.' });
  const cls = String(finding?.cls || finding?.tool || 'vulnerability').replace(/^impact[-:]/, '');
  const title = `fix(security): ${cls} in ${filePath}`;
  const body = `Automated fix suggested by **Securovix Shannon** for a proven \`${cls}\` finding.\n\n> ⚠️ Suggested patch — review before merging; not verified against the full codebase.`;
  try {
    const out = await openPullRequest({ token: tok, repo: selectedRepo, path: filePath, content, title, body });
    audit(ctx, 'remediation.pull_request_opened', 'repository', selectedRepo, { path: filePath, cls, url: out.url });
    res.json({ ok: true, url: out.url, branch: out.branch });
  } catch (e) {
    res.status(502).json({ error: `Could not open PR: ${e.message}` });
  }
});

function workspaceConfirmedFindings(scanId) {
  const broker = join(WORKSPACES, scanId, 'broker');
  if (!existsSync(broker)) return [];
  const out = [];
  for (const category of readdirSync(broker)) {
    const path = join(broker, category, 'findings.json');
    if (!existsSync(path)) continue;
    try {
      const rows = JSON.parse(readFileSync(path, 'utf-8'));
      if (Array.isArray(rows)) out.push(...rows);
      else if (Array.isArray(rows?.findings)) out.push(...rows.findings);
    } catch {}
  }
  return out;
}

app.post(['/api/scans', '/api/v1/scans'], async (req, res) => {
  const ctx = requirePermission(req, res, 'scans.run');
  if (!ctx) return;
  if (limited(req, res, `scan:${ctx.user.id}`, 20, 60 * 60 * 1000)) return;
  const { targetUrl, authType, username, password, retryPreset, focusUrls, avoidUrls, warRoom } = req.body;
  if (!targetUrl) return res.status(400).json({ error: 'Target URL is required' });

  // ---- AUTHORIZATION GATE ----
  // Active scanning of a system you don't control is illegal. External targets require a logged-in
  // user, an explicit authorization attestation, AND proven domain ownership. Localhost is exempt
  // (built-in labs / self-demo). This is the safety boundary for multi-tenant / client use.
  const targetHost = hostOf(targetUrl);
  if (await privateTarget(targetHost)) return res.status(400).json({ error: PRIVATE_TARGET });
  if (!localExempt(targetHost)) {
    if (req.body.authorized !== true)
      return res
        .status(403)
        .json({ error: 'You must confirm you are authorized to test this target.', needsAuthorization: true });
    if (!isVerified(ctx.user.id, targetHost))
      return res.status(403).json({
        error: `You have not verified ownership of ${registrable(targetHost)}. Verify it first (prove control via DNS, a /.well-known file, or a meta tag).`,
        needsVerification: registrable(targetHost),
      });
  }

  const settings = settingsFor(req);
  const providerKeys = await aiKeysForRequest(req);
  const apiKey = providerKeys.claude;
  if (!apiKey)
    return res
      .status(400)
      .json({ error: 'Anthropic API key required. An organization owner or admin can add it in Settings.' });
  if (!(await consumeOrgQuota(ctx, res, 'scans'))) return;

  const scanId = randomUUID().slice(0, 8);
  const projectId = req.body?.projectId || null;
  if (projectId && !listProjects(ctx.org.id).some((p) => p.id === projectId))
    return res.status(400).json({ error: 'Project does not belong to the active organization.' });
  saveScanOwner({ scanId, orgId: ctx.org.id, userId: ctx.user.id, projectId, createdAt: Date.now() });
  const config = {
    target: { url: targetUrl, urls: {} },
    pipeline: { retryPreset: retryPreset || 'fast', maxConcurrentPipelines: 3 },
  };
  if (focusUrls)
    config.target.urls.focus = focusUrls
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
  if (avoidUrls)
    config.target.urls.avoid = avoidUrls
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
  if (authType && authType !== 'none') {
    config.authentication = { type: authType };
    if (username) config.authentication.username = username;
    if (password) config.authentication.password = password;
  }
  const env = {
    ...process.env,
    ANTHROPIC_API_KEY: apiKey,
    SHANNON_MODEL: settings.model || 'claude-opus-4-7',
    SHANNON_SCAN_ID: scanId,
    SHANNON_OWNER_USER_ID: ctx.user.id,
    SHANNON_ORG_ID: ctx.org.id,
    SHANNON_PROJECT_ID: projectId || '',
  };
  if (settings.baseUrl) env.SHANNON_LLM_BASE_URL = settings.baseUrl;
  // Multi-LLM war room — when enabled, pass extra provider keys + a flag through env so the scanner's
  // Red/Blue phases can route through the war-room orchestrator. run-scan.mjs reads these opportunistically.
  if (warRoom) {
    env.SHANNON_WAR_ROOM = '1';
    if (providerKeys?.openai) env.OPENAI_API_KEY = providerKeys.openai;
    if (providerKeys?.gemini) env.GOOGLE_API_KEY = providerKeys.gemini;
    if (providerKeys?.glm) env.ZHIPU_API_KEY = providerKeys.glm;
  }
  // Access-control testing (BOLA/BFLA) — the client supplies 2+ authenticated identities (a cookie
  // or a login form). Passed to run-scan via env (not written to the config file on disk). Bounded
  // and sanitized; resources are auto-discovered by crawling as each identity.
  const acIds = Array.isArray(req.body.accessControl?.identities) ? req.body.accessControl.identities : [];
  const cleanIds = acIds
    .slice(0, 4)
    .map((it) => {
      const o = { label: String(it.label || '').slice(0, 40), role: it.role === 'admin' ? 'admin' : 'user' };
      if (it.cookie) o.cookie = String(it.cookie).slice(0, 4096);
      else if (it.header) o.header = String(it.header).slice(0, 4096);
      else if (it.loginUrl && it.username) {
        o.loginUrl = String(it.loginUrl).slice(0, 2048);
        o.username = String(it.username).slice(0, 256);
        o.password = String(it.password || '').slice(0, 256);
        if (it.userField) o.userField = String(it.userField).slice(0, 64);
        if (it.passField) o.passField = String(it.passField).slice(0, 64);
      }
      return o;
    })
    .filter((o) => o.cookie || o.header || o.loginUrl);
  for (const identity of cleanIds) {
    if (!identity.loginUrl) continue;
    let loginHost = '';
    try {
      loginHost = hostOf(identity.loginUrl);
    } catch {}
    if (
      !loginHost ||
      (!localExempt(loginHost) && registrable(loginHost) !== registrable(targetHost)) ||
      (await privateTarget(loginHost))
    ) {
      return res.status(400).json({ error: 'Each login URL must be on the same domain as the scan target.' });
    }
  }
  if (cleanIds.length >= 2) env.SHANNON_AC = JSON.stringify({ identities: cleanIds });

  // Advanced scan options. Continuous monitoring diffs against the last baseline; an alert webhook
  // pings on new exposures. Network scanning (unauth services on the verified host) requires an
  // explicit authorization acknowledgment in addition to the domain-ownership gate.
  if (req.body.monitor) env.SHANNON_MONITOR = '1';
  if (typeof req.body.alertWebhook === 'string' && /^https:\/\//i.test(req.body.alertWebhook)) {
    if (!(await publicOriginAllowed(req.body.alertWebhook.slice(0, 2048)).catch(() => false))) {
      return res.status(400).json({ error: 'The alert address must be a public https address.' });
    }
    env.SHANNON_ALERT_WEBHOOK = req.body.alertWebhook.slice(0, 2048);
  }
  if (req.body.networkScan && req.body.networkAuthorized === true) {
    // Authorization: a DOMAIN target already passed the domain-ownership gate (its host serves the
    // verified domain). A raw-IP target must fall inside a VERIFIED CIDR range. Localhost is exempt.
    const isRawIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(targetHost);
    let netOk = localExempt(targetHost) || !isRawIp;
    if (isRawIp && !netOk) {
      const cidrs = Object.keys(listCidrs(getUser(req)?.id));
      netOk = cidrs.some((c) => ipInCidr(targetHost, c));
    }
    if (netOk) env.SHANNON_NETWORK_SCAN = '1';
  }

  // The scan's requests carry the organization's own-test mark for this site, so Defender on the
  // site files them as a test of yours. Signed here because only the dashboard holds the key.
  const scanMark = signOwnTest(SESSION_SECRET, {
    orgId: ctx.org.id,
    target: targetUrl,
    kind: 'scan',
    ttlMs: OWN_TEST_SCAN_TTL_MS,
  });
  if (scanMark) env.SHANNON_TEST_MARK = JSON.stringify(scanMark);

  if (isSupabase() && process.env.SHANNON_DURABLE_JOBS !== '0') {
    const durableConfig = structuredClone(config);
    Reflect.deleteProperty(durableConfig, 'authentication');
    const job = await enqueueJob({
      orgId: ctx.org.id,
      userId: ctx.user.id,
      type: 'scan',
      payload: {
        scanId,
        targetUrl,
        projectId,
        config: durableConfig,
        model: settings.model || 'claude-opus-4-7',
        baseUrl: settings.baseUrl || null,
        warRoom: warRoom === true,
        monitor: req.body.monitor === true,
        networkScan: env.SHANNON_NETWORK_SCAN === '1',
        testMark: scanMark,
      },
      secretEnc: encryptSecret({
        apiKey,
        authentication: config.authentication || null,
        providerKeys: warRoom
          ? {
              openai: providerKeys?.openai || null,
              gemini: providerKeys?.gemini || null,
              glm: providerKeys?.glm || null,
            }
          : null,
        accessControl: cleanIds,
        alertWebhook: env.SHANNON_ALERT_WEBHOOK || null,
      }),
      maxAttempts: 3,
      idempotencyKey: `scan:${scanId}`,
    });
    audit(ctx, 'scan.queued', 'scan', scanId, { target: targetUrl, projectId, jobId: job.id });
    return res.status(202).json({ scanId, jobId: job.id, status: 'queued' });
  }

  // Authentication belongs in a short-lived, private file—not a repository artifact.
  // Durable jobs already keep it in the encrypted job secret above.
  const scanTempDir = mkdtempSync(join(os.tmpdir(), 'shannon-dashboard-scan-'));
  const configPath = join(scanTempDir, 'scan.yaml');
  writeFileSync(configPath, stringifyYaml(config), { mode: 0o600 });

  const child = spawn('node', [join(ROOT, 'run-scan.mjs'), '--config', configPath], {
    cwd: ROOT,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const cleanScanConfig = () => {
    try {
      rmSync(scanTempDir, { recursive: true, force: true });
    } catch (error) {
      console.error('[scan] temporary credential cleanup failed:', error.message);
    }
  };
  child.once('error', cleanScanConfig);

  const phasePatterns = SCAN_PHASES;

  const scan = {
    child,
    output: '',
    startedAt: new Date().toISOString(),
    target: targetUrl,
    phases: [],
    currentPhase: null,
    sseClients: [],
    userId: ctx.user.id,
    orgId: ctx.org.id,
    projectId,
  };
  runningScans.set(scanId, scan);

  function process_(chunk) {
    scan.output += chunk;
    const line = chunk.toString();
    for (const p of phasePatterns) {
      if (p.re.test(line)) {
        if (scan.currentPhase) {
          scan.currentPhase.status = 'done';
          scan.currentPhase.endedAt = Date.now();
        }
        scan.currentPhase = { id: p.id, name: p.name, status: 'running', startedAt: Date.now() };
        scan.phases.push(scan.currentPhase);
        bc(scan, { type: 'phase', phase: p.id, name: p.name, status: 'running' });
      }
    }
    if (/Done \(/.test(line) && scan.currentPhase?.status === 'running') {
      scan.currentPhase.status = 'done';
      scan.currentPhase.endedAt = Date.now();
      const cm = line.match(/\$([0-9.]+)/);
      if (cm) scan.currentPhase.cost = Number.parseFloat(cm[1]);
      const tm = line.match(/(\d+\.?\d*)s/);
      if (tm) scan.currentPhase.duration = Number.parseFloat(tm[1]);
      bc(scan, {
        type: 'phase-done',
        phase: scan.currentPhase.id,
        cost: scan.currentPhase.cost,
        duration: scan.currentPhase.duration,
      });
    }
    if (/Scan Complete/.test(line)) bc(scan, { type: 'complete' });
    bc(scan, { type: 'output', line: line.trim() });
  }

  function bc(scan, data) {
    const msg = `data: ${JSON.stringify(data)}\n\n`;
    scan.sseClients = scan.sseClients.filter((c) => {
      try {
        c.write(msg);
        return true;
      } catch {
        return false;
      }
    });
  }

  child.stdout.on('data', (d) => process_(d));
  child.stderr.on('data', (d) => process_(d));
  child.on('close', (code) => {
    cleanScanConfig();
    scan.status = code === 0 ? 'completed' : 'failed';
    if (code === 0) {
      try {
        persistConfirmedFindings(ctx, workspaceConfirmedFindings(scanId), {
          source: 'pentest-scan',
          projectId,
          scanId,
        });
      } catch (e) {
        console.error('[team] finding import failed:', e.message);
      }
    }
    bc(scan, { type: code === 0 ? 'complete' : 'failed' });
  });

  audit(ctx, 'scan.started', 'scan', scanId, { target: targetUrl, projectId });
  res.json({ scanId, status: 'started' });
});

// ---- API: Stop scan ----
app.post('/api/scans/:id/stop', async (req, res) => {
  const ctx = scanContext(req, res, req.params.id, 'scans.stop');
  if (!ctx) return;
  const scan = runningScans.get(req.params.id);
  if (!scan) {
    const job = (await listJobs(ctx.org.id, 500)).find(
      (item) => item.type === 'scan' && item.payload?.scanId === req.params.id,
    );
    if (!job) return res.status(404).json({ error: 'Scan not found or already finished' });
    if (!['queued', 'running'].includes(job.status))
      return res.status(409).json({ error: `Cannot stop a ${job.status} scan.` });
    await updateJob(job.id, { status: 'cancelled', error: 'Cancelled by user', lockedBy: null, lockedAt: null });
    audit(ctx, 'scan.stopped', 'scan', req.params.id, { jobId: job.id });
    return res.json({ ok: true, message: 'Scan cancellation requested' });
  }
  try {
    scan.child.kill('SIGTERM');
    setTimeout(() => {
      try {
        scan.child.kill('SIGKILL');
      } catch {}
    }, 3000);
    scan.status = 'stopped';
    audit(ctx, 'scan.stopped', 'scan', req.params.id);
    bc_ext(scan, { type: 'stopped' });
    res.json({ ok: true, message: 'Scan stopped' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---- API: Mark stale scan as failed ----
app.post('/api/scans/:id/mark-failed', async (req, res) => {
  const ctx = scanContext(req, res, req.params.id, 'scans.stop');
  if (!ctx) return;
  const wsDir = join(WORKSPACES, req.params.id);
  const sessionPath = join(wsDir, 'session.json');
  if (!existsSync(sessionPath)) {
    const job = (await listJobs(ctx.org.id, 500)).find(
      (item) => item.type === 'scan' && item.payload?.scanId === req.params.id,
    );
    if (!job) return res.status(404).json({ error: 'Scan not found' });
    if (job.status === 'succeeded') return res.json({ ok: true, message: 'Already completed' });
    await updateJob(job.id, { status: 'dead-letter', error: 'Manually marked failed', lockedBy: null, lockedAt: null });
    audit(ctx, 'scan.marked_failed', 'scan', req.params.id, { jobId: job.id });
    return res.json({ ok: true, message: 'Scan marked as failed' });
  }

  try {
    const session = JSON.parse(readFileSync(sessionPath, 'utf-8'));
    if (session.status === 'completed') return res.json({ ok: true, message: 'Already completed' });
    session.status = 'failed';
    session.completedAt = new Date().toISOString();
    session.failReason = 'Manually stopped — scan process was stale or crashed';
    writeFileSync(sessionPath, JSON.stringify(session, null, 2));
    // Also clean up from running scans map
    runningScans.delete(req.params.id);
    audit(ctx, 'scan.marked_failed', 'scan', req.params.id);
    res.json({ ok: true, message: 'Scan marked as failed' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

function bc_ext(scan, data) {
  const msg = `data: ${JSON.stringify(data)}\n\n`;
  scan.sseClients = scan.sseClients.filter((c) => {
    try {
      c.write(msg);
      return true;
    } catch {
      return false;
    }
  });
}

// ---- API: Live status ----
app.get('/api/scans/:id/live', async (req, res) => {
  const ctx = scanContext(req, res, req.params.id);
  if (!ctx) return;
  const scan = runningScans.get(req.params.id);
  if (scan)
    return res.json({
      status: scan.status || 'running',
      output: scan.output,
      target: scan.target,
      phases: scan.phases,
    });
  const wsDir = join(WORKSPACES, req.params.id);
  if (existsSync(join(wsDir, 'session.json'))) {
    const session = JSON.parse(readFileSync(join(wsDir, 'session.json'), 'utf-8'));
    return res.json({ status: session.status || 'completed' });
  }
  const job = (await listJobs(ctx.org.id, 500)).find(
    (item) => item.type === 'scan' && item.payload?.scanId === req.params.id,
  );
  if (job)
    return res.json({
      status: scanStatusOfJob(job),
      output: job.result?.outputTail || '',
      target: job.result?.target || job.payload?.targetUrl,
      phases: Array.isArray(job.result?.phases) ? job.result.phases : [],
      attempts: job.attempts,
      error: job.error || null,
    });
  res.status(404).json({ error: 'Not found' });
});

// ---- SSE ----
app.get('/api/scans/:id/events', async (req, res) => {
  const ctx = scanContext(req, res, req.params.id);
  if (!ctx) return;
  const scan = runningScans.get(req.params.id);
  if (!scan) {
    const initial = (await listJobs(ctx.org.id, 500)).find(
      (item) => item.type === 'scan' && item.payload?.scanId === req.params.id,
    );
    if (!initial) return res.status(404).json({ error: 'Not found' });
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    });
    // The worker runs this scan in another process. It stores what the scanner printed and the
    // phases so far; each viewer is sent what it has not seen yet, as the same events a scan run
    // by this process sends.
    const write = (data) => res.write(`data: ${JSON.stringify(data)}\n\n`);
    const seen = createSeen();
    let previous = '';
    let note = '';
    let ended = false;
    const send = async () => {
      if (ended) return;
      const job = await getJob(initial.id).catch(() => null);
      if (!job) return;
      const snapshot = JSON.stringify({ status: job.status, attempts: job.attempts, error: job.error || null });
      if (snapshot !== previous) write({ type: 'job', ...JSON.parse(snapshot) });
      previous = snapshot;
      // Say why nothing is moving, once per state.
      const waiting =
        job.status !== 'queued'
          ? ''
          : job.attempts > 0
            ? 'The scan was interrupted and is waiting to start again.'
            : 'Queued: waiting for the scan worker to pick this up.';
      if (waiting && waiting !== note) write({ type: 'output', line: waiting });
      note = waiting;
      for (const event of progressSince(seen, job.result)) write(event);
      if (['succeeded', 'cancelled', 'dead-letter', 'failed'].includes(job.status)) {
        ended = true;
        clearInterval(timer);
        if (seen.carry.trim()) write({ type: 'output', line: seen.carry.trim() });
        const type = job.status === 'succeeded' ? 'complete' : job.status === 'cancelled' ? 'stopped' : 'failed';
        write({
          type,
          status: job.status,
          ...(type === 'failed' ? { error: String(job.error || '').slice(0, 600) || null } : {}),
        });
        res.end();
      }
    };
    const timer = setInterval(
      () => send().catch(() => {}),
      Math.max(100, Number(process.env.SHANNON_SCAN_EVENTS_POLL_MS || 2_000)),
    );
    timer.unref?.();
    req.on('close', () => clearInterval(timer));
    await send();
    return;
  }
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
  for (const phase of scan.phases) {
    res.write(
      `data: ${JSON.stringify({ type: 'phase', phase: phase.id, name: phase.name, status: phase.status })}\n\n`,
    );
    if (phase.status === 'done')
      res.write(
        `data: ${JSON.stringify({ type: 'phase-done', phase: phase.id, cost: phase.cost, duration: phase.duration })}\n\n`,
      );
  }
  scan.sseClients.push(res);
  req.on('close', () => {
    scan.sseClients = scan.sseClients.filter((c) => c !== res);
  });
});

// ---- API: Available models ----
app.get('/api/models', (req, res) => {
  // Latest available models as of May 2026.
  res.json([
    // Anthropic
    {
      id: 'claude-opus-4-7',
      name: 'Claude Opus 4.7',
      tier: 'flagship',
      desc: 'Most capable Anthropic model — best for deep red-team reasoning',
    },
    {
      id: 'claude-sonnet-4-6',
      name: 'Claude Sonnet 4.6',
      tier: 'large',
      desc: 'Fast + capable — strong balance for either side',
    },
    {
      id: 'claude-haiku-4-5-20251001',
      name: 'Claude Haiku 4.5',
      tier: 'small',
      desc: 'Fastest, lowest cost — ideal for high-volume scans',
    },
    // OpenAI
    { id: 'gpt-5', name: 'GPT-5', tier: 'flagship', desc: 'OpenAI flagship — broad knowledge, fast all-rounder' },
    { id: 'gpt-5-mini', name: 'GPT-5 Mini', tier: 'small', desc: 'OpenAI cost-efficient tier' },
    { id: 'o3', name: 'OpenAI o3', tier: 'reason', desc: 'Deep reasoning model — best for chain analysis' },
    { id: 'gpt-4o', name: 'GPT-4o (legacy)', tier: 'large', desc: 'Previous-gen OpenAI flagship' },
    // Google
    {
      id: 'gemini-2.5-pro',
      name: 'Gemini 2.5 Pro',
      tier: 'flagship',
      desc: 'Huge context window — great for recon + chain analysis',
    },
    { id: 'gemini-2.5-flash', name: 'Gemini 2.5 Flash', tier: 'small', desc: 'Fast Google tier' },
    // Zhipu
    { id: 'glm-4-plus', name: 'GLM-4-Plus', tier: 'large', desc: 'Zhipu — cost-efficient blue-team workhorse' },
    // Custom
    { id: 'custom', name: 'Custom Model', tier: 'custom', desc: 'Any model via custom base URL' },
  ]);
});

// Health-check endpoint — Railway will hit this to confirm the container is alive.
app.get('/healthz', (_req, res) => res.json({ ok: true, service: 'dashboard', uptime: process.uptime() }));

app.get('/readyz', async (_req, res) => {
  try {
    const database = await enterpriseHealth();
    res.json({ ok: true, database, durableJobs: isSupabase() && process.env.SHANNON_DURABLE_JOBS !== '0' });
  } catch (error) {
    res.status(503).json({ ok: false, error: error.message });
  }
});

app.get('/api/system/readiness', async (req, res) => {
  const ctx = requirePermission(req, res, 'settings.manage');
  if (!ctx) return;
  const now = Date.now();
  const strong = (value) => !!value && String(value).length >= 32 && !/replace-me|change-me/i.test(String(value));
  const recentDate = (value, maxAgeDays) =>
    Number.isFinite(Date.parse(value || '')) && now - Date.parse(value) <= maxAgeDays * 86_400_000;
  const [database, workerEvents, edgeEvents, dockerSandbox, browserRuntime, orgOidc, orgScim] = await Promise.all([
    enterpriseHealth().catch((error) => ({ ok: false, error: error.message })),
    listOperationalEvents('worker', 5).catch(() => []),
    listOperationalEvents('edge', 5, ctx.org.id).catch(() => []),
    sandboxAvailable().catch(() => false),
    import('playwright').then(() => true).catch(() => false),
    getOrgSecret(ctx.org.id, 'oidc', 'default').catch(() => null),
    getOrgSecret(ctx.org.id, 'scim', 'default').catch(() => null),
  ]);
  const workerHeartbeat = workerEvents.find((event) => ['worker.heartbeat', 'worker.started'].includes(event.event));
  const edgeHeartbeat = edgeEvents.find((event) => event.event === 'edge.heartbeat');
  const recent = (event, maxAge) => !!event && now - Number(event.createdAt || 0) <= maxAge;
  const checks = [
    {
      key: 'database',
      label: 'Supabase database',
      status: database.ok && database.backend === 'supabase' ? 'ready' : 'configure',
      detail: database.ok ? `Backend: ${database.backend}` : database.error,
    },
    {
      key: 'secrets',
      label: 'Session and encryption secrets',
      status:
        strong(process.env.SHANNON_SESSION_SECRET) && strong(process.env.SHANNON_ENCRYPTION_KEY)
          ? 'ready'
          : 'configure',
      detail: 'Two independent secrets of at least 32 characters',
    },
    {
      key: 'public-url',
      label: 'Public application URL',
      status: /^https:\/\//.test(process.env.SHANNON_PUBLIC_URL || '') ? 'ready' : 'configure',
      detail: process.env.SHANNON_PUBLIC_URL || 'Set SHANNON_PUBLIC_URL',
    },
    {
      key: 'email',
      label: 'Transactional email',
      status: process.env.RESEND_API_KEY || process.env.SHANNON_EMAIL_WEBHOOK_URL ? 'ready' : 'configure',
      detail: process.env.RESEND_API_KEY
        ? 'Resend configured'
        : process.env.SHANNON_EMAIL_WEBHOOK_URL
          ? 'HTTPS relay configured'
          : 'Verification, reset and invitation mail cannot be delivered',
    },
    {
      key: 'worker',
      label: 'Durable background worker',
      status: recent(workerHeartbeat, 180_000) ? 'ready' : 'configure',
      detail: workerHeartbeat
        ? `Last heartbeat ${new Date(workerHeartbeat.createdAt).toISOString()}`
        : 'Deploy railway.worker.json',
    },
    {
      key: 'browser',
      label: 'Headless browser proofs',
      status: process.env.SHANNON_HEADLESS === '1' && browserRuntime ? 'ready' : 'configure',
      detail: browserRuntime ? 'Set SHANNON_HEADLESS=1' : 'Playwright runtime is not installed',
    },
    {
      key: 'sandbox',
      label: 'Isolated code sandbox',
      status: dockerSandbox ? 'ready' : process.env.SHANNON_SANDBOX_RUNNER_URL ? 'configure' : 'optional',
      detail: dockerSandbox
        ? 'Authenticated dedicated runner and Docker isolation available'
        : process.env.SHANNON_SANDBOX_RUNNER_URL
          ? 'Configured runner is unreachable or Docker is unavailable'
          : 'Requires a Docker-capable dedicated runner; custom checks remain available',
    },
    {
      key: 'edge',
      label: 'Public Defender Edge',
      status: recent(edgeHeartbeat, 300_000) ? 'ready' : 'optional',
      detail: edgeHeartbeat
        ? `Last heartbeat ${new Date(edgeHeartbeat.createdAt).toISOString()}`
        : 'Deploy railway.edge.json when public reverse-proxy protection is required',
    },
    {
      key: 'sso',
      label: 'Company SSO',
      status:
        orgOidc || (process.env.OIDC_ISSUER && process.env.OIDC_CLIENT_ID && process.env.OIDC_CLIENT_SECRET)
          ? 'ready'
          : 'optional',
      detail: orgOidc?.config?.issuer || process.env.OIDC_ISSUER || 'OIDC is optional',
    },
    {
      key: 'scim',
      label: 'SCIM provisioning',
      status:
        orgScim || (strong(process.env.SHANNON_SCIM_TOKEN) && process.env.SHANNON_SCIM_ORG_ID) ? 'ready' : 'optional',
      detail: orgScim ? `Configured for ${ctx.org.name}` : process.env.SHANNON_SCIM_ORG_ID || 'SCIM is optional',
    },
    {
      key: 'metrics',
      label: 'Protected metrics',
      status: strong(process.env.SHANNON_METRICS_TOKEN) ? 'ready' : 'configure',
      detail: 'Prometheus endpoint bearer token',
    },
    {
      key: 'backups',
      label: 'Backup restore test',
      status: recentDate(process.env.SHANNON_BACKUPS_VERIFIED_AT, 100) ? 'ready' : 'configure',
      detail:
        process.env.SHANNON_BACKUPS_VERIFIED_AT ||
        'Set SHANNON_BACKUPS_VERIFIED_AT after a successful staging restore (repeat quarterly)',
    },
    {
      key: 'alerts',
      label: 'Production alert test',
      status: recentDate(process.env.SHANNON_ALERTS_VERIFIED_AT, 45) ? 'ready' : 'configure',
      detail:
        process.env.SHANNON_ALERTS_VERIFIED_AT ||
        'Set SHANNON_ALERTS_VERIFIED_AT after an end-to-end on-call alert test',
    },
    {
      key: 'incident-contact',
      label: 'Security incident contact',
      status: /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(process.env.SHANNON_SECURITY_CONTACT || '') ? 'ready' : 'configure',
      detail: process.env.SHANNON_SECURITY_CONTACT || 'Set the monitored security contact address',
    },
    {
      key: 'billing',
      label: 'Stripe billing',
      status: billingEnabled() ? 'ready' : 'optional',
      detail: billingEnabled() ? 'Checkout and signed webhooks configured' : 'Optional; paid checkout remains disabled',
    },
  ];
  const operatorActions = {
    backups: {
      owner: 'Platform operations',
      cadence: 'Quarterly',
      environmentVariable: 'SHANNON_BACKUPS_VERIFIED_AT',
      steps: [
        'Confirm Supabase production backups or PITR are enabled and record the real retention period.',
        'Restore the newest backup into a separate non-production Supabase project; never overwrite production for a test.',
        'Start a staging Dashboard against the restore and verify users, organizations, findings, Defender events, encrypted-secret access, and a private artifact download.',
        'Save the evidence and UTC completion date, then set SHANNON_BACKUPS_VERIFIED_AT=YYYY-MM-DD on the Railway Dashboard service and redeploy.',
      ],
    },
    alerts: {
      owner: 'On-call operations',
      cadence: 'Monthly',
      environmentVariable: 'SHANNON_ALERTS_VERIFIED_AT',
      steps: [
        'Configure Railway deployment/crash alerts for Dashboard, Worker, and Defender Edge, plus an external HTTPS check for the Sandbox Runner.',
        'Trigger a controlled staging failure and confirm the alert reaches the monitored on-call destination.',
        'Record delivery time, acknowledgement, owner, and evidence without copying secrets into the ticket.',
        'Set SHANNON_ALERTS_VERIFIED_AT=YYYY-MM-DD on the Railway Dashboard service and redeploy.',
      ],
    },
  };
  for (const check of checks) {
    if (operatorActions[check.key]) check.action = operatorActions[check.key];
  }
  const requiredKeys = new Set([
    'database',
    'secrets',
    'public-url',
    'email',
    'worker',
    'browser',
    'metrics',
    'backups',
    'alerts',
    'incident-contact',
  ]);
  const required = checks.filter((item) => requiredKeys.has(item.key));
  // Every organization's owner may see whether the service is ready. The details (addresses,
  // contacts, which variables to set) describe the platform, so only its operator gets them.
  const operator = isPlatformOperator(req, ctx.user);
  res.json({
    ok: required.every((item) => item.status === 'ready'),
    ready: required.filter((item) => item.status === 'ready').length,
    required: required.length,
    checks: operator ? checks : checks.map(({ key, label, status }) => ({ key, label, status })),
    generatedAt: now,
    organization: { id: ctx.org.id, name: ctx.org.name },
  });
});

app.get('/metrics', async (req, res) => {
  const configured = String(process.env.SHANNON_METRICS_TOKEN || '');
  const supplied = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const valid =
    configured &&
    supplied.length === configured.length &&
    _crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(configured));
  if (!valid) return res.status(401).type('text/plain').send('unauthorized\n');
  const jobs = await listJobs(null, 500);
  const counts = {};
  for (const job of jobs) counts[`${job.type}:${job.status}`] = (counts[`${job.type}:${job.status}`] || 0) + 1;
  const lines = [
    '# HELP shannon_process_uptime_seconds Dashboard process uptime.',
    '# TYPE shannon_process_uptime_seconds gauge',
    `shannon_process_uptime_seconds ${process.uptime()}`,
    '# HELP shannon_jobs Jobs by type and status (latest 500).',
    '# TYPE shannon_jobs gauge',
    ...Object.entries(counts).map(([key, value]) => {
      const [type, status] = key.split(':');
      return `shannon_jobs{type="${type.replaceAll('"', '')}",status="${status.replaceAll('"', '')}"} ${value}`;
    }),
  ];
  res.type('text/plain; version=0.0.4').send(`${lines.join('\n')}\n`);
});

// ── Self-defense status / control ───────────────────────────────────────────────────────────────
// Reports whether this dashboard is defending itself, and lets an operator flip monitor⇄enforce
// without a redeploy. Read-only when the feature is off, so the UI can explain how to enable it.
app.get('/api/defender/self', (req, res) => {
  if (!requirePlatformOperator(req, res)) return;
  if (!SELF_DEFENSE) return res.json({ enabled: false });
  res.json({
    enabled: true,
    mode: SELF_DEFENSE.getMode(),
    stats: SELF_DEFENSE.stats(),
    recent: SELF_DEFENSE.recent().slice(0, 25),
    bans: SELF_DEFENSE.bans(),
    banPolicy: SELF_DEFENSE.banPolicy(),
    platformOrgConfigured: !!process.env.SHANNON_PLATFORM_ORG_ID,
  });
});

// Live stream of self-defense activity: detections as they happen, ban decisions, mode changes.
app.get('/api/defender/self/events', (req, res) => {
  if (!requirePlatformOperator(req, res)) return;
  if (!SELF_DEFENSE) return res.status(409).json({ error: 'self-defense is not enabled' });
  res.writeHead(200, {
    'content-type': 'text/event-stream',
    'cache-control': 'no-cache, no-transform',
    connection: 'keep-alive',
    'x-accel-buffering': 'no',
  });
  res.write(
    `data: ${JSON.stringify({ type: 'hello', mode: SELF_DEFENSE.getMode(), stats: SELF_DEFENSE.stats(), bans: SELF_DEFENSE.bans(), banPolicy: SELF_DEFENSE.banPolicy() })}\n\n`,
  );
  SELF_SSE.add(res);
  const heartbeat = setInterval(() => {
    try {
      res.write(': ping\n\n'); // keeps intermediaries from dropping an idle stream
    } catch {}
  }, 25_000);
  heartbeat.unref?.();
  req.on('close', () => {
    clearInterval(heartbeat);
    SELF_SSE.delete(res);
  });
});

app.post('/api/defender/self/unban', (req, res) => {
  if (!requirePlatformOperator(req, res)) return;
  if (!SELF_DEFENSE) return res.status(409).json({ error: 'self-defense is not enabled' });
  const ip = String(req.body?.ip || '')
    .trim()
    .slice(0, 64);
  if (!ip) return res.status(400).json({ error: 'ip required' });
  const lifted = SELF_DEFENSE.unban(ip);
  audit(requestContext(req), 'defender.self_unban', 'defender', ip, { lifted });
  res.json({ ok: true, lifted });
});

app.post('/api/defender/self/mode', (req, res) => {
  if (!requirePlatformOperator(req, res)) return;
  const ctx = requestContext(req);
  if (!SELF_DEFENSE) return res.status(409).json({ error: 'self-defense is not enabled' });
  const mode = SELF_DEFENSE.setMode(req.body?.mode);
  audit(ctx, 'defender.self_mode_changed', 'defender', 'self', { mode });
  res.json({ mode });
});

// ── SDK reporting (@securovix/defender running in a customer's own app) ─────────────────────────
// The key carries its user, organization and revocation version and is verified by HMAC. A per-user
// version permits targeted rotation while SHANNON_SESSION_SECRET remains the emergency global reset.
function defenderApiKey(userId, orgId, version = 0) {
  const payload = Buffer.from(JSON.stringify({ uid: userId, oid: orgId, v: Number(version || 0) })).toString(
    'base64url',
  );
  const sig = _crypto.createHmac('sha256', SESSION_SECRET).update(`defender-key:${payload}`).digest('base64url');
  return `sk_${payload}.${sig}`;
}
function verifyDefenderKey(key) {
  const m = /^sk_([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/.exec(String(key || ''));
  if (!m) return null;
  const expected = _crypto.createHmac('sha256', SESSION_SECRET).update(`defender-key:${m[1]}`).digest('base64url');
  if (expected.length !== m[2].length || !_crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(m[2])))
    return null;
  try {
    const payload = JSON.parse(Buffer.from(m[1], 'base64url').toString());
    const membership = getMembership(payload.oid, payload.uid);
    const user = loadUsers()[payload.uid];
    const versionMatches = user && Number(payload.v || 0) === Number(user.defenderKeyVersion || 0);
    return membership && versionMatches && !user.disabledAt && can(membership.role, 'defender.manage')
      ? { userId: payload.uid, orgId: payload.oid }
      : null;
  } catch {
    return null;
  }
}

// Limit each SDK batch; accepted events are persisted per organization.
const SDK_REPORT_MAX = 200;

const CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const CISA_KEV_TTL_MS = 6 * 60 * 60_000;
let cisaKevCache = null;
let cisaKevRequest = null;

async function loadCisaKev() {
  if (cisaKevCache && Date.now() - cisaKevCache.fetchedAt < CISA_KEV_TTL_MS) return cisaKevCache;
  if (cisaKevRequest) return cisaKevRequest;
  cisaKevRequest = (async () => {
    try {
      const response = await fetch(CISA_KEV_URL, {
        headers: { accept: 'application/json', 'user-agent': 'Securovix-Shannon/1.0 threat-intelligence' },
        signal: AbortSignal.timeout(12_000),
      });
      if (!response.ok) throw new Error(`CISA KEV returned HTTP ${response.status}`);
      const raw = await response.text();
      if (raw.length > 12_000_000) throw new Error('CISA KEV response exceeded the safety limit');
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed.vulnerabilities)) throw new Error('CISA KEV response is invalid');
      const vulnerabilities = parsed.vulnerabilities
        .map((item) => ({
          cveId: String(item.cveID || '').slice(0, 32),
          vendor: String(item.vendorProject || '').slice(0, 120),
          product: String(item.product || '').slice(0, 160),
          name: String(item.vulnerabilityName || '').slice(0, 240),
          dateAdded: String(item.dateAdded || '').slice(0, 20),
          dueDate: String(item.dueDate || '').slice(0, 20),
          ransomwareUse: String(item.knownRansomwareCampaignUse || 'Unknown').slice(0, 24),
          action: String(item.requiredAction || '').slice(0, 600),
          notes: String(item.notes || '').slice(0, 500),
        }))
        .filter((item) => /^CVE-\d{4}-\d+$/i.test(item.cveId));
      cisaKevCache = {
        fetchedAt: Date.now(),
        catalogVersion: String(parsed.catalogVersion || '').slice(0, 40),
        dateReleased: String(parsed.dateReleased || '').slice(0, 60),
        vulnerabilities,
      };
      return cisaKevCache;
    } catch (error) {
      if (cisaKevCache) return { ...cisaKevCache, stale: true, warning: String(error?.message || error).slice(0, 200) };
      throw error;
    } finally {
      cisaKevRequest = null;
    }
  })();
  return cisaKevRequest;
}

// A report that carries this organization's own signed test mark is the AI Agent (or its monitor)
// testing a site the organization owns. It is kept, so the owner can see the test arrived and
// whether it was blocked, but it is filed as a test: one entry per run, no severity, already closed,
// no alert sent, and left out of every attack count. A mark that does not check out is ignored and
// the report is an attack like any other.
function ownTestOf(orgId, raw, site) {
  return typeof raw?.test === 'string' ? verifyOwnTest(SESSION_SECRET, raw.test, { orgId, url: site }) : null;
}
const notOwnTest = (event) => !isOwnTest(event);
const OWN_TESTS = createOwnTestLedger({
  append: (event) => appendDefenseEvent(event),
  update: (orgId, id, patch) => updateDefenseEvent(orgId, id, patch),
  newId: () => randomUUID(),
  settleMs: Math.max(10, Number(process.env.SHANNON_OWN_TEST_SETTLE_MS) || 2000),
});
// "www.example.com/path?x=1" or a bare host -> the host as the site reported it.
const reportedHost = (value) =>
  String(value || '')
    .replace(/^[a-z][a-z0-9+.-]*:\/\//i, '')
    .split(/[/?#]/)[0]
    .slice(0, 255);

function defenderSeverity(cls) {
  const value = String(cls || '').toLowerCase();
  if (/(rce|command|cmd-injection|sqli|auth-bypass|metadata)/.test(value)) return 'critical';
  if (/(path-traversal|nosql|ssrf|ssti|xxe|authz|idor)/.test(value)) return 'high';
  if (/(xss|prompt|csrf|header|graphql)/.test(value)) return 'medium';
  return 'low';
}

// How many detections one organization may store per minute from each source, and one alert per
// kind of attack per site per minute. A leaked site key, or a real flood, must not be able to push
// an organization's whole history out, or send its owner a message per request.
const INTAKE = createIntakeGate({
  perMinute: Math.max(10, Number(process.env.SHANNON_DEFENDER_INTAKE_PER_MINUTE) || 300),
});
function sendDefenseAlert(orgId, event, userId, site) {
  if (!INTAKE.alertOnce(orgId, `${event.source}|${site}|${event.cls}`)) return;
  queueIntegrationEvent(
    orgId,
    { id: `defender:${event.id}`, type: 'defender.detection', at: event.at, data: event },
    userId,
  ).catch((error) => console.error('[defender] integration event failed:', error.message));
}
// Stores one reported detection, or, once the minute's allowance is used, one notice that the rest
// of the minute is not being kept. Returns whether the detection itself was stored.
function storeDetection({ orgId, userId, source, site, detection, metadata = {} }) {
  const turn = INTAKE.admit(orgId, source);
  if (turn === 'drop') return false;
  const flood = turn === 'overflow';
  const event = {
    id: randomUUID(),
    orgId,
    userId,
    at: flood ? new Date().toISOString() : detection.at,
    method: flood ? 'FLOOD' : detection.method,
    url: flood
      ? `${site}: more than ${INTAKE.perMinute} detections in one minute. The rest of this minute is not stored.`
      : detection.url,
    cls: flood ? 'report-flood' : detection.cls,
    enforced: flood ? false : detection.enforced,
    srcIp: flood ? null : detection.srcIp,
    severity: flood ? 'high' : defenderSeverity(detection.cls),
    source,
    status: !flood && detection.enforced ? 'contained' : 'open',
    metadata,
    createdAt: Date.now(),
  };
  appendDefenseEvent(event);
  sendDefenseAlert(orgId, event, userId, site);
  return !flood;
}

app.post('/api/defender/report', (req, res) => {
  const principal = verifyDefenderKey((req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
  if (!principal) return res.status(401).json({ error: 'invalid api key' });
  // Counted per organization, not per address: the sender is the customer's server.
  if (!rateLimit(`defender-report:${principal.orgId}`, { limit: 240, windowMs: 60_000 }).ok) {
    return res.status(429).json({ error: 'Too many reports. Send detections in batches.' });
  }
  const incoming = Array.isArray(req.body?.detections) ? req.body.detections : [];
  if (!incoming.length) return res.json({ accepted: 0 });

  let accepted = 0;
  for (const raw of incoming.slice(0, SDK_REPORT_MAX)) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) continue;
    const d = cleanDetection(raw);
    // The Express package reports a path, so it sends the site's name beside it.
    const site = typeof raw.host === 'string' && raw.host ? raw.host : d.url;
    const own = ownTestOf(principal.orgId, raw, site);
    if (own) {
      OWN_TESTS.record({
        orgId: principal.orgId,
        userId: principal.userId,
        source: 'sdk',
        token: raw.test,
        kind: own.kind,
        site: reportedHost(site),
        detection: d,
        at: d.at,
      });
      accepted += 1;
      continue;
    }
    if (
      storeDetection({
        orgId: principal.orgId,
        userId: principal.userId,
        source: 'sdk',
        site: reportedHost(site),
        detection: d,
      })
    )
      accepted += 1;
  }
  res.json({ accepted });
});

app.get('/api/defender/sdk', (req, res) => {
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  const user = ctx.user;
  res.json({
    apiKey: defenderApiKey(user.id, ctx.org.id, user.defenderKeyVersion),
    reports: listDefenseEvents(ctx.org.id, 25),
  });
});

app.post('/api/defender/sdk/rotate', (req, res) => {
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  ctx.user.defenderKeyVersion = Number(ctx.user.defenderKeyVersion || 0) + 1;
  saveUsers(loadUsers());
  audit(ctx, 'defender.sdk_key_rotated', 'organization', ctx.org.id, { version: ctx.user.defenderKeyVersion });
  res.json({ apiKey: defenderApiKey(ctx.user.id, ctx.org.id, ctx.user.defenderKeyVersion) });
});

// ── Website protection settings ──────────────────────────────────────────────────
// One set per organization. The owner changes them in Settings; every website that carries the
// organization's key reads them and applies them within a minute, so nothing has to be redeployed.
const defenderPolicyRecord = (orgId) => getOrgSecret(orgId, 'defender-policy', 'site');

app.get('/api/defender/policy', async (req, res) => {
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  const record = await defenderPolicyRecord(ctx.org.id);
  const lastReport = listDefenseEvents(ctx.org.id, 200).find((event) => event.source === 'sdk');
  res.json({
    ok: true,
    policy: policyFor(record?.config?.policy),
    rules: DEFENDER_RULES,
    updatedAt: record?.updatedAt || null,
    // When a website last reported something, which shows the key is installed and working.
    lastReportAt: lastReport?.at || null,
    apiKey: defenderApiKey(ctx.user.id, ctx.org.id, ctx.user.defenderKeyVersion),
    endpoint: publicBaseUrl(req),
  });
});

app.put('/api/defender/policy', async (req, res) => {
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  const checked = normalizePolicy(req.body?.policy);
  if (!checked.ok) return res.status(400).json({ error: checked.error });
  const previous = await defenderPolicyRecord(ctx.org.id);
  const now = Date.now();
  await saveOrgSecret({
    id: previous?.id || `osec_${randomUUID().replaceAll('-', '')}`,
    orgId: ctx.org.id,
    kind: 'defender-policy',
    name: 'site',
    config: { policy: checked.policy },
    // Nothing here is secret; the column is required, so it holds an empty sealed value.
    secretEnc: previous?.secretEnc || encryptSecret({}),
    createdBy: previous?.createdBy || ctx.user.id,
    createdAt: previous?.createdAt || now,
    updatedAt: now,
  });
  audit(ctx, 'defender.policy_updated', 'organization', ctx.org.id, {
    enabled: checked.policy.enabled,
    mode: checked.policy.mode,
    disabled: checked.policy.disabled,
    skip: checked.policy.skip.length,
  });
  res.json({ ok: true, policy: checked.policy, updatedAt: now });
});

// Read by the organization's websites.
app.get('/api/defender/sdk/policy', async (req, res) => {
  const principal = verifyDefenderKey((req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
  if (!principal) return res.status(401).json({ error: 'invalid api key' });
  const record = await defenderPolicyRecord(principal.orgId).catch(() => null);
  res.setHeader('cache-control', 'no-store');
  res.json({ policy: policyFor(record?.config?.policy), version: record?.updatedAt || 0 });
});

// The adapter as one file, so a customer adds a single file to their own project.
app.get('/api/defender/sdk/download/:kind', (req, res) => {
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  const code = sdkBundle(req.params.kind);
  if (!code) return res.status(404).json({ error: 'Unknown download.' });
  res.setHeader('content-type', 'text/javascript; charset=utf-8');
  res.setHeader(
    'content-disposition',
    `attachment; filename="securovix-defender${req.params.kind === 'express' ? '-express' : ''}.mjs"`,
  );
  res.end(code);
});

// ── Weekly attack summary ───────────────────────────────────────────────────────────────────────
// An email to each organization's owners and admins every Monday: what was blocked, who was banned,
// where it came from. A week with nothing to report sends nothing. Each person can switch it off.
const DIGEST_ROLES = new Set(['owner', 'admin']);

function defenseDigest(orgId, { from, to }) {
  const events = listDefenseEventsSince(orgId, from - 7 * DAY).filter(notOwnTest);
  const inside = events.filter((event) => Number(event.createdAt) >= from && Number(event.createdAt) < to);
  // The store keeps the newest 2,000 events per organization. At that size the counts are a floor
  // and the week before is incomplete, so no comparison is offered.
  const capped = events.length >= 2000;
  return buildDefenseDigest(inside, {
    orgName: getOrganization(orgId)?.name || '',
    from,
    to,
    previousTotal: capped
      ? null
      : events.filter((event) => Number(event.createdAt) < from && event.cls !== 'repeat-offender').length,
    dashboardUrl: String(process.env.SHANNON_PUBLIC_URL || '').replace(/\/$/, ''),
    capped,
  });
}

export async function runDefenseDigests(now = Date.now()) {
  if (process.env.SHANNON_DEFENSE_DIGEST === '0') return { sent: 0, skipped: 'disabled' };
  if (process.env.NODE_ENV === 'production' && !process.env.RESEND_API_KEY && !process.env.SHANNON_EMAIL_WEBHOOK_URL) {
    return { sent: 0, skipped: 'email is not configured' };
  }
  const week = lastCompleteWeek(now);
  // From Monday 08:00 UTC, and never more than three days late — an old summary is noise.
  if (now < week.to + 8 * 3_600_000 || now > week.to + 3 * DAY)
    return { sent: 0, skipped: 'outside the sending window' };
  let sent = 0;
  for (const orgId of listDefenseEventOrgIds()) {
    const digest = defenseDigest(orgId, week);
    if (!digest) continue;
    for (const member of listMembers(orgId)) {
      if (!DIGEST_ROLES.has(member.role) || !member.email) continue;
      if (loadUsers()[member.userId]?.disabledAt) continue;
      const settings = loadUserSettings(member.userId);
      if (settings.defenseDigest === false) continue;
      if (settings.defenseDigestSent?.[orgId] === week.key) continue;
      // Marked before sending, and stored with the user's settings so it survives a restart: a
      // failure costs one missed summary, never the same summary twice.
      saveUserSettings(member.userId, {
        ...settings,
        defenseDigestSent: { ...(settings.defenseDigestSent || {}), [orgId]: week.key },
      });
      try {
        await dispatchEmail(
          { to: member.email, subject: digest.subject, text: digest.text, html: digest.html },
          { orgId, userId: member.userId },
        );
        sent += 1;
      } catch (error) {
        console.error('[defender] weekly summary email failed:', error.message);
      }
    }
  }
  return { sent, week: week.key };
}

app.get('/api/defender/digest', (req, res) => {
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  const now = Date.now();
  const digest = defenseDigest(ctx.org.id, { from: now - 7 * DAY, to: now });
  res.json({
    ok: true,
    enabled: loadUserSettings(ctx.user.id).defenseDigest !== false,
    eligible: DIGEST_ROLES.has(ctx.membership.role),
    digest: digest
      ? { subject: digest.subject, text: digest.text, totals: digest.totals, period: digest.period }
      : null,
  });
});

app.post('/api/defender/digest', (req, res) => {
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  const enabled = req.body?.enabled !== false;
  saveUserSettings(ctx.user.id, { ...loadUserSettings(ctx.user.id), defenseDigest: enabled });
  res.json({ ok: true, enabled });
});

app.post('/api/defender/digest/send', async (req, res) => {
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  if (limited(req, res, 'defense-digest-send', 3, 60 * 60_000)) return;
  const now = Date.now();
  const digest = defenseDigest(ctx.org.id, { from: now - 7 * DAY, to: now });
  if (!digest)
    return res.status(409).json({ error: 'No attacks were recorded in the last 7 days, so there is nothing to send.' });
  try {
    await dispatchEmail(
      { to: ctx.user.email, subject: digest.subject, text: digest.text, html: digest.html },
      { orgId: ctx.org.id, userId: ctx.user.id },
    );
  } catch (error) {
    return res
      .status(503)
      .json({ error: `The email could not be sent: ${String(error?.message || error).slice(0, 200)}` });
  }
  res.json({ ok: true, to: ctx.user.email });
});

// ---------- Guard: identity and cloud defence (Microsoft 365, Google Workspace) ----------
const GUARD_PROVIDERS = {
  microsoft: createMicrosoftProvider(),
  google: createGoogleProvider(),
  simulation: createSimulationProvider(),
};
const GUARD_STORE = {
  connections: guardConnections,
  incidents: guardIncidents,
  actions: guardActions,
  state: guardState,
  settings: guardSettings,
  listFindings: async (orgId) => listFindings(orgId),
  // The organization's own tests are not attacks on it, so Guard never sees them.
  listDefenseEventsSince: async (orgId, since) => listDefenseEventsSince(orgId, since).filter(notOwnTest),
  listVulnerabilityMatches: (orgId) => listVulnerabilityMatches(orgId),
};
export const guardEngine = createGuardEngine({
  store: GUARD_STORE,
  providers: GUARD_PROVIDERS,
  encrypt: encryptSecret,
  decrypt: decryptSecret,
  notify: (orgId, event) => queueIntegrationEvent(orgId, event),
  loadBadIps: () => loadBadIps(),
  publicUrl: () => String(process.env.SHANNON_PUBLIC_URL || '').replace(/\/$/, ''),
});
registerGuardRoutes(app, {
  requirePermission,
  audit,
  limited,
  engine: guardEngine,
  store: GUARD_STORE,
  providers: GUARD_PROVIDERS,
  encrypt: encryptSecret,
  decrypt: decryptSecret,
  aiKeysForRequest,
  runChat,
  describeAiError,
  renderMarkdown,
  can,
});

// Guard Phase 2: endpoint agents and the malware sandbox (CAPE, operator-hosted, optional).
export const guardEndpoints = createEndpointService({
  store: {
    agents: guardAgents,
    commands: guardCommands,
    samples: guardSamples,
    hashes: guardHashes,
    endpoint: guardEndpoint,
  },
  engine: guardEngine,
  cape: createCapeClient(),
  publicUrl: () => String(process.env.SHANNON_PUBLIC_URL || '').replace(/\/$/, ''),
});
guardEngine.attachAgents(guardEndpoints);
registerEndpointRoutes(app, {
  endpoints: guardEndpoints,
  engine: guardEngine,
  store: GUARD_STORE,
  requirePermission,
  audit,
  limited,
  can,
});

// Every few minutes: pull each organization's connections and check Defender traffic against
// open Shannon findings. One organization at a time, so a slow tenant cannot pile up syncs.
let guardCycleRunning = false;
export async function runGuardCycles() {
  if (process.env.SHANNON_GUARD_SYNC === '0' || guardCycleRunning) return { skipped: true };
  guardCycleRunning = true;
  const results = {};
  try {
    const connections = await guardConnections.list({}, { limit: 500 });
    const orgIds = new Set([
      ...connections.filter((c) => c.enabled !== false).map((c) => c.orgId),
      ...listDefenseEventOrgIds(),
    ]);
    for (const orgId of orgIds) {
      try {
        results[orgId] = await guardEngine.syncOrg(orgId);
      } catch (error) {
        console.error('[guard] sync failed:', error.message);
      }
    }
    try {
      results.endpoints = await guardEndpoints.cycle();
    } catch (error) {
      console.error('[guard] endpoint cycle failed:', error.message);
    }
  } finally {
    guardCycleRunning = false;
  }
  return results;
}

app.get('/api/defender/events', (req, res) => {
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  const severity = String(req.query.severity || '');
  const status = String(req.query.status || '');
  let events = listDefenseEvents(ctx.org.id, Number(req.query.limit) || 200);
  if (severity) events = events.filter((event) => event.severity === severity);
  if (status) events = events.filter((event) => event.status === status);
  res.json({ ok: true, events });
});

app.get('/api/defender/intelligence', async (req, res) => {
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  if (limited(req, res, `defender-intelligence:${ctx.org.id}`, 60, 5 * 60_000)) return;
  const query = String(req.query.q || '')
    .trim()
    .toLowerCase()
    .slice(0, 120);
  try {
    const catalog = await loadCisaKev();
    let matches = catalog.vulnerabilities;
    if (query) {
      matches = matches.filter((item) =>
        [item.cveId, item.vendor, item.product, item.name].some((value) => value.toLowerCase().includes(query)),
      );
    }
    res.json({
      ok: true,
      source: 'CISA Known Exploited Vulnerabilities',
      sourceUrl: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
      catalogVersion: catalog.catalogVersion,
      dateReleased: catalog.dateReleased,
      fetchedAt: new Date(catalog.fetchedAt).toISOString(),
      stale: catalog.stale === true,
      total: catalog.vulnerabilities.length,
      matchCount: matches.length,
      vulnerabilities: matches.slice(0, 20),
    });
  } catch (error) {
    res.status(503).json({
      error: 'Threat intelligence is temporarily unavailable.',
      detail: String(error?.message || error).slice(0, 200),
    });
  }
});

app.get('/api/defender/program', async (req, res) => {
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  const [stored, assets, cycles] = await Promise.all([
    getDefenseProgram(ctx.org.id),
    listDefenseAssets(ctx.org.id),
    listDefenseCycles(ctx.org.id, 20),
  ]);
  res.json({
    ok: true,
    program: stored || {
      orgId: ctx.org.id,
      enabled: false,
      cadenceHours: 24,
      responseMode: 'recommend',
      nextRunAt: null,
      lastRunAt: null,
      lastCycleId: null,
    },
    assets,
    cycles,
    safety: {
      automaticRuleChanges: false,
      note: 'Learning changes prioritization and recommendations only. Blocking requires an explicitly enforced Edge route or SDK policy.',
    },
  });
});

app.put('/api/defender/program', async (req, res) => {
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  const cadenceHours = Number(req.body?.cadenceHours || 24);
  if (!Number.isInteger(cadenceHours) || cadenceHours < 1 || cadenceHours > 168) {
    return res.status(400).json({ error: 'Cadence must be between 1 and 168 hours.' });
  }
  const program = await saveDefenseProgram({
    orgId: ctx.org.id,
    enabled: req.body?.enabled === true,
    cadenceHours,
    responseMode: req.body?.responseMode === 'bounded-auto' ? 'bounded-auto' : 'recommend',
    createdBy: ctx.user.id,
    nextRunAt: req.body?.enabled === true ? Date.now() : null,
  });
  audit(ctx, 'defender.program_updated', 'defense-program', ctx.org.id, {
    enabled: program.enabled,
    cadenceHours,
    responseMode: program.responseMode,
  });
  res.json({ ok: true, program });
});

app.post('/api/defender/program/run', async (req, res) => {
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  const program = await getDefenseProgram(ctx.org.id);
  const cycleId = `dcy_${randomUUID()}`;
  const job = await enqueueJob({
    orgId: ctx.org.id,
    userId: ctx.user.id,
    type: 'defense-cycle',
    payload: { cycleId, trigger: 'manual', responseMode: program?.responseMode || 'recommend' },
    idempotencyKey: `defense-cycle:manual:${cycleId}`,
    maxAttempts: 3,
  });
  audit(ctx, 'defender.cycle_requested', 'defense-cycle', cycleId, { jobId: job.id });
  res.status(202).json({ ok: true, cycleId, jobId: job.id });
});

app.post('/api/defender/assets', async (req, res) => {
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  const type = String(req.body?.type || '').toLowerCase();
  const allowedTypes = ['web', 'api', 'domain', 'cidr', 'cloud', 'repository', 'identity', 'endpoint'];
  if (!allowedTypes.includes(type)) return res.status(400).json({ error: 'Choose a valid asset type.' });
  let locator = String(req.body?.locator || '')
    .trim()
    .slice(0, 500);
  if (!locator) return res.status(400).json({ error: 'Asset locator is required.' });
  if (['web', 'api', 'domain'].includes(type)) {
    const host = hostOf(locator);
    if (!host) return res.status(400).json({ error: 'Provide a valid domain or URL.' });
    if (!localExempt(host) && !isVerified(ctx.user.id, host))
      return res
        .status(403)
        .json({ error: 'Verify ownership of this domain before adding it to continuous defense.', host });
    locator = type === 'domain' ? host : locator;
  }
  if (type === 'cidr') {
    if (!parseCidr(locator)) return res.status(400).json({ error: 'Provide a valid IPv4 CIDR range.' });
    if (!Object.hasOwn(listCidrs(ctx.user.id), locator))
      return res.status(403).json({ error: 'Verify control of this IP range before adding it.' });
  }
  const criticality = ['low', 'medium', 'high', 'critical'].includes(req.body?.criticality)
    ? req.body.criticality
    : 'medium';
  const projectId = req.body?.projectId ? String(req.body.projectId) : null;
  if (projectId && !listProjects(ctx.org.id).some((project) => project.id === projectId)) {
    return res.status(400).json({ error: 'Choose a project from the active organization.' });
  }
  const asset = await saveDefenseAsset({
    orgId: ctx.org.id,
    projectId,
    type,
    locator,
    criticality,
    name: sanitizeLabel(req.body?.name || locator, 100) || locator.slice(0, 100),
    status: 'active',
    coverage: 'inventory',
    createdBy: ctx.user.id,
    config: { sensorRequired: !['web', 'api', 'domain'].includes(type) },
  });
  audit(ctx, 'defender.asset_added', 'defense-asset', asset.id, { type, locator, criticality });
  res.status(201).json({
    ok: true,
    asset,
    protected: asset.coverage === 'online',
    nextStep: ['web', 'api', 'domain'].includes(type)
      ? 'Add an Edge route or install the Defender SDK.'
      : 'Install or connect a supported sensor; inventory alone does not inspect this asset.',
  });
});

app.delete('/api/defender/assets/:id', async (req, res) => {
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  const existing = (await listDefenseAssets(ctx.org.id)).find((item) => item.id === req.params.id);
  if (!existing) return res.status(404).json({ error: 'Asset not found.' });
  await deleteDefenseAsset(ctx.org.id, existing.id);
  audit(ctx, 'defender.asset_removed', 'defense-asset', existing.id, {
    type: existing.type,
    locator: existing.locator,
  });
  res.json({ ok: true });
});

app.patch('/api/defender/events/:id', (req, res) => {
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  const status = String(req.body?.status || '');
  if (!['open', 'investigating', 'contained', 'closed', 'false-positive'].includes(status)) {
    return res.status(400).json({ error: 'Choose a valid incident status.' });
  }
  const current = listDefenseEvents(ctx.org.id, 500).find((event) => event.id === req.params.id);
  if (!current) return res.status(404).json({ error: 'Defense incident not found.' });
  const previousStatus = current.status;
  const event = updateDefenseEvent(ctx.org.id, current.id, {
    status,
    metadata: { ...(current.metadata || {}), statusChangedAt: Date.now(), statusChangedBy: ctx.user.id },
  });
  audit(ctx, 'defender.incident_status_changed', 'defense-event', event.id, { from: previousStatus, to: status });
  queueIntegrationEvent(
    ctx.org.id,
    {
      id: `defender-status:${event.id}:${status}`,
      type: 'defender.incident.updated',
      at: new Date().toISOString(),
      data: event,
    },
    ctx.user.id,
  ).catch((error) => console.error('[defender] incident integration event failed:', error.message));
  res.json({ ok: true, event });
});

// ── Edge routes (consumed by packages/defender-edge) ────────────────────────────────────────────
// Durable hostname → origin mappings for the public multi-tenant proxy. The edge can pull this list
// with a scoped SDK credential and keeps its last valid routes if the dashboard becomes unavailable.

const EDGE_HEARTBEATS = new Map();

function edgePlatformAuthorized(req) {
  const configured = String(process.env.SHANNON_EDGE_PLATFORM_TOKEN || '');
  const supplied = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  return (
    configured.length >= 32 &&
    supplied.length === configured.length &&
    _crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(configured))
  );
}

function recordEdgeHeartbeat(req, orgId, routeCount) {
  if (Date.now() - Number(EDGE_HEARTBEATS.get(orgId) || 0) <= 60_000) return;
  EDGE_HEARTBEATS.set(orgId, Date.now());
  appendOperationalEvent({
    service: 'edge',
    instanceId: String(req.headers['x-shannon-edge-instance'] || req.headers['user-agent'] || 'edge').slice(0, 160),
    level: 'info',
    event: 'edge.heartbeat',
    orgId,
    metadata: { routes: routeCount },
    createdAt: Date.now(),
  }).catch(() => {});
}

// The shared edge uses one platform credential to fetch every tenant route. Organization identity
// is derived from the stored hostname mapping, never trusted from edge-supplied telemetry.
app.get('/api/platform/defender/edge/routes', (req, res) => {
  if (!edgePlatformAuthorized(req)) return res.status(401).json({ error: 'invalid edge platform token' });
  const list = listEdgeRoutes().map((v) => ({ host: v.host, origin: v.origin, mode: v.mode, createdAt: v.createdAt }));
  const counts = new Map();
  for (const route of listEdgeRoutes()) counts.set(route.orgId, (counts.get(route.orgId) || 0) + 1);
  for (const [orgId, count] of counts) recordEdgeHeartbeat(req, orgId, count);
  res.json({ routes: list });
});

app.post('/api/platform/defender/edge/report', (req, res) => {
  if (!edgePlatformAuthorized(req)) return res.status(401).json({ error: 'invalid edge platform token' });
  const routesByHost = new Map(listEdgeRoutes().map((route) => [route.host, route]));
  const incoming = Array.isArray(req.body?.detections) ? req.body.detections : [];
  let accepted = 0;
  // The edge sends up to 500 detections at a time, for every organization it serves.
  for (const raw of incoming.slice(0, 500)) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) continue;
    const host = (typeof raw.host === 'string' ? raw.host : '').toLowerCase().split(':')[0];
    const route = routesByHost.get(host);
    if (!route) continue;
    const d = cleanDetection(raw);
    const own = ownTestOf(route.orgId, raw, host);
    if (own) {
      OWN_TESTS.record({
        orgId: route.orgId,
        userId: route.userId,
        source: 'edge',
        token: raw.test,
        kind: own.kind,
        site: host,
        detection: d,
        metadata: { host },
      });
      accepted += 1;
      continue;
    }
    if (
      storeDetection({
        orgId: route.orgId,
        userId: route.userId,
        source: 'edge',
        site: host,
        detection: d,
        metadata: { host },
      })
    )
      accepted += 1;
  }
  res.json({ accepted });
});

// A customer-operated collector uses the same revocable organization SDK key to prove liveness.
// Heartbeats never grant scanning scope; they only show that an explicitly inventoried asset has a
// currently connected sensor. Coverage expires in the daily model when heartbeats stop.
app.post('/api/defender/sensors/heartbeat', async (req, res) => {
  if (limited(req, res, 'defender-sensor-heartbeat', 600, 5 * 60_000)) return;
  const principal = verifyDefenderKey((req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
  if (!principal) return res.status(401).json({ error: 'invalid api key' });
  const assetId = String(req.body?.assetId || '');
  const asset = (await listDefenseAssets(principal.orgId)).find((item) => item.id === assetId);
  if (!asset) return res.status(404).json({ error: 'asset not found in this organization' });
  const at = Date.now();
  const updated = await updateDefenseAsset(principal.orgId, asset.id, {
    coverage: 'online',
    config: {
      ...(asset.config || {}),
      lastSeenAt: at,
      sensorType: sanitizeLabel(req.body?.sensorType || 'collector', 60),
      sensorVersion: sanitizeLabel(req.body?.sensorVersion || '', 40),
    },
  });
  res.json({ ok: true, assetId: updated.id, coverage: 'online', lastSeenAt: at, heartbeatWithinMs: 15 * 60_000 });
});

app.get('/api/defender/edge/routes', (req, res) => {
  const principal = verifyDefenderKey((req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
  const ctx = principal ? null : requirePermission(req, res, 'defender.manage');
  if (!principal && !ctx) return;
  const orgId = principal?.orgId || ctx.org.id;
  const list = listEdgeRoutes({ orgId }).map((v) => ({
    host: v.host,
    origin: v.origin,
    mode: v.mode,
    createdAt: v.createdAt,
  }));
  if (principal && Date.now() - Number(EDGE_HEARTBEATS.get(orgId) || 0) > 60_000) {
    recordEdgeHeartbeat(req, orgId, list.length);
  }
  res.json({ routes: list });
});

app.post('/api/defender/edge/routes', async (req, res) => {
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  const user = ctx.user;
  const { host, origin, mode } = req.body || {};
  if (!host || !origin) return res.status(400).json({ error: 'host and origin are required' });

  let parsed;
  try {
    parsed = new URL(origin);
  } catch {
    return res.status(400).json({ error: 'invalid origin URL — include the scheme, e.g. https://origin.example.com' });
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return res.status(400).json({ error: 'origin must be an http(s) URL' });
  }

  // Same gate as everything else: you may not put a blocking proxy in front of a host you have not
  // proven you own, and you may not point one at an origin you do not own either.
  const h = hostOf(String(host));
  if (!h) return res.status(400).json({ error: 'invalid public hostname' });
  if (!localExempt(h) && !isVerified(user.id, h)) {
    return res.status(403).json({ error: 'needsVerification', host: h });
  }
  if (!isVerified(user.id, parsed.hostname)) {
    return res.status(403).json({ error: 'originNeedsVerification', host: parsed.hostname });
  }
  if (!(await publicOriginAllowed(parsed))) {
    return res.status(400).json({ error: 'origin must resolve only to public IP addresses' });
  }

  const occupied = listEdgeRoutes().find((item) => item.host === h && item.orgId !== ctx.org.id);
  if (occupied)
    return res.status(409).json({ error: 'This public hostname is already assigned to another organization.' });

  const route = {
    host: h,
    origin,
    mode: mode === 'enforce' ? 'enforce' : 'monitor',
    userId: user.id,
    orgId: ctx.org.id,
    createdAt: Date.now(),
  };
  saveEdgeRoute(route);
  audit(ctx, 'defender.edge_route_created', 'edge-route', h, { origin: parsed.origin, mode });
  res.json({ host: h, origin, mode: mode === 'enforce' ? 'enforce' : 'monitor' });
});

app.delete('/api/defender/edge/routes/:host', (req, res) => {
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  const user = ctx.user;
  const h = String(req.params.host || '').toLowerCase();
  const cur = listEdgeRoutes({ orgId: ctx.org.id }).find((r) => r.host === h);
  if (!cur) return res.status(404).json({ error: 'not found' });
  removeEdgeRoute(h, ctx.org.id);
  audit(ctx, 'defender.edge_route_removed', 'edge-route', h);
  res.json({ ok: true });
});

// ── Live Defender ───────────────────────────────────────────────────────────────────────────────
// A connected system is protected inline by a filtering reverse proxy. Ownership verification is
// mandatory (you may not point a blocker at a host you do not own) and monitor mode is the default.
const defenders = new Map(); // id -> { system, runtime, sseClients, events }
// Each connected defender holds an open listening socket for the process lifetime, so connects
// are capped per user and a second defender for the same origin is refused outright.
const MAX_DEFENDERS_PER_USER = 5;
const DEF_REPLAY = 50; // events replayed to a new SSE client so the feed is not blank on connect

function localDefenderUnavailable(req, res) {
  if (process.env.NODE_ENV !== 'production' && process.env.SHANNON_ENABLE_LOCAL_DEFENDER === '1') return false;
  res
    .status(404)
    .json({ error: 'Local diagnostic Defender is disabled in production. Use Edge routes or the organization SDK.' });
  return true;
}

function defBroadcast(entry, payload) {
  const line = `data: ${JSON.stringify(payload)}\n\n`;
  for (const c of entry.sseClients) {
    try {
      c.write(line);
    } catch {}
  }
}

app.post('/api/defender/connect', async (req, res) => {
  if (localDefenderUnavailable(req, res)) return;
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  const user = ctx.user;

  const { origin } = req.body || {};
  if (!origin) return res.status(400).json({ error: 'origin required' });

  let host;
  try {
    host = hostOf(origin);
  } catch {
    return res.status(400).json({ error: 'invalid origin URL' });
  }

  // hostOf() tolerates a schemeless origin by internally guessing https://, but httpProxyConnector
  // parses the raw origin with `new URL(origin)` and needs an explicit, real http(s) scheme — never
  // guess one here, since guessing would proxy to an endpoint the user did not actually choose.
  let parsed;
  try {
    parsed = new URL(origin);
  } catch {
    return res.status(400).json({ error: 'invalid origin URL — include the scheme, e.g. https://app.example.com' });
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return res.status(400).json({ error: 'origin must be an http(s) URL' });
  }

  if (!isLocalHost(host) && !(await publicOriginAllowed(parsed))) {
    return res.status(400).json({ error: 'origin must resolve only to public IP addresses' });
  }
  if (isLocalHost(host) && process.env.NODE_ENV === 'production') {
    return res.status(400).json({ error: 'local origins are disabled in production' });
  }

  if (!localExempt(host) && !isVerified(user.id, host)) {
    return res.status(403).json({ error: 'needsVerification', host });
  }

  const mine = [...defenders.values()].filter((e) => e.system.userId === user.id);
  if (mine.length >= MAX_DEFENDERS_PER_USER) {
    return res.status(409).json({
      error: `you already have ${mine.length} connected defenders (limit ${MAX_DEFENDERS_PER_USER}) — disconnect one first`,
    });
  }
  const dupe = mine.some((e) => {
    try {
      return new URL(e.system.origin).origin === parsed.origin;
    } catch {
      return false;
    }
  });
  if (dupe) {
    return res.status(409).json({ error: 'that origin already has a defender connected — disconnect it first' });
  }

  const id = `def-${Math.random().toString(16).slice(2, 10)}`;
  const system = {
    id,
    userId: user.id,
    orgId: ctx.org.id,
    kind: 'web',
    origin,
    mode: 'monitor',
    createdAt: new Date().toISOString(),
  };
  const entry = { system, runtime: null, sseClients: [], events: [] };
  defenders.set(id, entry);

  let runtime;
  try {
    runtime = await runDefender({
      connect: ({ onEvent }) => httpProxyConnector({ origin, onEvent }),
      mode: 'monitor',
      deps: {},
      onUpdate: (d) => {
        entry.events.push(d);
        if (entry.events.length > 500) entry.events.shift();
        defBroadcast(entry, { type: 'defense', ...d });
      },
    });
  } catch (err) {
    defenders.delete(id);
    return res.status(500).json({ error: 'failed to start defender', detail: String(err?.message || err) });
  }
  entry.runtime = runtime;

  audit(ctx, 'defender.connected', 'defender', id, { origin: parsed.origin });
  res.json({ id, mode: 'monitor', proxyUrl: runtime.meta.url, origin, graph: runtime.graph });
});

app.get('/api/defender/list', (req, res) => {
  if (localDefenderUnavailable(req, res)) return;
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  const rows = [...defenders.values()]
    .filter((e) => e.system.orgId === ctx.org.id)
    .map((e) => ({
      ...e.system,
      proxyUrl: e.runtime?.meta?.url || null,
      stats: e.runtime?.stats?.() || { events: 0, defenses: 0 },
    }));
  res.json({ systems: rows });
});

app.get('/api/defender/overview', (req, res) => {
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  // The numbers and the incident list are attacks. The organization's own tests (one entry per
  // run) are summed up apart, so they never crowd an attack out of view.
  const all = listDefenseEvents(ctx.org.id, 500);
  const events = all.filter(notOwnTest);
  const own = all.filter(isOwnTest);
  const routes = listEdgeRoutes({ orgId: ctx.org.id });
  const systems = [...defenders.values()]
    .filter((entry) => entry.system.orgId === ctx.org.id)
    .map((entry) => ({
      ...entry.system,
      proxyUrl: entry.runtime?.meta?.url || null,
      stats: entry.runtime?.stats?.() || { events: 0, defenses: 0 },
    }));
  const since = Date.now() - 24 * 60 * 60_000;
  const last24h = events.filter((event) => Number(event.createdAt || new Date(event.at).getTime()) >= since);
  const classes = {};
  for (const event of events) classes[event.cls || 'unknown'] = (classes[event.cls || 'unknown'] || 0) + 1;
  res.json({
    ok: true,
    stats: {
      total: events.length,
      last24h: last24h.length,
      blocked: events.filter((event) => event.enforced).length,
      open: events.filter((event) => ['open', 'investigating'].includes(event.status || 'open')).length,
      critical: events.filter(
        (event) => event.severity === 'critical' && ['open', 'investigating'].includes(event.status || 'open'),
      ).length,
      edgeRoutes: routes.length,
      enforcingRoutes: routes.filter((route) => route.mode === 'enforce').length,
      connectedSystems: systems.length,
      protectedAssets:
        routes.filter((route) => route.mode === 'enforce').length +
        systems.filter((system) => system.mode === 'enforce').length,
    },
    topClasses: Object.entries(classes)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([name, count]) => ({ name, count })),
    events: events.slice(0, 100),
    ownTests: {
      runs: own.length,
      runs24h: own.filter((event) => Number(event.createdAt) >= since).length,
      requests: own.reduce((sum, event) => sum + Number(event.metadata.ownTest.requests || 0), 0),
      blocked: own.reduce((sum, event) => sum + Number(event.metadata.ownTest.blocked || 0), 0),
      lastAt: own[0]?.at || null,
      recent: own.slice(0, 20),
    },
    routes,
    systems,
  });
});

app.post('/api/defender/:id/mode', (req, res) => {
  if (localDefenderUnavailable(req, res)) return;
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  const user = ctx.user;
  const entry = defenders.get(req.params.id);
  if (!entry || entry.system.userId !== user.id || entry.system.orgId !== ctx.org.id)
    return res.status(404).json({ error: 'not found' });
  if (!entry.runtime) return res.status(409).json({ error: 'defender not running' });
  const mode = entry.runtime.setMode(req.body?.mode);
  entry.system.mode = mode;
  audit(ctx, 'defender.mode_changed', 'defender', entry.system.id, { mode });
  defBroadcast(entry, { type: 'mode', mode });
  res.json({ id: entry.system.id, mode });
});

app.post('/api/defender/:id/disconnect', async (req, res) => {
  if (localDefenderUnavailable(req, res)) return;
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  const user = ctx.user;
  const entry = defenders.get(req.params.id);
  if (!entry || entry.system.userId !== user.id || entry.system.orgId !== ctx.org.id)
    return res.status(404).json({ error: 'not found' });
  try {
    await entry.runtime?.stop?.();
  } catch {}
  for (const c of entry.sseClients) {
    try {
      c.end();
    } catch {}
  }
  entry.sseClients.length = 0;
  defenders.delete(req.params.id);
  audit(ctx, 'defender.disconnected', 'defender', req.params.id);
  res.json({ ok: true });
});

app.get('/api/defender/:id/events', (req, res) => {
  if (localDefenderUnavailable(req, res)) return;
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  const entry = defenders.get(req.params.id);
  if (!entry || entry.system.userId !== ctx.user.id || entry.system.orgId !== ctx.org.id) return res.status(404).end();
  res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive' });
  const stats = entry.runtime?.stats?.() || { events: 0, defenses: 0 };
  res.write(`data: ${JSON.stringify({ type: 'hello', mode: entry.system.mode, stats })}\n\n`);
  // Replay recent defenses so a client that connects between attacks sees history, not a blank feed.
  for (const d of entry.events.slice(-DEF_REPLAY)) {
    try {
      res.write(`data: ${JSON.stringify({ type: 'defense', replay: true, ...d })}\n\n`);
    } catch {}
  }
  entry.sseClients.push(res);
  req.on('close', () => {
    const i = entry.sseClients.indexOf(res);
    if (i >= 0) entry.sseClients.splice(i, 1);
  });
});

export async function startDashboard({ port = PORT, scheduleMonitors = true } = {}) {
  try {
    await initDb();
  } catch (e) {
    console.error('FATAL: db init failed.', e.message);
    throw e;
  }
  const server = await new Promise((resolveServer, reject) => {
    const candidate = app.listen(port, (error) => {
      if (error) return reject(error);
      const address = candidate.address();
      const boundPort = address && typeof address === 'object' ? address.port : port;
      console.log(`\n  Securovix Dashboard running at http://localhost:${boundPort}\n`);
      resolveServer(candidate);
    });
    candidate.once('error', reject);
  });
  if (scheduleMonitors) {
    // Continuous monitoring: check for due monitors shortly after boot, then every 10 minutes.
    setTimeout(runDueMonitors, 30_000).unref?.();
    setInterval(runDueMonitors, 10 * 60 * 1000).unref?.();
    // Weekly attack summary: checked hourly, sends once per person per week (see runDefenseDigests).
    const digests = () =>
      runDefenseDigests().catch((error) => console.error('[defender] weekly summary failed:', error.message));
    setTimeout(digests, 60_000).unref?.();
    setInterval(digests, 60 * 60 * 1000).unref?.();
    // Guard: identity and cloud sync, every 2 minutes by default.
    const guardCycle = () => runGuardCycles().catch((error) => console.error('[guard] cycle failed:', error.message));
    setTimeout(guardCycle, 45_000).unref?.();
    setInterval(guardCycle, Math.max(60_000, Number(process.env.SHANNON_GUARD_INTERVAL_MS) || 120_000)).unref?.();
  }
  return server;
}

export { app, withEngine, runDueMonitors };

if (process.argv[1] && resolve(process.argv[1]) === __filename) {
  startDashboard().catch(() => process.exit(1));
}
