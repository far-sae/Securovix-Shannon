import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import _crypto from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import Anthropic from '@anthropic-ai/sdk';
import express from 'express';
import QRCode from 'qrcode';
import { parse as parseYaml } from 'yaml';
import { crawl } from '../../crawler.mjs';
import { runDefender } from '../../defender/agent.mjs';
import { httpProxyConnector } from '../../defender/connectors.mjs';
import { cmdContext, sqliExtract, ssrfMetadata } from '../../impact.mjs';
import { checkIpControl, ipInCidr, ipVerifyToken, parseCidr, verificationInstructions } from '../../ip-ownership.mjs';
import { sendMonitorAlert } from '../../monitor.mjs';
import {
  PROBERS,
  detectionRule,
  fetchT,
  injReq,
  login,
  setScanOrigin,
  setSessionHeaders,
} from '../../purple-engine.mjs';
import { createSelfDefense } from '../../defender/middleware.mjs';
import { diffRuns } from './agent-history.mjs';
import { runAgentCampaign, runAgentLoop } from './agent-loop.mjs';
import { runSecurityTeam } from './agent-team.mjs';
import { toJson, toMarkdown, toSarif } from './agent-report.mjs';
import { analyzeSurface } from './agent-understand.mjs';
import { locateFinding } from './code-locate.mjs';
import { evaluateMatcher, sanitizeCheck } from './custom-check.mjs';
import { analyzePersonalThreat } from './personal-shield.mjs';
import {
  appendDefenseEvent,
  appendAudit,
  addVerified,
  allMonitors,
  createOrganization,
  getFinding,
  getMembership,
  getOrganization,
  getAgentRun,
  getScanOwner,
  initDb,
  isSupabase,
  listAudit,
  listDefenseEvents,
  listEdgeRoutes,
  listAgentRuns,
  listFindings,
  listMembers,
  listMonitors,
  listOrganizations,
  listProjects,
  loadUserSettings,
  loadLeaderboard,
  loadUsers,
  loadVerified,
  removeMembership,
  removeEdgeRoute,
  removeMonitor,
  removeVerified,
  refreshDbIfStale,
  saveAgentRun,
  saveFinding,
  saveEdgeRoute,
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
import { openPullRequest } from './github-pr.mjs';
import { gatherLeads } from './leads.mjs';
import { diffToDelta, dueMonitors } from './monitor-schedule.mjs';
import { applyLineFix, generatePatch } from './patch.mjs';
import { runInSandbox, sandboxAvailable } from './sandbox.mjs';
import {
  appendOperationalEvent,
  consumeScanAuthGrant,
  consumeUsage,
  consumeAuthToken,
  createScanAuthGrant,
  createAuthToken,
  deleteOrgSecret,
  deleteDefenseAsset,
  deleteIntegration,
  enqueueJob,
  enterpriseHealth,
  findAuthToken,
  findSsoIdentity,
  getJob,
  getIntegration,
  getEntitlement,
  getDefenseProgram,
  getOrgSecret,
  listArtifacts,
  listDeliveries,
  listDefenseAssets,
  listDefenseCycles,
  listIntegrations,
  listJobs,
  listUsage,
  listOperationalEvents,
  listOrgSecrets,
  readArtifact,
  saveIntegration,
  saveEntitlement,
  saveDefenseAsset,
  saveDefenseProgram,
  saveOrgSecret,
  saveSsoIdentity,
  signedArtifactUrl,
  updateDefenseAsset,
  updateJob,
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
import {
  ROLES,
  can,
  canChangeMember,
  sanitizeLabel,
  slugifyOrg,
  validateFindingTransition,
} from './team-access.mjs';

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
app.use(express.json({
  limit: '2mb',
  verify(req, _res, buffer) {
    if (req.originalUrl === '/api/billing/webhook') req.rawBody = Buffer.from(buffer);
  },
}));
app.use((req, res, next) => {
  res.setHeader('x-content-type-options', 'nosniff');
  res.setHeader('x-frame-options', 'DENY');
  res.setHeader('referrer-policy', 'strict-origin-when-cross-origin');
  res.setHeader('permissions-policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('cross-origin-opener-policy', 'same-origin');
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
const SELF_DEFENSE = process.env.SHANNON_DEFEND_SELF === '1'
  ? createSelfDefense({ mode: process.env.SHANNON_DEFEND_SELF_MODE === 'enforce' ? 'enforce' : 'monitor' })
  : null;
if (SELF_DEFENSE) {
  app.use(SELF_DEFENSE.middleware);
  console.log(`[defender] self-defense active in ${SELF_DEFENSE.getMode()} mode`);
}

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
    throw new Error('SHANNON_SESSION_SECRET is required in production; use an independent random value of at least 32 bytes');
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
  plan: 'pro', label: 'Pro',
  pricing: { monthly: Number(process.env.SHANNON_PRO_MONTHLY_GBP || 99), yearly: Number(process.env.SHANNON_PRO_YEARLY_GBP || 990), currency: 'GBP' },
  features: ['Everything in Free', 'Higher organization limits', 'SSO and SCIM', 'Priority operations support'],
  limits: PRO_LIMITS,
};

function billingEnabled() {
  return !!(process.env.STRIPE_SECRET_KEY && process.env.STRIPE_WEBHOOK_SECRET && process.env.STRIPE_PRO_MONTHLY_PRICE_ID);
}

async function organizationPlan(orgId) {
  const entitlement = await getEntitlement(orgId);
  const paid = entitlement?.plan === 'pro' && ['active', 'trialing'].includes(entitlement.status)
    && (!entitlement.currentPeriodEnd || entitlement.currentPeriodEnd > Date.now());
  return { plan: paid ? 'pro' : 'free', limits: paid ? { ...PRO_LIMITS, ...(entitlement.limits || {}) } : FREE_LIMITS, entitlement };
}

async function consumeOrgQuota(ctx, res, metric, amount = 1) {
  const current = await organizationPlan(ctx.org.id);
  const limit = Number(current.limits[metric] || 0);
  const usage = await consumeUsage(ctx.org.id, metric, amount, limit);
  res.setHeader('x-shannon-limit', String(limit));
  res.setHeader('x-shannon-remaining', String(Math.max(0, limit - usage.used)));
  if (usage.allowed) return true;
  res.status(429).json({ error: `Daily organization limit reached for ${metric}.`, code: 'ORG_USAGE_LIMIT', metric, used: usage.used, limit, plan: current.plan, upgradeAvailable: billingEnabled() });
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
if (process.env.NODE_ENV === 'production' && (String(process.env.SHANNON_SESSION_SECRET).length < 32 || /replace-me|change-me/i.test(process.env.SHANNON_SESSION_SECRET))) {
  throw new Error('SHANNON_SESSION_SECRET must be a non-placeholder value of at least 32 characters');
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
  if (!user || (!allowed.includes(user.email.toLowerCase()) && !(process.env.NODE_ENV !== 'production' && csIsLocalhost(req)))) {
    res.status(403).json({ error: 'Platform operator permission required.' });
    return null;
  }
  return user;
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
]);
app.use('/api', async (req, res, next) => {
  try {
    await refreshDbIfStale(Number(process.env.SHANNON_CACHE_REFRESH_MS || 5000));
  } catch (error) {
    return res.status(503).json({ error: `Database refresh failed: ${error.message}` });
  }
  const relative = req.path;
  const bearerRoute =
    req.headers.authorization &&
    (relative === '/defender/report'
      || relative === '/defender/sensors/heartbeat'
      || (relative === '/defender/edge/routes' && req.method === 'GET')
      || relative === '/platform/defender/edge/routes'
      || relative === '/platform/defender/edge/report');
  if (PUBLIC_API.has(relative) || bearerRoute) return next();
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'Authentication required.' });
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

async function issueAuthToken(req, {
  kind,
  email,
  userId = null,
  orgId = null,
  role = null,
  createdBy = null,
  ttlMs,
  linkPath,
  subject,
  message,
}) {
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
      ip: (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '').toString().split(',')[0].trim(),
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
  const verificationRequired = process.env.SHANNON_REQUIRE_EMAIL_VERIFICATION === '1';
  if (!verificationRequired) setSessionCookie(res, id);
  res.status(verificationRequired ? 202 : 200).json({
    ok: true,
    verificationRequired,
    user: publicUser(users[id]),
    organizations: listOrganizations(id),
    ...(process.env.NODE_ENV !== 'production' && verification ? { developmentToken: verification.token } : {}),
  });
});

app.post('/api/auth/login', (req, res) => {
  if (limited(req, res, 'login', 10, 15 * 60 * 1000)) return;
  const email = String(req.body?.email || '')
    .trim()
    .toLowerCase();
  const password = String(req.body?.password || '');
  const u = findUserByEmail(email);
  if (!u || !u.passwordHash || !verifyPassword(password, u.passwordHash, u.salt)) {
    return res.status(401).json({ error: 'Wrong email or password.' });
  }
  if (u.disabledAt) return res.status(403).json({ error: 'This account is disabled.' });
  if (process.env.SHANNON_REQUIRE_EMAIL_VERIFICATION === '1' && !u.emailVerifiedAt) {
    return res.status(403).json({ error: 'Verify your email before signing in.', emailVerificationRequired: true });
  }
  if (u.mfaEnabled) {
    return res.json({ ok: true, mfaRequired: true, challenge: signChallenge({ uid: u.id }, 'mfa-login') });
  }
  setSessionCookie(res, u.id);
  res.json({ ok: true, user: publicUser(u) });
});

app.post('/api/auth/mfa/login', async (req, res) => {
  if (limited(req, res, 'mfa-login', 10, 15 * 60 * 1000)) return;
  const challenge = verifyChallenge(req.body?.challenge, 'mfa-login');
  const user = challenge ? loadUsers()[challenge.uid] : null;
  if (!user || !user.mfaEnabled || user.disabledAt) return res.status(401).json({ error: 'Invalid MFA challenge.' });
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
  if (!verified) return res.status(401).json({ error: 'Invalid authentication code.' });
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
  setSessionCookie(res, user.id);
  res.json({ ok: true, user: publicUser(user) });
});

app.post('/api/auth/email/resend', async (req, res) => {
  if (limited(req, res, 'email-resend', 5, 60 * 60_000)) return;
  const email = String(req.body?.email || '').trim().toLowerCase();
  const user = findUserByEmail(email);
  let verification = null;
  if (user && !user.emailVerifiedAt && !user.disabledAt) {
    try {
      verification = await issueAuthToken(req, {
        kind: 'email-verification', email, ttlMs: 24 * 60 * 60_000,
        linkPath: '/?verify=', subject: 'Verify your Securovix Shannon email',
        message: 'Verify your email address to activate your security workspace.',
      });
    } catch (error) {
      console.error('[auth] verification email failed:', error.message);
    }
  }
  res.json({
    ok: true,
    message: 'If that account requires verification, a new link has been sent.',
    ...(process.env.NODE_ENV !== 'production' && verification ? { developmentToken: verification.token } : {}),
  });
});

app.post('/api/auth/password/request', async (req, res) => {
  if (limited(req, res, 'password-reset', 5, 60 * 60_000)) return;
  const email = String(req.body?.email || '').trim().toLowerCase();
  const user = findUserByEmail(email);
  let reset = null;
  if (user && !user.disabledAt) {
    try {
      reset = await issueAuthToken(req, {
        kind: 'password-reset', email, userId: user.id, ttlMs: 30 * 60_000,
        linkPath: '/?reset=', subject: 'Reset your Securovix Shannon password',
        message: 'Use this one-time link to reset your password. It expires in 30 minutes.',
      });
    } catch (error) {
      console.error('[auth] password reset email failed:', error.message);
    }
  }
  res.json({
    ok: true,
    message: 'If an account exists for that email, a reset link has been sent.',
    ...(process.env.NODE_ENV !== 'production' && reset ? { developmentToken: reset.token } : {}),
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
  setSessionCookie(res, user.id);
  res.json({ ok: true, user: publicUser(user) });
});

app.post('/api/auth/invitations/accept', async (req, res) => {
  const password = String(req.body?.password || '');
  const tokenHash = hashToken(req.body?.token);
  const preview = await findAuthToken(tokenHash, 'invitation');
  if (preview && !findUserByEmail(preview.email)) {
    if (password.length < 12) return res.status(400).json({ error: 'Choose a password with at least 12 characters.' });
    if (!req.body?.acceptedTerms) return res.status(400).json({ error: 'You must accept the Terms and Privacy Policy.' });
  }
  const record = await consumeAuthToken(tokenHash, 'invitation');
  if (!record || !record.orgId || !ROLES.includes(record.role) || record.role === 'owner') {
    return res.status(400).json({ error: 'This invitation is invalid or expired.' });
  }
  let user = findUserByEmail(record.email);
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
    id: randomUUID(), orgId: record.orgId, actorUserId: user.id,
    action: 'invitation.accepted', resourceType: 'membership', resourceId: user.id,
    metadata: { role: record.role }, createdAt: Date.now(),
  });
  setSessionCookie(res, user.id);
  res.json({ ok: true, user: publicUser(user), organization: getOrganization(record.orgId) });
});

app.get('/api/auth/mfa/status', (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'Authentication required.' });
  let enrollment = null;
  try { enrollment = decryptSecret(user.mfaSecretEnc); } catch {}
  const pending = !!(!user.mfaEnabled && enrollment?.pending && Date.now() - Number(enrollment.createdAt || 0) < 15 * 60_000);
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
  try { enrollment = decryptSecret(user.mfaSecretEnc); } catch {}
  if (!enrollment?.pending || Date.now() - Number(enrollment.createdAt || 0) >= 15 * 60_000) {
    user.mfaSecretEnc = null;
    saveUsers(loadUsers());
    await waitForUserWrites();
    return res.status(400).json({ error: 'MFA enrollment expired. Start again to create a new QR code.' });
  }
  const secret = enrollment.secret;
  if (!secret || !verifyTotp(secret, req.body?.code)) return res.status(400).json({ error: 'Invalid authentication code.' });
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
  try { secret = decryptSecret(user.mfaSecretEnc)?.secret; } catch {}
  if (!secret || !verifyTotp(secret, req.body?.code)) return res.status(400).json({ error: 'Invalid authentication code.' });
  const recoveryCodes = createRecoveryCodes();
  user.mfaRecoveryCodes = hashRecoveryCodes(recoveryCodes);
  user.sessionInvalidBefore = Date.now();
  saveUsers(loadUsers());
  await waitForUserWrites();
  setSessionCookie(res, user.id);
  const ctx = requestContext(req);
  if (ctx) audit(ctx, 'authentication.mfa_recovery_codes_regenerated', 'user', user.id, { recoveryCodes: recoveryCodes.length });
  res.json({ ok: true, recoveryCodes, recoveryCodesRemaining: recoveryCodes.length });
});

app.delete('/api/auth/mfa', async (req, res) => {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'Authentication required.' });
  if (limited(req, res, `mfa-disable:${user.id}`, 6, 15 * 60 * 1000)) return;
  if (!user.mfaEnabled) return res.status(409).json({ error: 'MFA is not enabled.' });
  let secret;
  try { secret = decryptSecret(user.mfaSecretEnc)?.secret; } catch {}
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
  const url =
    'https://accounts.google.com/o/oauth2/v2/auth?' +
    new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: 'openid email profile',
      access_type: 'online',
      prompt: 'select_account',
      state,
    });
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
      headers: { authorization: 'Bearer ' + td.access_token },
    });
    const profile = await userResp.json();
    if (!userResp.ok || !profile.email) throw new Error('userinfo failed');
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
    res.status(500).send('Google sign-in failed: ' + e.message);
  }
});

// OIDC discovery is shared by the legacy platform provider and encrypted organization providers.
const OIDC_DISCOVERY_CACHE = new Map();
async function oidcDiscovery(configuredIssuer = process.env.OIDC_ISSUER) {
  const issuer = String(configuredIssuer || '').replace(/\/$/, '');
  if (!issuer) throw new Error('OIDC_ISSUER is not configured');
  if (!(await publicOriginAllowed(issuer))) throw new Error('OIDC issuer must be a public HTTPS origin');
  const cached = OIDC_DISCOVERY_CACHE.get(issuer);
  if (cached?.expiresAt > Date.now()) return cached.value;
  const response = await fetch(`${issuer}/.well-known/openid-configuration`, { signal: AbortSignal.timeout(10_000) });
  if (!response.ok) throw new Error(`OIDC discovery returned ${response.status}`);
  const value = await response.json();
  if (!value.authorization_endpoint || !value.token_endpoint || !value.userinfo_endpoint) {
    throw new Error('OIDC provider discovery is incomplete');
  }
  const endpointsArePublic = await Promise.all(
    [value.authorization_endpoint, value.token_endpoint, value.userinfo_endpoint].map((endpoint) => publicOriginAllowed(endpoint)),
  );
  if (endpointsArePublic.some((allowed) => !allowed)) throw new Error('OIDC endpoints must use public HTTPS origins');
  OIDC_DISCOVERY_CACHE.set(issuer, { expiresAt: Date.now() + 60 * 60_000, value });
  return value;
}

async function organizationIdentityConfig(orgId, kind) {
  const row = await getOrgSecret(orgId, kind, 'default');
  if (!row) return null;
  let secret = {};
  try { secret = decryptSecret(row.secretEnc) || {}; } catch {}
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
    oidc: oidc ? { configured: true, ...oidc.config, updatedAt: oidc.updatedAt, startUrl: `${publicBaseUrl(req)}/auth/sso/org/${encodeURIComponent(ctx.org.id)}/start` } : { configured: false },
    scim: scim ? { configured: true, updatedAt: scim.updatedAt, baseUrl: `${publicBaseUrl(req)}/scim/v2/orgs/${encodeURIComponent(ctx.org.id)}` } : { configured: false },
  });
});

app.put('/api/team/:orgId/identity/oidc', async (req, res) => {
  const ctx = orgContext(req, res, 'settings.manage');
  if (!ctx) return;
  const issuer = String(req.body?.issuer || '').replace(/\/$/, '');
  const clientId = String(req.body?.clientId || '').trim();
  const clientSecret = String(req.body?.clientSecret || '');
  if (!/^https:\/\//i.test(issuer) || !clientId || clientSecret.length < 8) return res.status(400).json({ error: 'Issuer, client ID, and client secret are required; issuer must use HTTPS.' });
  try { await oidcDiscovery(issuer); } catch (error) { return res.status(400).json({ error: `OIDC discovery failed: ${error.message}` }); }
  const previous = await getOrgSecret(ctx.org.id, 'oidc', 'default');
  const now = Date.now();
  const requestedDomains = String(req.body?.allowedDomains || '').split(',').map((item) => item.trim().toLowerCase()).filter(Boolean);
  if (!requestedDomains.length) return res.status(400).json({ error: 'At least one verified email domain is required.' });
  const allowedDomains = [];
  for (const value of requestedDomains) {
    let domain;
    try { domain = registrable(hostOf(value)); } catch { return res.status(400).json({ error: `Invalid email domain: ${value}` }); }
    if (!domain.includes('.') || !isVerified(ctx.user.id, domain)) {
      return res.status(403).json({ error: `Verify ownership of ${domain} in Domains before enabling it for SSO.` });
    }
    if (!allowedDomains.includes(domain)) allowedDomains.push(domain);
  }
  await saveOrgSecret({
    id: previous?.id || `osec_${randomUUID().replaceAll('-', '')}`, orgId: ctx.org.id, kind: 'oidc', name: 'default',
    config: { issuer, clientId, scopes: String(req.body?.scopes || 'openid email profile'), name: sanitizeLabel(req.body?.name || 'Company SSO', 80), allowedDomains },
    secretEnc: encryptSecret({ clientSecret }), createdBy: previous?.createdBy || ctx.user.id,
    createdAt: previous?.createdAt || now, updatedAt: now,
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
    id: previous?.id || `osec_${randomUUID().replaceAll('-', '')}`, orgId: ctx.org.id, kind: 'scim', name: 'default', config: {},
    secretEnc: encryptSecret({ token }), createdBy: previous?.createdBy || ctx.user.id,
    createdAt: previous?.createdAt || now, updatedAt: now,
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
  const config = org && await organizationIdentityConfig(org.id, 'oidc');
  if (!org || !config?.issuer || !config?.clientId || !config?.clientSecret) return res.status(404).send('Organization SSO is not configured.');
  try {
    const discovery = await oidcDiscovery(config.issuer);
    const state = randomToken(24), verifier = randomToken(48);
    const flow = signChallenge({ state, verifier, orgId: org.id }, 'org-oidc-flow', 10 * 60_000);
    const challenge = _crypto.createHash('sha256').update(verifier).digest('base64url');
    res.append('Set-Cookie', `shannon_org_oidc_state=${flow}; HttpOnly; SameSite=Lax; Path=/auth/sso/org/callback; Max-Age=600${COOKIE_SECURE ? '; Secure' : ''}`);
    const redirectUri = `${publicBaseUrl(req)}/auth/sso/org/callback`;
    const target = new URL(discovery.authorization_endpoint);
    target.search = new URLSearchParams({ client_id: config.clientId, redirect_uri: redirectUri, response_type: 'code', scope: config.scopes || 'openid email profile', state, code_challenge: challenge, code_challenge_method: 'S256' });
    res.redirect(target.toString());
  } catch (error) { res.status(502).send(`SSO initialization failed: ${error.message}`); }
});

app.get('/auth/sso/org/callback', async (req, res) => {
  const flow = verifyChallenge(parseCookies(req).shannon_org_oidc_state || '', 'org-oidc-flow');
  const expected = String(flow?.state || ''), actual = String(req.query?.state || '');
  const stateOk = expected.length > 0 && expected.length === actual.length && _crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(actual));
  if (!stateOk || !req.query?.code || !flow?.orgId) return res.status(400).send('Invalid SSO callback. Start sign-in again.');
  res.append('Set-Cookie', `shannon_org_oidc_state=; HttpOnly; SameSite=Lax; Path=/auth/sso/org/callback; Max-Age=0${COOKIE_SECURE ? '; Secure' : ''}`);
  try {
    const config = await organizationIdentityConfig(flow.orgId, 'oidc');
    if (!config) throw new Error('Organization SSO configuration was removed');
    const discovery = await oidcDiscovery(config.issuer);
    const redirectUri = `${publicBaseUrl(req)}/auth/sso/org/callback`;
    const tokenResponse = await fetch(discovery.token_endpoint, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', code: String(req.query.code), redirect_uri: redirectUri, client_id: config.clientId, client_secret: config.clientSecret, code_verifier: String(flow.verifier) }), signal: AbortSignal.timeout(10_000) });
    const tokens = await tokenResponse.json();
    if (!tokenResponse.ok || !tokens.access_token) throw new Error(tokens.error_description || tokens.error || 'token exchange failed');
    const profileResponse = await fetch(discovery.userinfo_endpoint, { headers: { authorization: `Bearer ${tokens.access_token}` }, signal: AbortSignal.timeout(10_000) });
    const profile = await profileResponse.json();
    if (!profileResponse.ok || !profile.sub || !profile.email || profile.email_verified === false) throw new Error('SSO user profile is incomplete or unverified');
    const email = String(profile.email).toLowerCase();
    const emailDomain = registrable(email.split('@')[1] || '');
    if (!config.allowedDomains?.includes(emailDomain)) throw new Error('Your email domain is not allowed for this workspace');
    const providerKey = `${config.issuer}#org=${flow.orgId}`;
    const identity = await findSsoIdentity(providerKey, String(profile.sub));
    const users = loadUsers();
    let user = (identity && users[identity.userId]) || findUserByEmail(email);
    if (!user) { const id = _crypto.randomBytes(8).toString('hex'); user = { id, email, name: profile.name || email, picture: profile.picture || null, emailVerifiedAt: Date.now(), disabledAt: null, mfaEnabled: false, mfaSecretEnc: null, mfaRecoveryCodes: [], createdAt: Date.now(), subscription: null }; users[id] = user; }
    if (user.disabledAt) return res.status(403).send('This account is disabled.');
    user.emailVerifiedAt ||= Date.now(); saveUsers(users); await waitForUserWrites();
    await saveSsoIdentity({ provider: providerKey, subject: String(profile.sub), userId: user.id, email, createdAt: Date.now(), lastLoginAt: Date.now() });
    if (!getMembership(flow.orgId, user.id)) saveMembership({ orgId: flow.orgId, userId: user.id, role: 'viewer', createdAt: Date.now() });
    setSessionCookie(res, user.id);
    res.append('Set-Cookie', `shannon_org=${encodeURIComponent(flow.orgId)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL_DAYS * 86400}${COOKIE_SECURE ? '; Secure' : ''}`);
    res.redirect('/');
  } catch (error) { res.status(502).send(`SSO sign-in failed: ${error.message}`); }
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
    res.append('Set-Cookie', `shannon_oidc_state=${flow}; HttpOnly; SameSite=Lax; Path=/auth/sso/callback; Max-Age=600${COOKIE_SECURE ? '; Secure' : ''}`);
    const redirectUri = `${publicBaseUrl(req)}/auth/sso/callback`;
    const target = new URL(discovery.authorization_endpoint);
    target.search = new URLSearchParams({
      client_id: clientId, redirect_uri: redirectUri, response_type: 'code',
      scope: process.env.OIDC_SCOPES || 'openid email profile', state,
      code_challenge: challenge, code_challenge_method: 'S256',
    });
    res.redirect(target.toString());
  } catch (error) {
    res.status(502).send(`SSO initialization failed: ${error.message}`);
  }
});

app.get('/auth/sso/callback', async (req, res) => {
  const flow = verifyChallenge(parseCookies(req).shannon_oidc_state || '', 'oidc-flow');
  const expected = String(flow?.state || '');
  const actual = String(req.query?.state || '');
  const stateOk = expected.length > 0 && expected.length === actual.length && _crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(actual));
  if (!stateOk || !req.query?.code) return res.status(400).send('Invalid SSO callback. Start sign-in again.');
  res.append('Set-Cookie', `shannon_oidc_state=; HttpOnly; SameSite=Lax; Path=/auth/sso/callback; Max-Age=0${COOKIE_SECURE ? '; Secure' : ''}`);
  try {
    const discovery = await oidcDiscovery();
    const redirectUri = `${publicBaseUrl(req)}/auth/sso/callback`;
    const tokenResponse = await fetch(discovery.token_endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code', code: String(req.query.code), redirect_uri: redirectUri,
        client_id: process.env.OIDC_CLIENT_ID, client_secret: process.env.OIDC_CLIENT_SECRET,
        code_verifier: String(flow.verifier),
      }),
      signal: AbortSignal.timeout(10_000),
    });
    const tokens = await tokenResponse.json();
    if (!tokenResponse.ok || !tokens.access_token) throw new Error(tokens.error_description || tokens.error || 'token exchange failed');
    const profileResponse = await fetch(discovery.userinfo_endpoint, {
      headers: { authorization: `Bearer ${tokens.access_token}` },
      signal: AbortSignal.timeout(10_000),
    });
    const profile = await profileResponse.json();
    if (!profileResponse.ok || !profile.sub || !profile.email) throw new Error('SSO user profile is incomplete');
    if (profile.email_verified === false) throw new Error('SSO provider has not verified this email address');
    const email = String(profile.email).toLowerCase();
    const allowedDomains = String(process.env.SHANNON_SSO_ALLOWED_DOMAINS || '').split(',').map((item) => item.trim().toLowerCase()).filter(Boolean);
    if (allowedDomains.length && !allowedDomains.includes(email.split('@')[1])) throw new Error('Your email domain is not allowed for this workspace');
    const provider = String(process.env.OIDC_ISSUER).replace(/\/$/, '');
    const identity = await findSsoIdentity(provider, String(profile.sub));
    const users = loadUsers();
    let user = (identity && users[identity.userId]) || findUserByEmail(email);
    if (!user) {
      const id = _crypto.randomBytes(8).toString('hex');
      user = {
        id, email, name: profile.name || email, picture: profile.picture || null,
        emailVerifiedAt: Date.now(), disabledAt: null, mfaEnabled: false,
        mfaSecretEnc: null, mfaRecoveryCodes: [], createdAt: Date.now(), subscription: null,
      };
      users[id] = user;
    } else if (user.disabledAt) {
      return res.status(403).send('This account is disabled.');
    }
    user.emailVerifiedAt ||= Date.now();
    if (!user.picture && profile.picture) user.picture = profile.picture;
    saveUsers(users);
    await waitForUserWrites();
    await saveSsoIdentity({ provider, subject: String(profile.sub), userId: user.id, email, createdAt: Date.now(), lastLoginAt: Date.now() });
    ensurePersonalOrg(user);
    setSessionCookie(res, user.id);
    res.redirect('/');
  } catch (error) {
    res.status(502).send(`SSO sign-in failed: ${error.message}`);
  }
});

function requireScim(req, res, next) {
  const configured = String(process.env.SHANNON_SCIM_TOKEN || '');
  const supplied = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const valid = configured.length >= 24 && configured.length === supplied.length && _crypto.timingSafeEqual(Buffer.from(configured), Buffer.from(supplied));
  if (!valid) return res.status(401).set('www-authenticate', 'Bearer').json({ schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], status: '401', detail: 'Unauthorized' });
  const orgId = process.env.SHANNON_SCIM_ORG_ID;
  if (!orgId || !getOrganization(orgId)) return res.status(503).json({ schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], status: '503', detail: 'SCIM organization is not configured' });
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
  const config = getOrganization(orgId) && await organizationIdentityConfig(orgId, 'scim');
  const configured = String(config?.token || '');
  const supplied = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const valid = configured.length >= 24 && configured.length === supplied.length && _crypto.timingSafeEqual(Buffer.from(configured), Buffer.from(supplied));
  if (!valid) return res.status(401).set('www-authenticate', 'Bearer').json({ schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], status: '401', detail: 'Unauthorized' });
  req.scimOrgId = orgId;
  req.scimTenantScoped = true;
  next();
}

const scimRouter = express.Router();
scimRouter.get('/ServiceProviderConfig', (_req, res) => res.json({
  schemas: ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
  patch: { supported: true }, bulk: { supported: false }, filter: { supported: true, maxResults: 200 },
  changePassword: { supported: false }, sort: { supported: false }, etag: { supported: false },
}));
scimRouter.get('/Users', (req, res) => {
  let users = listMembers(req.scimOrgId).map((member) => loadUsers()[member.userId]).filter(Boolean);
  const match = /^userName\s+eq\s+"([^"]+)"$/i.exec(String(req.query.filter || ''));
  if (match) users = users.filter((user) => user.email === match[1].toLowerCase());
  const resources = users.map(scimUser);
  res.json({ schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'], totalResults: resources.length, startIndex: 1, itemsPerPage: resources.length, Resources: resources });
});
scimRouter.get('/Users/:id', (req, res) => {
  const membership = getMembership(req.scimOrgId, req.params.id);
  const user = membership && loadUsers()[req.params.id];
  if (!user) return res.status(404).json({ schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], status: '404', detail: 'User not found' });
  res.json(scimUser(user));
});
scimRouter.post('/Users', async (req, res) => {
  const email = String(req.body?.userName || req.body?.emails?.[0]?.value || '').trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], status: '400', detail: 'A valid userName is required' });
  const users = loadUsers();
  let user = findUserByEmail(email);
  if (!user) {
    const id = _crypto.randomBytes(8).toString('hex');
    user = {
      id, email, name: sanitizeLabel(req.body?.displayName || req.body?.name?.formatted || email, 100),
      emailVerifiedAt: Date.now(), disabledAt: !req.scimTenantScoped && req.body?.active === false ? Date.now() : null,
      mfaEnabled: false, mfaSecretEnc: null, mfaRecoveryCodes: [], createdAt: Date.now(), subscription: null,
    };
    users[id] = user;
    saveUsers(users);
    await waitForUserWrites();
  }
  if (req.body?.active !== false && !getMembership(req.scimOrgId, user.id)) saveMembership({ orgId: req.scimOrgId, userId: user.id, role: 'viewer', createdAt: Date.now() });
  res.status(201).json(scimUser(user, req.body?.active !== false && !user.disabledAt));
});
scimRouter.patch('/Users/:id', (req, res) => {
  const membership = getMembership(req.scimOrgId, req.params.id);
  const user = membership && loadUsers()[req.params.id];
  if (!user) return res.status(404).json({ schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], status: '404', detail: 'User not found' });
  for (const operation of req.body?.Operations || []) {
    const path = String(operation.path || '').toLowerCase();
    if (path === 'active' || (!path && Object.hasOwn(operation.value || {}, 'active'))) {
      const active = path === 'active' ? operation.value : operation.value.active;
      if (req.scimTenantScoped) {
        if (active === false) removeMembership(req.scimOrgId, user.id);
        else if (!getMembership(req.scimOrgId, user.id)) saveMembership({ orgId: req.scimOrgId, userId: user.id, role: 'viewer', createdAt: Date.now() });
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
  if (req.scimTenantScoped) removeMembership(req.scimOrgId, user.id);
  else { user.disabledAt = Date.now(); saveUsers(loadUsers()); }
  res.status(204).end();
});

app.use('/scim/v2/orgs/:orgId', requireOrgScim, scimRouter);
app.use('/scim/v2', requireScim, scimRouter);

async function stripeRequest(path, params) {
  const response = await fetch(`https://api.stripe.com/v1/${path}`, {
    method: 'POST',
    headers: { authorization: `Bearer ${process.env.STRIPE_SECRET_KEY}`, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params), signal: AbortSignal.timeout(15_000),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data?.error?.message || `Stripe returned ${response.status}`);
  return data;
}

export function verifyStripeWebhook(raw, header, secret, now = Date.now()) {
  header = String(header || '');
  const timestamp = header.split(',').find((item) => item.startsWith('t='))?.slice(2);
  const signatures = header.split(',').filter((item) => item.startsWith('v1=')).map((item) => item.slice(3));
  if (!raw || !timestamp || !secret || Math.abs(now / 1000 - Number(timestamp)) > 300) return null;
  const expected = _crypto.createHmac('sha256', secret).update(`${timestamp}.${raw.toString('utf8')}`).digest('hex');
  const valid = signatures.some((value) => value.length === expected.length && _crypto.timingSafeEqual(Buffer.from(value), Buffer.from(expected)));
  if (!valid) return null;
  try { return JSON.parse(raw.toString('utf8')); } catch { return null; }
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
      mode: 'subscription', 'line_items[0][price]': price, 'line_items[0][quantity]': '1',
      customer_email: ctx.user.email, client_reference_id: ctx.org.id,
      'metadata[orgId]': ctx.org.id, 'subscription_data[metadata][orgId]': ctx.org.id,
      success_url: `${base}/?billing=success`, cancel_url: `${base}/?billing=cancelled`,
      allow_promotion_codes: 'true',
    });
    audit(ctx, 'billing.checkout_created', 'organization', ctx.org.id, { cycle, sessionId: session.id });
    res.json({ ok: true, url: session.url });
  } catch (error) { res.status(502).json({ error: `Could not create checkout: ${error.message}` }); }
});

app.post('/api/billing/webhook', async (req, res) => {
  if (!billingEnabled()) return res.status(503).json({ error: 'Billing is not configured.' });
  const event = verifiedStripeEvent(req);
  if (!event) return res.status(400).json({ error: 'Invalid Stripe signature.' });
  const object = event.data?.object || {};
  const orgId = String(object.metadata?.orgId || object.client_reference_id || '');
  if (orgId && getOrganization(orgId)) {
    const eventAt = Number(event.created || 0) * 1000 || Date.now();
    const current = await getEntitlement(orgId);
    if (current?.updatedAt && current.updatedAt >= eventAt) return res.json({ received: true, duplicateOrStale: true });
    if (event.type === 'checkout.session.completed') {
      const paid = object.payment_status === 'paid' || object.payment_status === 'no_payment_required';
      await saveEntitlement({ orgId, plan: 'pro', status: paid ? 'active' : 'incomplete', provider: 'stripe', providerCustomerId: String(object.customer || ''), providerSubscriptionId: String(object.subscription || ''), currentPeriodEnd: null, limits: PRO_LIMITS, updatedAt: eventAt });
    } else if (event.type === 'customer.subscription.updated' || event.type === 'customer.subscription.created' || event.type === 'customer.subscription.deleted') {
      await saveEntitlement({ orgId, plan: 'pro', status: event.type.endsWith('.deleted') ? 'canceled' : String(object.status || 'incomplete'), provider: 'stripe', providerCustomerId: String(object.customer || ''), providerSubscriptionId: String(object.id || ''), currentPeriodEnd: object.current_period_end ? Number(object.current_period_end) * 1000 : null, limits: PRO_LIMITS, updatedAt: eventAt });
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
  if (!billingEnabled() || !entitlement?.providerCustomerId) return res.status(409).json({ error: 'This organization has no Stripe subscription.' });
  try {
    const portal = await stripeRequest('billing_portal/sessions', { customer: entitlement.providerCustomerId, return_url: `${publicBaseUrl(req)}/` });
    res.json({ ok: true, url: portal.url });
  } catch (error) { res.status(502).json({ error: `Could not open billing portal: ${error.message}` }); }
});

app.get('/api/team/:orgId/usage', async (req, res) => {
  const ctx = orgContext(req, res, 'audit.read');
  if (!ctx) return;
  const current = await organizationPlan(ctx.org.id);
  const usage = await listUsage(ctx.org.id);
  res.json({ ok: true, plan: current.plan, limits: current.limits, usage, billingEnabled: billingEnabled() });
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
  if (message.length > 20_000 || link.length > 2_048) return res.status(413).json({ error: 'Submitted content is too large.' });
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
    return (resp.content || [])
      .filter((b) => b.type === 'text')
      .map((b) => b.text)
      .join('\n');
  }
  if (provider === 'openai') {
    if (!keys?.openai) throw new Error('No OpenAI key supplied');
    const r = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: { authorization: 'Bearer ' + keys.openai, 'content-type': 'application/json' },
      body: JSON.stringify({
        model: model || 'gpt-5',
        messages: [
          { role: 'system', content: system },
          { role: 'user', content: user },
        ],
        max_tokens: mt,
        temperature: 0.4,
      }),
    });
    const j = await r.json();
    if (!r.ok) throw new Error(j.error?.message || `OpenAI HTTP ${r.status}`);
    return j.choices?.[0]?.message?.content || '';
  }
  if (provider === 'gemini') {
    if (!keys?.gemini) throw new Error('No Gemini key supplied');
    const m = model || 'gemini-2.5-pro';
    const r = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(m)}:generateContent?key=${encodeURIComponent(keys.gemini)}`,
      {
        method: 'POST',
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
    return j.candidates?.[0]?.content?.parts?.map((p) => p.text || '').join('') || '';
  }
  if (provider === 'glm') {
    if (!keys?.glm) throw new Error('No GLM key supplied');
    const r = await fetch('https://open.bigmodel.cn/api/paas/v4/chat/completions', {
      method: 'POST',
      headers: { authorization: 'Bearer ' + keys.glm, 'content-type': 'application/json' },
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
    const fbSystem =
      system +
      `\n\n[FALLBACK ROLEPLAY: The "${agent.label}" provider failed (${err.message}). Continue in-character as ${agent.label} but execute on Anthropic.]`;
    const text = await csCallProvider('claude', null, fbSystem, user, keys, maxTokens);
    return { text, fallback: true, fallbackReason: err.message };
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
    const s = text.indexOf('{'),
      e = text.lastIndexOf('}');
    if (s >= 0 && e > s) body = text.slice(s, e + 1);
    else body = text;
  }

  // Strategy 2: strict parse on whatever we extracted.
  try {
    const obj = JSON.parse(body);
    return obj;
  } catch {
    /* fall through to salvage */
  }

  // Strategy 2b: trim from the last balanced } and try again.
  const lastBrace = body.lastIndexOf('}');
  if (lastBrace > 0) {
    try {
      const obj = JSON.parse(body.slice(0, lastBrace + 1));
      return obj;
    } catch {
      /* fall through */
    }
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
        try {
          out += String.fromCharCode(Number.parseInt(text.slice(i + 2, i + 6), 16));
          i += 4;
        } catch {
          out += n;
        }
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
    let depth = 0,
      j = i,
      inStr = false,
      escNext = false;
    for (; j < text.length; j++) {
      const c = text[j];
      if (escNext) {
        escNext = false;
        continue;
      }
      if (c === '\\') {
        escNext = true;
        continue;
      }
      if (c === '"') {
        inStr = !inStr;
        continue;
      }
      if (inStr) continue;
      if (c === '{') depth++;
      else if (c === '}') {
        depth--;
        if (depth === 0) {
          j++;
          break;
        }
      }
    }
    if (depth !== 0) break; // truncated — stop salvaging
    const raw = text.slice(i, j);
    try {
      out.push(JSON.parse(raw));
    } catch {
      /* skip malformed finding */
    }
    i = j;
  }
  return out;
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
  run.events.push(ev);
  const msg = `data: ${JSON.stringify(ev)}\n\n`;
  run.sseClients = run.sseClients.filter((c) => {
    try {
      c.write(msg);
      return true;
    } catch {
      return false;
    }
  });
}

async function csOrchestrate(runId) {
  const run = csRuns.get(runId);
  if (!run) return;
  const keys = run.keys || {};
  const agents = csPickAgents(keys);
  run.agents = agents;

  csBc(run, { type: 'agents', agents });
  csBc(run, { type: 'phases', phases: CS_PHASES });
  csBc(run, {
    type: 'lineup',
    summary: agents
      .map((a) => `${a.name}: ${CS_PROVIDERS[a.provider].label} (score ${a.score.toFixed(1)})`)
      .join(' · '),
  });

  for (let i = 0; i < CS_PHASES.length; i++) {
    if (run.cancelled) {
      csBc(run, { type: 'cancelled' });
      break;
    }
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
    const user = csBuildUser(run.code, run.filename, run.transcript, phase, isFinalSynth);

    let text = '',
      fallback = false,
      fbReason,
      errored = false;
    const t0 = Date.now();
    // The synthesis turn carries the full fixed source code + markdown report, so it
    // needs a much larger output budget than the analytical turns. 16k keeps us safe
    // for typical files (~2k LOC) without blowing past provider per-call caps.
    const maxTokens = isFinalSynth ? 16000 : 4000;
    try {
      const r = await csCallAgent(agent, sys, user, keys, maxTokens);
      text = r.text;
      fallback = r.fallback;
      fbReason = r.fallbackReason;
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
      phaseIndex: i,
      phaseId: phase.id,
      agentId: agent.id,
      label: agent.label,
      team: agent.team,
      step: phase.step,
      text,
      fallback,
      fallbackReason: fbReason,
      provider: agent.provider,
      realProvider,
      ms: dt,
      ts: Date.now(),
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

  csBc(run, { type: 'complete', result, agents });
}

app.post('/api/code-scan/multi/start', async (req, res) => {
  const ctx = requirePermission(req, res, 'scans.run');
  if (!ctx) return;
  if (limited(req, res, `code-scan:${ctx.user.id}`, 20, 60 * 60 * 1000)) return;
  const session = csSession(req);
  if (!session) return res.status(401).json({ ok: false, error: 'Authentication required.' });
  const { code, filename } = req.body || {};
  if (!code || typeof code !== 'string') return res.status(400).json({ ok: false, error: 'Provide source code.' });
  if (code.length > 1_000_000)
    return res.status(413).json({ ok: false, error: 'Code exceeds 1MB. Try splitting it into smaller files.' });

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
    filename: filename || null,
    keys,
    transcript: [],
    events: [],
    sseClients: [],
    agents: [],
    status: 'running',
    result: null,
    cancelled: false,
    startedAt: Date.now(),
    endedAt: null,
    session: sessForRun,
  };
  csRuns.set(runId, run);

  // Pre-pick agents synchronously so we can return the lineup with the start response.
  const lineup = csPickAgents(keys);
  run.agents = lineup;

  csOrchestrate(runId).catch((err) => {
    run.status = 'failed';
    run.error = err.message;
    run.endedAt = Date.now();
    csBc(run, { type: 'failed', error: err.message });
  });

  res.json({ ok: true, runId, agents: lineup, phases: CS_PHASES });
});

app.get('/api/code-scan/multi/:id/events', (req, res) => {
  const run = csRuns.get(req.params.id);
  const ctx = requestContext(req);
  if (!run || !ctx || run.session?.userId !== ctx.user.id || run.session?.orgId !== ctx.org.id)
    return res.status(404).json({ ok: false, error: 'Run not found' });
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
  for (const ev of run.events) res.write(`data: ${JSON.stringify(ev)}\n\n`);
  if (run.status === 'running') {
    run.sseClients.push(res);
    req.on('close', () => {
      run.sseClients = run.sseClients.filter((c) => c !== res);
    });
  } else {
    res.end();
  }
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
  try {
    return JSON.parse(raw);
  } catch {
    /* try first { ... last } */
  }
  const start = raw.indexOf('{'),
    end = raw.lastIndexOf('}');
  if (start >= 0 && end > start) {
    try {
      return JSON.parse(raw.slice(start, end + 1));
    } catch {
      return null;
    }
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
  const text = (r.content || [])
    .filter((b) => b.type === 'text')
    .map((b) => b.text)
    .join('\n');
  const parsed = extractJsonFence(text);
  if (!parsed) return { ok: false, error: 'Failed to parse model output', raw: text };
  return { ok: true, result: parsed };
}

app.post('/api/code-scan/quick', async (req, res) => {
  const ctx = requirePermission(req, res, 'scans.run');
  if (!ctx) return;
  if (limited(req, res, `quick-scan:${ctx.user.id}`, 60, 60 * 60 * 1000)) return;
  const session = csSession(req);
  if (!session) return res.status(401).json({ ok: false, error: 'Authentication required.' });
  const { code, filename } = req.body || {};
  if (!code || typeof code !== 'string') return res.status(400).json({ ok: false, error: 'Provide source code.' });
  if (code.length > 1_000_000) return res.status(413).json({ ok: false, error: 'File exceeds 1MB.' });

  const apiKey = (await aiKeysForRequest(req)).claude;
  if (!apiKey) return res.status(400).json({ ok: false, error: 'Anthropic key required.' });
  if (!(await consumeOrgQuota(ctx, res, 'codeFiles'))) return;

  try {
    const out = await quickScanFile({ apiKey, code, filename });
    res.json({ ok: true, ...out });
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
    try { keys[row.name] = String(decryptSecret(row.secretEnc)?.apiKey || ''); } catch {}
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

app.post('/api/settings', (req, res) => {
  const user = getUser(req);
  const current = settingsFor(req);
  const updated = { ...current, ...req.body };
  const sanitized = { provider: updated.provider, model: updated.model, baseUrl: updated.baseUrl };
  saveUserSettings(user.id, sanitized);
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
  const ctx = orgContext(req, res, 'settings.manage');
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
  try { previousSecret = previous ? decryptSecret(previous.secretEnc) || {} : {}; } catch {}
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
  audit(ctx, previous ? 'repository_provider.rotated' : 'repository_provider.created', 'repository-provider', 'github', { repo });
  res.json({ ok: true, provider: 'github', configured: true, repo, updatedAt: now });
});

app.delete('/api/team/:orgId/repository-provider', async (req, res) => {
  const ctx = orgContext(req, res, 'integrations.manage');
  if (!ctx) return;
  await deleteOrgSecret(ctx.org.id, 'repository-provider', 'github');
  audit(ctx, 'repository_provider.deleted', 'repository-provider', 'github');
  res.json({ ok: true });
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
  const email = String(req.body?.email || '').trim().toLowerCase();
  const role = String(req.body?.role || 'viewer');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (!ROLES.includes(role) || role === 'owner') return res.status(400).json({ error: 'Choose a valid non-owner role.' });
  const existing = findUserByEmail(email);
  if (existing && getMembership(ctx.org.id, existing.id)) return res.status(409).json({ error: 'That user is already a member.' });
  try {
    const invitation = await issueAuthToken(req, {
      kind: 'invitation', email, userId: existing?.id || null, orgId: ctx.org.id, role,
      createdBy: ctx.user.id, ttlMs: 7 * 24 * 60 * 60_000,
      linkPath: '/?invite=', subject: `You were invited to ${ctx.org.name}`,
      message: `${ctx.user.name || ctx.user.email} invited you to join ${ctx.org.name} as ${role}. This invitation expires in 7 days.`,
    });
    audit(ctx, 'invitation.created', 'invitation', email, { role });
    res.status(201).json({
      ok: true, email, role, expiresInDays: 7,
      ...(process.env.NODE_ENV !== 'production' ? { developmentToken: invitation.token } : {}),
    });
  } catch (error) {
    res.status(502).json({ error: `Unable to send invitation: ${error.message}` });
  }
});

app.post('/api/team/:orgId/members', (req, res) => {
  const ctx = orgContext(req, res, 'members.manage');
  if (!ctx) return;
  const email = String(req.body?.email || '').trim().toLowerCase();
  const role = String(req.body?.role || 'viewer');
  const user = findUserByEmail(email);
  if (!user) return res.status(404).json({ error: 'That user must create a Securovix account before being added.' });
  if (!ROLES.includes(role) || role === 'owner') return res.status(400).json({ error: 'Choose a valid non-owner role.' });
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
  if (!canChangeMember(ctx.membership, target, role)) return res.status(403).json({ error: 'Role change not permitted.' });
  if (target.role === 'owner' && role !== 'owner' && listMembers(ctx.org.id).filter((m) => m.role === 'owner').length === 1)
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
  if (!canChangeMember(ctx.membership, target, 'viewer')) return res.status(403).json({ error: 'Member removal not permitted.' });
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
  queueIntegrationEvent(ctx.org.id, {
    id: `finding-created:${finding.id}`,
    type: 'finding.created',
    at: new Date().toISOString(),
    data: finding,
  }, ctx.user.id).catch((error) => console.error('[integrations] finding event enqueue failed:', error.message));
  res.status(201).json({ ok: true, finding });
});

app.patch('/api/team/:orgId/findings/:findingId', (req, res) => {
  const ctx = orgContext(req, res, 'findings.read');
  if (!ctx) return;
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
      ? { reason: sanitizeLabel(req.body.reason, 1000), expiresAt: req.body.expiresAt || null, by: ctx.user.id, at: Date.now() }
      : null;
  }
  if (Object.hasOwn(req.body || {}, 'assigneeUserId')) {
    if (!can(ctx.membership.role, 'findings.triage')) return res.status(403).json({ error: 'Assignment not permitted.' });
    const assignee = req.body.assigneeUserId ? getMembership(ctx.org.id, req.body.assigneeUserId) : null;
    if (req.body.assigneeUserId && !assignee) return res.status(400).json({ error: 'Assignee must be an organization member.' });
    next.assigneeUserId = req.body.assigneeUserId || null;
    if (next.assigneeUserId && next.status === 'new') next.status = 'assigned';
  }
  saveFinding(next);
  audit(ctx, 'finding.updated', 'finding', next.id, {
    fromStatus: finding.status,
    toStatus: next.status,
    assigneeUserId: next.assigneeUserId,
  });
  queueIntegrationEvent(ctx.org.id, {
    id: `finding-updated:${next.id}:${next.updatedAt}`,
    type: 'finding.updated',
    at: new Date().toISOString(),
    data: next,
  }, ctx.user.id).catch((error) => console.error('[integrations] finding event enqueue failed:', error.message));
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
      if (!rawSecret.headers || typeof rawSecret.headers !== 'object' || Array.isArray(rawSecret.headers)) throw new Error('headers must be an object.');
      secret.headers = Object.fromEntries(Object.entries(rawSecret.headers).slice(0, 20).map(([name, value]) => [String(name).slice(0, 100), String(value).slice(0, 2000)]));
    } else secret[key] = String(rawSecret[key]).trim().slice(0, 4096);
  }
  const required = {
    webhook: ['config.url'], 'siem-http': ['config.url'], slack: ['secret.webhookUrl'], teams: ['secret.webhookUrl'],
    jira: ['config.baseUrl', 'config.projectKey', 'secret.email', 'secret.apiToken'],
    linear: ['config.teamId', 'secret.apiKey'],
  }[type] || [];
  for (const path of required) {
    const [group, key] = path.split('.');
    if (group === 'secret' && existingHasSecret && rawSecret === undefined) continue;
    if (!(group === 'config' ? config : secret)[key]) throw new Error(`${path} is required.`);
  }
  return { config, secret };
}

app.get('/api/team/:orgId/integrations', async (req, res) => {
  const ctx = orgContext(req, res, 'integrations.manage');
  if (!ctx) return;
  res.json({ ok: true, integrations: await listIntegrations(ctx.org.id) });
});

app.post('/api/team/:orgId/integrations', async (req, res) => {
  const ctx = orgContext(req, res, 'integrations.manage');
  if (!ctx) return;
  const type = String(req.body?.type || '');
  const name = sanitizeLabel(req.body?.name, 100);
  if (!INTEGRATION_TYPES.has(type) || !name) return res.status(400).json({ error: 'A valid integration type and name are required.' });
  let input;
  try { input = integrationInput(type, req.body?.config, req.body?.secret); }
  catch (error) { return res.status(400).json({ error: error.message }); }
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
  res.status(201).json({ ok: true, integration: { ...integration, secretEnc: undefined, hasSecret: !!integration.secretEnc } });
});

app.patch('/api/team/:orgId/integrations/:id', async (req, res) => {
  const ctx = orgContext(req, res, 'integrations.manage');
  if (!ctx) return;
  const current = await getIntegration(ctx.org.id, req.params.id);
  if (!current) return res.status(404).json({ error: 'Integration not found.' });
  let input = { config: current.config, secretEnc: current.secretEnc };
  if (req.body?.config !== undefined || req.body?.secret !== undefined) {
    try {
      const parsed = integrationInput(current.type, req.body?.config ?? current.config, req.body?.secret, !!current.secretEnc);
      input = { config: parsed.config, secretEnc: req.body?.secret === undefined ? current.secretEnc : encryptSecret(parsed.secret) };
    } catch (error) { return res.status(400).json({ error: error.message }); }
  }
  const integration = await saveIntegration({
    ...current,
    name: req.body?.name === undefined ? current.name : sanitizeLabel(req.body.name, 100),
    config: input.config,
    secretEnc: input.secretEnc,
    enabled: req.body?.enabled === undefined ? current.enabled : req.body.enabled === true,
    updatedAt: Date.now(),
  });
  audit(ctx, 'integration.updated', 'integration', integration.id, { type: integration.type, enabled: integration.enabled });
  res.json({ ok: true, integration: { ...integration, secretEnc: undefined, hasSecret: !!integration.secretEnc } });
});

app.delete('/api/team/:orgId/integrations/:id', async (req, res) => {
  const ctx = orgContext(req, res, 'integrations.manage');
  if (!ctx) return;
  if (!(await getIntegration(ctx.org.id, req.params.id))) return res.status(404).json({ error: 'Integration not found.' });
  await deleteIntegration(ctx.org.id, req.params.id);
  audit(ctx, 'integration.deleted', 'integration', req.params.id);
  res.json({ ok: true });
});

app.post('/api/team/:orgId/integrations/:id/test', async (req, res) => {
  const ctx = orgContext(req, res, 'integrations.manage');
  if (!ctx) return;
  const integration = await getIntegration(ctx.org.id, req.params.id);
  if (!integration) return res.status(404).json({ error: 'Integration not found.' });
  const jobs = await queueIntegrationEvent(ctx.org.id, {
    id: `integration-test:${randomUUID()}`,
    type: 'integration.test',
    at: new Date().toISOString(),
    data: { title: `Test event for ${integration.name}`, severity: 'info' },
  }, ctx.user.id, integration.id);
  audit(ctx, 'integration.test_queued', 'integration', integration.id);
  res.status(202).json({ ok: true, jobs: jobs.map((job) => ({ id: job.id, status: job.status })) });
});

app.get('/api/team/:orgId/deliveries', async (req, res) => {
  const ctx = orgContext(req, res, 'integrations.manage');
  if (!ctx) return;
  res.json({ ok: true, deliveries: await listDeliveries(ctx.org.id, Number(req.query.limit) || 100) });
});

app.get('/api/team/:orgId/jobs', async (req, res) => {
  const ctx = orgContext(req, res, 'jobs.read');
  if (!ctx) return;
  const jobs = await listJobs(ctx.org.id, Number(req.query.limit) || 100);
  res.json({
    ok: true,
    jobs: jobs.map(({ secretEnc: _secret, ...job }) => job),
  });
});

app.post('/api/team/:orgId/jobs/:id/cancel', async (req, res) => {
  const ctx = orgContext(req, res, 'scans.stop');
  if (!ctx) return;
  const job = (await listJobs(ctx.org.id, 500)).find((item) => item.id === req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found.' });
  if (!['queued', 'running'].includes(job.status)) return res.status(409).json({ error: `Cannot cancel a ${job.status} job.` });
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
  const artifact = (await listArtifacts(ctx.org.id, req.body?.scanId || null)).find((item) => item.id === req.params.id);
  if (!artifact) return res.status(404).json({ error: 'Artifact not found.' });
  res.json({ ok: true, ...(await signedArtifactUrl(artifact, 300)) });
});

// ---- API: List scans (no workspace paths exposed) ----
app.get('/api/scans', async (req, res) => {
  const ctx = requirePermission(req, res, 'scans.read');
  if (!ctx) return;
  const scans = (existsSync(WORKSPACES) ? readdirSync(WORKSPACES) : [])
    .filter((d) => {
      const p = join(WORKSPACES, d);
      const owner = getScanOwner(d);
      return owner?.orgId === ctx.org.id && statSync(p).isDirectory() && existsSync(join(p, 'session.json'));
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
  for (const job of await listJobs(ctx.org.id, 500)) {
    if (job.type !== 'scan' || !job.payload?.scanId || known.has(job.payload.scanId)) continue;
    scans.push({
      id: job.payload.scanId,
      jobId: job.id,
      target: job.result?.target || job.payload.targetUrl,
      status: job.status === 'succeeded' ? job.result?.status || 'completed' : job.status,
      startedAt: job.result?.startedAt || new Date(job.createdAt).toISOString(),
      completedAt: job.result?.completedAt || null,
      agents: 0,
      totalCost: 0,
      hasReport: job.status === 'succeeded' && Number(job.result?.artifactCount || 0) > 0,
      attempts: job.attempts,
      error: job.error || null,
    });
  }
  scans.sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt));
  res.json(scans);
});

// ---- API: Scan details ----
app.get('/api/scans/:id', async (req, res) => {
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
      try { return (await readArtifact(artifact)).toString('utf8'); } catch { return null; }
    };
    let session = job.result || { status: job.status, target: job.payload?.targetUrl, startedAt: new Date(job.createdAt).toISOString() };
    const sessionRaw = await readText('session.json');
    if (sessionRaw) {
      try { session = JSON.parse(sessionRaw); } catch {}
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
      vulns: {}, exploits: {}, queues: {},
    };
    for (const category of ['sqli', 'xss', 'auth-bypass', 'authz-bypass', 'ssrf', 'business-logic', 'misconfig', 'info-disclosure']) {
      files.vulns[category] = await readText(`vuln/${category}/analysis.md`);
      files.exploits[category] = await readText(`exploit/${category}/exploit-report.md`);
      const queue = await readText(`vuln/${category}/exploitation-queue.json`);
      try { files.queues[category] = queue ? JSON.parse(queue) : null; } catch { files.queues[category] = null; }
    }
    return res.json({ session, files, durable: true, job: { id: job.id, status: job.status, attempts: job.attempts, error: job.error } });
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
app.get('/api/scans/:id/report', async (req, res) => {
  const ctx = scanContext(req, res, req.params.id);
  if (!ctx) return;
  // SARIF export for CI/CD & GitHub code scanning.
  if (req.query.format === 'sarif') {
    const sp = join(WORKSPACES, req.params.id, 'purple', 'report.sarif');
    if (!existsSync(sp)) {
      const artifact = (await listArtifacts(ctx.org.id, req.params.id)).find((item) => item.metadata?.relativePath === 'purple/report.sarif');
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
    return res.end(await readArtifact(artifact));
  }
  res.setHeader('content-type', fmt === 'md' ? 'text/markdown; charset=utf-8' : 'text/html; charset=utf-8');
  res.setHeader('content-disposition', `inline; filename="shannon-pentest-${req.params.id}.${fmt}"`);
  res.end(readFileSync(p, 'utf-8'));
});

app.get('/api/scans/:id/broker', (req, res) => {
  if (!scanContext(req, res, req.params.id)) return;
  const scanDir = join(WORKSPACES, req.params.id);
  const brokerDir = join(scanDir, 'broker');
  const rj = (p) => {
    try {
      return existsSync(p) ? JSON.parse(readFileSync(p, 'utf-8')) : null;
    } catch {
      return null;
    }
  };

  const findings = [];
  const rows = [];
  const owaspCoverage = {};
  const cweCoverage = {};

  if (existsSync(brokerDir)) {
    for (const category of readdirSync(brokerDir)) {
      const catDir = join(brokerDir, category);
      if (!statSync(catDir).isDirectory()) continue;
      for (const f of rj(join(catDir, 'findings.json')) || []) findings.push({ category, ...f });
      const compliance = rj(join(catDir, 'compliance.json'));
      if (compliance) {
        for (const r of compliance.rows || []) rows.push(r);
        for (const [k, n] of Object.entries(compliance.owaspCoverage || {}))
          owaspCoverage[k] = (owaspCoverage[k] || 0) + n;
        for (const [k, n] of Object.entries(compliance.cweCoverage || {})) cweCoverage[k] = (cweCoverage[k] || 0) + n;
      }
    }
  }

  // Paired defenses from the Purple Engine: per confirmed exploit, a detection rule,
  // an inline-block proof, and LLM remediation (defense/<category>/defense.json).
  const defenses = [];
  const defenseDir = join(scanDir, 'defense');
  if (existsSync(defenseDir)) {
    for (const category of readdirSync(defenseDir)) {
      const d = rj(join(defenseDir, category, 'defense.json'));
      if (d) defenses.push(d);
    }
  }

  // Advanced layers surfaced to the client: attack chains + impact are already in `findings`
  // (their own classes); the monitoring delta and AI leads are separate report artifacts.
  const monitoring = rj(join(brokerDir, 'monitoring.json'));
  const aiLeads = rj(join(brokerDir, 'ai-leads.json')) || [];
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
function isLocalHost(h) {
  return h === 'localhost' || h === '::1' || /^127\./.test(h) || h.endsWith('.local');
}
function isPrivateAddress(address) {
  const value = String(address || '').toLowerCase();
  if (isIP(value) === 4) {
    const [a, b] = value.split('.').map(Number);
    return (
      a === 10 ||
      a === 127 ||
      a === 0 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127)
    );
  }
  if (isIP(value) === 6) {
    return value === '::1' || value === '::' || value.startsWith('fc') || value.startsWith('fd') || value.startsWith('fe8') || value.startsWith('fe9') || value.startsWith('fea') || value.startsWith('feb');
  }
  return false;
}
async function publicOriginAllowed(url) {
  const parsed = url instanceof URL ? url : new URL(url);
  if (!['http:', 'https:'].includes(parsed.protocol) || isLocalHost(parsed.hostname) || isPrivateAddress(parsed.hostname)) return false;
  try {
    const addresses = await lookup(parsed.hostname, { all: true, verbatim: true });
    return addresses.length > 0 && addresses.every((x) => !isPrivateAddress(x.address));
  } catch {
    return false;
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
      if (!(await publicOriginAllowed(url))) return '';
      const c = new AbortController();
      const t = setTimeout(() => c.abort(), 8000);
      const r = await fetch(url, { redirect: 'follow', signal: c.signal });
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
    if (html.includes(`shannon-site-verification`) && html.includes(token)) method = 'meta';
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
          content:
            'You are a penetration-test lead. In 2-3 sentences, say what this web app appears to be and where its risk concentrates, based ONLY on this reconnaissance JSON. Be concrete; do NOT invent findings or claim anything is exploitable.\n\n' +
            JSON.stringify(understanding).slice(0, 4000),
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
  return { probe, escalate, recrawl, fetchText };
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
    if (!grant) throw Object.assign(new Error('The authenticated-session grant is invalid, expired, or already used.'), { status: 401 });
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
    if (!isLocalHost(lh) && registrable(lh) !== registrable(th)) return {}; // cross-domain login → refuse
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
  if (!can(ctx.membership.role, 'scans.run')) return { status: 403, error: 'Your role cannot run active security tests.' };
  const raw = (rawTarget || '').trim();
  if (!raw) return { status: 400, error: 'Provide a target URL.' };
  const target = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  let host;
  try {
    host = hostOf(target);
  } catch {
    return { status: 400, error: 'That does not look like a valid URL.' };
  }
  if (!isLocalHost(host)) {
    if (!isVerified(ctx.user.id, host))
      return {
        status: 403,
        error: `Verify ownership of ${registrable(host)} first (Domains page).`,
        needsVerification: registrable(host),
      };
  }
  try {
    const headers = await resolveAuthHeaders(req, target);
    const plan = await organizationPlan(ctx.org.id);
    const quota = await consumeUsage(ctx.org.id, 'agentRuns', 1, Number(plan.limits.agentRuns || 0));
    if (!quota.allowed) return { status: 429, error: `Daily organization limit reached for agent runs (${quota.used}/${quota.limit}).` };
    const surface = await crawl({ target, maxPages: 25, timeoutMs: 7000, maxRequests: 120, headers });
    return { target, surface, headers, ctx };
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
  if (!isLocalHost(host) && !isVerified(ctx.user.id, host)) {
    return res.status(403).json({ error: `Verify ownership of ${registrable(host)} first.`, needsVerification: registrable(host) });
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
    try { loginHost = hostOf(loginUrl); } catch { return res.status(400).json({ error: 'Login URL is invalid.' }); }
    if (!isLocalHost(loginHost) && registrable(loginHost) !== registrable(host)) {
      return res.status(400).json({ error: 'The login URL must use the same registrable domain as the scan target.' });
    }
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
  audit(ctx, 'agent.auth_grant_created', 'scan-auth-grant', id, { targetOrigin: target.origin, expiresAt: now + 5 * 60_000 });
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
    const { probe, escalate, recrawl, fetchText } = agentDeps(r.target, r.headers);
    const run = annotateFixes(await runAgentCampaign({ surface: r.surface, probe, escalate, recrawl }));
    run.leads = await gatherLeads(r.surface, {
      fetchText,
      confirmedTargets: run.findings.map((f) => f.target).filter(Boolean),
    });
    run.savedId = persistRun(req, r.target, run);
    res.json({ ok: true, run });
  } catch (e) {
    res.status(500).json({ error: `Agent run failed: ${e.message}` });
  }
});

// Same autonomous campaign, STREAMED live over Server-Sent Events so the UI watches the agent work
// step-by-step. EventSource is GET-only and same-origin (cookies carry auth); the target is a query
// param. Gate/crawl errors are delivered as an SSE `error` event (the stream itself is always 200).
app.get('/api/agent/run/stream', async (req, res) => {
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
  try {
    const { probe, escalate, recrawl, fetchText } = agentDeps(r.target, r.headers);
    const run = annotateFixes(
      await runAgentCampaign({ surface: r.surface, probe, escalate, recrawl, onStep: (s) => send(s) }),
    );
    run.leads = await gatherLeads(r.surface, {
      fetchText,
      confirmedTargets: run.findings.map((f) => f.target).filter(Boolean),
    });
    run.savedId = persistRun(req, r.target, run);
    send({
      phase: 'leads',
      detail: `Gathered ${run.leads.length} potential lead(s) for manual review — UNPROVEN, kept separate from the ${run.stats.confirmed} confirmed finding(s).`,
    });
    send({ run }, 'done');
  } catch (e) {
    send({ message: `Agent run failed: ${e.message}` }, 'error');
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
    const out = await runSecurityTeam({ surface: r.surface, deps: teamDeps(r.target, r.headers), roster: { exploitAgents: 4 } });
    out.savedId = persistRun(req, r.target, { stats: out.stats, findings: out.findings, leads: [] });
    res.json({ ok: true, team: out });
  } catch (e) {
    res.status(500).json({ error: `Security team run failed: ${e.message}` });
  }
});

// Streamed live over SSE so the dashboard watches the team coordinate step by step (same transport
// contract as /api/agent/run/stream: GET, same-origin cookie auth, target as a query param).
app.get('/api/agent/team/stream', async (req, res) => {
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
  try {
    const out = await runSecurityTeam({
      surface: r.surface,
      deps: teamDeps(r.target, r.headers),
      roster: { exploitAgents: 4 },
      onEvent: (e) => send(e),
    });
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
      stats: run.stats || {},
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
async function executeAgentRun(target) {
  const surface = await crawl({ target, maxPages: 25, timeoutMs: 7000, maxRequests: 120 });
  const { probe, escalate, recrawl, fetchText } = agentDeps(target);
  const run = annotateFixes(await runAgentCampaign({ surface, probe, escalate, recrawl }));
  run.leads = await gatherLeads(surface, {
    fetchText,
    confirmedTargets: run.findings.map((f) => f.target).filter(Boolean),
  });
  return run;
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
        const run = await executeAgentRun(m.target);
        saveAgentRun(m.userId, {
          id: randomUUID().slice(0, 12),
          target: m.target,
          createdAt: Date.now(),
          stats: run.stats || {},
          findings: run.findings || [],
          leads: run.leads || [],
        });
        touchMonitor(m.userId, m.id, Date.now());
        if (m.webhookUrl && prev) {
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

app.post('/api/agent/monitors', (req, res) => {
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
  if (!isLocalHost(host) && !isVerified(user.id, host))
    return res.status(403).json({
      error: `Verify ownership of ${registrable(host)} first (Domains page).`,
      needsVerification: registrable(host),
    });
  const intervalHours = Math.max(1, Math.min(168, Number(req.body?.intervalHours) || 24));
  const webhookUrl = (req.body?.webhookUrl || '').trim() || null;
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
  if (!isLocalHost(host)) {
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
    setSessionHeaders({}); // send ONLY the headers the user supplied (don't leak a prior run's session)
    setScanOrigin(new URL(url).origin);
    const t0 = Date.now();
    const r = await fetchT(url, { method: m, headers: headers || {}, body: body || undefined }, 12000);
    const timeMs = Date.now() - t0;
    const hdrs = {};
    try {
      if (r.headers?.forEach) r.headers.forEach((v, k) => (hdrs[k] = v));
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
  if (!isLocalHost(host)) {
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
    setSessionHeaders({});
    setScanOrigin(origin);
    const r = await fetchT(origin + c.path, { method: c.method, body: c.body }, 12000);
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
  if (!isLocalHost(host)) {
    const user = getUser(req);
    if (!user) return res.status(401).json({ error: 'Sign in first.' });
    if (!isVerified(user.id, host))
      return res.status(403).json({
        error: `Verify ownership of ${registrable(host)} first (Domains page).`,
        needsVerification: registrable(host),
      });
  }
  if (!(await sandboxAvailable()))
    return res
      .status(400)
      .json({
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
  try { providerSecret = provider ? decryptSecret(provider.secretEnc) || {} : {}; } catch {}
  const tok = String(token || providerSecret.token || process.env.GITHUB_TOKEN || '').trim();
  const selectedRepo = String(repo || provider?.config?.repo || '').trim();
  if (!tok)
    return res.status(400).json({ error: 'Configure the organization GitHub credential in Settings before opening PRs.' });
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

app.post('/api/scans', async (req, res) => {
  const ctx = requirePermission(req, res, 'scans.run');
  if (!ctx) return;
  if (limited(req, res, `scan:${ctx.user.id}`, 20, 60 * 60 * 1000)) return;
  const {
    targetUrl,
    authType,
    username,
    password,
    retryPreset,
    focusUrls,
    avoidUrls,
    warRoom,
  } = req.body;
  if (!targetUrl) return res.status(400).json({ error: 'Target URL is required' });

  // ---- AUTHORIZATION GATE ----
  // Active scanning of a system you don't control is illegal. External targets require a logged-in
  // user, an explicit authorization attestation, AND proven domain ownership. Localhost is exempt
  // (built-in labs / self-demo). This is the safety boundary for multi-tenant / client use.
  const targetHost = hostOf(targetUrl);
  if (!isLocalHost(targetHost)) {
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
  if (cleanIds.length >= 2) env.SHANNON_AC = JSON.stringify({ identities: cleanIds });

  // Advanced scan options. Continuous monitoring diffs against the last baseline; an alert webhook
  // pings on new exposures. Network scanning (unauth services on the verified host) requires an
  // explicit authorization acknowledgment in addition to the domain-ownership gate.
  if (req.body.monitor) env.SHANNON_MONITOR = '1';
  if (typeof req.body.alertWebhook === 'string' && /^https:\/\//i.test(req.body.alertWebhook))
    env.SHANNON_ALERT_WEBHOOK = req.body.alertWebhook.slice(0, 2048);
  if (req.body.networkScan && req.body.networkAuthorized === true) {
    // Authorization: a DOMAIN target already passed the domain-ownership gate (its host serves the
    // verified domain). A raw-IP target must fall inside a VERIFIED CIDR range. Localhost is exempt.
    const isRawIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(targetHost);
    let netOk = isLocalHost(targetHost) || !isRawIp;
    if (isRawIp && !netOk) {
      const cidrs = Object.keys(listCidrs(getUser(req)?.id));
      netOk = cidrs.some((c) => ipInCidr(targetHost, c));
    }
    if (netOk) env.SHANNON_NETWORK_SCAN = '1';
  }

  if (isSupabase() && process.env.SHANNON_DURABLE_JOBS !== '0') {
    const durableConfig = structuredClone(config);
    delete durableConfig.authentication;
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
      },
      secretEnc: encryptSecret({
        apiKey,
        authentication: config.authentication || null,
        providerKeys: warRoom ? {
          openai: providerKeys?.openai || null,
          gemini: providerKeys?.gemini || null,
          glm: providerKeys?.glm || null,
        } : null,
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
  writeFileSync(configPath, yamlDump(config, 0), { mode: 0o600 });

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
    const job = (await listJobs(ctx.org.id, 500)).find((item) => item.type === 'scan' && item.payload?.scanId === req.params.id);
    if (!job) return res.status(404).json({ error: 'Scan not found or already finished' });
    if (!['queued', 'running'].includes(job.status)) return res.status(409).json({ error: `Cannot stop a ${job.status} scan.` });
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
    const job = (await listJobs(ctx.org.id, 500)).find((item) => item.type === 'scan' && item.payload?.scanId === req.params.id);
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
  const job = (await listJobs(ctx.org.id, 500)).find((item) => item.type === 'scan' && item.payload?.scanId === req.params.id);
  if (job) return res.json({
    status: job.status === 'succeeded' ? job.result?.status || 'completed' : job.status,
    output: job.result?.outputTail || '', target: job.result?.target || job.payload?.targetUrl,
    phases: [], attempts: job.attempts, error: job.error || null,
  });
  res.status(404).json({ error: 'Not found' });
});

// ---- SSE ----
app.get('/api/scans/:id/events', async (req, res) => {
  const ctx = scanContext(req, res, req.params.id);
  if (!ctx) return;
  const scan = runningScans.get(req.params.id);
  if (!scan) {
    const initial = (await listJobs(ctx.org.id, 500)).find((item) => item.type === 'scan' && item.payload?.scanId === req.params.id);
    if (!initial) return res.status(404).json({ error: 'Not found' });
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
    let previous = '';
    const send = async () => {
      const job = await getJob(initial.id).catch(() => null);
      if (!job) return;
      const snapshot = JSON.stringify({ status: job.status, attempts: job.attempts, error: job.error || null, output: job.result?.outputTail || '' });
      if (snapshot !== previous) res.write(`data: ${JSON.stringify({ type: 'job', ...JSON.parse(snapshot) })}\n\n`);
      previous = snapshot;
      if (['succeeded', 'cancelled', 'dead-letter', 'failed'].includes(job.status)) {
        res.write(`data: ${JSON.stringify({ type: job.status === 'succeeded' ? 'complete' : 'failed', status: job.status })}\n\n`);
        clearInterval(timer);
        res.end();
      }
    };
    const timer = setInterval(() => send().catch(() => {}), 2_000);
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

function yamlDump(obj, indent = 0) {
  const pad = '  '.repeat(indent);
  let out = '';
  for (const [k, v] of Object.entries(obj)) {
    if (v == null) continue;
    if (typeof v === 'object' && !Array.isArray(v)) out += `${pad}${k}:\n${yamlDump(v, indent + 1)}`;
    else if (Array.isArray(v)) {
      out += `${pad}${k}:\n`;
      for (const i of v) out += `${pad}  - ${i}\n`;
    } else out += `${pad}${k}: ${v}\n`;
  }
  return out;
}

// Health-check endpoint — Railway will hit this to confirm the container is alive.
app.get('/healthz', (_req, res) =>
  res.json({ ok: true, service: 'dashboard', uptime: process.uptime() }),
);

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
  const recentDate = (value, maxAgeDays) => Number.isFinite(Date.parse(value || '')) && now - Date.parse(value) <= maxAgeDays * 86_400_000;
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
    { key: 'database', label: 'Supabase database', status: database.ok && database.backend === 'supabase' ? 'ready' : 'configure', detail: database.ok ? `Backend: ${database.backend}` : database.error },
    { key: 'secrets', label: 'Session and encryption secrets', status: strong(process.env.SHANNON_SESSION_SECRET) && strong(process.env.SHANNON_ENCRYPTION_KEY) ? 'ready' : 'configure', detail: 'Two independent secrets of at least 32 characters' },
    { key: 'public-url', label: 'Public application URL', status: /^https:\/\//.test(process.env.SHANNON_PUBLIC_URL || '') ? 'ready' : 'configure', detail: process.env.SHANNON_PUBLIC_URL || 'Set SHANNON_PUBLIC_URL' },
    { key: 'email', label: 'Transactional email', status: process.env.RESEND_API_KEY || process.env.SHANNON_EMAIL_WEBHOOK_URL ? 'ready' : 'configure', detail: process.env.RESEND_API_KEY ? 'Resend configured' : process.env.SHANNON_EMAIL_WEBHOOK_URL ? 'HTTPS relay configured' : 'Verification, reset and invitation mail cannot be delivered' },
    { key: 'worker', label: 'Durable background worker', status: recent(workerHeartbeat, 180_000) ? 'ready' : 'configure', detail: workerHeartbeat ? `Last heartbeat ${new Date(workerHeartbeat.createdAt).toISOString()}` : 'Deploy railway.worker.json' },
    { key: 'browser', label: 'Headless browser proofs', status: process.env.SHANNON_HEADLESS === '1' && browserRuntime ? 'ready' : 'configure', detail: browserRuntime ? 'Set SHANNON_HEADLESS=1' : 'Playwright runtime is not installed' },
    { key: 'sandbox', label: 'Isolated code sandbox', status: dockerSandbox ? 'ready' : process.env.SHANNON_SANDBOX_RUNNER_URL ? 'configure' : 'optional', detail: dockerSandbox ? 'Authenticated dedicated runner and Docker isolation available' : process.env.SHANNON_SANDBOX_RUNNER_URL ? 'Configured runner is unreachable or Docker is unavailable' : 'Requires a Docker-capable dedicated runner; custom checks remain available' },
    { key: 'edge', label: 'Public Defender Edge', status: recent(edgeHeartbeat, 300_000) ? 'ready' : 'optional', detail: edgeHeartbeat ? `Last heartbeat ${new Date(edgeHeartbeat.createdAt).toISOString()}` : 'Deploy railway.edge.json when public reverse-proxy protection is required' },
    { key: 'sso', label: 'Company SSO', status: orgOidc || (process.env.OIDC_ISSUER && process.env.OIDC_CLIENT_ID && process.env.OIDC_CLIENT_SECRET) ? 'ready' : 'optional', detail: orgOidc?.config?.issuer || process.env.OIDC_ISSUER || 'OIDC is optional' },
    { key: 'scim', label: 'SCIM provisioning', status: orgScim || (strong(process.env.SHANNON_SCIM_TOKEN) && process.env.SHANNON_SCIM_ORG_ID) ? 'ready' : 'optional', detail: orgScim ? `Configured for ${ctx.org.name}` : process.env.SHANNON_SCIM_ORG_ID || 'SCIM is optional' },
    { key: 'metrics', label: 'Protected metrics', status: strong(process.env.SHANNON_METRICS_TOKEN) ? 'ready' : 'configure', detail: 'Prometheus endpoint bearer token' },
    { key: 'backups', label: 'Backup restore test', status: recentDate(process.env.SHANNON_BACKUPS_VERIFIED_AT, 100) ? 'ready' : 'configure', detail: process.env.SHANNON_BACKUPS_VERIFIED_AT || 'Set SHANNON_BACKUPS_VERIFIED_AT after a successful staging restore (repeat quarterly)' },
    { key: 'alerts', label: 'Production alert test', status: recentDate(process.env.SHANNON_ALERTS_VERIFIED_AT, 45) ? 'ready' : 'configure', detail: process.env.SHANNON_ALERTS_VERIFIED_AT || 'Set SHANNON_ALERTS_VERIFIED_AT after an end-to-end on-call alert test' },
    { key: 'incident-contact', label: 'Security incident contact', status: /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(process.env.SHANNON_SECURITY_CONTACT || '') ? 'ready' : 'configure', detail: process.env.SHANNON_SECURITY_CONTACT || 'Set the monitored security contact address' },
    { key: 'billing', label: 'Stripe billing', status: billingEnabled() ? 'ready' : 'optional', detail: billingEnabled() ? 'Checkout and signed webhooks configured' : 'Optional; paid checkout remains disabled' },
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
  const requiredKeys = new Set(['database', 'secrets', 'public-url', 'email', 'worker', 'browser', 'metrics', 'backups', 'alerts', 'incident-contact']);
  const required = checks.filter((item) => requiredKeys.has(item.key));
  res.json({
    ok: required.every((item) => item.status === 'ready'),
    ready: required.filter((item) => item.status === 'ready').length,
    required: required.length,
    checks,
    generatedAt: now,
    organization: { id: ctx.org.id, name: ctx.org.name },
  });
});

app.get('/metrics', async (req, res) => {
  const configured = String(process.env.SHANNON_METRICS_TOKEN || '');
  const supplied = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const valid = configured && supplied.length === configured.length && _crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(configured));
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
  });
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
  const payload = Buffer.from(JSON.stringify({ uid: userId, oid: orgId, v: Number(version || 0) })).toString('base64url');
  const sig = _crypto.createHmac('sha256', SESSION_SECRET).update(`defender-key:${payload}`).digest('base64url');
  return `sk_${payload}.${sig}`;
}
function verifyDefenderKey(key) {
  const m = /^sk_([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/.exec(String(key || ''));
  if (!m) return null;
  const expected = _crypto.createHmac('sha256', SESSION_SECRET).update(`defender-key:${m[1]}`).digest('base64url');
  if (expected.length !== m[2].length || !_crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(m[2]))) return null;
  try {
    const payload = JSON.parse(Buffer.from(m[1], 'base64url').toString());
    const membership = getMembership(payload.oid, payload.uid);
    const user = loadUsers()[payload.uid];
    const versionMatches = user && Number(payload.v || 0) === Number(user.defenderKeyVersion || 0);
    return membership && versionMatches && can(membership.role, 'defender.manage') ? { userId: payload.uid, orgId: payload.oid } : null;
  } catch {
    return null;
  }
}

// Limit each SDK batch; accepted events are persisted per organization.
const SDK_REPORT_MAX = 200;

function defenderSeverity(cls) {
  const value = String(cls || '').toLowerCase();
  if (/(rce|command|sqli|auth-bypass|metadata)/.test(value)) return 'critical';
  if (/(path-traversal|nosql|ssrf|ssti|authz|idor)/.test(value)) return 'high';
  if (/(xss|prompt|csrf|header|graphql)/.test(value)) return 'medium';
  return 'low';
}

app.post('/api/defender/report', (req, res) => {
  const principal = verifyDefenderKey((req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
  if (!principal) return res.status(401).json({ error: 'invalid api key' });
  const incoming = Array.isArray(req.body?.detections) ? req.body.detections : [];
  if (!incoming.length) return res.json({ accepted: 0 });

  let accepted = 0;
  for (const raw of incoming.slice(0, SDK_REPORT_MAX)) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) continue;
    const d = raw;
    const eventTime = typeof d.at === 'string' && Number.isFinite(Date.parse(d.at))
      ? new Date(d.at).toISOString()
      : new Date().toISOString();
    const event = {
      id: randomUUID(),
      orgId: principal.orgId,
      userId: principal.userId,
      at: eventTime,
      method: String(d.method || '').slice(0, 10),
      url: String(d.url || '').slice(0, 300),
      cls: String(d.cls || '').slice(0, 60),
      enforced: d.enforced === true,
      srcIp: d.srcIp ? String(d.srcIp).slice(0, 64) : null,
      severity: defenderSeverity(d.cls),
      source: 'sdk',
      status: d.enforced === true ? 'contained' : 'open',
      metadata: {},
      createdAt: Date.now(),
    };
    appendDefenseEvent(event);
    accepted += 1;
    queueIntegrationEvent(principal.orgId, {
      id: `defender:${event.id}`,
      type: 'defender.detection',
      at: event.at,
      data: event,
    }, principal.userId).catch((error) => console.error('[defender] integration event failed:', error.message));
  }
  res.json({ accepted });
});

app.get('/api/defender/sdk', (req, res) => {
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  const user = ctx.user;
  res.json({ apiKey: defenderApiKey(user.id, ctx.org.id, user.defenderKeyVersion), reports: listDefenseEvents(ctx.org.id, 25) });
});

app.post('/api/defender/sdk/rotate', (req, res) => {
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  ctx.user.defenderKeyVersion = Number(ctx.user.defenderKeyVersion || 0) + 1;
  saveUsers(loadUsers());
  audit(ctx, 'defender.sdk_key_rotated', 'organization', ctx.org.id, { version: ctx.user.defenderKeyVersion });
  res.json({ apiKey: defenderApiKey(ctx.user.id, ctx.org.id, ctx.user.defenderKeyVersion) });
});

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

app.get('/api/defender/program', async (req, res) => {
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  const [stored, assets, cycles] = await Promise.all([
    getDefenseProgram(ctx.org.id), listDefenseAssets(ctx.org.id), listDefenseCycles(ctx.org.id, 20),
  ]);
  res.json({
    ok: true,
    program: stored || { orgId: ctx.org.id, enabled: false, cadenceHours: 24, responseMode: 'recommend', nextRunAt: null, lastRunAt: null, lastCycleId: null },
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
  audit(ctx, 'defender.program_updated', 'defense-program', ctx.org.id, { enabled: program.enabled, cadenceHours, responseMode: program.responseMode });
  res.json({ ok: true, program });
});

app.post('/api/defender/program/run', async (req, res) => {
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  const program = await getDefenseProgram(ctx.org.id);
  const cycleId = `dcy_${randomUUID()}`;
  const job = await enqueueJob({
    orgId: ctx.org.id, userId: ctx.user.id, type: 'defense-cycle',
    payload: { cycleId, trigger: 'manual', responseMode: program?.responseMode || 'recommend' }, idempotencyKey: `defense-cycle:manual:${cycleId}`, maxAttempts: 3,
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
  let locator = String(req.body?.locator || '').trim().slice(0, 500);
  if (!locator) return res.status(400).json({ error: 'Asset locator is required.' });
  if (['web', 'api', 'domain'].includes(type)) {
    const host = hostOf(locator);
    if (!host) return res.status(400).json({ error: 'Provide a valid domain or URL.' });
    if (!isLocalHost(host) && !isVerified(ctx.user.id, host)) return res.status(403).json({ error: 'Verify ownership of this domain before adding it to continuous defense.', host });
    locator = type === 'domain' ? host : locator;
  }
  if (type === 'cidr') {
    if (!parseCidr(locator)) return res.status(400).json({ error: 'Provide a valid IPv4 CIDR range.' });
    if (!Object.hasOwn(listCidrs(ctx.user.id), locator)) return res.status(403).json({ error: 'Verify control of this IP range before adding it.' });
  }
  const criticality = ['low', 'medium', 'high', 'critical'].includes(req.body?.criticality) ? req.body.criticality : 'medium';
  const projectId = req.body?.projectId ? String(req.body.projectId) : null;
  if (projectId && !listProjects(ctx.org.id).some((project) => project.id === projectId)) {
    return res.status(400).json({ error: 'Choose a project from the active organization.' });
  }
  const asset = await saveDefenseAsset({
    orgId: ctx.org.id, projectId, type, locator, criticality,
    name: sanitizeLabel(req.body?.name || locator, 100) || locator.slice(0, 100),
    status: 'active', coverage: 'inventory', createdBy: ctx.user.id,
    config: { sensorRequired: !['web', 'api', 'domain'].includes(type) },
  });
  audit(ctx, 'defender.asset_added', 'defense-asset', asset.id, { type, locator, criticality });
  res.status(201).json({ ok: true, asset, protected: asset.coverage === 'online', nextStep: ['web', 'api', 'domain'].includes(type) ? 'Add an Edge route or install the Defender SDK.' : 'Install or connect a supported sensor; inventory alone does not inspect this asset.' });
});

app.delete('/api/defender/assets/:id', async (req, res) => {
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  const existing = (await listDefenseAssets(ctx.org.id)).find((item) => item.id === req.params.id);
  if (!existing) return res.status(404).json({ error: 'Asset not found.' });
  await deleteDefenseAsset(ctx.org.id, existing.id);
  audit(ctx, 'defender.asset_removed', 'defense-asset', existing.id, { type: existing.type, locator: existing.locator });
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
  queueIntegrationEvent(ctx.org.id, {
    id: `defender-status:${event.id}:${status}`,
    type: 'defender.incident.updated',
    at: new Date().toISOString(),
    data: event,
  }, ctx.user.id).catch((error) => console.error('[defender] incident integration event failed:', error.message));
  res.json({ ok: true, event });
});

// ── Edge routes (consumed by packages/defender-edge) ────────────────────────────────────────────
// Durable hostname → origin mappings for the public multi-tenant proxy. The edge can pull this list
// with a scoped SDK credential and keeps its last valid routes if the dashboard becomes unavailable.

const EDGE_HEARTBEATS = new Map();

function edgePlatformAuthorized(req) {
  const configured = String(process.env.SHANNON_EDGE_PLATFORM_TOKEN || '');
  const supplied = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  return configured.length >= 32 && supplied.length === configured.length
    && _crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(configured));
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
  for (const raw of incoming.slice(0, SDK_REPORT_MAX)) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) continue;
    const host = String(raw.host || '').toLowerCase().split(':')[0];
    const route = routesByHost.get(host);
    if (!route) continue;
    const event = {
      id: randomUUID(), orgId: route.orgId, userId: route.userId,
      at: typeof raw.at === 'string' && Number.isFinite(Date.parse(raw.at)) ? new Date(raw.at).toISOString() : new Date().toISOString(),
      method: String(raw.method || '').slice(0, 10), url: String(raw.url || '').slice(0, 300),
      cls: String(raw.cls || '').slice(0, 60), enforced: raw.enforced === true,
      srcIp: raw.srcIp ? String(raw.srcIp).slice(0, 64) : null,
      severity: defenderSeverity(raw.cls), source: 'edge', status: raw.enforced === true ? 'contained' : 'open',
      metadata: { host }, createdAt: Date.now(),
    };
    appendDefenseEvent(event);
    accepted += 1;
    queueIntegrationEvent(route.orgId, { id: `defender:${event.id}`, type: 'defender.detection', at: event.at, data: event }, route.userId)
      .catch((error) => console.error('[defender] integration event failed:', error.message));
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
      ...(asset.config || {}), lastSeenAt: at,
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
  const list = listEdgeRoutes({ orgId }).map((v) => ({ host: v.host, origin: v.origin, mode: v.mode, createdAt: v.createdAt }));
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
  if (!isLocalHost(h) && !isVerified(user.id, h)) {
    return res.status(403).json({ error: 'needsVerification', host: h });
  }
  if (!isVerified(user.id, parsed.hostname)) {
    return res.status(403).json({ error: 'originNeedsVerification', host: parsed.hostname });
  }
  if (!(await publicOriginAllowed(parsed))) {
    return res.status(400).json({ error: 'origin must resolve only to public IP addresses' });
  }

  const occupied = listEdgeRoutes().find((item) => item.host === h && item.orgId !== ctx.org.id);
  if (occupied) return res.status(409).json({ error: 'This public hostname is already assigned to another organization.' });

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

function defBroadcast(entry, payload) {
  const line = `data: ${JSON.stringify(payload)}\n\n`;
  for (const c of entry.sseClients) {
    try {
      c.write(line);
    } catch {}
  }
}

app.post('/api/defender/connect', async (req, res) => {
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

  if (!isLocalHost(host) && !isVerified(user.id, host)) {
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
  const system = { id, userId: user.id, orgId: ctx.org.id, kind: 'web', origin, mode: 'monitor', createdAt: new Date().toISOString() };
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
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  const rows = [...defenders.values()]
    .filter((e) => e.system.orgId === ctx.org.id)
    .map((e) => ({ ...e.system, proxyUrl: e.runtime?.meta?.url || null, stats: e.runtime?.stats?.() || { events: 0, defenses: 0 } }));
  res.json({ systems: rows });
});

app.get('/api/defender/overview', (req, res) => {
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  const events = listDefenseEvents(ctx.org.id, 500);
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
      critical: events.filter((event) => event.severity === 'critical' && ['open', 'investigating'].includes(event.status || 'open')).length,
      edgeRoutes: routes.length,
      enforcingRoutes: routes.filter((route) => route.mode === 'enforce').length,
      connectedSystems: systems.length,
      protectedAssets: routes.filter((route) => route.mode === 'enforce').length + systems.filter((system) => system.mode === 'enforce').length,
    },
    topClasses: Object.entries(classes)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([name, count]) => ({ name, count })),
    events: events.slice(0, 100),
    routes,
    systems,
  });
});

app.post('/api/defender/:id/mode', (req, res) => {
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  const user = ctx.user;
  const entry = defenders.get(req.params.id);
  if (!entry || entry.system.userId !== user.id || entry.system.orgId !== ctx.org.id) return res.status(404).json({ error: 'not found' });
  if (!entry.runtime) return res.status(409).json({ error: 'defender not running' });
  const mode = entry.runtime.setMode(req.body?.mode);
  entry.system.mode = mode;
  audit(ctx, 'defender.mode_changed', 'defender', entry.system.id, { mode });
  defBroadcast(entry, { type: 'mode', mode });
  res.json({ id: entry.system.id, mode });
});

app.post('/api/defender/:id/disconnect', async (req, res) => {
  const ctx = requirePermission(req, res, 'defender.manage');
  if (!ctx) return;
  const user = ctx.user;
  const entry = defenders.get(req.params.id);
  if (!entry || entry.system.userId !== user.id || entry.system.orgId !== ctx.org.id) return res.status(404).json({ error: 'not found' });
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
  }
  return server;
}

export { app };

if (process.argv[1] && resolve(process.argv[1]) === __filename) {
  startDashboard().catch(() => process.exit(1));
}
