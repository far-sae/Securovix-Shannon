// Google Workspace connector for Guard.
//
// Reads: Admin SDK Reports API activity (login, admin, user_accounts, token, drive). Acts: sign
// out, force password change, suspend/unsuspend, revoke an app's token.
//
// Setup (customer side): a service account with domain-wide delegation for these scopes, and a
// super-admin email for it to act as:
//   https://www.googleapis.com/auth/admin.reports.audit.readonly
//   https://www.googleapis.com/auth/admin.directory.user
//   https://www.googleapis.com/auth/admin.directory.user.security
// Google's login records carry an IP address but no location, so impossible travel and
// new-country checks only run on Microsoft 365. Drive audit needs Business Standard or higher.
import { createSign } from 'node:crypto';
import { emailsIn, ProviderError, requestJson } from './http.mjs';

const REPORTS = 'https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications';
const DIRECTORY = 'https://admin.googleapis.com/admin/directory/v1';
const SCOPES = [
  'https://www.googleapis.com/auth/admin.reports.audit.readonly',
  'https://www.googleapis.com/auth/admin.directory.user',
  'https://www.googleapis.com/auth/admin.directory.user.security',
];
const APPLICATIONS = ['login', 'admin', 'user_accounts', 'token', 'drive'];
const MIN = 60_000;
const DAY = 24 * 60 * MIN;
const tokenCache = new Map();

export function validateGoogle(input = {}) {
  const adminEmail = String(input.adminEmail || '')
    .trim()
    .toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(adminEmail))
    throw new Error('Admin email must be a super-admin address in your Workspace domain.');
  let key = input.serviceAccountJson;
  if (typeof key === 'string') {
    try {
      key = JSON.parse(key);
    } catch {
      throw new Error('Service account key must be the JSON file Google gave you.');
    }
  }
  if (!key?.client_email || !String(key?.private_key || '').includes('PRIVATE KEY'))
    throw new Error('Service account key must contain client_email and private_key.');
  return {
    config: {
      adminEmail,
      serviceAccount: key.client_email,
      customerId: String(input.customerId || 'my_customer').trim() || 'my_customer',
    },
    secret: { clientEmail: key.client_email, privateKey: key.private_key },
  };
}

const b64url = (value) => Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)).toString('base64url');

export function signedAssertion({ clientEmail, privateKey }, subject, now = Date.now()) {
  const iat = Math.floor(now / 1000);
  const unsigned = `${b64url({ alg: 'RS256', typ: 'JWT' })}.${b64url({ iss: clientEmail, sub: subject, scope: SCOPES.join(' '), aud: 'https://oauth2.googleapis.com/token', iat, exp: iat + 3600 })}`;
  const signature = createSign('RSA-SHA256').update(unsigned).sign(privateKey).toString('base64url');
  return `${unsigned}.${signature}`;
}

async function token(fetchImpl, config, secret, now = Date.now()) {
  const key = `${secret.clientEmail}|${config.adminEmail}`;
  const cached = tokenCache.get(key);
  if (cached && cached.expiresAt > now + MIN) return cached.token;
  const json = await requestJson(fetchImpl, 'https://oauth2.googleapis.com/token', {
    method: 'POST',
    form: {
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: signedAssertion(secret, config.adminEmail, now),
    },
  });
  tokenCache.set(key, { token: json.access_token, expiresAt: now + Number(json.expires_in || 3600) * 1000 });
  return json.access_token;
}

// ---------- normalization (pure, exported for tests) ----------

function params(event) {
  const out = {};
  for (const p of event?.parameters || []) out[p.name] = p.value ?? p.multiValue ?? p.boolValue ?? p.intValue ?? null;
  return out;
}

const RISK_EVENTS = new Set([
  'suspicious_login',
  'suspicious_login_less_secure_app',
  'suspicious_programmatic_login',
  'gov_attack_warning',
  'account_disabled_hijacked',
  'account_disabled_spamming_through_relay',
]);

export function normalizeActivity(application, item) {
  const out = [];
  const at = Date.parse(item?.id?.time);
  const email = String(item?.actor?.email || '').toLowerCase() || null;
  (item?.events || []).forEach((event, index) => {
    const p = params(event);
    const base = {
      id: `g:${application}:${item?.id?.uniqueQualifier}:${index}`,
      provider: 'google',
      at,
      user: { email },
      ip: item?.ipAddress || null,
      actor: email,
    };
    const name = String(event.name || '');
    if (application === 'login') {
      if (name === 'login_success')
        out.push({
          ...base,
          type: 'signin.success',
          outcome: 'success',
          risk: p.is_suspicious === true || p.is_suspicious === 'true' ? 'high' : null,
          geo: null,
        });
      else if (name === 'login_failure') out.push({ ...base, type: 'signin.failure', outcome: 'failure' });
      else if (
        name === 'login_challenge' &&
        /fail/i.test(String(p.login_challenge_status || '')) &&
        /prompt|push/i.test(JSON.stringify(p.login_challenge_method || ''))
      )
        out.push({ ...base, type: 'mfa.denied' });
      else if (RISK_EVENTS.has(name)) out.push({ ...base, type: 'signin.risk', detail: name.replace(/_/g, ' ') });
    } else if (application === 'admin') {
      if (name === 'ASSIGN_ROLE')
        out.push({
          ...base,
          type: 'role.assigned',
          user: { email: String(p.USER_EMAIL || '').toLowerCase() || null },
          target: { role: String(p.ROLE_NAME || ''), member: String(p.USER_EMAIL || '').toLowerCase() },
        });
      else if (name === 'GRANT_ADMIN_PRIVILEGE')
        out.push({
          ...base,
          type: 'role.assigned',
          user: { email: String(p.USER_EMAIL || '').toLowerCase() || null },
          target: { role: 'Super Admin', member: String(p.USER_EMAIL || '').toLowerCase() },
        });
      else if (name === 'ENFORCE_STRONG_AUTHENTICATION' && /false/i.test(String(p.NEW_VALUE)))
        out.push({
          ...base,
          type: 'mfa.disabled',
          target: {
            orgWide: true,
            detail: `2-Step Verification enforcement turned off${p.ORG_UNIT_NAME ? ` for ${p.ORG_UNIT_NAME}` : ''}`,
          },
        });
      else if (/FORWARD/i.test(name)) {
        const to = emailsIn(JSON.stringify(p))[0];
        if (to)
          out.push({
            ...base,
            type: 'forwarding.set',
            user: { email: String(p.USER_EMAIL || email || '').toLowerCase() },
            target: { to },
          });
      }
    } else if (application === 'user_accounts') {
      if (name === '2sv_disable')
        out.push({ ...base, type: 'mfa.disabled', target: { detail: '2-Step Verification turned off' } });
      else if (/forward/i.test(name)) {
        const to = emailsIn(JSON.stringify(p))[0];
        if (to) out.push({ ...base, type: 'forwarding.set', target: { to } });
      }
    } else if (application === 'token') {
      if (name === 'authorize') {
        const scopes = []
          .concat(p.scope || [])
          .flatMap((s) => String(s).split(/\s+/))
          .filter(Boolean);
        out.push({
          ...base,
          type: 'oauth.consent',
          target: {
            app: String(p.app_name || p.client_id || 'Unknown app'),
            clientId: String(p.client_id || '') || null,
            scopes,
            tenantWide: false,
          },
        });
      }
    } else if (application === 'drive') {
      if (name === 'download')
        out.push({ ...base, type: 'file.download', target: { file: p.doc_title || p.doc_id || null } });
      else if (
        name === 'change_document_visibility' &&
        /people_with_link|public_on_the_web/.test(String(p.visibility || ''))
      )
        out.push({ ...base, type: 'file.share', target: { file: p.doc_title || p.doc_id || null, anonymous: true } });
      else if (name === 'change_user_access' && p.target_user)
        out.push({
          ...base,
          type: 'file.share',
          target: { file: p.doc_title || p.doc_id || null, to: String(p.target_user).toLowerCase() },
        });
    }
  });
  return out.filter((e) => Number.isFinite(e.at));
}

export function createGoogleProvider({ fetchImpl = fetch } = {}) {
  const call = async (connection, secret, url, opts = {}) => {
    const bearer = await token(fetchImpl, connection.config, secret);
    return requestJson(fetchImpl, url, {
      ...opts,
      headers: { authorization: `Bearer ${bearer}`, ...(opts.headers || {}) },
    });
  };
  return {
    id: 'google',
    validate: validateGoogle,
    async test(connection, secret) {
      const checks = [];
      try {
        await call(connection, secret, `${REPORTS}/login?maxResults=1`);
        checks.push({ name: 'Audit reports', ok: true });
      } catch (error) {
        checks.push({
          name: 'Audit reports',
          ok: false,
          detail:
            error.status === 401 || error.status === 403
              ? 'Add the reports scope to the service account under domain-wide delegation, and use a super-admin email.'
              : error.message,
        });
      }
      let domains = [];
      try {
        const json = await call(
          connection,
          secret,
          `${DIRECTORY}/customer/${encodeURIComponent(connection.config.customerId)}/domains`,
        );
        domains = (json?.domains || []).map((d) => String(d.domainName).toLowerCase());
        checks.push({ name: 'Directory', ok: true });
      } catch (error) {
        checks.push({ name: 'Directory', ok: false, detail: error.message });
      }
      return { ok: checks.every((c) => c.ok), checks, domains };
    },
    async collect(connection, secret, { state = {}, now = Date.now() } = {}) {
      state.cursors ||= {};
      const events = [];
      const errors = [];
      for (const application of APPLICATIONS) {
        const since = Number(state.cursors[application] || now - (application === 'login' ? 7 * DAY : DAY));
        try {
          let pageToken = '';
          let latest = since;
          for (let page = 0; page < 20; page += 1) {
            const url = `${REPORTS}/${application}?startTime=${encodeURIComponent(new Date(since).toISOString())}&maxResults=1000${pageToken ? `&pageToken=${encodeURIComponent(pageToken)}` : ''}`;
            const json = await call(connection, secret, url);
            for (const item of json?.items || []) {
              for (const event of normalizeActivity(application, item)) {
                events.push(event);
                latest = Math.max(latest, event.at);
              }
            }
            pageToken = json?.nextPageToken || '';
            if (!pageToken) break;
          }
          state.cursors[application] = latest;
        } catch (error) {
          errors.push(`${application}: ${error.message}`);
        }
      }
      return { events, state, errors };
    },
    async act(connection, secret, type, params = {}) {
      const user = encodeURIComponent(String(params.user || ''));
      switch (type) {
        case 'revoke-sessions':
          await call(connection, secret, `${DIRECTORY}/users/${user}/signOut`, { method: 'POST' });
          return { detail: `Signed ${params.user} out of every session.` };
        case 'force-password-reset':
          await call(connection, secret, `${DIRECTORY}/users/${user}`, {
            method: 'PATCH',
            body: { changePasswordAtNextLogin: true },
          });
          return { detail: `${params.user} must choose a new password at next sign-in.` };
        case 'disable-user':
          await call(connection, secret, `${DIRECTORY}/users/${user}`, { method: 'PATCH', body: { suspended: true } });
          return { detail: `Suspended ${params.user}.`, undo: {} };
        case 'enable-user':
          await call(connection, secret, `${DIRECTORY}/users/${user}`, { method: 'PATCH', body: { suspended: false } });
          return { detail: `Unsuspended ${params.user}.` };
        case 'revoke-oauth-grant':
          if (!params.user)
            throw new ProviderError('Google revokes app access per person; this alert has no person attached.');
          await call(
            connection,
            secret,
            `${DIRECTORY}/users/${user}/tokens/${encodeURIComponent(String(params.clientId || ''))}`,
            { method: 'DELETE' },
          );
          // Google cannot re-grant a token on the person's behalf, so there is no undo.
          return {
            detail: `Revoked "${params.app || params.clientId}" for ${params.user}. They can grant it again themselves if it was legitimate.`,
            undo: null,
          };
        default:
          throw new ProviderError(`Google Workspace cannot perform "${type}".`);
      }
    },
  };
}
