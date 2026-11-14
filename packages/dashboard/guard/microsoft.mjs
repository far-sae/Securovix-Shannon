// Microsoft 365 connector for Guard.
//
// Reads: Entra ID sign-ins and directory audits (Microsoft Graph), Exchange and SharePoint audit
// records (Office 365 Management Activity API). Acts: sign out, force password change,
// disable/enable, remove/restore an inbox rule, revoke/restore an app's access.
//
// Setup (customer side): an app registration with a client secret and these APPLICATION
// permissions, admin-consented:
//   Microsoft Graph: AuditLog.Read.All, Directory.Read.All
//     for responses also: User.ReadWrite.All (or User.EnableDisableAccount.All +
//     User-PasswordProfile.ReadWrite.All), User.RevokeSessions.All, MailboxSettings.ReadWrite,
//     DelegatedPermissionGrant.ReadWrite.All, AppRoleAssignment.ReadWrite.All
//   Office 365 Management APIs: ActivityFeed.Read
// Sign-in logs need Entra ID P1 or P2 (included in Microsoft 365 Business Premium).
import { emailsIn, ProviderError, requestJson, stripPort } from './http.mjs';

const GRAPH = 'https://graph.microsoft.com/v1.0';
const MANAGE = 'https://manage.office.com';
const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;
const CONTENT_TYPES = ['Audit.Exchange', 'Audit.SharePoint'];

const tokenCache = new Map();

export function validateMicrosoft(input = {}) {
  const tenantId = String(input.tenantId || '').trim();
  const clientId = String(input.clientId || '').trim();
  const clientSecret = String(input.clientSecret || '').trim();
  const guid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (!guid.test(tenantId) && !/^[a-z0-9-]+\.onmicrosoft\.com$/i.test(tenantId))
    throw new Error('Tenant ID must be the directory (tenant) ID GUID or yourtenant.onmicrosoft.com.');
  if (!guid.test(clientId)) throw new Error('Client ID must be the application (client) ID GUID.');
  if (clientSecret.length < 10) throw new Error('Client secret is missing.');
  return { config: { tenantId, clientId }, secret: { clientSecret } };
}

async function token(fetchImpl, config, secret, scope, now = Date.now()) {
  const key = `${config.tenantId}|${config.clientId}|${scope}`;
  const cached = tokenCache.get(key);
  if (cached && cached.expiresAt > now + MIN) return cached.token;
  const json = await requestJson(
    fetchImpl,
    `https://login.microsoftonline.com/${encodeURIComponent(config.tenantId)}/oauth2/v2.0/token`,
    {
      method: 'POST',
      form: { client_id: config.clientId, client_secret: secret.clientSecret, scope, grant_type: 'client_credentials' },
    },
  );
  tokenCache.set(key, { token: json.access_token, expiresAt: now + Number(json.expires_in || 3600) * 1000 });
  return json.access_token;
}

function graphClient(fetchImpl, config, secret) {
  const call = async (path, opts = {}) => {
    const bearer = await token(fetchImpl, config, secret, 'https://graph.microsoft.com/.default');
    return requestJson(fetchImpl, path.startsWith('https://') ? path : `${GRAPH}${path}`, {
      ...opts,
      headers: { authorization: `Bearer ${bearer}`, ...(opts.headers || {}) },
    });
  };
  const pages = async (path, maxPages = 10) => {
    const items = [];
    let next = path;
    for (let page = 0; next && page < maxPages; page += 1) {
      const json = await call(next);
      items.push(...(json?.value || []));
      next = json?.['@odata.nextLink'] || null;
    }
    return items;
  };
  return { call, pages };
}

// ---------- normalization (pure, exported for tests) ----------

const IGNORED_SIGNIN_CODES = new Set([
  50074, 50076, 50079, 50140, 50158, 50072, 50097, 53003, 65001, 70044, 50132, 50133, 16000, 16001, 50199, 81010, 81012,
]);

export function normalizeSignIn(row) {
  const code = Number(row?.status?.errorCode ?? 0);
  if (IGNORED_SIGNIN_CODES.has(code)) return null; // interrupts, not failures
  const geo = row?.location?.geoCoordinates;
  const type = code === 0 ? 'signin.success' : code === 500121 ? 'mfa.denied' : 'signin.failure';
  return {
    id: `ms-signin:${row.id}`,
    provider: 'microsoft',
    type,
    at: Date.parse(row.createdDateTime),
    user: { id: row.userId || null, email: String(row.userPrincipalName || '').toLowerCase() || null },
    ip: stripPort(row.ipAddress),
    geo: row.location
      ? {
          country: row.location.countryOrRegion || null,
          city: row.location.city || null,
          lat: Number(geo?.latitude),
          lon: Number(geo?.longitude),
        }
      : null,
    device: row.deviceDetail
      ? {
          id:
            row.deviceDetail.deviceId ||
            `${row.deviceDetail.operatingSystem || '?'}/${row.deviceDetail.browser || '?'}`,
          os: row.deviceDetail.operatingSystem || null,
          browser: row.deviceDetail.browser || null,
        }
      : null,
    app: row.appDisplayName || row.clientAppUsed || null,
    outcome: code === 0 ? 'success' : 'failure',
    risk: ['high'].includes(String(row.riskLevelDuringSignIn || '').toLowerCase()) ? 'high' : null,
    detail: code ? row.status?.failureReason || String(code) : null,
  };
}

const modified = (resource, name) => {
  const prop = (resource?.modifiedProperties || []).find((p) => p.displayName === name);
  if (!prop) return '';
  const value = String(prop.newValue ?? '');
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.join(' ') : String(parsed);
  } catch {
    return value.replace(/^"|"$/g, '');
  }
};

const actorOf = (row) =>
  String(row?.initiatedBy?.user?.userPrincipalName || row?.initiatedBy?.app?.displayName || '').toLowerCase() || null;

export function normalizeDirectoryAudit(row) {
  const activity = String(row?.activityDisplayName || '');
  const target = (row?.targetResources || [])[0] || {};
  const base = {
    id: `ms-audit:${row.id}`,
    provider: 'microsoft',
    at: Date.parse(row.activityDateTime),
    actor: actorOf(row),
    ip: stripPort(row?.initiatedBy?.user?.ipAddress),
  };
  if (activity === 'Add member to role' || activity === 'Add eligible member to role') {
    const role =
      (row.targetResources || []).map((r) => modified(r, 'Role.DisplayName')).find(Boolean) || target.displayName || '';
    const member = String(
      (row.targetResources || []).find((r) => r.type === 'User')?.userPrincipalName || target.userPrincipalName || '',
    ).toLowerCase();
    return { ...base, type: 'role.assigned', user: { email: member || null }, target: { role, member } };
  }
  if (activity === 'Consent to application') {
    const permissions = (row.targetResources || []).map((r) => modified(r, 'ConsentAction.Permissions')).join(' ');
    const scopes = [...permissions.matchAll(/Scope:\s*([^,\]]*)/g)]
      .flatMap((m) => m[1].trim().split(/\s+/))
      .filter(Boolean);
    const adminConsent = (row.targetResources || []).some((r) =>
      /true/i.test(modified(r, 'ConsentContext.IsAdminConsent')),
    );
    return {
      ...base,
      type: 'oauth.consent',
      user: { email: actorOf(row) },
      target: {
        app: target.displayName || 'Unknown app',
        clientId: target.id || null,
        scopes: [...new Set(scopes)],
        tenantWide: adminConsent,
      },
    };
  }
  if (activity === 'Add app role assignment to service principal') {
    const scopes = (row.targetResources || []).map((r) => modified(r, 'AppRole.Value')).filter(Boolean);
    const app =
      (row.targetResources || []).map((r) => modified(r, 'ServicePrincipal.DisplayName')).find(Boolean) ||
      target.displayName ||
      'Unknown app';
    const clientId =
      (row.targetResources || []).map((r) => modified(r, 'ServicePrincipal.ObjectID')).find(Boolean) ||
      target.id ||
      null;
    return {
      ...base,
      type: 'oauth.consent',
      user: { email: actorOf(row) },
      target: { app, clientId, scopes, tenantWide: true },
    };
  }
  if (
    [
      'Disable Strong Authentication',
      'User deleted security info',
      'Admin deleted security info',
      'Admin deleted all security info',
    ].includes(activity)
  ) {
    return {
      ...base,
      type: 'mfa.disabled',
      user: { email: String(target.userPrincipalName || actorOf(row) || '').toLowerCase() || null },
      target: { detail: activity },
    };
  }
  if (activity === 'Delete conditional access policy' || activity === 'Delete security defaults policy') {
    return {
      ...base,
      type: 'mfa.disabled',
      user: { email: actorOf(row) },
      target: { orgWide: true, detail: `${activity}${target.displayName ? ` "${target.displayName}"` : ''}` },
    };
  }
  return null;
}

const param = (record, name) => {
  const list = [...(record?.Parameters || []), ...(record?.OperationProperties || [])];
  return list.find((p) => String(p.Name).toLowerCase() === name.toLowerCase())?.Value ?? '';
};
const truthy = (value) => /^(true|1)$/i.test(String(value));
const words = (value) =>
  String(value || '')
    .split(/[;,]/)
    .map((w) => w.trim())
    .filter(Boolean);

export function normalizeManagementRecord(record) {
  const op = String(record?.Operation || '');
  const base = {
    id: `ms-mgmt:${record.Id}`,
    provider: 'microsoft',
    at: Date.parse(/Z|[+-]\d\d:?\d\d$/.test(record.CreationTime) ? record.CreationTime : `${record.CreationTime}Z`),
    user: { email: String(record.UserId || '').toLowerCase() || null },
    ip: stripPort(record.ClientIP || record.ClientIPAddress),
  };
  if (op === 'New-InboxRule' || op === 'Set-InboxRule') {
    return {
      ...base,
      type: op === 'New-InboxRule' ? 'mailrule.created' : 'mailrule.updated',
      user: {
        email:
          String(param(record, 'Mailbox') || record.UserId || '')
            .toLowerCase()
            .replace(/^.*\\/, '') || base.user.email,
      },
      target: {
        name: String(param(record, 'Name') || param(record, 'Identity') || '').replace(/^.*\\/, ''),
        forwardTo: [...emailsIn(param(record, 'ForwardTo')), ...emailsIn(param(record, 'ForwardAsAttachmentTo'))],
        redirectTo: emailsIn(param(record, 'RedirectTo')),
        delete: truthy(param(record, 'DeleteMessage')) || truthy(param(record, 'SoftDeleteMessage')),
        moveToFolder: String(param(record, 'MoveToFolder') || '').replace(/^.*\\/, '') || null,
        markAsRead: truthy(param(record, 'MarkAsRead')),
        keywords: [
          ...words(param(record, 'SubjectContainsWords')),
          ...words(param(record, 'BodyContainsWords')),
          ...words(param(record, 'SubjectOrBodyContainsWords')),
        ],
      },
    };
  }
  if (op === 'UpdateInboxRules') {
    let actions = [];
    try {
      actions = JSON.parse(param(record, 'RuleActions') || '[]');
    } catch {}
    const list = Array.isArray(actions) ? actions : [];
    const types = list.map((a) => String(a.ActionType || '').toLowerCase());
    return {
      ...base,
      type: 'mailrule.created',
      target: {
        name: String(param(record, 'RuleName') || ''),
        forwardTo: list
          .filter((a) => /forward|redirect/i.test(a.ActionType || ''))
          .flatMap((a) => emailsIn(JSON.stringify(a.Recipients || a))),
        redirectTo: [],
        delete: types.some((t) => t.includes('delete')),
        moveToFolder:
          list.find((a) => /move/i.test(a.ActionType || ''))?.FolderName ||
          (types.some((t) => t.includes('move')) ? 'unknown folder' : null),
        markAsRead: types.some((t) => t.includes('markasread')),
        keywords: words(param(record, 'RuleCondition')),
      },
    };
  }
  if (op === 'Set-Mailbox') {
    const to = emailsIn(param(record, 'ForwardingSmtpAddress') || param(record, 'ForwardingAddress'))[0];
    if (!to) return null;
    return {
      ...base,
      type: 'forwarding.set',
      user: { email: String(param(record, 'Identity') || record.UserId || '').toLowerCase() },
      target: { to },
    };
  }
  if (op === 'FileDownloaded' || op === 'FileSyncDownloadedFull') {
    return { ...base, type: 'file.download', target: { file: record.SourceFileName || record.ObjectId || null } };
  }
  if (op === 'AnonymousLinkCreated') {
    return {
      ...base,
      type: 'file.share',
      target: { file: record.SourceFileName || record.ObjectId || null, anonymous: true },
    };
  }
  if (op === 'SharingInvitationCreated' || op === 'SharingSet' || op === 'AddedToSecureLink') {
    const to = emailsIn(record.TargetUserOrGroupName)[0];
    if (!to) return null;
    return { ...base, type: 'file.share', target: { file: record.SourceFileName || record.ObjectId || null, to } };
  }
  return null;
}

// ---------- collection ----------

const iso = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
const mgmtTime = (ms) => new Date(ms).toISOString().slice(0, 19);

async function managementFeed(fetchImpl, config, secret, state, now) {
  const bearer = await token(fetchImpl, config, secret, 'https://manage.office.com/.default');
  const base = `${MANAGE}/api/v1.0/${encodeURIComponent(config.tenantId)}/activity/feed`;
  const auth = { authorization: `Bearer ${bearer}` };
  const events = [];
  const errors = [];
  state.subscribed ||= {};
  for (const contentType of CONTENT_TYPES) {
    try {
      if (!state.subscribed[contentType]) {
        try {
          await requestJson(fetchImpl, `${base}/subscriptions/start?contentType=${contentType}`, {
            method: 'POST',
            headers: auth,
            body: {},
          });
        } catch (error) {
          if (!/AF20024|already enabled/i.test(`${error.message} ${error.body}`)) throw error;
        }
        state.subscribed[contentType] = now;
      }
      // Content windows must be at most 24 hours and within the last 7 days.
      let start = Math.max(Number(state.cursors?.[contentType] || now - HOUR), now - 7 * DAY + HOUR);
      while (start < now - MIN) {
        const end = Math.min(now, start + DAY - MIN);
        let next = `${base}/subscriptions/content?contentType=${contentType}&startTime=${mgmtTime(start)}&endTime=${mgmtTime(end)}`;
        for (let page = 0; next && page < 20; page += 1) {
          const { json, headers } = await requestJson(fetchImpl, next, { headers: auth, raw: true });
          for (const blob of json || []) {
            const records = await requestJson(fetchImpl, blob.contentUri, { headers: auth });
            for (const record of records || []) {
              const event = normalizeManagementRecord(record);
              if (event && Number.isFinite(event.at)) events.push(event);
            }
          }
          next = headers?.get?.('NextPageUri') || null;
        }
        state.cursors[contentType] = end;
        start = end;
      }
    } catch (error) {
      errors.push(`${contentType}: ${error.message}`);
    }
  }
  return { events, errors };
}

export function createMicrosoftProvider({ fetchImpl = fetch } = {}) {
  return {
    id: 'microsoft',
    validate: validateMicrosoft,
    async test(connection, secret) {
      const graph = graphClient(fetchImpl, connection.config, secret);
      const org = await graph.call('/organization?$select=displayName,verifiedDomains');
      const info = org?.value?.[0] || {};
      const checks = [{ name: 'Directory', ok: true, detail: info.displayName || 'connected' }];
      try {
        await graph.call('/auditLogs/signIns?$top=1');
        checks.push({ name: 'Sign-in logs', ok: true });
      } catch (error) {
        checks.push({
          name: 'Sign-in logs',
          ok: false,
          detail: error.status === 403 ? 'Needs AuditLog.Read.All and an Entra ID P1/P2 licence.' : error.message,
        });
      }
      try {
        await token(fetchImpl, connection.config, secret, 'https://manage.office.com/.default');
        checks.push({ name: 'Mailbox and file audit', ok: true });
      } catch (error) {
        checks.push({
          name: 'Mailbox and file audit',
          ok: false,
          detail: `Needs the Office 365 Management APIs permission ActivityFeed.Read. ${error.message}`,
        });
      }
      const domains = (info.verifiedDomains || []).map((d) => String(d.name).toLowerCase());
      return { ok: checks.every((c) => c.ok), checks, domains, name: info.displayName || null };
    },
    async collect(connection, secret, { state = {}, now = Date.now() } = {}) {
      const graph = graphClient(fetchImpl, connection.config, secret);
      state.cursors ||= {};
      const events = [];
      const errors = [];
      // First sync backfills a week of sign-ins so baselines are useful from day one.
      const signInSince = Number(state.cursors.signIns || now - 7 * DAY);
      try {
        const rows = await graph.pages(
          `/auditLogs/signIns?$filter=createdDateTime ge ${iso(signInSince)}&$top=1000`,
          state.cursors.signIns ? 10 : 30,
        );
        let latest = signInSince;
        for (const row of rows) {
          const event = normalizeSignIn(row);
          if (event && Number.isFinite(event.at)) {
            events.push(event);
            latest = Math.max(latest, event.at);
          }
        }
        state.cursors.signIns = latest;
      } catch (error) {
        errors.push(`sign-ins: ${error.message}`);
      }
      const auditSince = Number(state.cursors.audits || now - DAY);
      try {
        const rows = await graph.pages(
          `/auditLogs/directoryAudits?$filter=activityDateTime ge ${iso(auditSince)}&$top=500`,
        );
        let latest = auditSince;
        for (const row of rows) {
          const event = normalizeDirectoryAudit(row);
          if (event && Number.isFinite(event.at)) {
            events.push(event);
            latest = Math.max(latest, event.at);
          }
        }
        state.cursors.audits = latest;
      } catch (error) {
        errors.push(`directory audit: ${error.message}`);
      }
      const feed = await managementFeed(fetchImpl, connection.config, secret, state, now).catch((error) => ({
        events: [],
        errors: [error.message],
      }));
      events.push(...feed.events);
      errors.push(...feed.errors);
      return { events, state, errors };
    },
    async act(connection, secret, type, params = {}, undoData = null) {
      const graph = graphClient(fetchImpl, connection.config, secret);
      const user = encodeURIComponent(String(params.user || ''));
      switch (type) {
        case 'revoke-sessions':
          await graph.call(`/users/${user}/revokeSignInSessions`, { method: 'POST' });
          return { detail: `Signed ${params.user} out of every session.` };
        case 'force-password-reset':
          await graph.call(`/users/${user}`, {
            method: 'PATCH',
            body: { passwordProfile: { forceChangePasswordNextSignIn: true } },
          });
          return { detail: `${params.user} must choose a new password at next sign-in.` };
        case 'disable-user':
          await graph.call(`/users/${user}`, { method: 'PATCH', body: { accountEnabled: false } });
          return { detail: `Disabled ${params.user}.`, undo: {} };
        case 'enable-user':
          await graph.call(`/users/${user}`, { method: 'PATCH', body: { accountEnabled: true } });
          return { detail: `Re-enabled ${params.user}.` };
        case 'remove-inbox-rule': {
          const rules = await graph.pages(`/users/${user}/mailFolders/inbox/messageRules`, 2);
          const wanted = String(params.ruleName || '').toLowerCase();
          const matches = rules.filter((r) => String(r.displayName || '').toLowerCase() === wanted);
          if (!matches.length)
            throw new ProviderError(
              `No inbox rule named "${params.ruleName}" in ${params.user}'s mailbox. It may already be gone, or it was created as a hidden rule that only Exchange PowerShell can see.`,
            );
          for (const rule of matches)
            await graph.call(`/users/${user}/mailFolders/inbox/messageRules/${encodeURIComponent(rule.id)}`, {
              method: 'DELETE',
            });
          const keep = ({ displayName, sequence, isEnabled, conditions, actions, exceptions }) => ({
            displayName,
            sequence,
            isEnabled,
            conditions,
            actions,
            exceptions,
          });
          return {
            detail: `Removed ${matches.length} rule${matches.length > 1 ? 's' : ''} named "${params.ruleName}".`,
            undo: { rules: matches.map(keep) },
          };
        }
        case 'restore-inbox-rule': {
          for (const rule of undoData?.rules || [])
            await graph.call(`/users/${user}/mailFolders/inbox/messageRules`, { method: 'POST', body: rule });
          return { detail: `Restored the inbox rule for ${params.user}.` };
        }
        case 'revoke-oauth-grant': {
          const id = encodeURIComponent(String(params.clientId || ''));
          const grants = await graph.pages(
            `/oauth2PermissionGrants?$filter=clientId eq '${String(params.clientId).replace(/'/g, "''")}'`,
            2,
          );
          const roles = await graph.pages(`/servicePrincipals/${id}/appRoleAssignments`, 2).catch(() => []);
          for (const g of grants)
            await graph.call(`/oauth2PermissionGrants/${encodeURIComponent(g.id)}`, { method: 'DELETE' });
          for (const r of roles)
            await graph.call(`/servicePrincipals/${id}/appRoleAssignments/${encodeURIComponent(r.id)}`, {
              method: 'DELETE',
            });
          if (!grants.length && !roles.length)
            throw new ProviderError(`"${params.app || params.clientId}" has no access to revoke.`);
          return {
            detail: `Revoked ${grants.length + roles.length} permission grant${grants.length + roles.length > 1 ? 's' : ''} for "${params.app || params.clientId}".`,
            undo: {
              grants: grants.map(({ clientId, consentType, principalId, resourceId, scope }) => ({
                clientId,
                consentType,
                principalId,
                resourceId,
                scope,
              })),
              roles: roles.map(({ principalId, resourceId, appRoleId }) => ({ principalId, resourceId, appRoleId })),
            },
          };
        }
        case 'restore-oauth-grant': {
          const id = encodeURIComponent(String(params.clientId || ''));
          for (const g of undoData?.grants || [])
            await graph.call('/oauth2PermissionGrants', { method: 'POST', body: g });
          for (const r of undoData?.roles || [])
            await graph.call(`/servicePrincipals/${id}/appRoleAssignments`, { method: 'POST', body: r });
          return { detail: `Restored access for "${params.app || params.clientId}".` };
        }
        default:
          throw new ProviderError(`Microsoft 365 cannot perform "${type}".`);
      }
    },
  };
}
