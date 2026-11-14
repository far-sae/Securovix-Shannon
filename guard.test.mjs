// Guard: detection rules, provider normalizers, incidents, score, WAF rules. Pure, no server.
import assert from 'node:assert/strict';
import { generateKeyPairSync, createVerify } from 'node:crypto';
import { test } from 'node:test';

const { detect, judgeInboxRule, exploitAttempts, emptyBaseline } = await import(
  './packages/dashboard/guard/detect.mjs'
);
const { groupAlerts, securityScore, recommendedActions, isTakeoverChain } = await import(
  './packages/dashboard/guard/incidents.mjs'
);
const { wafRulesForFinding, blocklistRules } = await import('./packages/dashboard/guard/waf.mjs');
const ms = await import('./packages/dashboard/guard/microsoft.mjs');
const google = await import('./packages/dashboard/guard/google.mjs');
const { containmentMet } = await import('./packages/dashboard/guard/engine.mjs');

const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;
const T0 = Date.UTC(2026, 10, 1, 9);
const LONDON = { country: 'GB', city: 'London', lat: 51.5072, lon: -0.1276 };
const LAGOS = { country: 'NG', city: 'Lagos', lat: 6.5244, lon: 3.3792 };
const PARIS = { country: 'FR', city: 'Paris', lat: 48.8566, lon: 2.3522 };
const ORG = new Set(['acme.example']);
let n = 0;
const ev = (type, at, extra = {}) => ({
  id: `e${++n}`,
  provider: 'microsoft',
  type,
  at,
  user: { email: 'amy@acme.example' },
  ip: '198.51.100.10',
  ...extra,
});
const history = (days = 14) =>
  Array.from({ length: days }, (_, d) => ev('signin.success', T0 + d * DAY, { geo: LONDON }));
const run = (events, extra = {}) => detect(events, { orgId: 'org1', connectionId: 'c1', orgDomains: ORG, ...extra });
const rules = (result) => result.alerts.map((a) => a.rule);

test('impossible travel needs distance AND speed; a VPN-sized hop or a slow trip is fine', () => {
  const start = T0 + 14 * DAY;
  const fast = run([
    ...history(),
    ev('signin.success', start, { geo: LONDON }),
    ev('signin.success', start + 30 * MIN, { geo: LAGOS, ip: '203.0.113.66' }),
  ]);
  const travel = fast.alerts.find((a) => a.rule === 'impossible-travel');
  assert.ok(travel, 'London then Lagos 30 minutes later');
  assert.equal(travel.severity, 'high');
  assert.match(travel.explanation, /London, GB.*Lagos, NG.*km away, 30 minutes later/);
  assert.equal(travel.mitre[0].id, 'T1078.004');

  const slow = run([
    ev('signin.success', T0, { geo: LONDON }),
    ev('signin.success', T0 + 10 * HOUR, { geo: LAGOS, ip: '203.0.113.66' }),
  ]);
  assert.ok(!rules(slow).includes('impossible-travel'), '10 hours is a flight');
  const near = run([
    ev('signin.success', T0, { geo: LONDON }),
    ev('signin.success', T0 + 20 * MIN, { geo: PARIS, ip: '203.0.113.7' }),
  ]);
  assert.ok(!rules(near).includes('impossible-travel'), 'London to Paris is under the distance floor');
  const unlocated = run([
    ev('signin.success', T0, { geo: LONDON }),
    ev('signin.success', T0 + 9 * HOUR, { geo: null, ip: '203.0.113.8' }),
    ev('signin.success', T0 + 10 * HOUR, { geo: LAGOS, ip: '203.0.113.9' }),
  ]);
  assert.ok(!rules(unlocated).includes('impossible-travel'), 'an unlocated sign-in does not move the anchor time');
});

test('new country waits for a mature baseline, then fires once per country', () => {
  const young = run([...history(3), ev('signin.success', T0 + 4 * DAY, { geo: PARIS })]);
  assert.ok(!rules(young).includes('new-country'), 'three days of history is still learning');
  const mature = run([
    ...history(),
    ev('signin.success', T0 + 15 * DAY, { geo: PARIS }),
    ev('signin.success', T0 + 16 * DAY, { geo: PARIS }),
  ]);
  assert.equal(mature.alerts.filter((a) => a.rule === 'new-country').length, 1);
  assert.match(mature.alerts.find((a) => a.rule === 'new-country').explanation, /first time.*GB/);
});

test('MFA fatigue: five denials alert; a success right after is critical', () => {
  const denials = Array.from({ length: 5 }, (_, i) => ev('mfa.denied', T0 + i * MIN, { ip: '203.0.113.66' }));
  const r1 = run(denials);
  assert.deepEqual(rules(r1), ['mfa-fatigue']);
  assert.equal(r1.alerts[0].severity, 'high');
  const r2 = run([...denials, ev('signin.success', T0 + 7 * MIN, { ip: '203.0.113.66' })]);
  assert.equal(r2.alerts.filter((a) => a.rule === 'mfa-fatigue').at(-1).severity, 'critical');
  assert.ok(!rules(run(denials.slice(0, 4))).includes('mfa-fatigue'), 'four is not five');
});

test('password spray (one address, many people) and brute force (one person, many tries)', () => {
  const spray = Array.from({ length: 10 }, (_, i) =>
    ev('signin.failure', T0 + i * MIN, { ip: '203.0.113.99', user: { email: `u${i}@acme.example` } }),
  );
  const r = run(spray);
  assert.deepEqual(rules(r), ['password-spray']);
  assert.equal(r.alerts[0].user, null);
  assert.equal(r.alerts[0].ip, '203.0.113.99');
  const brute = run(Array.from({ length: 10 }, (_, i) => ev('signin.failure', T0 + i * MIN)));
  assert.deepEqual(rules(brute), ['brute-force']);
  const again = run(Array.from({ length: 30 }, (_, i) => ev('signin.failure', T0 + i * 20_000)));
  assert.equal(again.alerts.length, 1, 'one alert per hour, not one per failure');
});

test('sign-ins from feed or blocklist addresses, and the provider risk flag', () => {
  const badIps = new Map([['203.0.113.50', { source: 'abuse.ch Feodo Tracker', label: 'QakBot botnet server' }]]);
  const r = run(
    [
      ev('signin.success', T0, { ip: '203.0.113.50' }),
      ev('signin.failure', T0, { ip: '203.0.113.51' }),
      ev('signin.success', T0, { risk: 'high', ip: '203.0.113.52' }),
    ],
    { badIps, blocked: new Set(['203.0.113.51']) },
  );
  const bad = r.alerts.filter((a) => a.rule === 'bad-ip-signin');
  assert.deepEqual(
    bad.map((a) => a.severity),
    ['critical', 'high'],
  );
  assert.match(bad[0].explanation, /QakBot/);
  assert.match(bad[1].explanation, /your blocklist/);
  assert.ok(rules(r).includes('provider-risk'));
});

test('inbox rules: forwarding out, hiding, lure words; an ordinary filing rule is ignored', () => {
  assert.equal(judgeInboxRule({ name: 'Newsletters', moveToFolder: 'Newsletters', keywords: ['digest'] }, ORG), null);
  assert.equal(judgeInboxRule({ forwardTo: ['boss@acme.example'] }, ORG), null, 'internal forwarding is normal');
  const fwd = judgeInboxRule({ forwardTo: ['x@proton.me'] }, ORG);
  assert.equal(fwd.severity, 'high');
  assert.ok(fwd.forwarding);
  const hide = judgeInboxRule({ moveToFolder: 'RSS Feeds', markAsRead: true, keywords: ['Invoice'] }, ORG);
  assert.equal(hide.severity, 'high', 'hiding plus a lure word');
  const r = run([
    ev('mailrule.created', T0, {
      target: { name: '.', forwardTo: ['x@proton.me'], delete: true, keywords: ['payment'] },
    }),
  ]);
  assert.deepEqual(rules(r), ['mail-forwarding']);
  assert.equal(r.alerts[0].context.ruleName, '.');
  assert.equal(r.alerts[0].mitre[0].id, 'T1114.003');
  const fw = run([
    ev('forwarding.set', T0, { target: { to: 'x@gmail.com' } }),
    ev('forwarding.set', T0, { target: { to: 'y@acme.example' } }),
  ]);
  assert.equal(fw.alerts.length, 1);
});

test('app consents: risky scopes alert, harmless or trusted apps do not', () => {
  const consent = (scopes, app = 'Mail Backup Pro', extra = {}) =>
    ev('oauth.consent', T0, { target: { app, clientId: `id-${app}`, scopes, ...extra } });
  assert.equal(run([consent(['User.Read', 'openid', 'profile'])]).alerts.length, 0);
  const risky = run([consent(['Mail.ReadWrite', 'offline_access'])]);
  assert.equal(risky.alerts[0].severity, 'medium');
  assert.deepEqual(risky.alerts[0].context.scopes, ['Mail.ReadWrite']);
  assert.equal(run([consent(['Mail.Read'], 'X', { tenantWide: true })]).alerts[0].severity, 'high');
  assert.equal(run([consent(['https://mail.google.com/'], 'Zap')], { trustedApps: new Set(['zap']) }).alerts.length, 0);
});

test('downloads: a sliding hour catches a burst across the clock hour; normal volume is quiet', () => {
  const top = Math.ceil(T0 / HOUR) * HOUR;
  const burst = Array.from({ length: 60 }, (_, i) =>
    ev('file.download', top - 30 * 1000 * 30 + i * 30_000, { target: { file: `f${i}` } }),
  );
  const r = run(burst);
  assert.deepEqual(rules(r), ['mass-download']);
  assert.equal(r.alerts[0].context.count, 50);
  assert.equal(run(burst.slice(0, 40)).alerts.length, 0);
});

test('external sharing, new admins, MFA switched off', () => {
  const r = run([
    ev('file.share', T0, { target: { file: 'Pricing.xlsx', to: 'me@gmail.com' } }),
    ev('file.share', T0, { target: { file: 'Deck.pptx', to: 'partner@acme.example' } }),
    ev('file.share', T0, { target: { file: 'All.zip', anonymous: true } }),
    ev('role.assigned', T0, {
      actor: 'amy@acme.example',
      target: { role: 'Global Administrator', member: 'eve@acme.example' },
    }),
    ev('role.assigned', T0, { target: { role: 'Reports Reader', member: 'bob@acme.example' } }),
    ev('mfa.disabled', T0, { target: { orgWide: true, detail: 'Delete conditional access policy' } }),
  ]);
  assert.deepEqual(rules(r), ['external-share', 'external-share', 'admin-granted', 'mfa-disabled']);
  assert.equal(r.alerts.find((a) => a.rule === 'admin-granted').user, 'eve@acme.example');
  assert.equal(r.alerts.find((a) => a.rule === 'mfa-disabled').severity, 'critical');
});

test('the same events processed twice raise nothing new, and baselines carry over', () => {
  const first = run([...history(), ev('signin.success', T0 + 15 * DAY, { geo: PARIS })]);
  const again = detect([ev('signin.success', T0 + 15 * DAY, { id: first.alerts[0].evidence[0].id, geo: PARIS })], {
    orgId: 'org1',
    baselines: first.baselines,
    orgState: first.orgState,
    orgDomains: ORG,
  });
  assert.equal(again.alerts.length, 0);
  assert.equal(first.baselines.get('amy@acme.example').signins, 15);
  assert.deepEqual(Object.keys(emptyBaseline('x').recent), ['mfaDenied', 'failures']);
});

// ---------- provider normalizers ----------

test('Microsoft sign-ins: success with location, MFA denial, interrupts ignored', () => {
  const row = (errorCode, extra = {}) => ({
    id: `s${errorCode}`,
    createdDateTime: '2026-11-01T09:00:00Z',
    userPrincipalName: 'Amy@Acme.example',
    userId: 'u1',
    ipAddress: '203.0.113.66',
    status: { errorCode, failureReason: 'x' },
    location: { city: 'Lagos', countryOrRegion: 'NG', geoCoordinates: { latitude: 6.52, longitude: 3.37 } },
    deviceDetail: { operatingSystem: 'Linux', browser: 'Chrome' },
    appDisplayName: 'Office 365',
    riskLevelDuringSignIn: 'high',
    ...extra,
  });
  const ok = ms.normalizeSignIn(row(0));
  assert.equal(ok.type, 'signin.success');
  assert.equal(ok.user.email, 'amy@acme.example');
  assert.deepEqual(ok.geo, { country: 'NG', city: 'Lagos', lat: 6.52, lon: 3.37 });
  assert.equal(ok.risk, 'high');
  assert.equal(ms.normalizeSignIn(row(500121)).type, 'mfa.denied');
  assert.equal(ms.normalizeSignIn(row(50126)).type, 'signin.failure');
  assert.equal(ms.normalizeSignIn(row(50074)), null, 'MFA required is an interrupt, not a failure');
});

test('Microsoft directory audit: consent scopes, admin role, MFA removal', () => {
  const consent = ms.normalizeDirectoryAudit({
    id: 'a1',
    activityDisplayName: 'Consent to application',
    activityDateTime: '2026-11-01T09:05:00Z',
    initiatedBy: { user: { userPrincipalName: 'amy@acme.example', ipAddress: '203.0.113.66' } },
    targetResources: [
      {
        id: 'sp-1',
        displayName: 'Mail Backup Pro',
        modifiedProperties: [
          { displayName: 'ConsentContext.IsAdminConsent', newValue: '"False"' },
          {
            displayName: 'ConsentAction.Permissions',
            newValue:
              '"[] => [[Id: abc, ClientId: sp-1, PrincipalId: u1, ResourceId: r1, ConsentType: Principal, Scope:  Mail.ReadWrite offline_access, CreatedDateTime: , LastModifiedDateTime ]]; "',
          },
        ],
      },
    ],
  });
  assert.equal(consent.type, 'oauth.consent');
  assert.deepEqual(consent.target.scopes, ['Mail.ReadWrite', 'offline_access']);
  assert.equal(consent.target.clientId, 'sp-1');
  assert.equal(consent.target.tenantWide, false);
  const role = ms.normalizeDirectoryAudit({
    id: 'a2',
    activityDisplayName: 'Add member to role',
    activityDateTime: '2026-11-01T09:06:00Z',
    initiatedBy: { user: { userPrincipalName: 'amy@acme.example' } },
    targetResources: [
      {
        type: 'User',
        userPrincipalName: 'Eve@acme.example',
        modifiedProperties: [{ displayName: 'Role.DisplayName', newValue: '"Global Administrator"' }],
      },
    ],
  });
  assert.deepEqual(role.target, { role: 'Global Administrator', member: 'eve@acme.example' });
  assert.equal(
    ms.normalizeDirectoryAudit({
      id: 'a3',
      activityDisplayName: 'User deleted security info',
      activityDateTime: '2026-11-01T09:07:00Z',
      targetResources: [{ userPrincipalName: 'amy@acme.example' }],
    }).type,
    'mfa.disabled',
  );
  assert.equal(
    ms.normalizeDirectoryAudit({
      id: 'a4',
      activityDisplayName: 'Update user',
      activityDateTime: '2026-11-01T09:07:00Z',
    }),
    null,
  );
});

test('Microsoft Exchange and SharePoint audit records', () => {
  const rule = ms.normalizeManagementRecord({
    Id: 'm1',
    Operation: 'New-InboxRule',
    CreationTime: '2026-11-01T09:10:00',
    UserId: 'amy@acme.example',
    ClientIP: '203.0.113.66:51234',
    Parameters: [
      { Name: 'Name', Value: '.' },
      { Name: 'ForwardTo', Value: 'SMTP:collect@proton.me' },
      { Name: 'DeleteMessage', Value: 'True' },
      { Name: 'SubjectOrBodyContainsWords', Value: 'invoice;payment' },
    ],
  });
  assert.equal(rule.type, 'mailrule.created');
  assert.equal(rule.ip, '203.0.113.66');
  assert.equal(rule.at, Date.UTC(2026, 10, 1, 9, 10));
  assert.deepEqual(rule.target.forwardTo, ['collect@proton.me']);
  assert.deepEqual(rule.target.keywords, ['invoice', 'payment']);
  assert.equal(rule.target.delete, true);
  assert.equal(
    ms.normalizeManagementRecord({
      Id: 'm2',
      Operation: 'Set-Mailbox',
      CreationTime: '2026-11-01T09:11:00',
      UserId: 'amy@acme.example',
      Parameters: [
        { Name: 'Identity', Value: 'amy@acme.example' },
        { Name: 'ForwardingSmtpAddress', Value: 'smtp:x@gmail.com' },
      ],
    }).target.to,
    'x@gmail.com',
  );
  assert.equal(
    ms.normalizeManagementRecord({
      Id: 'm3',
      Operation: 'FileDownloaded',
      CreationTime: '2026-11-01T09:12:00',
      UserId: 'amy@acme.example',
      SourceFileName: 'a.pdf',
    }).type,
    'file.download',
  );
  assert.equal(
    ms.normalizeManagementRecord({
      Id: 'm4',
      Operation: 'AnonymousLinkCreated',
      CreationTime: '2026-11-01T09:12:00',
      UserId: 'amy@acme.example',
    }).target.anonymous,
    true,
  );
  assert.equal(
    ms.normalizeManagementRecord({ Id: 'm5', Operation: 'MailItemsAccessed', CreationTime: '2026-11-01T09:12:00' }),
    null,
  );
});

test('Google Workspace activity: login, 2SV, admin, token, drive', () => {
  const item = (events, extra = {}) => ({
    id: { time: '2026-11-01T09:00:00.000Z', uniqueQualifier: 'q1' },
    actor: { email: 'Amy@acme.example' },
    ipAddress: '203.0.113.66',
    events,
    ...extra,
  });
  assert.equal(
    google.normalizeActivity(
      'login',
      item([{ name: 'login_success', parameters: [{ name: 'is_suspicious', boolValue: true }] }]),
    )[0].risk,
    'high',
  );
  assert.equal(google.normalizeActivity('login', item([{ name: 'login_failure' }]))[0].type, 'signin.failure');
  assert.equal(google.normalizeActivity('login', item([{ name: 'suspicious_login' }]))[0].type, 'signin.risk');
  assert.equal(
    google.normalizeActivity(
      'login',
      item([
        {
          name: 'login_challenge',
          parameters: [
            { name: 'login_challenge_status', value: 'Challenge Failed' },
            { name: 'login_challenge_method', multiValue: ['google_prompt'] },
          ],
        },
      ]),
    )[0].type,
    'mfa.denied',
  );
  assert.deepEqual(
    google.normalizeActivity(
      'admin',
      item([{ name: 'GRANT_ADMIN_PRIVILEGE', parameters: [{ name: 'USER_EMAIL', value: 'eve@acme.example' }] }]),
    )[0].target,
    { role: 'Super Admin', member: 'eve@acme.example' },
  );
  assert.equal(
    google.normalizeActivity(
      'admin',
      item([{ name: 'ENFORCE_STRONG_AUTHENTICATION', parameters: [{ name: 'NEW_VALUE', value: 'false' }] }]),
    )[0].target.orgWide,
    true,
  );
  const token = google.normalizeActivity(
    'token',
    item([
      {
        name: 'authorize',
        parameters: [
          { name: 'app_name', value: 'Zap' },
          { name: 'client_id', value: '123.apps' },
          { name: 'scope', multiValue: ['https://mail.google.com/', 'openid'] },
        ],
      },
    ]),
  )[0];
  assert.deepEqual(token.target.scopes, ['https://mail.google.com/', 'openid']);
  assert.equal(
    google.normalizeActivity(
      'drive',
      item([
        {
          name: 'change_document_visibility',
          parameters: [
            { name: 'visibility', value: 'people_with_link' },
            { name: 'doc_title', value: 'All' },
          ],
        },
      ]),
    )[0].target.anonymous,
    true,
  );
  assert.equal(google.normalizeActivity('user_accounts', item([{ name: '2sv_disable' }]))[0].type, 'mfa.disabled');
});

test('Google service-account assertion is a valid RS256 JWT for the admin', () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const jwt = google.signedAssertion(
    { clientEmail: 'guard@proj.iam.gserviceaccount.com', privateKey: pem },
    'admin@acme.example',
    T0,
  );
  const [h, p, sig] = jwt.split('.');
  assert.ok(createVerify('RSA-SHA256').update(`${h}.${p}`).verify(publicKey, Buffer.from(sig, 'base64url')));
  const claims = JSON.parse(Buffer.from(p, 'base64url'));
  assert.equal(claims.sub, 'admin@acme.example');
  assert.equal(claims.exp - claims.iat, 3600);
  assert.match(claims.scope, /admin\.reports\.audit\.readonly/);
  assert.throws(
    () => google.validateGoogle({ adminEmail: 'admin@acme.example', serviceAccountJson: '{"client_email":"x"}' }),
    /private_key/,
  );
  assert.throws(() => ms.validateMicrosoft({ tenantId: 'nope', clientId: 'x', clientSecret: 'y' }), /Tenant ID/);
});

// ---------- incidents, score, containment ----------

test('incidents: a suspicious sign-in plus a forwarding rule on one person is one critical takeover', () => {
  const r = run([
    ...history(),
    ev('signin.success', T0 + 14 * DAY, { geo: LONDON }),
    ev('signin.success', T0 + 14 * DAY + 20 * MIN, { geo: LAGOS, ip: '203.0.113.66' }),
    ev('mailrule.created', T0 + 14 * DAY + 25 * MIN, { target: { name: '.', forwardTo: ['x@proton.me'] } }),
    ev('signin.failure', T0 + 14 * DAY, { ip: '203.0.113.99', user: { email: 'other@acme.example' } }),
  ]);
  const { changed, created } = groupAlerts([], r.alerts, { orgId: 'org1', now: T0 + 15 * DAY });
  assert.equal(created.length, 1);
  const incident = changed[0];
  assert.equal(incident.severity, 'critical');
  assert.equal(incident.title, 'Likely account takeover: amy@acme.example');
  assert.ok(isTakeoverChain(incident.alerts));
  assert.match(incident.summary, /\*\*What happened\.\*\*/);
  assert.match(incident.summary, /T1114\.003/);
  const types = incident.actions.map((a) => a.type);
  assert.ok(types.includes('revoke-sessions') && types.includes('remove-inbox-rule'));
  assert.deepEqual(incident.actions.find((a) => a.type === 'remove-inbox-rule').params, {
    user: 'amy@acme.example',
    ruleName: '.',
  });

  // A later alert for the same person joins the same incident; a week later starts a new one.
  const later = { ...r.alerts[0], id: 'gal_new', rule: 'mfa-disabled', at: incident.lastSeenAt + HOUR };
  assert.equal(groupAlerts([incident], [later], { orgId: 'org1' }).created.length, 0);
  assert.equal(
    groupAlerts([incident], [{ ...later, id: 'gal_newer', at: incident.lastSeenAt + 7 * DAY }], { orgId: 'org1' })
      .created.length,
    1,
  );

  assert.equal(
    containmentMet(incident, [{ type: 'revoke-sessions', params: { user: 'amy@acme.example' } }]),
    false,
    'the rule is still there',
  );
  assert.equal(
    containmentMet(incident, [
      { type: 'revoke-sessions', params: { user: 'amy@acme.example' } },
      { type: 'remove-inbox-rule', params: { user: 'amy@acme.example', ruleName: '.' } },
    ]),
    true,
  );
  assert.equal(
    containmentMet(incident, [{ type: 'disable-user', params: { user: 'AMY@acme.example' } }]),
    true,
    'disabling covers everything for that person',
  );
});

test('security score explains every deduction', () => {
  const clean = securityScore({ connections: [{ provider: 'microsoft' }] });
  assert.deepEqual(clean, { score: 100, grade: 'A', deductions: [] });
  const bad = securityScore({
    connections: [{ provider: 'simulation' }],
    incidents: [
      { status: 'open', severity: 'critical' },
      { status: 'contained', severity: 'critical' },
    ],
    findings: [
      { status: 'new', severity: 'high' },
      { status: 'resolved', severity: 'critical' },
    ],
    kevMatches: [{ status: 'open', details: { kev: { cveId: 'CVE-1' } } }],
  });
  assert.equal(bad.score, 100 - 15 - 15 - 5 - 10);
  assert.equal(bad.deductions.length, 4);
  assert.equal(recommendedActions([{ recommended: ['block-ip'], ip: null }]).length, 0, 'no address, no block action');
});

// ---------- Shannon link ----------

const finding = (cls, target, extra = {}) => ({
  id: `fnd_${cls}`,
  title: `${cls} in search`,
  severity: 'high',
  status: 'new',
  details: { cls, target },
  ...extra,
});

test('WAF rules: scoped to the vulnerable path, per class; code-only classes say why not', () => {
  const sqli = wafRulesForFinding(finding('sqli', 'https://shop.example/api/search?q=1'));
  assert.equal(sqli.applicable, true);
  assert.match(sqli.cloudflare.expression, /^lower\(http\.request\.uri\.path\) eq "\/api\/search" and \(/);
  assert.match(sqli.cloudflare.expression, /contains "union select"/);
  const json = JSON.stringify(sqli.aws);
  assert.match(json, /SqliMatchStatement/);
  assert.match(json, /"UriPath"/);
  assert.equal(sqli.aws.Action.Block !== undefined, true);
  const traversal = wafRulesForFinding(finding('path-traversal', 'https://shop.example/files?name=a'));
  assert.match(traversal.cloudflare.expression, /contains "\.\.\\\\"/, 'backslash escaped in the Cloudflare string');
  const quoted = wafRulesForFinding(finding('xss', 'https://shop.example/a"b'));
  assert.match(quoted.cloudflare.expression, /eq "\/a%22b"/, 'quotes in the path cannot break out');
  assert.equal(wafRulesForFinding(finding('security-headers', 'https://shop.example/')).applicable, false);
  assert.equal(
    wafRulesForFinding(finding('secrets-exposure', 'https://shop.example/.env')).cloudflare.expression,
    'lower(http.request.uri.path) eq "/.env"',
  );
  assert.equal(wafRulesForFinding(finding('sqli', 'not a url')).applicable, false);
  assert.equal(
    blocklistRules(['203.0.113.5', '2001:db8::1']).cloudflare.expression,
    'ip.src in {203.0.113.5 2001:db8::1}',
  );
  assert.deepEqual(blocklistRules(['203.0.113.5', '2001:db8::1']).aws.ipSet.Addresses, ['203.0.113.5/32']);
  assert.equal(blocklistRules([]), null);
});

test('exploit attempts: Defender traffic that hits a proven vulnerability, by class and path', () => {
  const findings = [
    finding('sqli', 'https://shop.example/api/search?q=1'),
    finding('xss', 'https://shop.example/old', { status: 'resolved' }),
  ];
  const events = [
    {
      id: 'd1',
      cls: 'sqli',
      url: '/api/search?q=1%27%20or%201=1',
      srcIp: '203.0.113.5',
      enforced: true,
      createdAt: T0,
    },
    { id: 'd2', cls: 'sqli', url: '/api/search?q=again', srcIp: '203.0.113.5', enforced: true, createdAt: T0 + MIN },
    { id: 'd3', cls: 'xss', url: '/api/search?q=<script>', srcIp: '203.0.113.5', enforced: true, createdAt: T0 },
    { id: 'd4', cls: 'xss', url: '/old?x=<script>', srcIp: '203.0.113.6', enforced: false, createdAt: T0 },
    { id: 'd5', cls: 'sqli', url: '/api/search', srcIp: '203.0.113.7', enforced: false, createdAt: T0 - DAY },
  ];
  const alerts = exploitAttempts(events, findings, { orgId: 'org1', since: T0 - HOUR });
  assert.equal(
    alerts.length,
    1,
    'same address, same hour, same finding: one alert; resolved findings and wrong classes are ignored',
  );
  assert.equal(alerts[0].severity, 'critical');
  assert.equal(alerts[0].context.findingId, 'fnd_sqli');
  assert.equal(alerts[0].mitre[0].id, 'T1190');
  assert.match(alerts[0].explanation, /blocked this request/);
});
