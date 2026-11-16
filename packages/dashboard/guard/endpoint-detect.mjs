// Guard endpoint detection (Phase 2): events from the Guard agent in, alerts out.
//
// The agent sends process starts (with command line, parent chain and file hash), file activity
// summaries, autostart changes, logons, LSASS access (from Sysmon when installed), canary-file
// changes and its own local ransomware verdicts. Rules here are behavioural: what a command does
// (delete shadow copies, dump LSASS, fetch a payload with a built-in tool), not which malware
// family did it. Known-bad file hashes come from the sandbox and the organization's blocklist.
//
// Two principles keep the alerts trustworthy:
//   * Judge what a thing does, not how it looks. An encoded PowerShell command is decoded and
//     judged on its content; an autostart entry is judged on where its program lives, who signed
//     it and what it runs. Encoding, or being new, is not an alert by itself.
//   * Every rule is measured. accuracy-corpus.mjs holds labelled harmless and hostile samples;
//     guard-accuracy.test.mjs fails when a harmless one alerts or a hostile one is missed.
//
// Pure: state in, state out. Every pattern is linear (bounded gaps, no nested unbounded repeats).
import { createHash } from 'node:crypto';
import { MITRE, RULES, SEVERITY_RANK, mitreFor } from './catalog.mjs';

const MIN = 60_000;
const MAX_CMD = 32_768; // Windows allows command lines up to 32,767 characters
export const ENDPOINT_DEFAULTS = Object.freeze({
  renameBurst: 20, // documents renamed to an unknown or appended extension...
  renameWindow: MIN, // ...within this window
  entropyBurst: 30, // known document types rewritten as encrypted-looking data...
  entropyWindow: 30_000, // ...within this window
  highEntropy: 7.5, // bits per byte; encrypted or compressed data sits near 8
  rdpHosts: 3,
  rdpWindow: 10 * MIN,
  repeatWindow: 10 * MIN, // the same command on the same machine alerts once per window
  stopGrace: 3 * MIN, // a stopped agent that is not back by then is reported
});

// ---------- text helpers ----------

// Command lines are normalized before matching: lower case, caret escapes and quotes removed,
// typographic dashes turned into "-", whitespace collapsed. "p^o^w^e^r^s^h^e^l^l" and
// "power""shell" both become "powershell".
export function normalizeCmd(cmd) {
  return String(cmd || '')
    .slice(0, MAX_CMD)
    .toLowerCase()
    .replace(/[\u2013\u2014\u2015]/g, '-')
    .replace(/[\^"]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}
const base = (path) =>
  String(path || '')
    .toLowerCase()
    .split(/[\\/]/)
    .pop();
const count = (text, re) => (text.match(re) || []).length;
const worse = (a, b) => ((SEVERITY_RANK[b] ?? 0) > (SEVERITY_RANK[a] ?? 0) ? b : a);
const short = (text, max = 160) => String(text || '').slice(0, max);

const ENV = [
  [/%(?:systemroot|windir)%|\$env:(?:systemroot|windir)\b/g, 'c:\\windows'],
  [/%programfiles(?:\(x86\))?%|\$env:programfiles\b/g, 'c:\\program files'],
  [/%(?:programdata|allusersprofile)%|\$env:(?:programdata|allusersprofile)\b/g, 'c:\\programdata'],
  [/%localappdata%|\$env:localappdata\b/g, 'c:\\users\\_\\appdata\\local'],
  [/%appdata%|\$env:appdata\b/g, 'c:\\users\\_\\appdata\\roaming'],
  [/%te?mp%|\$env:te?mp\b/g, 'c:\\users\\_\\appdata\\local\\temp'],
  [/%public%|\$env:public\b/g, 'c:\\users\\public'],
  [/%(?:userprofile|homepath)%|\$env:(?:userprofile|homepath)\b|\$home\b/g, 'c:\\users\\_'],
  [/%systemdrive%|\$env:systemdrive\b/g, 'c:'],
];
const expandEnv = (lower) => {
  if (!lower.includes('%') && !lower.includes('$')) return lower;
  let out = lower;
  for (const [re, value] of ENV) out = out.replace(re, value);
  return out;
};

// ---------- where a file lives ----------

// 'protected': only administrators/root can write there (Program Files, Windows, /usr, /opt).
// 'temp': temporary, download and world-writable drop folders, where malware lands first.
// 'user': anywhere else an ordinary account can write (profile, AppData, ProgramData, /home).
// 'remote': a network share. 'unknown': a bare name, found through PATH.
export function locate(path) {
  let s = String(path || '')
    .toLowerCase()
    .trim()
    .replace(/^["']|["']$/g, '');
  if (!s) return 'unknown';
  if (s.startsWith('/') && !s.startsWith('//')) {
    if (/^\/(?:tmp|dev\/shm|var\/tmp|run\/shm)\//.test(s)) return 'temp';
    if (/^\/(?:usr|bin|sbin|lib|lib32|lib64|opt|snap|etc|nix|boot|system|library|applications)\//.test(s))
      return 'protected';
    return 'user';
  }
  if (s.startsWith('~/')) return 'user';
  s = s
    .replace(/\//g, '\\')
    .replace(/^\\\\\?\\/, '')
    .replace(/^\\\?\?\\/, '')
    .replace(/^\\systemroot\\/, 'c:\\windows\\');
  if (/^(?:system32|syswow64)\\/.test(s)) s = `c:\\windows\\${s}`;
  if (s.startsWith('\\\\')) return 'remote';
  if (!/^[a-z]:\\/.test(s)) return 'unknown';
  const rest = s.slice(2);
  if (
    /^\\(?:windows\\(?:temp|tasks|tracing|debug|fonts|system32\\spool\\drivers\\color)|perflogs|\$recycle\.bin|users\\public|temp|tmp)\\/.test(
      rest,
    ) ||
    rest.includes('\\appdata\\local\\temp\\') ||
    /^\\users\\[^\\]{1,64}\\downloads\\/.test(rest)
  )
    return 'temp';
  if (/^\\(?:windows|program files|program files \(x86\)|programdata\\microsoft\\windows defender)\\/.test(rest))
    return 'protected';
  return 'user';
}

const EXEC_EXT = new Set(
  'exe dll sys com scr pif cpl ocx bat cmd ps1 psm1 vbs vbe js jse wsf wsh hta msi msp jar py lnk inf sct xsl sh'.split(
    ' ',
  ),
);
const PATH_STOP = new Set(['"', '<', '>', '|', '*', '?', '\r', '\n', "'"]);

// Windows paths named in a command. A path ends at the first program or script extension
// followed by a word boundary, so unquoted paths with spaces ("C:\Program Files\App\a.exe /s")
// are read whole. `exec` is false when no such extension was found (a data file or a folder).
function windowsPaths(lower) {
  const out = [];
  const start = /(?:[a-z]:\\|\\\\[a-z0-9._$-]{1,64}\\)/g;
  let m = start.exec(lower);
  while (m && out.length < 24) {
    const from = m.index;
    const limit = Math.min(lower.length, from + 400);
    let end = -1;
    let firstBreak = -1;
    for (let j = from + m[0].length; j < limit; j++) {
      const ch = lower[j];
      if (PATH_STOP.has(ch) || (ch === ':' && j > from + 1)) {
        if (firstBreak < 0) firstBreak = j;
        break;
      }
      if ((ch === ' ' || ch === ',') && firstBreak < 0) firstBreak = j;
      if (ch === '.') {
        let k = j + 1;
        while (k < limit && k - j <= 5 && /[a-z0-9]/.test(lower[k])) k++;
        const after = lower[k];
        if (EXEC_EXT.has(lower.slice(j + 1, k)) && (after === undefined || /[\s"',;)|&<>]/.test(after))) {
          end = k;
          break;
        }
      }
    }
    const exec = end > 0;
    const stop = exec ? end : firstBreak > 0 ? firstBreak : limit;
    out.push({ path: lower.slice(from, stop), index: from, end: stop, exec });
    start.lastIndex = Math.max(stop, from + m[0].length);
    m = start.exec(lower);
  }
  return out;
}

const UNIX_WRAPPERS = new Set(
  'sudo env exec nohup nice ionice timeout flock setsid stdbuf time command test [ if then do else'.split(' '),
);
const UNIX_SHELLS = new Set('sh bash dash zsh ksh ash busybox python python2 python3 perl ruby php node'.split(' '));
const UNIX_PATH = /^(?:~\/[\w.@+-]|\/[\w.@+-]+\/)[\w.@+/-]*$/;

// Programs and scripts in command position on a Unix command line (cron job, systemd ExecStart,
// shell command): the first word of each simple command, and the script handed to an
// interpreter. Arguments are data and are not reported, so "rsync /home/a /mnt/b" names rsync only.
function unixPrograms(text) {
  const out = [];
  // A cron file holds one job per line, each with its own schedule in front.
  const parts = String(text || '')
    .slice(0, 4096)
    .split('\n')
    .slice(0, 40)
    .flatMap((line) =>
      line
        .trim()
        .replace(/^(?:@[a-z]+|(?:[\d*/,-]+\s+){5})\s*/i, '')
        .split(/&&|\|\||[;|]|\$\(|`/),
    );
  for (const part of parts.slice(0, 60)) {
    const words = part.trim().split(/\s+/).filter(Boolean);
    let i = 0;
    let taken = 0;
    while (i < words.length && taken < 2) {
      const word = words[i].replace(/^["'(]+|["')]+$/g, '');
      i++;
      if (!word || /^[A-Za-z_][A-Za-z0-9_]*=/.test(word) || word.startsWith('-')) continue;
      const name = base(word);
      // "/usr/bin/x" or "~/x", never a Windows switch such as "/create" or "/i:http://…".
      const pathLike = UNIX_PATH.test(word);
      if (pathLike) out.push(word);
      if (UNIX_WRAPPERS.has(name)) continue;
      // The account column of /etc/cron.d lines ("root /usr/bin/x"): a bare word before a path.
      if (!pathLike && taken === 0 && /^[a-z_][a-z0-9_-]{0,31}$/i.test(word) && UNIX_PATH.test(words[i] || ''))
        continue;
      taken += 1;
      if (!UNIX_SHELLS.has(name.replace(/[\d.]+$/, ''))) break;
    }
  }
  return out;
}

// ---------- PowerShell ----------

const POWERSHELL = new Set(['powershell.exe', 'pwsh.exe', 'pwsh', 'powershell']);
const MENTIONS_POWERSHELL = /(?:^|[\\/ '(&|;])(?:powershell|pwsh)(?:\.exe)?(?: |$)/;
const ENCODED =
  /[ ]-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand) ([a-z0-9+/=]{16,})/;
const ENCODED_RAW = /[\s][-/\u2013\u2014\u2015]e[a-z]{0,13}\s+["']?([A-Za-z0-9+/=]{16,})/i;
const HIDDEN_WINDOW = / -w[a-z]{0,10} ?(?:hidden|hidde|hidd|hid|hi|h|1)\b/;
const NETWORK =
  /(?:downloadstring|downloaddata|downloadfile|net\.webclient|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|start-bitstransfer|httpwebrequest|net\.http|xmlhttp|\bcurl(?:\.exe)? |\bwget(?:\.exe)? )/;
const RUNS_CODE = /(?:\biex\b|invoke-expression|scriptblock\]::create|\.invoke\(|invokescript|invoke-command)/;
const DOWNLOAD_CRADLE =
  /(?:iex|invoke-expression)[^\n]{0,300}(?:downloadstring|downloaddata|invoke-webrequest|iwr |net\.webclient|invoke-restmethod|irm )|(?:downloadstring|invoke-webrequest|iwr |net\.webclient|invoke-restmethod|irm )[^\n]{0,300}(?:\| ?iex|\| ?invoke-expression)/;
// Guard's own install command (Guard page > Add a machine): it downloads the agent from the
// Guard server and installs it. Seen when a machine that already runs Guard is updated. The
// match needs both the agent download address and the install step that follows it.
const GUARD_INSTALL =
  /\/api\/endpoint-agent\/v1\/download\/(?:linux|windows|macos)\b[^\n]{0,700}securovix-guard(?:\.exe)? install --server /;
const SAVES_DOWNLOAD = /(?:-outfile|downloadfile\(|start-bitstransfer|\bcurl(?:\.exe)? [^\n|]{0,300} -o )/;
const RUNS_AFTER =
  /(?:start-process|invoke-item|\bsaps\b|rundll32|regsvr32|msiexec|mshta|wscript|cscript|\biex\b|invoke-expression|; ?& ?[$'(a-z]|; ?\.\\|; ?start )/;
const ATTACK_TOOLS =
  /(?:invoke-mimikatz|invoke-kerberoast|invoke-bloodhound|sharphound|powerview|invoke-shellcode|invoke-reflectivepeinjection|powersploit|invoke-powershelltcp|invoke-smbexec|invoke-wmiexec|invoke-thehash|get-gpppassword|invoke-dcsync|invoke-psexec|invoke-obfuscation|powercat|out-minidump|invoke-ninjacopy|get-keystrokes|invoke-tokenmanipulation|invoke-credentialinjection|invoke-rubeus|invoke-seatbelt|invoke-dllinjection)/;

export function decodeEncodedCommand(b64, max = 300) {
  try {
    const text = Buffer.from(String(b64 || ''), 'base64').toString('utf16le');
    return text.replace(/[^\x20-\x7e]/g, '').slice(0, max);
  } catch {
    return '';
  }
}

// How much of a decoded payload is ordinary text. Random bytes decode to mostly unprintable
// characters; a real script is nearly all printable.
function readable(b64) {
  try {
    const text = Buffer.from(String(b64 || ''), 'base64').toString('utf16le');
    if (!text.length) return 0;
    let ok = 0;
    for (let i = 0; i < text.length; i++) {
      const c = text.charCodeAt(i);
      if ((c >= 0x20 && c <= 0x7e) || c === 10 || c === 13 || c === 9) ok++;
    }
    return ok / text.length;
  } catch {
    return 0;
  }
}

/**
 * What a PowerShell command line does, after decoding any -EncodedCommand payload.
 * @returns {{ encoded, decoded, decodedNorm, hidden, findings: Array<{id, severity, what}>, severity, rule }}
 */
export function analyzePowershell(cmd, raw = '') {
  const original = ENCODED.test(` ${cmd}`) ? ENCODED_RAW.exec(` ${String(raw).slice(0, MAX_CMD)}`)?.[1] : null;
  const encoded = ENCODED.test(` ${cmd}`);
  const decodedFull = original ? decodeEncodedCommand(original, 16_000) : '';
  const decodedNorm = normalizeCmd(decodedFull);
  const text = decodedNorm ? `${cmd}\n${decodedNorm}` : cmd;
  // Obfuscation is measured on text that still has its quotes and backticks.
  const loose = `${String(raw).slice(0, MAX_CMD).toLowerCase()}\n${decodedFull.toLowerCase()}`;
  const hidden = HIDDEN_WINDOW.test(` ${cmd}`);
  const findings = [];
  const add = (id, severity, what) => findings.push({ id, severity, what });

  if (
    /(?:virtualalloc|virtualprotect|createthread|writeprocessmemory|getdelegateforfunctionpointer|ntcreatethreadex|queueuserapc|rtlmovememory)/.test(
      text,
    )
  )
    add('shellcode', 'critical', 'loads raw machine code into memory and runs it');
  if (/(?:amsiutils|amsiinitfailed|amsiscanbuffer|amsicontext|etweventwrite)/.test(text))
    add('amsi-bypass', 'critical', 'switches off the Windows script scanner (AMSI) before running');
  if (ATTACK_TOOLS.test(text)) add('attack-tool', 'critical', 'runs a known attack tool');
  if (
    /(?:net\.sockets\.tcpclient|net\.sockets\.tcplistener|system\.net\.sockets\.socket)/.test(text) &&
    /(?:getstream|streamreader|streamwriter|\biex\b|invoke-expression)/.test(text)
  )
    add('reverse-shell', 'critical', 'opens a network connection and runs whatever commands arrive over it');
  if (DOWNLOAD_CRADLE.test(text))
    add('cradle', encoded || hidden ? 'critical' : 'high', 'downloads code and runs it straight from memory');
  if (SAVES_DOWNLOAD.test(text) && RUNS_AFTER.test(text) && !GUARD_INSTALL.test(text))
    add('download-run', 'high', 'downloads a file and runs it in the same command');
  if (/frombase64string/.test(text) && RUNS_CODE.test(text))
    add('decode-run', 'high', 'unpacks hidden code and runs it');
  if (/assembly\]::load\(/.test(text) && /(?:frombase64string|downloaddata|\[byte\[\]\]|readallbytes)/.test(text))
    add('memory-load', 'high', 'loads a program into memory without a file');
  if (hidden && NETWORK.test(text)) add('hidden-network', 'high', 'runs with its window hidden and uses the network');

  let obfuscation = 0;
  if (count(loose, /\[char\]/g) >= 4) obfuscation += 2;
  if (count(loose, /[a-z]`[a-z]/g) >= 4) obfuscation += 2;
  if (count(loose, /['"]\s?\+\s?['"]/g) >= 6) obfuscation += 2;
  if (/-bxor/.test(loose)) obfuscation += 2;
  if (/\$(?:env:[a-z]+|pshome|shellid)\[\d/.test(loose)) obfuscation += 3;
  if (count(loose, /\{\d\}/g) >= 4 && /-f\s?['"(]/.test(loose)) obfuscation += 2;
  if (/\[-1\.\.-|\[array\]::reverse/.test(loose)) obfuscation += 2;
  if (count(loose, /-replace|\.replace\(/g) >= 4) obfuscation += 1;
  if (obfuscation >= 3 || (obfuscation >= 2 && RUNS_CODE.test(text)))
    add('obfuscated', 'high', 'is deliberately disguised (obfuscated) so it cannot be read at a glance');

  if (encoded && original && readable(original) < 0.7)
    add('unreadable', 'medium', 'carries a hidden (encoded) command that Guard could not read');

  const severity = findings.reduce((s, f) => worse(s, f.severity), null);
  return {
    encoded,
    hidden,
    decoded: decodedFull.slice(0, 300),
    decodedNorm,
    findings,
    severity,
    rule: findings.some((f) => f.id === 'reverse-shell') ? 'reverse-shell' : 'encoded-powershell',
  };
}

// ---------- rule tables ----------

const SHADOW = [
  /vssadmin(?:\.exe)? delete shadows/,
  /vssadmin(?:\.exe)? resize shadowstorage/,
  /wmic(?:\.exe)? shadowcopy [^\n]{0,120}delete/,
  /wbadmin(?:\.exe)? (?:delete (?:catalog|systemstatebackup|backup)|disable backup)/,
  /bcdedit(?:\.exe)? \/set (?:\{[a-z0-9-]{1,40}\} )?recoveryenabled no/,
  /bcdedit(?:\.exe)? \/set (?:\{[a-z0-9-]{1,40}\} )?bootstatuspolicy ignoreallfailures/,
  /win32_shadowcopy[^\n]{0,200}(?:remove-|delete)/,
  /diskshadow(?:\.exe)? [^\n]{0,80}delete shadows/,
  /reagentc(?:\.exe)? \/disable/,
  /\bsc(?:\.exe)? config vss start= ?disabled|\bnet1?(?:\.exe)? stop vss\b/,
];
const CREDENTIAL = [
  { re: /(?:sekurlsa::|lsadump::|kerberos::|mimikatz)/, mitre: 'T1003_1', what: 'a Mimikatz command' },
  {
    re: /comsvcs(?:\.dll)?[ ,#]+(?:#\+?0{0,6}24|minidump)/,
    mitre: 'T1003_1',
    what: 'the comsvcs.dll MiniDump trick to copy LSASS memory',
  },
  { re: /procdump(?:64)?(?:\.exe)? [^\n]{0,200}lsass/, mitre: 'T1003_1', what: 'ProcDump against LSASS' },
  {
    re: /(?:rdrleakdiag(?:\.exe)? [^\n]{0,80}\/fullmemdmp|sqldumper(?:\.exe)? \d+ 0 0x0?1[01]00?|tttracer(?:\.exe)? [^\n]{0,80}lsass|createdump(?:\.exe)? [^\n]{0,80}lsass)/,
    mitre: 'T1003_1',
    what: 'a Windows diagnostic tool used to copy LSASS memory',
  },
  {
    re: /\b(?:nanodump|lsassy|dumpert|pypykatz|safetykatz|sharpdump|handlekatz|lazagne|secretsdump|rubeus|sharphound|mimipenguin)\b/,
    mitre: 'T1003_1',
    what: 'a password-stealing tool',
  },
  {
    re: /reg(?:\.exe)? (?:save|export) (?:hklm|hkey_local_machine)\\(?:sam|security|system)\b/,
    mitre: 'T1003_2',
    what: 'a copy of the SAM/SECURITY registry hive',
  },
  {
    re: /harddiskvolumeshadowcopy\d{0,4}\\windows\\(?:ntds\\ntds\.dit|system32\\config\\(?:sam|security|system))\b/,
    mitre: 'T1003_2',
    what: 'password databases copied out of a shadow copy',
  },
  {
    re: /ntdsutil(?:\.exe)? [^\n]{0,120}(?:ifm|ac i ntds)/,
    mitre: 'T1003_3',
    what: 'ntdsutil copying the domain password database',
  },
  { re: /\\windows\\ntds\\ntds\.dit/, mitre: 'T1003_3', what: 'access to the domain password database (ntds.dit)' },
  {
    re: /findstr(?:\.exe)? [^\n]{0,80}cpassword/,
    mitre: 'T1003_1',
    what: 'a search for passwords stored in Group Policy files',
    severity: 'high',
  },
  {
    re: /netsh(?:\.exe)? wlan show profiles? [^\n]{0,120}key=clear/,
    mitre: 'T1003_1',
    what: 'saved Wi-Fi passwords shown in clear text',
    severity: 'medium',
  },
  {
    re: /\b(?:cat|less|more|head|tail|cp|scp|base64|xxd|strings|tar [^\n|;]{0,40}) [^\n|;]{0,60}\/etc\/shadow\b/,
    mitre: 'T1003_8',
    what: 'the Linux password file (/etc/shadow) read or copied',
    severity: 'high',
  },
];
const PROXY_DLL_EXPORTS =
  /(?:advpack\.dll,(?:launchinfsection|registerocx)|ieadvpack\.dll,launchinfsection|setupapi\.dll,installhinfsection|pcwutl\.dll,launchapplication|zipfldr\.dll,routethecall|mshtml(?:\.dll)?,runhtmlapplication|dfshim\.dll,shopenverbapplication|syssetup\.dll,setupinfobjectinstallaction|ieframe\.dll,openurl|shdocvw\.dll,openurl)/;
// rundll32 url.dll,FileProtocolHandler <web address> only opens the browser; anything else it is
// handed (a program, a script, a file: address) is being run through it.
const URL_DLL = /url\.dll,(?:openurl|fileprotocolhandler) ?(\S{0,300})/;
const LOLBIN = [
  { proc: 'certutil.exe', re: /-(?:urlcache|verifyctl)[^\n]{0,200}https?:/, what: 'certutil downloading a file' },
  { proc: 'certutil.exe', re: /-decode(?:hex)? /, what: 'certutil unpacking an encoded file' },
  { proc: 'bitsadmin.exe', re: /\/(?:transfer|addfile) /, what: 'bitsadmin downloading a file' },
  { proc: 'mshta.exe', re: /(?:https?:|javascript:|vbscript:)/, what: 'mshta running a remote or inline script' },
  { proc: 'rundll32.exe', re: /javascript:/, what: 'rundll32 running a script' },
  { proc: 'rundll32.exe', re: PROXY_DLL_EXPORTS, what: 'rundll32 used to start another program or install file' },
  {
    proc: 'rundll32.exe',
    test: (cmd) => {
      const m = URL_DLL.exec(cmd);
      return !!m && !/^https?:\/\/\S+$/.test(m[1]);
    },
    what: 'rundll32 used to launch a file through url.dll',
  },
  {
    proc: 'rundll32.exe',
    re: /shell32\.dll,shellexec_rundll/,
    what: 'rundll32 used to launch another program',
  },
  { proc: 'regsvr32.exe', re: /(?:\/i:https?:|scrobj\.dll)/, what: 'regsvr32 running a remote scriptlet' },
  { proc: 'msiexec.exe', re: /[/-](?:i|package|a)[^\n]{0,20}https?:/, what: 'msiexec installing from the internet' },
  { proc: 'msiexec.exe', re: /[/-][yz] /, what: 'msiexec used to register a DLL' },
  { proc: 'wmic.exe', re: /\/format:[^\n]{0,20}(?:https?:|\\\\)/, what: 'wmic loading a remote stylesheet (script)' },
  { proc: 'cmstp.exe', re: /\/(?:s|ni|au)\b[^\n]{0,200}\.inf/, what: 'cmstp installing a profile that runs a program' },
  { proc: 'installutil.exe', re: /\/u\b|\/logfile= ?\S{0,3}(?: |$)/, what: 'InstallUtil used to run code' },
  { proc: 'odbcconf.exe', re: /(?:[/-]a ?\{? ?regsvr|[/-]f )/, what: 'odbcconf used to load a DLL' },
  { proc: 'mavinject.exe', re: /\/injectrunning/, what: 'mavinject injecting a DLL into another process' },
  { proc: 'mavinject64.exe', re: /\/injectrunning/, what: 'mavinject injecting a DLL into another process' },
  { proc: 'pcalua.exe', re: / -a /, what: 'pcalua used to start another program' },
  {
    proc: 'msdt.exe',
    re: /(?:it_browseforfile|it_rebrowseforfile|\$\()/,
    what: 'the Windows troubleshooter used to run a command (the "Follina" trick)',
  },
  {
    proc: null,
    re: /\bbase64 (?:-d|--decode)[^\n|]{0,200}\| ?(?:sudo )?(?:ba|z|da|k)?sh\b/,
    what: 'hidden (base64) commands unpacked and run by a shell',
  },
  {
    proc: null,
    re: /\b(?:curl|wget)(?:\.exe)? [^\n|;&]{0,300}(?: -o ?| --output | -O ?)\S{1,200}\.(?:exe|dll|ps1|bat|cmd|vbs|js|hta|scr|msi)\b[^\n]{0,200}(?:&&?|;) ?(?:start |cmd |powershell|rundll32|regsvr32|msiexec|wscript|cscript|mshta|\S{1,200}\.(?:exe|bat|cmd|scr)\b)/,
    what: 'a program downloaded and run in the same command',
  },
  {
    proc: null,
    test: (cmd) =>
      /\b(?:curl|wget) [^\n|;&]{0,300}(?: -o ?| -O ?| --output )\S{1,200}[^\n]{0,120}(?:&&|;) ?(?:chmod \+x|(?:sudo )?(?:ba)?sh |\.\/)/.test(
        cmd,
      ) && !GUARD_INSTALL.test(cmd),
    what: 'a file downloaded, made executable and run in the same command',
  },
];
// A script fetched and piped straight into a shell. Installers do this too, so a named HTTPS
// site is a medium; a bare address or plain HTTP is how attackers serve it.
const PIPE_TO_SHELL =
  /(?:\b(?:curl|wget)\b[^|\n]{0,300}\| ?(?:sudo )?(?:(?:ba|z|da|k)?sh|python[\d.]*|perl)\b|\b(?:ba|z)?sh (?:-c )?[^\n]{0,20}(?:\$\(|<\() ?(?:curl|wget)\b)/;
const UNSAFE_SOURCE = /(?:http:\/\/|https?:\/\/\d{1,3}(?:\.\d{1,3}){3}\b)/;
const REVERSE_SHELL = [
  /\/dev\/(?:tcp|udp)\/[\w.-]{1,80}\/\d{1,5}/,
  /\bn(?:c|cat|etcat)(?:\.exe)? [^\n|]{0,120}(?: -e ?| --exec | -c )(?:\/bin\/|cmd|powershell|(?:ba)?sh\b)/,
  /\bmkfifo [^\n]{0,120}\| ?n(?:c|cat) /,
  /\bsocat [^\n]{0,160}exec:/,
  /\bpython[\d.]* -c [^\n]{0,600}socket[^\n]{0,600}(?:subprocess|pty\.spawn|os\.dup2)/,
  /\bperl -e [^\n]{0,400}socket[^\n]{0,400}(?:exec|open\(std)/,
  /\bphp -r [^\n]{0,300}fsockopen/,
  /\bruby -rsocket/,
];
const MINER =
  /(?:\bxmrig\b|\bminerd\b|\bcpuminer|\bnbminer\b|\blolminer\b|\bphoenixminer\b|\bethminer\b|stratum\+(?:tcp|ssl|tls):\/\/|--donate-level|--coin[= ]monero|--algo[= ](?:rx\/|randomx|cn\/|cryptonight)|\b(?:pool\.minexmr|supportxmr|nanopool|moneroocean|c3pool)\.)/;
const OFFICE = new Set([
  'winword.exe',
  'excel.exe',
  'powerpnt.exe',
  'outlook.exe',
  'onenote.exe',
  'msaccess.exe',
  'mspub.exe',
  'visio.exe',
  'eqnedt32.exe',
  'acrord32.exe',
  'acrobat.exe',
  'foxitpdfreader.exe',
]);
const SHELLS = new Set([
  'cmd.exe',
  'powershell.exe',
  'pwsh.exe',
  'wscript.exe',
  'cscript.exe',
  'mshta.exe',
  'rundll32.exe',
  'regsvr32.exe',
  'certutil.exe',
  'bitsadmin.exe',
  'msbuild.exe',
  'installutil.exe',
  'schtasks.exe',
  'wmic.exe',
  'curl.exe',
  'msiexec.exe',
  'mavinject.exe',
  'cmstp.exe',
]);
const WEB_SERVERS =
  /^(?:w3wp\.exe|httpd(?:\.exe)?|apache2?(?:\.exe)?|nginx(?:\.exe)?|php-fpm[\d.]*|php-cgi(?:\.exe)?|tomcat\d*(?:\.exe)?|uwsgi|caddy(?:\.exe)?)$/;
const WEB_CHILD_SHELLS = new Set(['cmd.exe', 'powershell.exe', 'pwsh.exe', 'sh', 'bash', 'dash', 'zsh']);
const WEB_RECON =
  /\b(?:whoami|id|uname -a|cat \/etc\/passwd|ifconfig|ipconfig|netstat|ps aux|net user|systeminfo|wget |curl |nc |ncat |python[\d.]* -c|perl -e|base64 -d|chmod \+x)|\/dev\/tcp\//;
const LATERAL = [
  {
    re: /\b(?:psexec(?:64)?|paexec)(?:\.exe)? [^\n]{0,40}\\\\/,
    mitre: 'T1021_2',
    what: 'PsExec running a command on another machine',
  },
  {
    re: /wmic(?:\.exe)? [^\n]{0,40}\/node:[^\n]{0,200}process call create/,
    mitre: 'T1047',
    what: 'WMI starting a process on another machine',
  },
  {
    re: /(?:invoke-wmimethod|invoke-cimmethod)[^\n]{0,200}-computername[^\n]{0,200}(?:win32_process|create)/,
    mitre: 'T1047',
    what: 'WMI starting a process on another machine',
  },
  {
    re: /\bwinrs(?:\.exe)? [^\n]{0,20}-r(?:emote)?:/,
    mitre: 'T1021_6',
    what: 'WinRS running a command on another machine',
  },
  {
    re: /(?:invoke-command|enter-pssession|new-pssession)[^\n]{0,200}-computername/,
    mitre: 'T1021_6',
    what: 'PowerShell remoting to another machine',
  },
  {
    re: /cmd(?:\.exe)? \/q \/c [^\n]{0,300}\\\\127\.0\.0\.1\\admin\$/,
    mitre: 'T1021_2',
    what: 'remote command execution over an admin share (the wmiexec/smbexec pattern)',
  },
  {
    re: /\bsc(?:\.exe)? \\\\[\w.-]{1,80} (?:create|start|config)\b/,
    mitre: 'T1021_2',
    what: 'a service created or started on another machine',
  },
  {
    re: /schtasks(?:\.exe)? \/create[^\n]{0,300} \/s [\w.-]{1,80}/,
    mitre: 'T1053_5',
    what: 'a scheduled task created on another machine',
  },
  {
    re: /\b(?:smbexec|wmiexec|atexec|dcomexec|crackmapexec|netexec|evil-winrm|impacket)\b/,
    mitre: 'T1021_2',
    what: 'a remote-execution attack tool',
  },
  {
    re: /gettypefromprogid\([^)]{1,80},[^)]{1,80}\)/,
    mitre: 'T1021_3',
    what: 'a DCOM object created on another machine to run a command',
  },
];
const AV_SERVICES =
  '(?:windefend|wdnissvc|sense|mpssvc|wscsvc|eventlog|sysmon(?:64)?|mcshield|mfemms|mfefire|sophos\\w*|savservice|csfalconservice|sentinelagent|cbdefense|ekrn|avp|bdservicehost)';
const AV_PROCESSES =
  '(?:msmpeng|mssense|nissrv|sysmon(?:64)?|mcshield|mfemms|csfalconservice|sentinelagent|sophos\\w*|ekrn|avp|bdservicehost)';
const EVASION = [
  {
    re: /set-mppreference[^\n]{0,200}-disable(?:realtimemonitoring|ioavprotection|behaviormonitoring|scriptscanning|blockatfirstseen|archivescanning|intrusionpreventionsystem)[: ]{1,2}(?:\$true|1)/,
    mitre: 'T1562_1',
    what: 'Microsoft Defender protection switched off',
  },
  {
    re: /add-mppreference[^\n]{0,200}-exclusion(?:path|process|extension)/,
    mitre: 'T1562_1',
    what: 'an exclusion added to Microsoft Defender',
    // An exclusion for one working folder is routine; one for a drive, a drop folder, a program
    // type or a script host tells Defender to look away from where malware runs.
    severity: (cmd) =>
      /-exclusion(?:extension|process)|-exclusionpath ['(]?(?:[a-z]:\\?['),]?(?: |$)|[^\n]{0,80}(?:\\temp\b|\\appdata\b|\\users\\public\b|\\programdata\b|\\downloads\b|\\windows\b))/.test(
        expandEnv(cmd),
      )
        ? 'high'
        : 'medium',
  },
  {
    re: new RegExp(
      `\\bsc(?:\\.exe)? (?:stop|delete) ${AV_SERVICES}\\b|\\bsc(?:\\.exe)? config ${AV_SERVICES} start= ?disabled|\\bnet1?(?:\\.exe)? stop ${AV_SERVICES}\\b|stop-service[^\\n]{0,40} ${AV_SERVICES}\\b`,
    ),
    mitre: 'T1562_1',
    what: 'a security service stopped or disabled',
  },
  {
    re: new RegExp(`taskkill(?:\\.exe)? [^\\n]{0,80}/im ${AV_PROCESSES}(?:\\.exe)?\\b`),
    mitre: 'T1562_1',
    what: 'a security program killed',
  },
  {
    re: /reg(?:\.exe)? add [^\n]{0,160}(?:disableantispyware|disableantivirus|disablerealtimemonitoring|disablebehaviormonitoring|disableonaccessprotection|disablescanonrealtimeenable)[^\n]{0,60}\/d ?0{0,7}1\b/,
    mitre: 'T1562_1',
    what: 'Microsoft Defender switched off in the registry',
  },
  {
    re: /mpcmdrun(?:\.exe)? [^\n]{0,40}-removedefinitions/,
    mitre: 'T1562_1',
    what: 'Microsoft Defender signatures removed',
  },
  { re: /fltmc(?:\.exe)? unload sysmon|\bsysmon(?:64)?(?:\.exe)? -u\b/, mitre: 'T1562_1', what: 'Sysmon unloaded' },
  {
    re: /(?:\bsc(?:\.exe)? (?:stop|delete|config) securovixguard\b|\bnet1?(?:\.exe)? stop securovixguard\b|stop-service[^\n]{0,40}securovixguard|taskkill(?:\.exe)? [^\n]{0,80}securovix-guard|securovix-guard(?:\.exe)? uninstall\b|systemctl (?:stop|disable|mask|kill) (?:--now )?securovix-guard|\b(?:pkill|killall)(?: -\d+| -[a-z]+)* securovix-guard)/,
    mitre: 'T1562_1',
    what: 'the Securovix Guard agent stopped or removed by command',
  },
  {
    re: /netsh(?:\.exe)? (?:advfirewall set (?:all|current|domain|private|public)profiles? state off|firewall set opmode disable)|set-netfirewallprofile[^\n]{0,120}-enabled[: ]{1,2}(?:false|\$false|0)\b/,
    mitre: 'T1562_4',
    what: 'the firewall switched off',
  },
  { re: /\bwevtutil(?:\.exe)? (?:cl|clear-log) /, mitre: 'T1070_1', what: 'an event log cleared' },
  { re: /\b(?:clear-eventlog|remove-eventlog)\b/, mitre: 'T1070_1', what: 'an event log cleared' },
  { re: /\bwevtutil(?:\.exe)? sl [^\n]{0,80}\/e:false/, mitre: 'T1562_2', what: 'an event log switched off' },
  {
    re: /auditpol(?:\.exe)? (?:\/clear|\/remove|\/set [^\n]{0,120}(?:success|failure):disable)/,
    mitre: 'T1562_2',
    what: 'Windows audit logging switched off',
  },
  { re: /fsutil(?:\.exe)? usn deletejournal/, mitre: 'T1070_4', what: 'the file-change journal deleted' },
  {
    re: /bcdedit(?:\.exe)? \/set (?:\{[a-z0-9-]{1,40}\} )?(?:testsigning on|nointegritychecks on|safeboot )/,
    mitre: 'T1562_1',
    what: 'Windows start-up protection changed (test signing, integrity checks or safe mode)',
  },
  {
    re: /\b(?:setenforce 0|systemctl (?:stop|disable|mask) (?:--now )?(?:auditd|falcon-sensor|apparmor|firewalld|ufw)|auditctl -e ?0|ufw disable|iptables -f\b|iptables --flush)/,
    mitre: 'T1562_1',
    what: 'Linux security controls switched off',
  },
  {
    re: /(?:\bhistory -c\b|\bunset histfile\b|\bhistfile=\/dev\/null|\bhistsize=0\b|\b(?:rm|shred|truncate)\b[^\n;|&]{0,60}(?:\.bash_history|\.zsh_history|\/var\/log\/(?:auth\.log|secure|wtmp|btmp|lastlog|syslog|messages))|ln -sf? \/dev\/null [^\n]{0,60}_history)/,
    mitre: 'T1070_3',
    what: 'command history or system logs wiped',
  },
];
const ACCESSIBILITY = '(?:sethc|utilman|osk|magnify|narrator|displayswitch|atbroker)';
const PERSIST_CMD = [
  {
    re: new RegExp(`image file execution options\\\\${ACCESSIBILITY}\\.exe[^\\n]{0,80}debugger`),
    mitre: 'T1546_8',
    what: 'a sign-in screen accessibility tool replaced with another program (a hidden back door)',
    severity: 'critical',
  },
  {
    re: new RegExp(
      `\\b(?:copy|move|xcopy|robocopy|copy-item|move-item)\\b[^\\n]{0,200}\\\\system32\\\\${ACCESSIBILITY}\\.exe`,
    ),
    mitre: 'T1546_8',
    what: 'a sign-in screen accessibility tool overwritten (a hidden back door)',
    severity: 'critical',
  },
  {
    re: /(?:__eventfilter|commandlineeventconsumer|activescripteventconsumer|__filtertoconsumerbinding)/,
    mitre: 'T1546_3',
    what: 'a WMI event subscription that runs a command by itself',
    severity: 'high',
  },
  {
    re: /reg(?:\.exe)? add [^\n]{0,80}\\currentversion\\winlogon[^\n]{0,40}\/v (?:shell|userinit)\b/,
    mitre: 'T1547_4',
    what: 'the Windows sign-in program changed',
    severity: 'high',
  },
  {
    re: /\bnet1?(?:\.exe)? localgroup (?:administrators|remote desktop users|administrateurs|administratoren) [^\n]{1,80} \/add\b/,
    mitre: 'T1136_1',
    what: 'an account added to the administrators or remote-desktop group',
    severity: 'high',
  },
  {
    re: /\buser(?:add|mod)\b[^\n]{0,120}(?: -o [^\n]{0,40}-u 0\b| -u 0\b[^\n]{0,40} -o\b| -g 0\b| -ag? (?:sudo|wheel|root)\b)/,
    mitre: 'T1136_1',
    what: 'an account created or changed to have root rights',
    severity: 'high',
  },
  {
    re: /(?:>>?|\btee(?: -a)?) ?\/etc\/ld\.so\.preload\b/,
    mitre: 'T1574_6',
    what: 'a library forced into every program (ld.so.preload)',
    severity: 'high',
  },
  {
    re: /\\start menu\\programs\\startup\\[^\n]{0,120}\.(?:exe|bat|cmd|vbs|js|lnk|ps1|hta|scr)\b/,
    mitre: 'T1547_1',
    what: 'a file placed in the Startup folder',
    payload: true,
  },
  { re: /schtasks(?:\.exe)? \/create\b/, mitre: 'T1053_5', what: 'a scheduled task created', payload: true },
  {
    re: /(?:register-scheduledtask|new-scheduledtaskaction)\b/,
    mitre: 'T1053_5',
    what: 'a scheduled task created',
    payload: true,
  },
  { re: /\bsc(?:\.exe)? create\b|\bnew-service\b/, mitre: 'T1543_3', what: 'a Windows service created', payload: true },
  {
    re: /reg(?:\.exe)? add [^\n]{0,40}\\(?:software\\microsoft\\windows\\currentversion\\run(?:once)?)\b/,
    mitre: 'T1547_1',
    what: 'a Run key added',
    payload: true,
  },
  {
    re: /(?:>>?|\btee(?: -a)?) ?(?:\/etc\/cron[\w./-]{0,80}|\/var\/spool\/cron[\w./-]{0,80}|\/etc\/rc\.local|\/etc\/profile\.d\/[\w.-]{1,80}|\/etc\/systemd\/system\/[\w.@-]{1,80})/,
    mitre: 'T1053_3',
    what: 'a start-up or scheduled job written',
    payload: true,
  },
];
const PERSIST_KIND = {
  'run-key': 'T1547_1',
  'startup-folder': 'T1547_1',
  service: 'T1543_3',
  'scheduled-task': 'T1053_5',
  cron: 'T1053_3',
  systemd: 'T1543_2',
  'launch-agent': 'T1543_1',
  'shell-profile': 'T1546_4',
  'ssh-key': 'T1098_4',
};

// Programs that exist to run other code. In an autostart entry, what matters is what they are
// told to run. PROXY hosts have almost no legitimate reason to run something from a folder any
// user can write to; general interpreters sometimes do (an admin's own script).
const PROXY_HOSTS = new Set(
  'wscript cscript mshta rundll32 regsvr32 msiexec odbcconf installutil regasm regsvcs msbuild cmstp forfiles'.split(
    ' ',
  ),
);
const GENERAL_HOSTS = new Set(
  'powershell pwsh cmd python pythonw python3 node java javaw bash sh perl ruby php conhost'.split(' '),
);
const hostName = (exe) => base(exe).replace(/\.exe$/, '');
const CMD_HOUSEKEEPING =
  /^\S+ (?:\/[a-z] ){0,4}\/c (?:if (?:not )?exist \S{1,300} )?(?:del|erase|rd|rmdir|md|mkdir|echo|rem|exit|ver|cls|title)\b[^&|\n]{0,600}$/;
const INLINE_RISK = [
  {
    re: /(?:mshta(?:\.exe)? [^\n]{0,40}(?:https?:|javascript:|vbscript:)|regsvr32[^\n]{0,80}\/i:https?:|rundll32[^\n]{0,80}javascript:)/,
    what: 'runs a script from the internet or written inline',
  },
  {
    re: /(?:certutil[^\n]{0,80}-urlcache|bitsadmin[^\n]{0,40}\/transfer|msiexec[^\n]{0,40}https?:)/,
    what: 'downloads a program each time it starts',
  },
  { re: PIPE_TO_SHELL, what: 'downloads a script and runs it each time it starts' },
  { re: /\bbase64 (?:-d|--decode)[^\n|]{0,200}\|/, what: 'unpacks hidden (base64) commands and runs them' },
  { re: /\/dev\/(?:tcp|udp)\/|\bn(?:c|cat) [^\n]{0,80}-e /, what: 'opens a remote shell' },
  { re: /\b(?:curl|wget)\b[^\n]{0,200}https?:/, what: 'downloads from the internet each time it starts' },
];

/**
 * How risky it is for this command to start by itself (a Run key, service, scheduled task, cron
 * line, systemd unit, or the payload of schtasks/sc/reg add).
 * @param {string} raw the command as written
 * @param {object} info { os, signer: { status: 'valid'|'invalid'|'unsigned' }, packageOwner, embedded }
 * @returns {{ level: 'none'|'medium'|'high', why: string, target: string|null }}
 */
export function commandRisk(raw, info = {}) {
  const text = String(raw || '').slice(0, 4096);
  // Driver and service paths come in kernel spellings: \??\C:\…, \SystemRoot\…, system32\….
  const lower = expandEnv(text.toLowerCase())
    .replace(/^(\s*"?)(?:\\\?\?\\|\\\\\?\\)/, '$1')
    .replace(/^(\s*"?)\\systemroot\\/, '$1c:\\windows\\')
    .replace(/^(\s*"?)(?=(?:system32|syswow64)\\)/, '$1c:\\windows\\');
  const cmd = normalizeCmd(lower);
  const none = { level: 'none', why: '', target: null };
  if (!cmd || cmd === 'com handler' || cmd === 'multiple actions') return none;
  const signed = info.signer?.status === 'valid';
  const unsigned = info.signer?.status === 'unsigned' || info.signer?.status === 'invalid';

  const os = String(info.os || '').toLowerCase();
  const win = os === 'linux' || os === 'macos' ? [] : windowsPaths(lower);
  const unix = os !== 'windows' && /(?:^|\s)[/~]/.test(text) ? unixPrograms(text) : [];
  let main = null;
  if (!info.embedded) {
    const t = lower.trim();
    if (t.startsWith('"')) main = t.slice(1, t.indexOf('"', 1) > 0 ? t.indexOf('"', 1) : undefined);
    else if (win[0]?.index === 0) main = win[0].path;
    else if (!unix.length) main = t.split(/\s/)[0];
  }
  const target = main || win.find((p) => p.exec)?.path || unix[0] || null;

  if (MENTIONS_POWERSHELL.test(cmd)) {
    const ps = analyzePowershell(cmd, text);
    const worst = ps.findings.find((f) => f.severity === ps.severity);
    if (worst && ps.severity !== 'medium') return { level: 'high', why: `it ${worst.what}`, target };
    if (ps.hidden && !win.some((p) => p.exec && p.path !== main && locate(p.path) === 'protected'))
      return { level: 'high', why: 'it runs PowerShell with the window hidden', target };
  }
  const inline = INLINE_RISK.find((r) => r.re.test(cmd));
  if (inline) return { level: 'high', why: `it ${inline.what}`, target };

  const host = main ? hostName(main) : null;
  // "cmd /c del <file>" tidies a file up; the path it names is data, not something being run.
  if (host === 'cmd' && CMD_HOUSEKEEPING.test(cmd)) return none;
  const viaProxy = host
    ? PROXY_HOSTS.has(host)
    : [...PROXY_HOSTS].some((p) => new RegExp(`\\b${p}(?:\\.exe)?\\b`).test(cmd));
  const viaGeneral = host ? GENERAL_HOSTS.has(host) : false;
  // What a host program is told to run: for proxies any path counts (they load .dat and .tmp
  // files as code), for everything else only programs and scripts.
  const handed = win.filter((p) => p.path !== main && (p.exec || viaProxy));
  for (const p of handed) {
    const loc = locate(p.path);
    if (loc === 'temp')
      return {
        level: 'high',
        why: `it starts ${p.path}, which sits in a temporary or download folder`,
        target: p.path,
      };
    if (loc === 'remote' && (viaProxy || viaGeneral || info.embedded))
      return { level: 'medium', why: `it starts ${p.path} from a network share`, target: p.path };
    if (loc === 'user' && viaProxy)
      return {
        level: 'high',
        why: `it uses ${host || 'a system tool'} to run ${p.path}, a file any user account can change`,
        target: p.path,
      };
    if (loc === 'user' && (viaGeneral || info.embedded)) {
      if (info.embedded && unsignedHome(p.path))
        return { level: 'high', why: `it starts ${p.path} from a user profile folder`, target: p.path };
      return { level: 'medium', why: `it runs ${p.path}, a file any user account can change`, target: p.path };
    }
  }
  for (const p of unix) {
    const loc = locate(p);
    if (loc === 'temp') return { level: 'high', why: `it starts ${p}, which sits in a temporary folder`, target: p };
    if (loc === 'user' && !info.packageOwner)
      return { level: 'medium', why: `it starts ${p}, which is outside the system folders`, target: p };
  }
  if (main && !viaProxy && !viaGeneral) {
    // A Store app's shortcut sits in the user profile; the program itself is in a protected folder.
    const loc = info.resolved && locate(info.resolved) === 'protected' ? 'protected' : locate(main);
    if (loc === 'temp')
      return signed
        ? {
            level: 'medium',
            why: `it starts ${main} from a temporary or download folder (the program is signed)`,
            target: main,
          }
        : { level: 'high', why: `it starts ${main}, which sits in a temporary or download folder`, target: main };
    if (loc === 'remote') return { level: 'medium', why: `it starts ${main} from a network share`, target: main };
    if (loc === 'user' && !signed) {
      // AppData\Local\Programs is where per-user installers put applications, and small vendors
      // often do not sign. Anywhere else, an unsigned program that starts itself is a red flag.
      if (unsigned)
        return {
          level: main.includes('\\appdata\\local\\programs\\') ? 'medium' : 'high',
          why: `it starts ${main}, an unsigned program in a folder any user account can change`,
          target: main,
        };
      if (unsignedHome(main))
        return { level: 'high', why: `it starts ${main} from a user profile folder`, target: main };
      return {
        level: 'medium',
        why: `it starts ${main}, which is outside the protected program folders`,
        target: main,
      };
    }
  }
  if (
    (viaGeneral || (!host && MENTIONS_POWERSHELL.test(cmd))) &&
    !handed.length &&
    /(?:powershell|pwsh)(?:\.exe)? [^\n]{0,80}(?:-c(?:ommand)? |-e[a-z]{0,13} )/.test(cmd)
  )
    return { level: 'medium', why: 'it runs a PowerShell command written into the entry itself', target };
  return none;
}
// AppData\Roaming with no signature information is the classic malware autostart location.
const unsignedHome = (path) => path.includes('\\appdata\\roaming\\');

// ---------- processes that are not what they claim ----------

const SYSTEM_NAMES = new Set(
  'svchost.exe lsass.exe csrss.exe smss.exe winlogon.exe services.exe wininit.exe explorer.exe spoolsv.exe taskhostw.exe dllhost.exe conhost.exe rundll32.exe lsm.exe dwm.exe ctfmon.exe searchindexer.exe runtimebroker.exe sihost.exe fontdrvhost.exe wmiprvse.exe regsvr32.exe mshta.exe wscript.exe cscript.exe'.split(
    ' ',
  ),
);
const DOUBLE_EXT =
  /\.(?:pdf|docx?|xlsx?|pptx?|txt|rtf|csv|jpe?g|png|gif|zip|mp[34]|html?)\s{0,40}\.(?:exe|scr|com|pif|bat|cmd|js|jse|vbs|vbe|hta|lnk|wsf)$/;
const DROP_DIR =
  /^[a-z]:\\(?:users\\public\\(?!desktop\\)|perflogs\\|\$recycle\.bin\\|windows\\(?:fonts|tasks|debug|tracing|system32\\spool\\drivers\\color)\\)/;
const WSH = new Set(['wscript.exe', 'cscript.exe', 'mshta.exe']);
const WSH_SCRIPT = /\.(?:js|jse|vbs|vbe|wsf|wsh|hta)$/;
const INSTALLER_PARENT = /^(?:msiexec\.exe|.{1,60}\.tmp|.{0,40}(?:setup|install|update|unins)\w{0,40}\.exe)$/;

// ---------- ransomware: which file changes count ----------

const DATA_EXT = new Set(
  'doc docx docm dot dotx xls xlsx xlsm xlsb ppt pptx pptm pdf txt rtf csv tsv odt ods odp md json xml html htm jpg jpeg png gif bmp tif tiff psd ai svg mp3 wav mp4 mov avi mkv zip rar 7z sql db sqlite mdb accdb pst ost msg eml vsd vsdx dwg dxf indd key pages numbers tex py js ts java c cpp h cs go rs php rb kt swift'.split(
    ' ',
  ),
);
const KNOWN_EXT = new Set([
  ...DATA_EXT,
  ...'tmp bak old orig part partial crdownload download opdownload temp swp swo lock lck lnk url ini log dat bin exe dll msi iso img gz bz2 xz zst tar tgz cab jar apk torrent ics vcf cfg conf yaml yml toml css scss less map woff woff2 ttf otf ico webp heic heif raw cr2 nef arw dng m4a m4v flac ogg webm wmv epub mobi azw3 srt vtt sig asc sha256 sha1 md5 sum patch diff rej idx pack rev'.split(
    ' ',
  ),
]);
const NOISY_DIR =
  /[\\/](?:\.git|\.svn|\.hg|node_modules|\.venv|venv|__pycache__|\.cache|\.gradle|\.m2|\.nuget|\.cargo|target|\.next|\.vs|\.idea|\$recycle\.bin|appdata)[\\/]/;
const extOf = (path) => {
  const name = base(path);
  const dot = name.lastIndexOf('.');
  return dot > 0 ? name.slice(dot + 1) : '';
};
// "report.docx.locked": a known document type with one more extension added on the end.
function appendedTo(path) {
  const name = base(path);
  const last = name.lastIndexOf('.');
  if (last <= 0) return null;
  const inner = name.slice(0, last);
  const dot = inner.lastIndexOf('.');
  if (dot <= 0) return null;
  const innerExt = inner.slice(dot + 1);
  const outer = name.slice(last + 1);
  return DATA_EXT.has(innerExt) && !KNOWN_EXT.has(outer) && outer.length <= 12 ? outer : null;
}
/** A rename that looks like encryption: a document given an unknown or appended extension. */
export function suspiciousRename(oldPath, newPath) {
  if (NOISY_DIR.test(String(newPath || '').toLowerCase())) return false;
  const from = extOf(oldPath);
  const to = extOf(newPath);
  if (!to || to === from || to.length > 12) return false;
  if (appendedTo(newPath)) return true;
  return DATA_EXT.has(from) && !KNOWN_EXT.has(to);
}
/** An encrypted-looking write that says something: a known document type, or an appended extension. */
export function suspiciousWrite(path) {
  const lower = String(path || '').toLowerCase();
  if (NOISY_DIR.test(lower)) return false;
  return DATA_EXT.has(extOf(lower)) || !!appendedTo(lower);
}

// Security products that read LSASS memory as part of their job. Only trusted from a folder that
// needs administrator rights to write to: the name alone proves nothing.
const LSASS_BENIGN = new Set(
  'msmpeng.exe mssense.exe csrss.exe wininit.exe services.exe lsm.exe wmiprvse.exe svchost.exe securovix-guard.exe mrt.exe taskmgr.exe vmtoolsd.exe mcshield.exe mfemms.exe mfefire.exe csfalconservice.exe sentinelagent.exe sentinelservicehost.exe cb.exe repmgr.exe avp.exe ekrn.exe bdservicehost.exe savservice.exe sophosfilescanner.exe wrsa.exe cylancesvc.exe elastic-endpoint.exe sysmon.exe sysmon64.exe'.split(
    ' ',
  ),
);
const VM_READ = 0x10;

function alertId(orgId, rule, key) {
  return `gal_${createHash('sha256').update(`${orgId}|${rule}|${key}`).digest('hex').slice(0, 24)}`;
}
const digest = (text) => createHash('sha256').update(String(text)).digest('hex').slice(0, 16);
// The parts of a command or path that stay the same between runs and between people: account
// names, version numbers, GUIDs and process ids are blanked.
const shape = (text) =>
  String(text || '')
    .toLowerCase()
    .replace(/\\users\\[^\\]{1,64}\\/g, '\\users\\*\\')
    .replace(/\/home\/[^/]{1,64}\//g, '/home/*/')
    .replace(/\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?/g, '#')
    .replace(/\b[0-9a-f]{8,}\b/g, '#')
    .replace(/\d{2,}/g, '#');
/** What an owner can mark as expected: one exact command, or one file. */
export const commandTrust = (scan, shown) => ({
  fp: `cmd:${digest(shape(scan))}`,
  label: `the command "${short(shown, 140)}"`,
});
export const fileTrust = (path) => ({ fp: `file:${digest(shape(path))}`, label: String(path) });

export function emptyHostState() {
  return { renames: [], entropy: [], seen: [] };
}

function trim(list, now, window) {
  while (list.length && list[0][0] < now - window) list.shift();
  if (list.length > 5000) list.splice(0, list.length - 5000);
}

/**
 * @param {Array} events agent events
 * @param {object} state { orgId, hosts: { [hostId]: hostState }, org: { rdp: [] }, hashes: Map<sha256, info>, allow: Set }
 */
export function detectEndpoint(events, state) {
  const opts = { ...ENDPOINT_DEFAULTS, ...(state.options || {}) };
  const orgId = state.orgId;
  const hosts = state.hosts || {};
  const org = state.org || { rdp: [] };
  org.rdp ||= [];
  const hashes = state.hashes || new Map();
  const allow = new Set([...(state.allow || [])].map((x) => String(x).toLowerCase()));
  // Commands and files the organization marked as expected. Only alerts that carry a `trust`
  // fingerprint can be silenced this way; ransomware, credential theft and the like never do.
  const trusted = new Set((org.trusted || []).map((t) => t.fp));
  const alerts = new Map();

  const raise = (rule, event, { key, severity, explanation, context = {}, mitre, trust }) => {
    if (trust && trusted.has(trust.fp)) return;
    const id = alertId(orgId, rule, `${event.host?.id}|${key}`);
    if (alerts.has(id)) return;
    // The file a response would act on (quarantine, send to the sandbox). A program in a
    // protected folder is part of Windows or installed software: the tool an attacker used
    // (reg.exe, powershell.exe, bash), not the thing to remove. Only a file proven malicious by
    // its hash is offered from there.
    let subject = Object.hasOwn(context, 'path')
      ? context.path
      : event.file?.path || event.persistence?.path || event.process?.path || null;
    if (subject && rule !== 'malicious-file' && locate(subject) === 'protected') subject = null;
    alerts.set(id, {
      id,
      orgId,
      connectionId: null,
      rule,
      title: RULES[rule].title,
      severity,
      at: event.at,
      user: null,
      host: { id: event.host?.id || null, name: event.host?.name || null },
      ip: event.logon?.source || null,
      mitre: mitre ? mitre.map((m) => MITRE[m]).filter(Boolean) : mitreFor(rule),
      explanation,
      trust: trust && severity !== 'critical' ? trust : undefined,
      evidence: [
        {
          id: event.id,
          type: event.type,
          at: event.at,
          user: event.user || event.process?.user || null,
          ip: event.logon?.source || null,
          place: event.host?.name || null,
          app: event.process?.name || null,
          outcome: event.detail?.killed ? 'process stopped by agent' : null,
          target: {
            pid: event.process?.pid ?? null,
            cmdline: event.process?.cmdline ? String(event.process.cmdline).slice(0, 1000) : undefined,
            parents: event.process?.parents?.slice(0, 6),
            path: event.file?.path || event.process?.path || event.persistence?.path || undefined,
            sha256: event.file?.sha256 || event.process?.sha256 || undefined,
            autostart: event.persistence
              ? {
                  kind: event.persistence.kind || null,
                  name: event.persistence.name || null,
                  command: short(event.persistence.command, 600) || null,
                  signer: event.persistence.signer || undefined,
                }
              : undefined,
          },
        },
      ],
      recommended: RULES[rule].actions,
      context: {
        pid: event.process?.pid ?? event.detail?.pid ?? null,
        processName: event.process?.name || event.detail?.process || null,
        sha256: event.file?.sha256 || event.process?.sha256 || null,
        ...context,
        path: subject,
      },
    });
  };

  const sorted = [...(events || [])]
    .filter((e) => e && Number.isFinite(e.at) && e.host?.id)
    .sort((a, b) => a.at - b.at);
  for (const event of sorted) {
    if (!hosts[event.host.id]) hosts[event.host.id] = emptyHostState();
    const host = hosts[event.host.id];
    if (event.id) {
      if (host.seen.includes(event.id)) continue;
      host.seen.push(event.id);
      if (host.seen.length > 2000) host.seen.splice(0, host.seen.length - 2000);
    }
    const where = event.host.name || 'a machine';
    const proc = event.process || {};
    const name = base(proc.name || proc.path);
    const cmd = normalizeCmd(proc.cmdline);
    const sha = String(event.file?.sha256 || proc.sha256 || '').toLowerCase();
    if ((sha && allow.has(sha)) || (proc.path && allow.has(String(proc.path).toLowerCase()))) continue;
    const parents = (proc.parents || []).map((p) => base(p.name || p.path || p));
    const quote = proc.cmdline ? ` ("${short(proc.cmdline)}")` : '';

    if (sha && hashes.has(sha)) {
      const info = hashes.get(sha);
      raise('malicious-file', event, {
        key: `${sha}|${proc.pid ?? event.file?.path ?? ''}`,
        severity: 'critical',
        explanation: `${where} ${event.type === 'process.start' ? `ran ${proc.path || name}` : `wrote ${event.file?.path || 'a file'}`}, which is known malware${info.family ? ` (${info.family})` : ''} — ${info.source || 'Securovix sandbox'} verdict for SHA-256 ${sha.slice(0, 16)}….`,
        // The agent may already have stopped or quarantined it on its own (malware.blocked).
        context: {
          family: info.family || null,
          killed: !!event.detail?.killed,
          quarantined: !!event.detail?.quarantined,
        },
      });
    }

    switch (event.type) {
      case 'process.start': {
        // Hidden PowerShell is decoded first, and every rule below reads the decoded text too:
        // "vssadmin delete shadows" is the same act whether typed or base64-encoded.
        const ps = POWERSHELL.has(name) || MENTIONS_POWERSHELL.test(cmd) ? analyzePowershell(cmd, proc.cmdline) : null;
        const scan = ps?.decodedNorm ? `${cmd} ${ps.decodedNorm}` : cmd;
        // The same command from a parent and its child, or run again and again, is one alert.
        const key = `${digest(scan)}|${Math.floor(event.at / opts.repeatWindow)}`;
        const path = String(proc.path || '').toLowerCase();
        const cmdTrust = commandTrust(
          scan,
          ps?.encoded && ps.decoded ? `${name} (hidden script: ${ps.decoded})` : proc.cmdline,
        );

        if (SHADOW.some((re) => re.test(scan))) {
          raise('shadow-copy-deletion', event, {
            key,
            severity: 'critical',
            explanation: `${where} ran a command that deletes Windows backups or turns off recovery${quote}. Ransomware does this just before it encrypts, so the files cannot be restored.`,
          });
        }
        const cred = CREDENTIAL.find((c) => c.re.test(scan));
        if (cred) {
          raise('credential-dumping', event, {
            key,
            severity: cred.severity || 'critical',
            mitre: [cred.mitre],
            explanation: `${where} ran ${cred.what}${quote}. Whoever did this is collecting passwords to move to other machines.`,
          });
        }
        const lol = LOLBIN.find((l) => (!l.proc || l.proc === name) && (l.test ? l.test(scan) : l.re.test(scan)));
        if (lol) {
          raise('lolbin-abuse', event, {
            key,
            severity: 'high',
            explanation: `${where}: ${lol.what}${quote}. Attackers use built-in tools like this so no new program has to be installed.`,
            trust: cmdTrust,
          });
        } else if (PIPE_TO_SHELL.test(scan)) {
          const unsafe = UNSAFE_SOURCE.test(scan);
          raise('lolbin-abuse', event, {
            key,
            severity: unsafe ? 'high' : 'medium',
            trust: cmdTrust,
            explanation: `${where}: a script was downloaded and handed straight to a shell${quote}. ${unsafe ? 'It came from a bare address or over plain HTTP, which is how attackers serve these.' : 'Software installers do this too: check that this was a deliberate install from a site you trust.'}`,
          });
        }
        // rundll32 / regsvr32 loading a file from a folder any user can write to.
        if (
          (name === 'rundll32.exe' || name === 'regsvr32.exe') &&
          !lol &&
          !parents.some((p) => INSTALLER_PARENT.test(p))
        ) {
          const loaded = windowsPaths(expandEnv(String(proc.cmdline || '').toLowerCase())).find(
            (p) => base(p.path) !== name && ['temp', 'user'].includes(locate(p.path)),
          );
          if (loaded)
            raise('lolbin-abuse', event, {
              key,
              // Temp, ProgramData and AppData\Roaming are where these DLLs are dropped; a per-user
              // application folder is less telling.
              severity:
                locate(loaded.path) === 'temp' || /\\programdata\\|\\appdata\\roaming\\/.test(loaded.path)
                  ? 'high'
                  : 'medium',
              explanation: `${where}: ${name} loaded ${loaded.path}, a file in a folder any user account can write to${quote}. Malware is often delivered as a DLL and started this way.`,
              context: { path: loaded.path },
              trust: fileTrust(loaded.path),
            });
        }
        if (name === 'msbuild.exe') {
          const project = windowsPaths(expandEnv(String(proc.cmdline || '').toLowerCase())).find(
            (p) => base(p.path) !== name,
          );
          if (project && (locate(project.path) === 'temp' || /\.(?:xml|txt|tmp)$/.test(project.path)))
            raise('lolbin-abuse', event, {
              key,
              severity: 'high',
              explanation: `${where}: MSBuild was pointed at ${project.path}${quote}. A build file can carry code that runs as it is "built", which gets past application allow-lists.`,
              trust: fileTrust(project.path),
            });
        }
        if (WSH.has(name)) {
          const script = windowsPaths(expandEnv(String(proc.cmdline || '').toLowerCase())).find((p) =>
            WSH_SCRIPT.test(p.path),
          );
          const loc = script ? locate(script.path) : null;
          if (script && (loc === 'temp' || loc === 'user' || loc === 'remote'))
            raise('risky-script', event, {
              key,
              severity: loc === 'temp' || /\\appdata\\|\\programdata\\/.test(script.path) ? 'high' : 'medium',
              mitre: [/\.(?:js|jse)$/.test(script.path) ? 'T1059_7' : 'T1059_5'],
              explanation: `${where} ran the script ${script.path} with ${name}${quote}. ${loc === 'temp' ? 'Scripts opened from a download, an email attachment or a temporary folder are a common way malware starts.' : 'It sits in a folder any user account can write to, and script hosts are a common way malware starts and keeps itself running.'}`,
              context: { path: script.path },
              trust: fileTrust(script.path),
            });
        }
        if (ps?.severity) {
          const worst = ps.findings.find((f) => f.severity === ps.severity);
          const others = ps.findings.filter((f) => f !== worst).map((f) => f.what);
          raise(ps.rule, event, {
            key,
            severity: ps.severity,
            explanation: `${where} ran PowerShell that ${worst.what}${others.length ? ` (it also ${others.slice(0, 2).join(', and ')})` : ''}${ps.encoded && ps.decoded ? `. The command was hidden (base64); it decodes to: "${ps.decoded}"` : quote}.`,
            context: ps.decoded ? { decoded: ps.decoded } : {},
            trust: ps.rule === 'reverse-shell' ? undefined : cmdTrust,
          });
        }
        if (REVERSE_SHELL.some((re) => re.test(scan))) {
          raise('reverse-shell', event, {
            key,
            severity: 'critical',
            explanation: `${where} opened a command shell to another computer${quote}. Whoever is on the other end can now type commands on this machine.`,
          });
        }
        if (MINER.test(scan)) {
          raise('cryptominer', event, {
            key,
            severity: 'high',
            explanation: `${where} started a cryptocurrency miner${quote}. Someone is using this machine's processor for their own profit, which usually means they already have a way in.`,
          });
        }
        if (SHELLS.has(name) && parents.some((p) => OFFICE.has(p))) {
          raise('office-spawned-shell', event, {
            key,
            severity: 'high',
            explanation: `${parents.find((p) => OFFICE.has(p))} started ${name} on ${where}${quote}. Documents do not normally start command shells; this is how macro malware runs.`,
          });
        }
        if (parents[0] && WEB_SERVERS.test(parents[0]) && WEB_CHILD_SHELLS.has(name)) {
          const windows = name.endsWith('.exe');
          if (windows || WEB_RECON.test(scan))
            raise('webshell', event, {
              key,
              severity: REVERSE_SHELL.some((re) => re.test(scan)) || PIPE_TO_SHELL.test(scan) ? 'critical' : 'high',
              explanation: `The web server (${parents[0]}) on ${where} started a command shell${quote}. A website should not be running system commands like this: someone may have planted a web shell.`,
            });
        }
        const lateral =
          LATERAL.find((l) => l.re.test(scan)) ||
          (name === 'psexesvc.exe'
            ? { mitre: 'T1021_2', what: 'the PsExec service running a command sent from another machine' }
            : null);
        if (lateral) {
          raise('lateral-movement', event, {
            key,
            severity: 'high',
            mitre: [lateral.mitre],
            explanation: `${where}: ${lateral.what}${quote}. Admins sometimes do this; attackers always do.`,
            trust: cmdTrust,
          });
        }
        const evasion = EVASION.find((e) => e.re.test(scan));
        if (evasion) {
          raise('defense-evasion', event, {
            key,
            severity: typeof evasion.severity === 'function' ? evasion.severity(scan) : evasion.severity || 'high',
            mitre: [evasion.mitre],
            explanation: `${where}: ${evasion.what}${quote}.`,
          });
        }
        const persist = PERSIST_CMD.find((p) => p.re.test(scan));
        if (persist) {
          // For "create a task/service/Run key" the command it installs decides; the rest are
          // suspicious whatever they point at.
          const risk = persist.payload
            ? commandRisk(String(proc.cmdline || '').replace(/^\s*"?[^"\s]+"?\s*/, ''), {
                embedded: true,
                os: event.host.os,
              })
            : { level: persist.severity, why: '' };
          if (risk.level !== 'none')
            raise('persistence-created', event, {
              key,
              severity: risk.level,
              mitre: [persist.mitre],
              explanation: `${where}: ${persist.what}${risk.why ? `, and ${risk.why}` : ''}${quote}.`,
              context: { path: risk.target || null },
              trust: persist.payload ? (risk.target ? fileTrust(risk.target) : cmdTrust) : undefined,
            });
        }
        if (path) {
          const winPath = /^[a-z]:\\/.test(path) || path.startsWith('\\\\');
          if (winPath && SYSTEM_NAMES.has(name) && !/^(?:\\\\\?\\)?[a-z]:\\windows\\/.test(path))
            raise('masquerading', event, {
              key: `name|${path}`,
              severity: 'high',
              mitre: ['T1036_5'],
              explanation: `A program called ${name} is running on ${where} from ${proc.path}. The real ${name} only lives in the Windows folder: this one borrowed the name to look harmless.`,
              trust: fileTrust(path),
            });
          else if (DOUBLE_EXT.test(path) || path.includes('\u202e'))
            raise('masquerading', event, {
              key: `ext|${path}`,
              severity: 'high',
              mitre: ['T1036_7'],
              explanation: `${where} ran ${proc.path}, a program named to look like a document. Someone was meant to believe they were opening a file.`,
              trust: fileTrust(path),
            });
          else if (DROP_DIR.test(path) || path.startsWith('/dev/shm/') || path.endsWith(' (deleted)'))
            raise('masquerading', event, {
              key: `dir|${path}`,
              severity: 'high',
              mitre: ['T1036_5'],
              explanation: `${where} ran a program from ${proc.path}${path.endsWith(' (deleted)') ? ', whose file was deleted right after it started' : ', a place programs are not installed to'}. Malware hides in places like this.`,
              trust: fileTrust(path),
            });
        }
        break;
      }
      case 'persistence.created': {
        const p = event.persistence || {};
        const risk = commandRisk(p.command || p.path, {
          signer: p.signer,
          resolved: p.resolved,
          packageOwner: p.packageOwner,
          os: event.host.os,
        });
        const kind = String(p.kind || 'autostart').replace(/-/g, ' ');
        // /etc/ld.so.preload loads a library into every program that starts. Almost nothing
        // legitimate uses it; rootkits do.
        if (p.kind === 'ld-preload')
          raise('persistence-created', event, {
            key: `ld-preload|${normalizeCmd(p.command)}`,
            severity: 'high',
            mitre: ['T1574_6'],
            explanation: `/etc/ld.so.preload on ${where} now forces ${p.command || 'a library'} into every program that starts. Almost nothing legitimate does this; it is a common way to hide a rootkit.`,
            context: { path: p.path || null, persistenceKind: p.kind, name: p.name || null },
          });
        else if (risk.level !== 'none')
          raise('persistence-created', event, {
            key: `${p.kind}|${p.name}|${normalizeCmd(p.command || p.path)}`,
            severity: risk.level,
            mitre: [PERSIST_KIND[p.kind] || 'T1547_1'],
            explanation: `A new ${kind} "${p.name || ''}" on ${where} will start ${p.command || p.path || 'a program'} automatically. Guard flagged it because ${risk.why}${p.signer?.status === 'valid' && p.signer.subject ? ` (signed by ${p.signer.subject})` : ''}.`,
            context: { path: risk.target || p.path || null, persistenceKind: p.kind || null, name: p.name || null },
            trust: risk.target
              ? fileTrust(risk.target)
              : commandTrust(normalizeCmd(p.command || p.path), p.command || p.path),
          });
        if (/psexesvc/i.test(p.name || '')) {
          raise('lateral-movement', event, {
            key: `psexesvc|${event.id}`,
            severity: 'high',
            mitre: ['T1021_2'],
            explanation: `The PsExec service was installed on ${where}: someone is running commands on it from another machine.`,
          });
        }
        break;
      }
      case 'lsass.access': {
        const source = base(proc.name || proc.path);
        const access = Number.parseInt(String(event.detail?.access || ''), 16);
        // Reading LSASS memory needs PROCESS_VM_READ. Handles without it (task managers, process
        // listings) cannot copy secrets and are not reported.
        if (Number.isFinite(access) && !(access & VM_READ)) break;
        if (LSASS_BENIGN.has(source) && (!proc.path || locate(proc.path) === 'protected')) break;
        raise('credential-dumping', event, {
          key: `lsass|${proc.pid}|${source}`,
          severity: 'critical',
          mitre: ['T1003_1'],
          explanation: `${source || 'A process'} on ${where} opened the memory of LSASS, where Windows keeps sign-in secrets${event.detail?.access ? ` (access ${event.detail.access})` : ''}. Only security software should do this.`,
        });
        break;
      }
      case 'canary.touched': {
        // A decoy that was rewritten or renamed was handled like a document by something that
        // works through folders. One that was only deleted may be a person clearing a folder.
        const change = event.detail?.change || 'changed';
        const certain = change !== 'deleted' || !!event.detail?.killed;
        raise('canary-touched', event, {
          key: `${event.file?.path}|${Math.floor(event.at / MIN)}`,
          severity: certain ? 'critical' : 'high',
          explanation: `A decoy file Guard planted on ${where} (${event.file?.path || 'a canary'}) was ${change}${proc.name ? ` by ${proc.name}` : ''}. ${certain ? 'Nobody should ever touch it: this is almost always ransomware working through the folders.' : 'If someone cleared out that folder by hand this is harmless; if not, treat it as ransomware starting.'}${event.detail?.killed ? ' The agent stopped the process.' : ''}`,
          context: { killed: !!event.detail?.killed },
        });
        break;
      }
      case 'ransomware.detected': {
        const d = event.detail || {};
        // Older agents report any burst of random-looking writes, including a git checkout or a
        // download cache. Inside a tool's own folder (.git, node_modules) that is not reported;
        // elsewhere, without a document behind it, it is a notice and not an emergency.
        const entropyOnly = !d.killed && /rewritten/.test(String(d.reason || ''));
        if (entropyOnly && NOISY_DIR.test(String(event.file?.path || '').toLowerCase())) break;
        const backed =
          d.killed ||
          !event.file?.path ||
          suspiciousWrite(event.file.path) ||
          !/rewritten/.test(String(d.reason || ''));
        raise('ransomware-behaviour', event, {
          // 'seen' and 'stopped it' are separate reports: the second must not be dropped as a repeat.
          key: `${d.pid ?? ''}|${d.killed ? 'stopped' : 'seen'}|${Math.floor(event.at / MIN)}`,
          severity: backed ? 'critical' : 'medium',
          explanation: `The Guard agent on ${where} saw ${d.reason || 'ransomware-like file activity'}${d.files ? ` (${d.files} files)` : ''}${d.process ? `, most likely from ${d.process}` : ''}. ${d.killed ? 'It stopped that process on the spot; isolate the machine until it is checked.' : backed ? 'Isolate the machine now.' : `The last file was ${event.file.path}, which is not a document type, so this may be a program writing its own compressed data. Check what was running.`}`,
          context: { killed: !!d.killed, files: d.files || null },
        });
        break;
      }
      case 'file.rename': {
        if (!suspiciousRename(event.file?.oldPath, event.file?.path)) break;
        const ext = extOf(event.file.path);
        host.renames.push([event.at, ext]);
        trim(host.renames, event.at, opts.renameWindow);
        const total = host.renames.length;
        if (total >= opts.renameBurst) {
          const same = host.renames.filter(([, e]) => e === ext).length;
          raise('ransomware-behaviour', event, {
            key: `rename|${Math.floor(event.at / opts.renameWindow)}`,
            severity: 'critical',
            explanation:
              same >= total / 2
                ? `${same} documents on ${where} were renamed to ".${ext}" within a minute. Ransomware renames every file it encrypts.`
                : `${total} documents on ${where} were renamed to unfamiliar file types within a minute. Ransomware renames every file it encrypts.`,
            context: { ext, files: total },
          });
        }
        break;
      }
      case 'file.write': {
        if (!(Number(event.file?.entropy) >= opts.highEntropy)) break;
        if (!suspiciousWrite(event.file?.path)) break;
        host.entropy.push([event.at, event.file?.path || '']);
        trim(host.entropy, event.at, opts.entropyWindow);
        if (host.entropy.length >= opts.entropyBurst) {
          raise('ransomware-behaviour', event, {
            key: `entropy|${Math.floor(event.at / opts.entropyWindow)}`,
            severity: 'critical',
            explanation: `${host.entropy.length} documents on ${where} were rewritten with random-looking (encrypted) content within ${Math.round(opts.entropyWindow / 1000)} seconds.`,
            context: { files: host.entropy.length },
          });
        }
        break;
      }
      case 'logon': {
        const l = event.logon || {};
        if (l.type !== 'rdp' || !l.source) break;
        org.rdp.push([event.at, l.source, event.host.id]);
        while (org.rdp.length && org.rdp[0][0] < event.at - opts.rdpWindow) org.rdp.shift();
        if (org.rdp.length > 5000) org.rdp.splice(0, org.rdp.length - 5000);
        const reached = new Set(org.rdp.filter(([, s]) => s === l.source).map(([, , h]) => h));
        if (reached.size >= opts.rdpHosts) {
          raise('rdp-spread', event, {
            key: `${l.source}|${Math.floor(event.at / opts.rdpWindow)}`,
            severity: 'high',
            explanation: `${l.source} signed in over Remote Desktop to ${reached.size} machines within ${Math.round(opts.rdpWindow / MIN)} minutes, the latest ${where}${l.user ? ` as ${l.user}` : ''}.`,
            context: { hosts: [...reached] },
          });
        }
        break;
      }
      case 'agent.offline': {
        // The agent said why it is about to go quiet (shutdown, sleep, upgrade). Remembered so
        // the silence that follows is not mistaken for someone stopping Guard.
        host.offline = { at: event.at, reason: short(event.detail?.reason, 40) || 'shutdown' };
        host.pendingStop = undefined;
        break;
      }
      case 'agent.tamper': {
        const reason = String(event.detail?.reason || '');
        // "The service was stopped" is also what a restart looks like. It is held for a moment:
        // the endpoint service reports it if the agent stays down, or comes back unchanged.
        if (/service was stopped/i.test(reason) && !state.immediateTamper) {
          host.pendingStop = { at: event.at, reason: short(reason, 200), eventId: event.id };
          break;
        }
        raise('agent-tamper', event, {
          key: `${event.id}`,
          severity: event.detail?.severity === 'medium' ? 'medium' : 'high',
          explanation: `The Guard agent on ${where} reported: ${reason || 'it is being stopped or removed'}. If nobody in IT did this, assume someone is hiding their tracks.`,
        });
        break;
      }
      default:
        break;
    }
  }
  return { alerts: [...alerts.values()], hosts, org };
}

// A laptop or desktop that goes quiet has usually been closed or switched off, so silence there
// is shown as "offline" and nothing more. A server is expected to stay up.
export function expectsOnline(agent, overrides = {}) {
  if (typeof overrides?.[agent.id] === 'boolean') return overrides[agent.id];
  const os = String(agent.os || '').toLowerCase();
  if (os === 'linux') return true;
  return os === 'windows' && /server/i.test(String(agent.osVersion || ''));
}

// Machines that should be on but stopped checking in without saying they were shutting down.
// Called by the endpoint service. A stopped Guard service is reported separately (stoppedAgentAlert).
export function staleAgentAlerts(
  agents,
  { orgId, now = Date.now(), graceMs = 10 * MIN, hosts = {}, expectOnline = {} } = {},
) {
  return (agents || [])
    .filter((a) => a.status === 'active' && a.lastSeenAt && now - a.lastSeenAt > graceMs && !a.tamperAlertedAt)
    .filter((a) => expectsOnline(a, expectOnline))
    .filter((a) => {
      const said = hosts[a.id]?.offline;
      return !(said && said.at >= a.lastSeenAt - 2 * MIN);
    })
    .map((a) => {
      const minutes = Math.round((now - a.lastSeenAt) / MIN);
      const event = {
        id: `stale:${a.id}:${a.lastSeenAt}`,
        type: 'agent.offline',
        at: now,
        host: { id: a.id, name: a.hostname },
      };
      return {
        id: alertId(orgId, 'agent-offline', `${a.id}|${a.lastSeenAt}`),
        orgId,
        connectionId: null,
        rule: 'agent-offline',
        title: RULES['agent-offline'].title,
        severity: 'medium',
        at: now,
        user: null,
        host: { id: a.id, name: a.hostname },
        ip: null,
        mitre: mitreFor('agent-offline'),
        explanation: `${a.hostname} has not reported to Guard for ${minutes} minutes and did not say it was shutting down. It is marked as a machine that should stay on. Check that it is running and reachable; if it is, check that the Guard service was not stopped.`,
        evidence: [
          {
            id: event.id,
            type: event.type,
            at: now,
            user: null,
            ip: null,
            place: a.hostname,
            app: null,
            outcome: null,
            target: { pid: null },
          },
        ],
        recommended: RULES['agent-offline'].actions,
        context: { pid: null, processName: null, path: null, sha256: null, lastSeenAt: a.lastSeenAt },
      };
    });
}

/** The alert for a Guard service that was stopped by hand: still down, or back without a new version. */
export function stoppedAgentAlert(agent, pending, { orgId, now = Date.now(), back = false } = {}) {
  const seconds = Math.max(1, Math.round((now - pending.at) / 1000));
  const long = seconds >= 120 ? `${Math.round(seconds / 60)} minutes` : `${seconds} seconds`;
  const { alerts } = detectEndpoint(
    [
      {
        id: `stop:${pending.eventId || pending.at}:${back ? 'back' : 'down'}`,
        type: 'agent.tamper',
        at: back ? now : pending.at,
        host: { id: agent.id, name: agent.hostname },
        detail: {
          severity: back ? 'medium' : 'high',
          reason: back
            ? `the Guard service was stopped for ${long} and then started again, with no update in between. Nothing on the machine was recorded during that gap`
            : `the Guard service was stopped on this machine ${long} ago and has not started again`,
        },
      },
    ],
    { orgId, immediateTamper: true },
  );
  return alerts[0];
}
