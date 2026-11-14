// Guard endpoint detection (Phase 2): events from the Guard agent in, alerts out.
//
// The agent sends process starts (with command line, parent chain and file hash), file activity
// summaries, autostart changes, logons, LSASS access (from Sysmon when installed), canary-file
// changes and its own local ransomware verdicts. Rules here are behavioural: what a command does
// (delete shadow copies, dump LSASS, fetch a payload with a built-in tool), not which malware
// family did it. Known-bad file hashes come from the sandbox and the organization's blocklist.
//
// Pure: state in, state out. Every pattern is linear (no nested or adjacent unbounded repeats).
import { createHash } from 'node:crypto';
import { mitreFor, MITRE, RULES } from './catalog.mjs';

const MIN = 60_000;
export const ENDPOINT_DEFAULTS = Object.freeze({
  renameBurst: 20, // files renamed to the same new extension...
  renameWindow: MIN, // ...within this window
  entropyBurst: 30, // high-entropy rewrites...
  entropyWindow: 30_000, // ...within this window
  highEntropy: 7.5, // bits per byte; encrypted or compressed data sits near 8
  rdpHosts: 3,
  rdpWindow: 10 * MIN,
});

// Command lines are normalized before matching: lower case, caret escapes and quotes removed,
// whitespace collapsed. "p^o^w^e^r^s^h^e^l^l" and "power""shell" both become "powershell".
export function normalizeCmd(cmd) {
  return String(cmd || '')
    .toLowerCase()
    .replace(/[\^"]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 8192);
}
const base = (path) =>
  String(path || '')
    .toLowerCase()
    .split(/[\\/]/)
    .pop();

const SHADOW = [
  /vssadmin(?:\.exe)? delete shadows/,
  /vssadmin(?:\.exe)? resize shadowstorage/,
  /wmic(?:\.exe)? shadowcopy delete/,
  /wbadmin(?:\.exe)? delete (?:catalog|systemstatebackup|backup)/,
  /bcdedit(?:\.exe)? \/set \{?default\}? recoveryenabled no/,
  /bcdedit(?:\.exe)? \/set \{?default\}? bootstatuspolicy ignoreallfailures/,
  /win32_shadowcopy[^|]{0,200}\|[^|]{0,80}(?:remove-|delete)/,
];
const CREDENTIAL = [
  { re: /(?:sekurlsa::|lsadump::|mimikatz)/, mitre: 'T1003_1', what: 'a Mimikatz command' },
  {
    re: /comsvcs(?:\.dll)?[ ,#]+(?:#24|minidump)/,
    mitre: 'T1003_1',
    what: 'the comsvcs.dll MiniDump trick to copy LSASS memory',
  },
  { re: /procdump(?:64)?(?:\.exe)? [^\n]{0,200}lsass/, mitre: 'T1003_1', what: 'ProcDump against LSASS' },
  {
    re: /reg(?:\.exe)? save hklm\\(?:sam|security|system)\b/,
    mitre: 'T1003_2',
    what: 'a copy of the SAM/SECURITY registry hive',
  },
  {
    re: /ntdsutil(?:\.exe)? [^\n]{0,120}(?:ifm|ac i ntds)/,
    mitre: 'T1003_3',
    what: 'ntdsutil copying the domain password database',
  },
  { re: /\\windows\\ntds\\ntds\.dit/, mitre: 'T1003_3', what: 'access to the domain password database (ntds.dit)' },
];
const LOLBIN = [
  { proc: 'certutil.exe', re: /-(?:urlcache|verifyctl)[^\n]{0,200}https?:/, what: 'certutil downloading a file' },
  { proc: 'bitsadmin.exe', re: /\/transfer /, what: 'bitsadmin downloading a file' },
  { proc: 'mshta.exe', re: /(?:https?:|javascript:|vbscript:)/, what: 'mshta running a remote or inline script' },
  {
    proc: 'rundll32.exe',
    re: /(?:javascript:|url\.dll,(?:openurl|fileprotocolhandler)|shell32\.dll,shellexec_rundll[^\n]{0,200}https?:)/,
    what: 'rundll32 running a script or URL',
  },
  { proc: 'regsvr32.exe', re: /(?:\/i:https?:|scrobj\.dll)/, what: 'regsvr32 running a remote scriptlet' },
  { proc: 'msiexec.exe', re: /\/i[^\n]{0,20}https?:/, what: 'msiexec installing from the internet' },
  {
    proc: null,
    re: /(?:curl|wget)[^|\n]{0,300}\|\s?(?:sudo )?(?:ba|z|da)?sh\b/,
    what: 'a script downloaded and piped straight into a shell',
  },
];
const POWERSHELL = new Set(['powershell.exe', 'pwsh.exe', 'pwsh', 'powershell']);
const ENCODED =
  / -(?:e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand) ([a-z0-9+/=]{40,})/;
const DOWNLOAD_CRADLE =
  /(?:iex|invoke-expression)[^\n]{0,300}(?:downloadstring|downloaddata|invoke-webrequest|iwr |net\.webclient|invoke-restmethod|irm )|(?:downloadstring|invoke-webrequest|iwr |net\.webclient|invoke-restmethod|irm )[^\n]{0,300}(?:\| ?iex|\| ?invoke-expression)/;
const OFFICE = new Set([
  'winword.exe',
  'excel.exe',
  'powerpnt.exe',
  'outlook.exe',
  'onenote.exe',
  'msaccess.exe',
  'mspub.exe',
  'visio.exe',
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
]);
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
];
const EVASION = [
  {
    re: /set-mppreference[^\n]{0,200}-disable(?:realtimemonitoring|ioavprotection|behaviormonitoring|scriptscanning) (?:\$true|1)/,
    mitre: 'T1562_1',
    what: 'Microsoft Defender protection switched off',
  },
  {
    re: /add-mppreference[^\n]{0,200}-exclusion(?:path|process|extension)/,
    mitre: 'T1562_1',
    what: 'an exclusion added to Microsoft Defender',
  },
  {
    re: /\bsc(?:\.exe)? (?:stop|delete) windefend\b|\bsc(?:\.exe)? config windefend start= ?disabled/,
    mitre: 'T1562_1',
    what: 'the Microsoft Defender service stopped or disabled',
  },
  {
    re: /netsh(?:\.exe)? (?:advfirewall set (?:all|current|domain|private|public)profiles? state off|firewall set opmode disable)/,
    mitre: 'T1562_1',
    what: 'the firewall switched off',
  },
  { re: /\bwevtutil(?:\.exe)? (?:cl|clear-log) /, mitre: 'T1070_1', what: 'an event log cleared' },
  { re: /\b(?:clear-eventlog|remove-eventlog)\b/, mitre: 'T1070_1', what: 'an event log cleared' },
  {
    re: /\b(?:setenforce 0|systemctl (?:stop|disable|mask) (?:auditd|falcon-sensor|securovix-guard)|auditctl -e ?0)\b/,
    mitre: 'T1562_1',
    what: 'Linux security controls switched off',
  },
];
const PERSIST_CMD = [
  { re: /schtasks(?:\.exe)? \/create\b/, mitre: 'T1053_5', what: 'a scheduled task created' },
  { re: /\bsc(?:\.exe)? create\b|\bnew-service\b/, mitre: 'T1543_3', what: 'a Windows service created' },
  {
    re: /reg(?:\.exe)? add [^\n]{0,40}\\(?:software\\microsoft\\windows\\currentversion\\run(?:once)?)\b/,
    mitre: 'T1547_1',
    what: 'a Run key added',
  },
];
const PERSIST_KIND = {
  'run-key': 'T1547_1',
  service: 'T1543_3',
  'scheduled-task': 'T1053_5',
  cron: 'T1053_3',
  systemd: 'T1543_2',
  'launch-agent': 'T1543_1',
};
const SUSPICIOUS_LOCATION =
  /(?:\\appdata\\(?:local\\temp|roaming)\\|\\users\\public\\|\\downloads\\|\\windows\\temp\\|\\programdata\\[^\\]{1,60}\.exe|\/tmp\/|\/dev\/shm\/|\/var\/tmp\/)/;
const LSASS_BENIGN = new Set([
  'msmpeng.exe',
  'csrss.exe',
  'wininit.exe',
  'services.exe',
  'lsm.exe',
  'wmiprvse.exe',
  'svchost.exe',
  'securovix-guard.exe',
  'mrt.exe',
  'taskmgr.exe',
  'vmtoolsd.exe',
]);

function alertId(orgId, rule, key) {
  return `gal_${createHash('sha256').update(`${orgId}|${rule}|${key}`).digest('hex').slice(0, 24)}`;
}

export function decodeEncodedCommand(b64) {
  try {
    const text = Buffer.from(b64, 'base64').toString('utf16le');
    return text.replace(/[^\x20-\x7e]/g, '').slice(0, 300);
  } catch {
    return '';
  }
}

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
  const alerts = new Map();

  const raise = (rule, event, { key, severity, explanation, context = {}, mitre }) => {
    const id = alertId(orgId, rule, `${event.host?.id}|${key}`);
    if (alerts.has(id)) return;
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
          },
        },
      ],
      recommended: RULES[rule].actions,
      context: {
        pid: event.process?.pid ?? event.detail?.pid ?? null,
        processName: event.process?.name || event.detail?.process || null,
        path: event.file?.path || event.persistence?.path || event.process?.path || null,
        sha256: event.file?.sha256 || event.process?.sha256 || null,
        ...context,
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
    const quote = proc.cmdline ? ` ("${String(proc.cmdline).slice(0, 160)}")` : '';

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
        if (SHADOW.some((re) => re.test(cmd))) {
          raise('shadow-copy-deletion', event, {
            key: `${proc.pid}|${event.id}`,
            severity: 'critical',
            explanation: `${where} ran a command that deletes Windows backups or turns off recovery${quote}. Ransomware does this just before it encrypts, so the files cannot be restored.`,
          });
        }
        const cred = CREDENTIAL.find((c) => c.re.test(cmd));
        if (cred) {
          raise('credential-dumping', event, {
            key: `${proc.pid}|${event.id}`,
            severity: 'critical',
            mitre: [cred.mitre],
            explanation: `${where} ran ${cred.what}${quote}. Whoever did this is collecting passwords to move to other machines.`,
          });
        }
        const lol = LOLBIN.find((l) => (!l.proc || l.proc === name) && l.re.test(cmd));
        if (lol) {
          raise('lolbin-abuse', event, {
            key: `${proc.pid}|${event.id}`,
            severity: 'high',
            explanation: `${where}: ${lol.what}${quote}. Attackers use built-in tools like this so no new program has to be installed.`,
          });
        }
        if (POWERSHELL.has(name)) {
          const encoded = ENCODED.exec(` ${cmd}`);
          const original = encoded ? / -\w+ ([A-Za-z0-9+/=]{40,})/.exec(` ${proc.cmdline}`)?.[1] : null;
          if (encoded || DOWNLOAD_CRADLE.test(cmd)) {
            const decoded = original ? decodeEncodedCommand(original) : '';
            raise('encoded-powershell', event, {
              key: `${proc.pid}|${event.id}`,
              severity: decoded && DOWNLOAD_CRADLE.test(decoded.toLowerCase()) ? 'critical' : 'high',
              explanation: encoded
                ? `${where} ran PowerShell with a hidden (base64) command${decoded ? `, which decodes to: "${decoded}"` : ''}.`
                : `${where} ran PowerShell that downloads code and runs it straight from memory${quote}.`,
              context: decoded ? { decoded } : {},
            });
          }
        }
        if (SHELLS.has(name) && parents.some((p) => OFFICE.has(p))) {
          raise('office-spawned-shell', event, {
            key: `${proc.pid}|${event.id}`,
            severity: 'high',
            explanation: `${parents.find((p) => OFFICE.has(p))} started ${name} on ${where}${quote}. Documents do not normally start command shells; this is how macro malware runs.`,
          });
        }
        const lateral =
          LATERAL.find((l) => l.re.test(cmd)) ||
          (name === 'psexesvc.exe'
            ? { mitre: 'T1021_2', what: 'the PsExec service running a command sent from another machine' }
            : null);
        if (lateral) {
          raise('lateral-movement', event, {
            key: `${proc.pid}|${event.id}`,
            severity: 'high',
            mitre: [lateral.mitre],
            explanation: `${where}: ${lateral.what}${quote}. Admins sometimes do this; attackers always do.`,
          });
        }
        const evasion = EVASION.find((e) => e.re.test(cmd));
        if (evasion) {
          raise('defense-evasion', event, {
            key: `${proc.pid}|${event.id}`,
            severity: 'high',
            mitre: [evasion.mitre],
            explanation: `${where}: ${evasion.what}${quote}.`,
          });
        }
        const persist = PERSIST_CMD.find((p) => p.re.test(cmd));
        if (
          persist &&
          (SUSPICIOUS_LOCATION.test(cmd) ||
            /(?:powershell|mshta|rundll32|regsvr32|wscript|cscript|certutil|http)/.test(cmd.replace(/^\S+/, '')))
        ) {
          raise('persistence-created', event, {
            key: `${proc.pid}|${event.id}`,
            severity: 'high',
            mitre: [persist.mitre],
            explanation: `${where}: ${persist.what} that starts a script or a program from a temporary folder${quote}.`,
          });
        }
        break;
      }
      case 'persistence.created': {
        const p = event.persistence || {};
        const target = normalizeCmd(p.command || p.path);
        const risky =
          SUSPICIOUS_LOCATION.test(target) ||
          /(?:powershell|mshta|rundll32|regsvr32|wscript|cscript|certutil|curl|wget|base64|http)/.test(target);
        raise('persistence-created', event, {
          key: `${p.kind}|${p.name}|${target}`,
          severity: risky ? 'high' : 'medium',
          mitre: [PERSIST_KIND[p.kind] || 'T1547_1'],
          explanation: `A new ${String(p.kind || 'autostart').replace(/-/g, ' ')} "${p.name || ''}" on ${where} will start ${p.command || p.path || 'a program'} automatically${risky ? '. It runs a script or a program from a temporary folder, which legitimate installers rarely do' : ''}.`,
          context: { path: p.path || null, persistenceKind: p.kind || null, name: p.name || null },
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
        if (LSASS_BENIGN.has(source)) break;
        raise('credential-dumping', event, {
          key: `lsass|${proc.pid}|${source}`,
          severity: 'critical',
          mitre: ['T1003_1'],
          explanation: `${source || 'A process'} on ${where} opened the memory of LSASS, where Windows keeps sign-in secrets${event.detail?.access ? ` (access ${event.detail.access})` : ''}. Only security software should do this.`,
        });
        break;
      }
      case 'canary.touched': {
        raise('canary-touched', event, {
          key: `${event.file?.path}|${Math.floor(event.at / MIN)}`,
          severity: 'critical',
          explanation: `A decoy file Guard planted on ${where} (${event.file?.path || 'a canary'}) was ${event.detail?.change || 'changed'}${proc.name ? ` by ${proc.name}` : ''}. Nobody should ever touch it: this is almost always ransomware working through the folders.${event.detail?.killed ? ' The agent stopped the process.' : ''}`,
          context: { killed: !!event.detail?.killed },
        });
        break;
      }
      case 'ransomware.detected': {
        const d = event.detail || {};
        raise('ransomware-behaviour', event, {
          // 'seen' and 'stopped it' are separate reports: the second must not be dropped as a repeat.
          key: `${d.pid ?? ''}|${d.killed ? 'stopped' : 'seen'}|${Math.floor(event.at / MIN)}`,
          severity: 'critical',
          explanation: `The Guard agent on ${where} saw ${d.reason || 'ransomware-like file activity'}${d.files ? ` (${d.files} files)` : ''}${d.process ? `, most likely from ${d.process}` : ''}. ${d.killed ? 'It stopped that process on the spot; isolate the machine until it is checked.' : 'Isolate the machine now.'}`,
          context: { killed: !!d.killed, files: d.files || null },
        });
        break;
      }
      case 'file.rename': {
        const ext = String(event.file?.path || '')
          .toLowerCase()
          .split('.')
          .pop();
        const oldExt = String(event.file?.oldPath || '')
          .toLowerCase()
          .split('.')
          .pop();
        if (!ext || ext === oldExt || ext.length > 12) break;
        host.renames.push([event.at, ext]);
        trim(host.renames, event.at, opts.renameWindow);
        const same = host.renames.filter(([, e]) => e === ext).length;
        if (same >= opts.renameBurst) {
          raise('ransomware-behaviour', event, {
            key: `rename|${ext}|${Math.floor(event.at / opts.renameWindow)}`,
            severity: 'critical',
            explanation: `${same} files on ${where} were renamed to ".${ext}" within a minute. Ransomware renames every file it encrypts.`,
            context: { ext, files: same },
          });
        }
        break;
      }
      case 'file.write': {
        if (!(Number(event.file?.entropy) >= opts.highEntropy)) break;
        host.entropy.push([event.at, event.file?.path || '']);
        trim(host.entropy, event.at, opts.entropyWindow);
        if (host.entropy.length >= opts.entropyBurst) {
          raise('ransomware-behaviour', event, {
            key: `entropy|${Math.floor(event.at / opts.entropyWindow)}`,
            severity: 'critical',
            explanation: `${host.entropy.length} files on ${where} were rewritten with random-looking (encrypted) content within ${Math.round(opts.entropyWindow / 1000)} seconds.`,
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
      case 'agent.tamper': {
        raise('agent-tamper', event, {
          key: `${event.id}`,
          severity: 'high',
          explanation: `The Guard agent on ${where} reported: ${event.detail?.reason || 'it is being stopped or removed'}. If nobody in IT did this, assume someone is hiding their tracks.`,
        });
        break;
      }
      default:
        break;
    }
  }
  return { alerts: [...alerts.values()], hosts, org };
}

// Agents that stopped checking in while they were expected online. Called by the engine.
export function staleAgentAlerts(agents, { orgId, now = Date.now(), graceMs = 10 * MIN } = {}) {
  return (agents || [])
    .filter((a) => a.status === 'active' && a.lastSeenAt && now - a.lastSeenAt > graceMs && !a.tamperAlertedAt)
    .map((a) =>
      Object.assign(
        detectEndpoint(
          [
            {
              id: `stale:${a.id}:${a.lastSeenAt}`,
              type: 'agent.tamper',
              at: now,
              host: { id: a.id, name: a.hostname },
              detail: {
                reason: `no check-in for ${Math.round((now - a.lastSeenAt) / MIN)} minutes. The machine may simply be off; if it should be on, someone may have stopped the agent`,
              },
            },
          ],
          { orgId },
        ).alerts[0],
        { severity: 'medium' },
      ),
    );
}
