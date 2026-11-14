// Guard's fixed vocabulary: detection rules, MITRE ATT&CK techniques, response actions.
// Pure data, shared by the detection engine, the incident builder, the routes and the tests.

export const SEVERITY_RANK = Object.freeze({ info: 0, low: 1, medium: 2, high: 3, critical: 4 });
export const maxSeverity = (a, b) => ((SEVERITY_RANK[b] ?? 0) > (SEVERITY_RANK[a] ?? 0) ? b : a);

export const MITRE = Object.freeze({
  T1078: { id: 'T1078.004', name: 'Valid Accounts: Cloud Accounts', tactic: 'Initial Access' },
  T1110_1: { id: 'T1110.001', name: 'Brute Force: Password Guessing', tactic: 'Credential Access' },
  T1110_3: { id: 'T1110.003', name: 'Brute Force: Password Spraying', tactic: 'Credential Access' },
  T1621: { id: 'T1621', name: 'Multi-Factor Authentication Request Generation', tactic: 'Credential Access' },
  T1564_8: { id: 'T1564.008', name: 'Hide Artifacts: Email Hiding Rules', tactic: 'Defense Evasion' },
  T1114_3: { id: 'T1114.003', name: 'Email Collection: Email Forwarding Rule', tactic: 'Collection' },
  T1528: { id: 'T1528', name: 'Steal Application Access Token', tactic: 'Credential Access' },
  T1530: { id: 'T1530', name: 'Data from Cloud Storage', tactic: 'Collection' },
  T1567: { id: 'T1567', name: 'Exfiltration Over Web Service', tactic: 'Exfiltration' },
  T1098_3: { id: 'T1098.003', name: 'Account Manipulation: Additional Cloud Roles', tactic: 'Persistence' },
  T1556_6: {
    id: 'T1556.006',
    name: 'Modify Authentication Process: Multi-Factor Authentication',
    tactic: 'Defense Evasion',
  },
  T1190: { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
  // Endpoint (Phase 2)
  T1486: { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact' },
  T1490: { id: 'T1490', name: 'Inhibit System Recovery', tactic: 'Impact' },
  T1003_1: { id: 'T1003.001', name: 'OS Credential Dumping: LSASS Memory', tactic: 'Credential Access' },
  T1003_2: { id: 'T1003.002', name: 'OS Credential Dumping: Security Account Manager', tactic: 'Credential Access' },
  T1003_3: { id: 'T1003.003', name: 'OS Credential Dumping: NTDS', tactic: 'Credential Access' },
  T1105: { id: 'T1105', name: 'Ingress Tool Transfer', tactic: 'Command and Control' },
  T1218: { id: 'T1218', name: 'System Binary Proxy Execution', tactic: 'Defense Evasion' },
  T1059_1: { id: 'T1059.001', name: 'Command and Scripting Interpreter: PowerShell', tactic: 'Execution' },
  T1204_2: { id: 'T1204.002', name: 'User Execution: Malicious File', tactic: 'Execution' },
  T1547_1: { id: 'T1547.001', name: 'Boot or Logon Autostart: Registry Run Keys', tactic: 'Persistence' },
  T1543_3: { id: 'T1543.003', name: 'Create or Modify System Process: Windows Service', tactic: 'Persistence' },
  T1543_2: { id: 'T1543.002', name: 'Create or Modify System Process: Systemd Service', tactic: 'Persistence' },
  T1543_1: { id: 'T1543.001', name: 'Create or Modify System Process: Launch Agent', tactic: 'Persistence' },
  T1053_5: { id: 'T1053.005', name: 'Scheduled Task/Job: Scheduled Task', tactic: 'Persistence' },
  T1053_3: { id: 'T1053.003', name: 'Scheduled Task/Job: Cron', tactic: 'Persistence' },
  T1021_1: { id: 'T1021.001', name: 'Remote Services: Remote Desktop Protocol', tactic: 'Lateral Movement' },
  T1021_2: { id: 'T1021.002', name: 'Remote Services: SMB/Windows Admin Shares', tactic: 'Lateral Movement' },
  T1021_6: { id: 'T1021.006', name: 'Remote Services: Windows Remote Management', tactic: 'Lateral Movement' },
  T1047: { id: 'T1047', name: 'Windows Management Instrumentation', tactic: 'Execution' },
  T1562_1: { id: 'T1562.001', name: 'Impair Defenses: Disable or Modify Tools', tactic: 'Defense Evasion' },
  T1070_1: { id: 'T1070.001', name: 'Indicator Removal: Clear Windows Event Logs', tactic: 'Defense Evasion' },
});

// kind: what the rule is about. 'signin' rules plus a 'persistence' rule on the same person is
// the classic account-takeover chain, so the incident builder escalates that pair to critical.
export const RULES = Object.freeze({
  'impossible-travel': {
    title: 'Impossible travel',
    kind: 'signin',
    mitre: ['T1078'],
    actions: ['revoke-sessions', 'force-password-reset', 'disable-user'],
  },
  'new-country': {
    title: 'Sign-in from a new country',
    kind: 'signin',
    mitre: ['T1078'],
    actions: ['revoke-sessions', 'force-password-reset'],
  },
  'bad-ip-signin': {
    title: 'Sign-in from a known-bad address',
    kind: 'signin',
    mitre: ['T1078'],
    actions: ['revoke-sessions', 'force-password-reset', 'block-ip'],
  },
  'provider-risk': {
    title: 'Sign-in the provider flagged as risky',
    kind: 'signin',
    mitre: ['T1078'],
    actions: ['revoke-sessions', 'force-password-reset'],
  },
  'mfa-fatigue': {
    title: 'MFA fatigue (repeated push denials)',
    kind: 'signin',
    mitre: ['T1621'],
    actions: ['revoke-sessions', 'force-password-reset', 'disable-user'],
  },
  'brute-force': {
    title: 'Repeated failed sign-ins on one account',
    kind: 'signin',
    mitre: ['T1110_1'],
    actions: ['block-ip', 'force-password-reset'],
  },
  'password-spray': {
    title: 'Password spraying from one address',
    kind: 'spray',
    mitre: ['T1110_3'],
    actions: ['block-ip'],
  },
  'inbox-rule': {
    title: 'Suspicious inbox rule',
    kind: 'persistence',
    mitre: ['T1564_8'],
    actions: ['remove-inbox-rule', 'revoke-sessions', 'force-password-reset'],
  },
  'mail-forwarding': {
    title: 'Mail forwarded outside the organization',
    kind: 'persistence',
    mitre: ['T1114_3'],
    actions: ['remove-inbox-rule', 'revoke-sessions'],
  },
  'oauth-consent': {
    title: 'Risky app given access to mail or files',
    kind: 'persistence',
    mitre: ['T1528'],
    actions: ['revoke-oauth-grant', 'revoke-sessions'],
  },
  'mass-download': {
    title: 'Unusually many file downloads',
    kind: 'exfiltration',
    mitre: ['T1530'],
    actions: ['revoke-sessions', 'disable-user'],
  },
  'external-share': {
    title: 'Files shared outside the organization',
    kind: 'exfiltration',
    mitre: ['T1567'],
    actions: ['revoke-sessions'],
  },
  'admin-granted': {
    title: 'New administrator',
    kind: 'persistence',
    mitre: ['T1098_3'],
    actions: ['disable-user', 'revoke-sessions'],
  },
  'mfa-disabled': {
    title: 'MFA turned off or weakened',
    kind: 'persistence',
    mitre: ['T1556_6'],
    actions: ['revoke-sessions', 'force-password-reset'],
  },
  'exploit-attempt': {
    title: 'Attack on a vulnerability Shannon proved',
    kind: 'exploit',
    mitre: ['T1190'],
    actions: ['block-ip'],
  },
  // ----- Endpoint (Phase 2): alerts carry a host, incidents group per machine -----
  'ransomware-behaviour': {
    title: 'Ransomware behaviour',
    kind: 'ransomware',
    mitre: ['T1486'],
    actions: ['isolate-host', 'kill-process'],
  },
  'canary-touched': {
    title: 'Ransomware canary file changed',
    kind: 'ransomware',
    mitre: ['T1486'],
    actions: ['isolate-host', 'kill-process'],
  },
  'shadow-copy-deletion': {
    title: 'Backups or shadow copies deleted',
    kind: 'ransomware',
    mitre: ['T1490'],
    actions: ['isolate-host', 'kill-process'],
  },
  'credential-dumping': {
    title: 'Credential dumping',
    kind: 'credential',
    mitre: ['T1003_1'],
    actions: ['isolate-host', 'kill-process'],
  },
  'lolbin-abuse': {
    title: 'Built-in system tool used to fetch or run code',
    kind: 'execution',
    mitre: ['T1218', 'T1105'],
    actions: ['kill-process', 'collect-file'],
  },
  'encoded-powershell': {
    title: 'Hidden or downloaded PowerShell',
    kind: 'execution',
    mitre: ['T1059_1'],
    actions: ['kill-process'],
  },
  'office-spawned-shell': {
    title: 'Office document started a shell',
    kind: 'execution',
    mitre: ['T1204_2'],
    actions: ['kill-process', 'isolate-host'],
  },
  'persistence-created': {
    title: 'New autostart entry',
    kind: 'host-persistence',
    mitre: ['T1547_1'],
    actions: ['quarantine-file', 'kill-process'],
  },
  'lateral-movement': {
    title: 'Remote execution on another machine',
    kind: 'lateral',
    mitre: ['T1021_2'],
    actions: ['isolate-host', 'kill-process'],
  },
  'rdp-spread': {
    title: 'One address signing in to many machines over RDP',
    kind: 'lateral',
    mitre: ['T1021_1'],
    actions: ['isolate-host'],
  },
  'defense-evasion': {
    title: 'Security tools disabled or logs cleared',
    kind: 'evasion',
    mitre: ['T1562_1'],
    actions: ['isolate-host', 'kill-process'],
  },
  'malicious-file': {
    title: 'Known malicious file',
    kind: 'malware',
    mitre: ['T1204_2'],
    actions: ['quarantine-file', 'kill-process', 'isolate-host'],
  },
  'agent-tamper': {
    title: 'Guard agent stopped or removed',
    kind: 'evasion',
    mitre: ['T1562_1'],
    actions: ['isolate-host'],
  },
});

export const HOST_KINDS = Object.freeze([
  'ransomware',
  'credential',
  'execution',
  'host-persistence',
  'lateral',
  'evasion',
  'malware',
]);

export const mitreFor = (rule) => (RULES[rule]?.mitre || []).map((key) => MITRE[key]).filter(Boolean);

// reversible: whether "Undo" exists. Honest about the ones that cannot be undone.
export const ACTIONS = Object.freeze({
  'revoke-sessions': {
    label: 'Sign the user out everywhere',
    needs: ['user'],
    reversible: false,
    note: 'Harmless to repeat; the person signs in again.',
  },
  'force-password-reset': { label: 'Force a password change at next sign-in', needs: ['user'], reversible: false },
  'disable-user': { label: 'Disable the account', needs: ['user'], reversible: true, undo: 'enable-user' },
  'enable-user': { label: 'Re-enable the account', needs: ['user'], reversible: false, internal: true },
  'remove-inbox-rule': {
    label: 'Remove the inbox rule',
    needs: ['user', 'ruleName'],
    reversible: true,
    undo: 'restore-inbox-rule',
  },
  'restore-inbox-rule': { label: 'Restore the inbox rule', needs: ['user'], reversible: false, internal: true },
  'revoke-oauth-grant': {
    label: "Revoke the app's access",
    needs: ['clientId'],
    reversible: true,
    undo: 'restore-oauth-grant',
  },
  'restore-oauth-grant': { label: "Restore the app's access", needs: ['clientId'], reversible: false, internal: true },
  'block-ip': { label: 'Block the address', needs: ['ip'], reversible: true, undo: 'unblock-ip' },
  'unblock-ip': { label: 'Unblock the address', needs: ['ip'], reversible: false, internal: true },
  // Endpoint actions are commands the Guard agent carries out (channel 'agent'). They start as
  // 'pending' and become 'done' or 'failed' when the agent reports back.
  'isolate-host': {
    label: 'Isolate the machine from the network',
    needs: ['host'],
    reversible: true,
    undo: 'release-host',
    channel: 'agent',
    note: 'The machine keeps its connection to Securovix only.',
  },
  'release-host': {
    label: 'Reconnect the machine to the network',
    needs: ['host'],
    reversible: false,
    internal: true,
    channel: 'agent',
  },
  'kill-process': {
    label: 'Stop the process and everything it started',
    needs: ['host', 'pid'],
    reversible: false,
    channel: 'agent',
  },
  'quarantine-file': {
    label: 'Quarantine the file',
    needs: ['host', 'path'],
    reversible: true,
    undo: 'restore-file',
    channel: 'agent',
  },
  'restore-file': {
    label: 'Restore the file from quarantine',
    needs: ['host', 'path'],
    reversible: false,
    internal: true,
    channel: 'agent',
  },
  'collect-file': {
    label: 'Send the file to the malware sandbox',
    needs: ['host', 'path'],
    reversible: false,
    channel: 'agent',
  },
});

// App scopes that read or move mail and files. A consent to any of these deserves a look.
export const RISKY_SCOPES = Object.freeze([
  // Microsoft Graph / Exchange
  'mail.read',
  'mail.readwrite',
  'mail.send',
  'mail.read.shared',
  'mail.readwrite.shared',
  'mailboxsettings.readwrite',
  'files.read.all',
  'files.readwrite.all',
  'sites.read.all',
  'sites.readwrite.all',
  'full_access_as_user',
  'full_access_as_app',
  'exchange.manageasapp',
  'ews.accessasuser.all',
  'imap.accessasuser.all',
  'directory.readwrite.all',
  'user.readwrite.all',
  'application.readwrite.all',
  'rolemanagement.readwrite.directory',
  // Google
  'https://mail.google.com/',
  'https://www.googleapis.com/auth/gmail.readonly',
  'https://www.googleapis.com/auth/gmail.modify',
  'https://www.googleapis.com/auth/gmail.settings.basic',
  'https://www.googleapis.com/auth/gmail.settings.sharing',
  'https://www.googleapis.com/auth/drive',
  'https://www.googleapis.com/auth/drive.readonly',
  'https://www.googleapis.com/auth/admin.directory.user',
]);

export const PRIVILEGED_ROLES = Object.freeze([
  'global administrator',
  'company administrator',
  'privileged role administrator',
  'privileged authentication administrator',
  'security administrator',
  'exchange administrator',
  'sharepoint administrator',
  'user administrator',
  'application administrator',
  'cloud application administrator',
  'authentication administrator',
  'billing administrator',
  'super admin',
  '_seed_admin_role',
  'user management admin',
  'groups admin',
  'services admin',
]);

export const PERSONAL_MAIL_DOMAINS = Object.freeze([
  'gmail.com',
  'googlemail.com',
  'outlook.com',
  'hotmail.com',
  'live.com',
  'msn.com',
  'yahoo.com',
  'ymail.com',
  'icloud.com',
  'me.com',
  'aol.com',
  'proton.me',
  'protonmail.com',
  'gmx.com',
  'gmx.net',
  'mail.com',
  'yandex.com',
  'yandex.ru',
  'zoho.com',
  'tutanota.com',
  'qq.com',
  '163.com',
]);

// Folders attackers move mail into so the victim never sees replies from the bank or IT.
export const HIDING_FOLDERS = Object.freeze([
  'rss feeds',
  'rss subscriptions',
  'archive',
  'conversation history',
  'junk email',
  'deleted items',
  'notes',
]);
export const LURE_WORDS = Object.freeze([
  'invoice',
  'payment',
  'wire',
  'bank',
  'password',
  'security',
  'phish',
  'hack',
  'compromise',
  'suspicious',
  'fraud',
  'helpdesk',
  'it support',
  'mfa',
]);

export const PROVIDERS = Object.freeze({
  microsoft: {
    label: 'Microsoft 365',
    actions: [
      'revoke-sessions',
      'force-password-reset',
      'disable-user',
      'enable-user',
      'remove-inbox-rule',
      'restore-inbox-rule',
      'revoke-oauth-grant',
      'restore-oauth-grant',
    ],
  },
  google: {
    label: 'Google Workspace',
    actions: ['revoke-sessions', 'force-password-reset', 'disable-user', 'enable-user', 'revoke-oauth-grant'],
  },
  simulation: {
    label: 'Demo tenant (simulated)',
    actions: [
      'revoke-sessions',
      'force-password-reset',
      'disable-user',
      'enable-user',
      'remove-inbox-rule',
      'restore-inbox-rule',
      'revoke-oauth-grant',
      'restore-oauth-grant',
    ],
  },
});
