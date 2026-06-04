import type { ToolDescriptor } from '../types.js';

// Minimal Phase-1a descriptors. Phase 1b expands params per tool as classes land.
export const DESCRIPTORS: ToolDescriptor[] = [
  {
    id: 'sqlmap',
    bin: 'sqlmap',
    params: [
      { name: 'url', flag: '-u', required: true, pattern: '^https?://[^\\s]+$' },
      { name: 'level', flag: '--level', enumValues: ['1', '2', '3'] },
      { name: 'risk', flag: '--risk', enumValues: ['1', '2'] },
    ],
    blocklist: [
      '--os-shell', '--os-pwn', '--os-cmd', '--file-read', '--file-write',
      '--priv-esc', '--second-url', '--dns-domain', '--eval', '--tamper',
    ],
  },
  {
    id: 'nuclei',
    bin: 'nuclei',
    params: [
      { name: 'target', flag: '-u', required: true, pattern: '^https?://[^\\s]+$' },
      { name: 'severity', flag: '-severity', pattern: '^[a-z,]+$' },
    ],
    blocklist: ['-code', '-headless', '-iserver', '-itoken', '-duc'],
  },
  {
    id: 'ffuf',
    bin: 'ffuf',
    params: [
      { name: 'url', flag: '-u', required: true, pattern: '^https?://[^\\s]+FUZZ[^\\s]*$' },
      { name: 'wordlist', flag: '-w', required: true, pattern: '^[\\w./-]+$' },
      { name: 'rate', flag: '-rate', pattern: '^\\d{1,3}$' },
    ],
    blocklist: ['-x', '-input-cmd'],
  },
  {
    id: 'sstimap',
    bin: 'sstimap',
    params: [
      { name: 'url', flag: '-u', required: true, pattern: '^https?://[^\\s]+$' },
      { name: 'osCmd', flag: '--os-cmd', enumValues: ['id', 'whoami', 'hostname'] },
    ],
    blocklist: ['--os-shell', '--upload', '--download', '--force-overwrite'],
  },
];
