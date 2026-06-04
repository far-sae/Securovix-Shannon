import { describe, it, expect } from 'vitest';
import { ToolRegistry } from './registry.js';
import { DESCRIPTORS } from './descriptors.js';

const reg = new ToolRegistry(DESCRIPTORS);

describe('ToolRegistry.buildArgv', () => {
  it('builds a valid argv for an allowlisted tool + params', () => {
    const argv = reg.buildArgv('sqlmap', { url: 'https://app.example.com/p?id=1', level: '2' });
    expect(argv).toEqual(['sqlmap', '-u', 'https://app.example.com/p?id=1', '--level', '2']);
  });
  it('rejects an unknown tool', () => {
    expect(() => reg.buildArgv('metasploit', {})).toThrow(/unknown tool/i);
  });
  it('rejects an undeclared param (allowlist)', () => {
    expect(() => reg.buildArgv('sqlmap', { url: 'https://x/y', osShell: 'true' })).toThrow(/not allowed/i);
  });
  it('rejects a value failing its pattern', () => {
    expect(() => reg.buildArgv('sqlmap', { url: 'file:///etc/passwd' })).toThrow(/invalid value/i);
  });
  it('rejects a value outside its enum', () => {
    expect(() => reg.buildArgv('sqlmap', { url: 'https://x/y', level: '9' })).toThrow(/invalid value/i);
  });
  it('rejects a missing required param', () => {
    expect(() => reg.buildArgv('sqlmap', { level: '1' })).toThrow(/required/i);
  });
  it('rejects shell metacharacters in any value', () => {
    expect(() => reg.buildArgv('sqlmap', { url: 'https://x/y;rm -rf /' })).toThrow(/invalid value/i);
  });
  it('a blocklisted token can never be produced — it is not even a declared param', () => {
    expect(() => reg.buildArgv('sqlmap', { '--os-shell': '1' })).toThrow(/not allowed/i);
    expect(reg.descriptor('sqlmap').blocklist).toContain('--os-shell');
  });
});
