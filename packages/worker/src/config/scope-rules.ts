// Path matching for scope rules (target.urls.focus / avoid).
// Rules:
//   - "re:<pattern>"  → explicit RegExp match against the path
//   - contains * or ? → glob (`*` = one path segment, `**` = any depth, `?` = one char)
//   - otherwise       → prefix match (back-compat with legacy bare-path configs)
export function matchesPath(rule: string, path: string): boolean {
  if (rule.startsWith('re:')) {
    return new RegExp(rule.slice(3)).test(path);
  }
  if (rule.includes('*') || rule.includes('?')) {
    return globToRegExp(rule).test(path);
  }
  return path.startsWith(rule);
}

function globToRegExp(glob: string): RegExp {
  let re = '^';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') {
        re += '.*'; // ** = any number of segments/chars
        i++;
      } else {
        re += '[^/]*'; // * = within a single segment
      }
    } else if (c === '?') {
      re += '[^/]';
    } else if ('.+^${}()|[]\\'.includes(c)) {
      re += `\\${c}`;
    } else {
      re += c;
    }
  }
  return new RegExp(`${re}$`);
}

// Validates an IPv4 CIDR like "10.0.0.0/8". (IPv6 CIDR validation is a Phase 1
// concern alongside the ScopeEnforcer; Phase 0 only needs IPv4 config validation.)
export function isValidCidr(cidr: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(cidr);
  if (!m) return false;
  const octets = [m[1], m[2], m[3], m[4]].map(Number);
  if (octets.some((o) => o > 255)) return false;
  const prefix = Number(m[5]);
  return prefix >= 0 && prefix <= 32;
}
