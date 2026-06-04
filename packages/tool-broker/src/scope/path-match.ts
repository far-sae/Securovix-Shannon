// "re:<pattern>" → RegExp; contains * or ? → glob (* within segment, ** any depth);
// otherwise → prefix. Mirrors worker config/scope-rules.ts for enforcement use.
export function matchesPath(rule: string, path: string): boolean {
  if (rule.startsWith('re:')) return new RegExp(rule.slice(3)).test(path);
  if (rule.includes('*') || rule.includes('?')) return globToRegExp(rule).test(path);
  return path.startsWith(rule);
}

function globToRegExp(glob: string): RegExp {
  let re = '^';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') {
        re += '.*';
        i++;
      } else {
        re += '[^/]*';
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
