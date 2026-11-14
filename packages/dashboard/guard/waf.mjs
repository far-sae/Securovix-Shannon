// Shannon -> WAF: a temporary block in front of a vulnerability Shannon proved, until the code
// fix ships. Rules are scoped to the vulnerable path so they cannot break the rest of the site.
// Output is copy-ready: a Cloudflare custom-rule expression and an AWS WAF (v2) rule.

const TOKENS = {
  sqli: [
    'union select',
    'union all select',
    "' or ",
    "'or'",
    "' and ",
    'sleep(',
    'benchmark(',
    'waitfor delay',
    'information_schema',
    'pg_sleep',
  ],
  'sqli-auth-bypass': ["' or ", "'or'", "'--", "' --", "admin'", '" or '],
  xss: ['<script', 'javascript:', 'onerror=', 'onload=', '<svg', '<iframe', 'onmouseover=', '<img'],
  'path-traversal': ['../', '..\\', '/etc/passwd', 'win.ini', '%2e%2e'],
  'cmd-injection': [
    '$(',
    '`',
    ';cat ',
    '|cat ',
    ';id',
    '|id',
    '&&',
    '||',
    '/bin/sh',
    '/bin/bash',
    'wget ',
    'curl ',
    'nc -e',
  ],
  'rce-ssti': ['{{', '{%', '${', '<%', '#{', '*{'],
  templates: ['{{', '{%', '${', '<%', '#{'],
  ssrf: [
    '169.254.169.254',
    'metadata.google.internal',
    '100.100.100.200',
    'localhost',
    '127.0.0.1',
    '0.0.0.0',
    '[::1]',
    'file://',
    'gopher://',
    'dict://',
  ],
  nosql: ['$ne', '$gt', '$where', '$regex', '[$', '$nin'],
  'open-redirect': ['=//', '=http:', '=https:', '=%2f%2f', '=\\\\'],
  'llm-prompt-injection': [
    'ignore previous',
    'ignore all previous',
    'system prompt',
    'you are now',
    'disregard the above',
  ],
  'llm-indirect-injection': ['ignore previous', 'ignore all previous', 'system prompt', 'you are now'],
};

// Classes a WAF cannot fix: the answer is code or configuration.
const NOT_WAF = {
  'security-headers': 'Add the missing headers in the app or at the CDN; a block rule does not help.',
  'cors-misconfig': 'Fix the CORS allow-list in the app; a block rule does not help.',
  'verbose-errors': 'Turn off detailed error pages in production.',
  csrf: 'Add CSRF tokens or SameSite cookies in the app.',
  'mass-assignment': 'Allow-list the fields the endpoint accepts.',
  'authz-bypass': 'Add the missing ownership/role check on the server.',
  'graphql-idor': 'Add the missing ownership check in the resolver.',
  'graphql-advanced': 'Disable introspection and add depth/cost limits in the GraphQL server.',
  'api-data-exposure': 'Stop returning the extra fields from the API.',
  'token-forgery': 'Fix token signing and verification.',
  'auth-testing': 'Fix the authentication flow in the app.',
  'rce-deser': 'Stop deserializing untrusted data; a WAF signature is easy to bypass here.',
};

const cfString = (s) => `"${String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;

function targetOf(finding) {
  const details = finding?.details || {};
  const cls = String(details.cls || details.tool || '').toLowerCase();
  let url = null;
  try {
    url = new URL(String(details.target || ''));
  } catch {}
  return { cls, url, path: url ? url.pathname || '/' : '' };
}

function awsByteMatch(search, field, constraint = 'CONTAINS') {
  return {
    ByteMatchStatement: {
      SearchString: search,
      FieldToMatch: field,
      TextTransformations: [
        { Priority: 0, Type: 'URL_DECODE' },
        { Priority: 1, Type: 'HTML_ENTITY_DECODE' },
        { Priority: 2, Type: 'LOWERCASE' },
      ],
      PositionalConstraint: constraint,
    },
  };
}

const or = (statements) => (statements.length === 1 ? statements[0] : { OrStatement: { Statements: statements } });
const and = (statements) => (statements.length === 1 ? statements[0] : { AndStatement: { Statements: statements } });
const QUERY = { QueryString: {} };
const BODY = { Body: { OversizeHandling: 'MATCH' } };

function awsRule(name, statement) {
  const metric = name.replace(/[^A-Za-z0-9_-]/g, '-').slice(0, 128);
  return {
    Name: metric,
    Priority: 10,
    Action: { Block: {} },
    Statement: statement,
    VisibilityConfig: { SampledRequestsEnabled: true, CloudWatchMetricsEnabled: true, MetricName: metric },
  };
}

/**
 * @returns {{ applicable: boolean, reason?: string, cls, path, host, cloudflare?, aws?, notes: string[] }}
 */
export function wafRulesForFinding(finding) {
  const { cls, url, path } = targetOf(finding);
  const base = {
    findingId: finding?.id || null,
    title: finding?.title || '',
    cls,
    path,
    host: url?.host || null,
    notes: [],
  };
  if (!url) return { ...base, applicable: false, reason: 'The finding has no target URL to scope a rule to.' };
  if (NOT_WAF[cls]) return { ...base, applicable: false, reason: NOT_WAF[cls] };
  const name = `securovix-${finding.id || cls}`;
  const description = `Securovix: temporary block for "${String(finding.title || cls).slice(0, 80)}" until the fix ships`;
  const pathMatch = `lower(http.request.uri.path) eq ${cfString(path.toLowerCase())}`;
  const awsPath = awsByteMatch(path.toLowerCase(), { UriPath: {} }, 'EXACTLY');

  if (cls === 'secrets-exposure') {
    return {
      ...base,
      applicable: true,
      cloudflare: { description, action: 'block', expression: pathMatch },
      aws: awsRule(name, awsPath),
      notes: [
        'Blocks the exposed path entirely. Also rotate every secret that was exposed: blocking does not un-leak them.',
      ],
    };
  }
  if (cls === 'host-header') {
    return {
      ...base,
      applicable: true,
      cloudflare: { description, action: 'block', expression: `not http.host in {${cfString(url.host)}}` },
      aws: awsRule(name, {
        NotStatement: {
          Statement: awsByteMatch(url.host.toLowerCase(), { SingleHeader: { Name: 'host' } }, 'EXACTLY'),
        },
      }),
      notes: [
        'Refuses any request whose Host header is not your real host name. Add any other host names you serve before enabling it.',
      ],
    };
  }
  if (cls === 'crlf') {
    return {
      ...base,
      applicable: true,
      cloudflare: {
        description,
        action: 'block',
        expression: `${pathMatch} and (lower(raw.http.request.uri.query) contains "%0d" or lower(raw.http.request.uri.query) contains "%0a")`,
      },
      aws: awsRule(name, and([awsPath, or([awsByteMatch('\r', QUERY), awsByteMatch('\n', QUERY)])])),
      notes: [],
    };
  }
  if (cls === 'xxe') {
    return {
      ...base,
      applicable: true,
      cloudflare: {
        description,
        action: 'block',
        expression: `${pathMatch} and lower(http.request.body.raw) contains "<!entity"`,
      },
      aws: awsRule(name, and([awsPath, awsByteMatch('<!entity', BODY)])),
      notes: [
        'XXE arrives in the request body. Cloudflare can only inspect bodies on plans with body inspection (http.request.body.raw); otherwise use the AWS rule or disable external entities in the XML parser, which is the real fix.',
      ],
    };
  }
  const tokens = TOKENS[cls];
  if (!tokens) return { ...base, applicable: false, reason: `No WAF template for "${cls}" yet; fix it in code.` };

  const query = 'lower(url_decode(http.request.uri.query))';
  const cfAttack = tokens.map((t) => `${query} contains ${cfString(t.toLowerCase())}`).join(' or ');
  let awsAttack;
  if (cls === 'sqli' || cls === 'sqli-auth-bypass') {
    const sqli = (field) => ({
      SqliMatchStatement: {
        FieldToMatch: field,
        TextTransformations: [
          { Priority: 0, Type: 'URL_DECODE' },
          { Priority: 1, Type: 'HTML_ENTITY_DECODE' },
        ],
        SensitivityLevel: 'HIGH',
      },
    });
    awsAttack = or([sqli(QUERY), sqli(BODY)]);
  } else if (cls === 'xss') {
    const xss = (field) => ({
      XssMatchStatement: {
        FieldToMatch: field,
        TextTransformations: [
          { Priority: 0, Type: 'URL_DECODE' },
          { Priority: 1, Type: 'HTML_ENTITY_DECODE' },
        ],
      },
    });
    awsAttack = or([xss(QUERY), xss(BODY)]);
  } else {
    awsAttack = or(
      tokens.flatMap((t) => [awsByteMatch(t.toLowerCase(), QUERY), awsByteMatch(t.toLowerCase(), BODY)]).slice(0, 20),
    );
  }
  const notes = [
    'Scoped to the vulnerable path only, so the rest of the site is untouched. Start it in Log/Count mode for a day if the endpoint is busy.',
    'The Cloudflare rule checks the query string. If the vulnerable parameter is sent in a form or JSON body, also turn on the Cloudflare Managed Ruleset, or use the AWS rule, which checks the body too.',
    'This is a stopgap. The finding stays open until Shannon re-tests the fix.',
  ];
  return {
    ...base,
    applicable: true,
    cloudflare: { description, action: 'block', expression: `${pathMatch} and (${cfAttack})` },
    aws: awsRule(name, and([awsPath, awsAttack])),
    notes,
  };
}

// The organization's Guard blocklist as WAF rules, so a "Block address" in Guard can be enforced
// at the edge too.
export function blocklistRules(ips) {
  const list = [...new Set((ips || []).map(String).filter(Boolean))].slice(0, 1000);
  if (!list.length) return null;
  return {
    cloudflare: {
      description: 'Securovix Guard blocklist',
      action: 'block',
      expression: `ip.src in {${list.join(' ')}}`,
    },
    aws: {
      ipSet: {
        Name: 'securovix-guard-blocklist',
        Scope: 'REGIONAL',
        IPAddressVersion: 'IPV4',
        Addresses: list.filter((ip) => !ip.includes(':')).map((ip) => (ip.includes('/') ? ip : `${ip}/32`)),
      },
      note: 'Create this IP set (and an IPV6 one for any IPv6 addresses), then add a rule with IPSetReferenceStatement and Action Block.',
    },
  };
}
