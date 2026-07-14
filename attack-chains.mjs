#!/usr/bin/env node
/**
 * Attack-path chaining — the correlation layer that turns a LIST of proven findings into a pentest
 * STORY. Deterministic and proof-based: a chain is realized ONLY when every step it needs is backed
 * by a CONFIRMED finding. No guessing.
 *
 * Model: curated CHAIN TEMPLATES. Each template has one or more "groups"; a group is satisfied when
 * at least one of its finding classes was confirmed (optionally matching a sub-type via `detail`). A
 * template realizes only when EVERY group is satisfied, and the narrative names the exact findings
 * that formed the chain. Templates surface the two kinds of insight a findings LIST can't:
 *   - emergent multi-finding chains (leaked secrets + an exposed datastore → full data breach), and
 *   - single findings whose real IMPACT is far bigger than the label (SSRF → cloud account takeover).
 */

const g = (cls, detail) => ({ cls, detail });

const CHAIN_TEMPLATES = [
  {
    id: 'secrets-to-datastore',
    severity: 'critical',
    title: 'Full datastore compromise',
    groups: [[g('secrets-exposure'), g('api-data-exposure'), g('path-traversal'), g('sqli')], [g('exposed-service')]],
    narrative: (m) =>
      `credentials leaked via ${m[0]} are reused to authenticate to the datastore exposed by ${m[1]} → full read/write of the data store`,
  },
  {
    id: 'ssrf-to-cloud',
    severity: 'critical',
    title: 'Cloud account takeover',
    groups: [[g('ssrf')]],
    narrative: (m) =>
      `${m[0]} reaches the cloud metadata endpoint (169.254.169.254) → IAM credentials are retrieved → used against the cloud API → cloud account takeover`,
  },
  {
    id: 'redis-to-rce',
    severity: 'critical',
    title: 'Remote code execution',
    groups: [[g('exposed-service', /redis/i)]],
    narrative: (m) =>
      `${m[0]} (unauthenticated Redis) allows writing a cron job / loading a module → remote code execution`,
  },
  {
    id: 'authbypass-to-admin',
    severity: 'critical',
    title: 'Full application / admin control',
    groups: [[g('sqli-auth-bypass'), g('token-forgery'), g('access-control', /BFLA|admin/i)]],
    narrative: (m) =>
      `${m[0]} yields administrator access → every privileged function is operable → full application control`,
  },
  {
    id: 'traversal-to-secrets',
    severity: 'high',
    title: 'Credential disclosure via file read',
    groups: [
      [g('path-traversal')],
      [g('secrets-exposure'), g('api-data-exposure'), g('exposed-service'), g('token-forgery')],
    ],
    narrative: (m) =>
      `${m[0]} reads server-side config/keys, compounding ${m[1]} → credentials and internal secrets are disclosed`,
  },
  {
    id: 'storedxss-to-ato',
    severity: 'high',
    title: 'Account takeover',
    groups: [[g('stored-dom-xss', /stored/i)]],
    narrative: (m) =>
      `${m[0]} executes in other users' browsers → an administrator session is stolen → account takeover`,
  },
  {
    id: 'takeover-to-phishing',
    severity: 'high',
    title: 'Credential / session theft from a trusted host',
    groups: [[g('attack-surface')]],
    narrative: (m) =>
      `${m[0]} lets an attacker serve content from a trusted subdomain → convincing phishing / cookie theft`,
  },
];

const F = (severity, target, detail, findings) => ({
  tool: 'attack-chain',
  severity,
  target,
  detail,
  raw: JSON.stringify({ tool: 'attack-chain', detail, findings }),
});

export function buildAttackChains(report) {
  const confirmed = new Map(); // cls → [details]
  for (const e of (report.exploits || []).filter((x) => x.confirmed > 0))
    confirmed.set(
      e.cls,
      (e.findings || []).map((f) => f.detail || ''),
    );

  const matchGroup = (group) => {
    for (const opt of group) {
      const details = confirmed.get(opt.cls);
      if (!details) continue;
      if (!opt.detail || details.some((d) => opt.detail.test(d))) return opt.cls;
    }
    return null;
  };

  const chains = [];
  for (const tpl of CHAIN_TEMPLATES) {
    const matched = tpl.groups.map(matchGroup);
    if (matched.some((m) => m === null)) continue; // a required step isn't confirmed → chain not realized
    const findings = [...new Set(matched)];
    const detail = `Attack chain (${findings.join(' + ')}) ⇒ ${tpl.title}: ${tpl.narrative(matched)}`;
    chains.push(F(tpl.severity, report.target, detail, findings));
  }
  chains.sort((a, b) => (a.severity === 'critical' ? 0 : 1) - (b.severity === 'critical' ? 0 : 1));
  return { chains };
}

export { CHAIN_TEMPLATES };
