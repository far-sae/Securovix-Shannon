# Securovix Shannon

**Autonomous, proof-based penetration-testing platform.** Every finding is confirmed by a
benign proof signal before it is reported as confirmed, reducing false-positive risk. The
current engine is **pure Node.js (no Docker)** and runs on **Windows, macOS, and Linux**.

> Shannon does not "flag suspicious responses." A vulnerability is recorded **only** when a
> deterministic prober proves it — arithmetic evaluated by the DB, a planted canary reflected
> back, a controlled differential between a TRUE and a FALSE payload, an out-of-band callback
> that actually fired, or an exposed-file signature that actually matched.

---

## How it works — two layers

| Layer | Role | Trust |
|-------|------|-------|
| **Deterministic proof engine** (`purple-engine.mjs` + module files) | Sends real crafted requests, confirms with benign proof markers, differentials, and controls | **Truth.** A finding exists iff a proof fired. |
| **LLM layer** (optional, needs `ANTHROPIC_API_KEY`) | Remediation text, detection rules, a *refute-only* judge, and a *propose-but-verify* reasoner | **Judgment.** It can never *create* a finding — only explain or attempt to refute one. |

Because the engine is the source of truth, **35 of 36 detection classes run with no API key at
all.** The key only enriches reporting and the AI-reasoning class.

For every **confirmed** finding the engine also emits a concrete **detection rule** (WAF/SIEM)
and, for payload classes, stands up a **live inline filtering proxy** that re-runs the exploit
and proves it is now **blocked (403)** — attack *and* defense in one pass.

---

## Detection coverage — 36 classes across 5 layers

| Layer | Classes (examples) |
|-------|--------------------|
| **Web** (25 + 2) | SQLi (error-based · boolean-blind · time-based), NoSQL, XSS (reflected · stored · DOM, headless-executed), SSRF, XXE (OOB), command injection, path traversal, CRLF / header injection, host-header, open redirect, CSRF, mass-assignment, IDOR, verbose errors, auth-testing (weak creds · no-rate-limit · user-enumeration), access-control **BOLA/BFLA** (multi-identity), API excessive-data-exposure, GraphQL abuse (introspection · suggestion · batching) |
| **TLS/SSL** | Deprecated protocols, expired / self-signed / hostname-mismatch certs, weak keys |
| **DNS / attack surface** | Subdomain enumeration (crt.sh) + **subdomain-takeover** (dangling CNAME + service fingerprint) |
| **Cloud** | Publicly-listable, site-referenced storage buckets (S3 / GCS / Azure) |
| **Network** (opt-in) | Unauthenticated Redis / Memcached / Elasticsearch / anonymous FTP |
| **LLM attack surface** | **Prompt injection — direct & indirect (2nd-order), with reproducible evidence.** Discovers where an LLM sits behind the HTTP surface, then confirms injection only when the model emits a *computed* marker (arithmetic / reversed-nonce oracle) absent from a control — no LLM-judge. Chains a benign, read-only **system-prompt-leak** impact proof. Mapped to the **OWASP LLM Top 10 (2025)**. See [`docs/research/llm-attack-surface.md`](docs/research/llm-attack-surface.md). |

### Platform intelligence (layered on top of raw findings)

- **Attack-path chaining** — correlates confirmed findings into real kill chains
  (secrets→datastore, SSRF→cloud, Redis→RCE, auth-bypass→admin, traversal→secrets,
  stored-XSS→account-takeover, takeover→phishing).
- **Demonstrated impact** — benign, read-only post-exploitation: extracts the real DB version
  from a SQLi error; proves `uid=0(root)` from a command-injection context.
- **Continuous monitoring + alerts** — stable finding IDs, baseline diffing, and Slack/Discord/
  generic-webhook alerts fired **only** on *newly appeared* exposures.
- **AI reasoning** (key-gated) — the LLM *proposes* privileged field names / attack ideas; the
  engine *deterministically verifies* each before it can become a finding.
- **Personal Security Shield** — read-only, deterministic analysis of suspicious messages and links
  for phishing, credential theft, payment pressure, dangerous attachments, suspicious destinations,
  and prompt-injection language. It does not open links, execute content, invoke an AI model, or store
  the submitted message.
- **Multi-agent security team** — a blackboard-coordinated team of role-specialized agents (recon ·
  exploit pool · remediation · report) that runs a full engagement hands-off with autonomous handoffs,
  rendered as a live "graph of agents." Agents orchestrate; the deterministic engine still confirms
  every confirmed finding and separates unverified leads from reproducible evidence. See
  [`docs/research/multi-agent-security-team.md`](docs/research/multi-agent-security-team.md).
- **Live Defender (blue team)** — connect a system you own on the **Defender** page and Shannon sits
  inline in front of it as a filtering reverse proxy, matching the **URL and body** of every request
  (not headers or cookies) against the engine's deterministic attack signatures. Unlike the offensive
  engine — where a finding includes execution evidence — a live request is judged
  by signature alone, so **inline blocking is restricted to a conservative allowlist of classes**
  (`path-traversal`, `nosql`, `llm-prompt-injection`) whose patterns are specific enough for
  production traffic; **every other class is detected and alerted on, then forwarded**, because those
  signatures exist to re-test a replayed exploit and would otherwise match ordinary requests (a bare
  apostrophe, an HTML tag, a newline in a textarea). Each non-benign request is posted to a live
  blackboard as a defense fact and streamed to the dashboard's activity feed. **Monitor-only by
  default** (it never blocks until you switch to Enforce) and **fail-open** (a classifier error
  forwards traffic, never breaks your app). The LLM layer may raise an alert or explain, but can
  never cause a block. *This slice:* the proxy listens on **loopback (127.0.0.1) on the dashboard
  host** over plain HTTP with no TLS — so it suits a dashboard running on your own machine — its port
  is ephemeral and **changes on every restart**, and connected defenders are in-memory only, so a
  restart loses them and they must be reconnected.

---

## Authorization model

Shannon is for targets you **own or are explicitly authorized to test.**

- **Dashboard** enforces ownership before a scan can start: a **domain-ownership gate**
  (DNS TXT / `.well-known` / meta tag) and an **IP-ownership range gate** (CIDR + HMAC token +
  control proof). `localhost` and `--selftest` are exempt.
- **CLI** trusts the operator: it scans whatever `--target` you give it. Only point it at systems
  you are authorized to test.
- **Network scanning is opt-in** (`--network-scan`) and, via the dashboard, restricted to a host
  inside a verified IP range with an explicit authorization acknowledgment.

Every proof marker is **benign and non-destructive** — Shannon never drops tables, never writes
data, never DoSes a target.

---

## Quick start (proof engine)

Requires **Node.js ≥ 18** and **pnpm ≥ 9**. No Docker.

```bash
git clone https://github.com/far-sae/Securovix-Shannon.git
cd Securovix-Shannon
pnpm install
```

### Prove it works — self-test (no target, no key, no network)

Runs the full exploit→defense loop against an in-process vulnerable app:

```bash
node purple-engine.mjs --selftest
```

### Scan a target you own

```bash
node purple-engine.mjs --target https://staging.yoursite.com --label yoursite
```

Results land in `workspaces/purple-<id>/` (see [Output](#output)).

### Optional LLM enrichment

Create `.env` in the project root (the engine reads it automatically):

```bash
ANTHROPIC_API_KEY=sk-ant-api03-xxxxx   # optional — only for remediation text, judge, AI-reasoning
```

---

## CLI reference

```
node purple-engine.mjs --target <url> [options]

Authentication / session
  --cookie "k=v"                     send a session cookie
  --header "K: V"                    send an arbitrary header (repeatable)
  --login-url U --username U --password P   form-login first, then scan behind the session
  --user-field / --pass-field        override the login field names (default username/password)

Access control (BOLA / BFLA) — enabled automatically with ≥ 2 identities
  --user2-cookie "k=v"  | --user2-login-url U --user2-username U --user2-password P   2nd peer → BOLA
  --admin-cookie "k=v"  | --admin-login-url U --admin-username U --admin-password P   admin → BFLA

Scope / behavior
  --no-crawl                         probe only the target URL (skip crawling)
  --max-pages N                      crawl budget (default 40)
  --headless                         drive a real browser for stored/DOM-XSS execution + SPA crawl
  --network-scan                     OPT-IN: unauth Redis/Memcached/Elasticsearch/anon-FTP
  --monitor                          diff vs the last baseline → report only NEW exposures
  --label NAME                       label for the workspace/report

  --selftest                         full loop against an in-process vuln app (no Docker/target)
```

Environment equivalents: `SHANNON_HEADLESS=1`, `SHANNON_NETWORK_SCAN=1`, `SHANNON_MONITOR=1`,
`SHANNON_ALERT_WEBHOOK=<url>` (monitoring alerts), `SHANNON_SESSION_SECRET` (dashboard sessions),
`PORT` (dashboard port).

---

## Dashboard

A web UI (Express + vanilla-JS SPA) to launch scans, verify domain/IP ownership, and browse
findings, attack paths, demonstrated impact, monitoring diffs, and reports.

```bash
node packages/dashboard/server.mjs
# → Securovix Dashboard running at http://localhost:3000   (override with PORT)
```

It surfaces the SARIF export, the evidence report, and the "Advanced options" (monitoring
webhook, opt-in network scan) for each scan.

### Team workspace

The dashboard includes organization-scoped RBAC, projects, shared finding triage, assignments,
risk-acceptance/false-positive decisions, and an append-only activity feed. Confirmed agent and
pentest findings are imported into the active organization's queue automatically. See
[`docs/TEAM-OPERATIONS.md`](docs/TEAM-OPERATIONS.md) and apply the team-workspace Supabase migration
before enabling it in production.

For durable multi-server operation on Railway with Supabase, scalable workers, private artifacts,
SSO/SCIM/MFA, integrations, retention, and monitoring, follow
[`docs/ENTERPRISE-DEPLOYMENT.md`](docs/ENTERPRISE-DEPLOYMENT.md).

---

## Output

```
workspaces/purple-<id>/
  purple/
    exploit-defend.json          # machine-readable findings + defense results
    exploit-defend-report.md     # combined attack/defense report
    certification-report.md/.html# evidence → impact → chain narrative, CVSS + framework mappings
    report.sarif                 # SARIF 2.1.0 — GitHub code scanning / CI
  broker/
    <class>/findings.json        # per-class confirmed findings + proofs
    monitoring.json              # baseline diff (with --monitor)
    ai-leads.json                # LLM leads (labeled, unverified)
  defense/
    <class>/defense.json         # detection rule + inline-proxy block proof
```

Findings map to **CVSS 3.1**, **OWASP** (WSTG · ASVS · Top 10), **CWE**, **MITRE ATT&CK**,
**PCI DSS 4.0**, and **ISO 27001**.

These framework mappings are informational evidence references, not an audit, certification,
attestation, or statement that Securovix or a customer is compliant.

---

## CI / GitHub code scanning

Shannon emits **SARIF 2.1.0**, so findings show up natively in GitHub's Security tab.
Copy `.github/workflows/shannon-scan.yml.example` → `shannon-scan.yml` and set:

- Secret `ANTHROPIC_API_KEY` (optional), Secret `SHANNON_ALERT_WEBHOOK` (optional)
- Variable `SHANNON_TARGET` — a URL you own/authorize

The workflow runs the proof scan (with `--monitor`) and uploads the SARIF report.

---

## Tests

```bash
npm test        # 52 tests across 8 files — node:test, no network required
```

| Suite | Covers |
|-------|--------|
| `engine.test.mjs` · `crawler.test.mjs` · `templates.test.mjs` · `cvss.test.mjs` · `cert-report.test.mjs` | engine internals, crawler, payload templates, CVSS scoring, report rendering |
| `advanced.test.mjs` | pure-logic modules: attack-chains, monitor, ip-ownership, sarif, cloud-exposure |
| `probers.test.mjs` | detection probers vs local mock servers (SQLi error+blind, NoSQL, CRLF, host-header, CSRF, mass-assignment, verbose-errors, API-data-exposure, GraphQL, auth-testing, network-scan) |
| `flows.test.mjs` | flow modules: access-control (BOLA/BFLA), impact (SQLi-extract + root), cloud-exposure, attack-surface takeover |

Each prober/flow test asserts it **confirms on a vulnerable response and abstains on a safe one**
— the zero-false-positive property is regression-gated in CI.

```bash
pnpm lint       # Biome check + format
```

---

## Repository layout

```
purple-engine.mjs        # the proof engine + CLI entry point
crawler.mjs / crawler-headless.mjs
tls-scan.mjs             attack-surface.mjs   cloud-exposure.mjs   network-scan.mjs
access-control.mjs       impact.mjs           attack-chains.mjs    monitor.mjs
ai-reason.mjs            ip-ownership.mjs      sarif.mjs           cvss.mjs
templates.mjs            cert-report.mjs
*.test.mjs               # 8 committed test suites (npm test)
packages/
  dashboard/             # Express + SPA control panel (node server.mjs)
  tool-broker/           # findings broker
  cli/  worker/          # legacy Temporal/Docker orchestration (see below)
docs/                    # capability sheet + explainer (HTML + PDF)
.github/workflows/       # ci.yml (runs npm test) + shannon-scan.yml.example
```

---

## Legacy: Temporal / Docker orchestration

An earlier architecture (in `packages/cli` = the published `@keygraph/shannon`, plus
`packages/worker`, `Dockerfile`, and `docker-compose.yml`) runs LLM agents inside a
Temporal-orchestrated Docker worker. It is **WSL2 + Docker only** and is retained for the
container-based, config-file workflow:

```bash
pnpm build                         # compile the CLI + worker first (dist/ is not checked in)
export SHANNON_LOCAL=1
node packages/cli/dist/index.js scan --config my-target.yaml
```

It reads a YAML config (`shannon.example.yaml`), starts Temporal via Docker Compose, builds the
worker image, and writes a full workspace (recon → vuln → exploit → war-room → forensic package).
See the git history and `shannon.example.yaml` for the config schema, auth types (form / SSO /
API-key / HTTP-basic), retry presets, and per-agent model tiers. New work targets the pure-Node
proof engine above.

---

## Responsible use

Only test systems you own or are explicitly authorized to assess. Shannon's proofs are benign by
design, but running any scanner against a system without authorization may be illegal. You are
responsible for how you use it.

---

## License

MIT
