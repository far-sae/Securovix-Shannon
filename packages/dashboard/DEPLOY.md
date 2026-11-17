# Hosting the Securovix Shannon dashboard (so people can use it)

The dashboard **and the AI Agent are pure Node.js — no Docker required to run them.** Point any Node
host at `packages/dashboard/server.mjs` and it works. Docker is offered only for portability.

## What you need

| Env var | Required | Purpose |
|---|---|---|
| `PORT` | no (default 3000) | Listen port |
| `SHANNON_SESSION_SECRET` | recommended | Signs login sessions |
| `SUPABASE_URL` + `SUPABASE_SERVICE_ROLE_KEY` | for persistence | Users, leaderboard, verified domains survive restarts (else local JSON, wiped on redeploy). See `supabase/schema.sql`. |
| `ANTHROPIC_API_KEY` | optional | Only the AI *narrative* + war-room. The agent, all 36 proof classes, and the deterministic fix/plan run **without** it. |

### Defender self-protection (recommended production settings)

| Env var | Set to | What it does |
|---|---|---|
| `SHANNON_DEFEND_SELF` | `1` | Inspects every dashboard request. |
| `SHANNON_DEFEND_SELF_MODE` | `enforce` | Blocks confirmed attacks (403). `monitor` only records. Can also be flipped live on the Defender page — the fastest kill switch. |
| `SHANNON_DEFEND_SELF_BAN` | `1` | Tracks repeat offenders. |
| `SHANNON_DEFEND_SELF_BAN_MODE` | `enforce` | Refuses banned IPs. Without it bans are report-only. |
| `SHANNON_DEFEND_SELF_HONEYPOT` | (unset) | Honeypot paths are on by default; set `0` to turn them off. |
| `SHANNON_DEFEND_SELF_SCANNERS` | (unset) | Attack-tool detection is on by default; set `0` to turn it off (for example while you run your own scanner against the dashboard). |
| `SHANNON_PLATFORM_ORG_ID` | your org id | Sends confirmed detections and bans to that organization's alert integrations. |
| `SHANNON_LOGIN_LOCK_THRESHOLD` | (unset = 10) | Failed sign-ins for one account, from any address, before that account is locked. |
| `SHANNON_LOGIN_LOCK_MINUTES` | (unset = 15) | How long the lock lasts. A password reset lifts it at once. |
| `SHANNON_DEFENSE_DIGEST` | (unset) | The weekly attack summary email is on by default; set `0` to turn it off for everyone. Needs `SHANNON_PUBLIC_URL` for the link back to the dashboard. |
| `SHANNON_DEFENDER_INTAKE_PER_MINUTE` | (unset = 300) | Detections one organization may store per minute from each source (its sites, the shared edge). Past it, one notice is stored and the rest of that minute is dropped. Alerts are already limited to one per kind of attack per site per minute. |
| `SHANNON_ALLOW_LOCAL_TARGETS` | (unset) | In production, targets on the server itself (`localhost`, `127.*`, `*.local`) are refused. Set `1` only on a private installation that tests sites on the same machine. |
| `SHANNON_LOCAL_OPERATOR` | (unset) | Outside production, set `1` to treat a signed-in user on this machine as the platform operator. Never has an effect in production; operators are the emails in `SHANNON_PLATFORM_ADMINS`. |
| `SHANNON_DEV_TOKENS` | (unset) | Outside production, set `1` to have sign-up, reset and invitation answers include the one-time token (for local development without an email provider). Never has an effect in production. |
| `SHANNON_REQUIRE_EMAIL_VERIFICATION` | (unset) | In production with an email provider configured, new accounts must open a verification link before they can sign in or use any feature. Set `0` to switch that off, or `1` to force it on anywhere. |

What is blocked: path traversal, NoSQL injection, prompt injection, and the strict (structural)
forms of SQL injection, XSS, command injection, template injection, server-side request forgery and
XML external entities. "Strict" means the shape of a real attack, never a single character: a quote
that breaks out into a tautology, comment or stacked statement; `<script>`, inline event handlers and
`javascript:` calls; a shell separator followed by a command (`; cat /etc/…`, `$(id)`); `{{7*7}}` and
`${jndi:…}`; cloud metadata addresses; `<!ENTITY … SYSTEM …>`. The full table is in
`packages/defender-sdk/README.md`. A request for scanner bait (`/.env`, `/.git/config`,
`/wp-login.php`, `*.php` …) gets a plain 404, and a request from a tool that names itself (sqlmap,
nikto, nuclei …) gets a 403; both ban that IP immediately. Bans are stored in the database
(`supabase/migrations/20261112120000_defender_bans.sql`), so a redeploy does not lift them and every
instance enforces the same list. The assistant, finding evidence and API scan routes are not
inspected because they carry attack text by design. Alerts are delivered by the worker service
(`railway.worker.json`) — deploy it or detections stay queued.

Account lockout: sign-in is limited per address (10 attempts in 15 minutes) and per account. After
10 wrong passwords for one account — from any number of addresses — that account is locked for 15
minutes, including for the correct password, and the same happens for wrong two-factor codes. The
count is kept in memory, per server instance.

Weekly attack summary: every Monday from 08:00 UTC, each organization's owners and admins get one
email covering the previous Monday-to-Sunday week — attacks detected and blocked, bans, attack types
and the most active source addresses. An organization with no attacks that week gets nothing. Each
person can turn it off on the Defender page, where they can also preview the last 7 days or send it
to themselves. It uses the same email provider as password reset (`RESEND_API_KEY` or
`SHANNON_EMAIL_WEBHOOK_URL`) and is skipped in production when neither is set.

Protecting a site hosted elsewhere (for example `www.securovix.com` on Vercel): use the web adapter,
`@securovix/defender/web`. The ready-made file is `packages/defender-sdk/examples/vercel-middleware.js`
and the instructions are in `packages/defender-sdk/README.md`.

### Guard: identity and cloud defence (Microsoft 365, Google Workspace)

Apply `supabase/migrations/20261113120000_guard.sql` first. Guard runs inside the dashboard
process (no worker needed): every 2 minutes it reads each connected tenant, runs the detections,
groups alerts into incidents, sends new or escalated incidents to the organization's alert
integrations as `guard.incident`, and runs autopilot if an owner switched it on.

| Env var | Set to | What it does |
|---|---|---|
| `SHANNON_GUARD_SYNC` | (unset) | Background sync is on by default; `0` turns it off (the "Check now" button still works). |
| `SHANNON_GUARD_INTERVAL_MS` | (unset = 120000) | How often to sync. Minimum 60000. |
| `SHANNON_GUARD_INTEL` | (unset) | Downloads the abuse.ch Feodo Tracker IP blocklist every 6 hours; `0` turns it off. Nothing about the customer is sent. |
| `SHANNON_ENCRYPTION_KEY` | 32+ random characters | Required in production; tenant secrets are stored encrypted with it. |
| `SHANNON_GUARD_DEMO` | (unset) | A production server shows only real data: the demo tenant cannot be added and its scenarios cannot run. Set `1` to offer it (for example to show Guard to a prospect). Outside production it is always available. |

Customers connect on the **Guard** page (owners and admins). Microsoft 365 needs an app
registration with application permissions `AuditLog.Read.All`, `Directory.Read.All` and Office 365
Management APIs `ActivityFeed.Read`; one-click responses also need `User.ReadWrite.All`,
`User.RevokeSessions.All`, `MailboxSettings.ReadWrite`, `DelegatedPermissionGrant.ReadWrite.All`,
`AppRoleAssignment.ReadWrite.All`. Sign-in logs need Entra ID P1 (included in Business Premium).
Google Workspace needs a service account with domain-wide delegation for
`admin.reports.audit.readonly`, `admin.directory.user`, `admin.directory.user.security`. Google's
logs have no location, so travel checks are Microsoft-only. The **demo tenant** (off in
production unless `SHANNON_GUARD_DEMO=1`) needs nothing and can play an account takeover, a
password spray or insider data theft. Removing it deletes everything it simulated: its incidents,
the actions taken on them, the addresses those actions blocked and the baselines of its users.
Removing a real tenant keeps its incident history (`DELETE …/connections/:id?purge=1` removes
that too).

What it detects: impossible travel, first sign-in from a new country (after a 7-day, 10-sign-in
learning period per person), sign-ins from threat-feed or blocklisted addresses, the provider's own
risk flag, MFA fatigue, brute force, password spraying, suspicious inbox rules and external
forwarding, risky app consents (mail/file scopes), download spikes against each person's normal,
sharing to personal addresses or anonymous links, new administrators, MFA turned off. Each is
mapped to MITRE ATT&CK. Joined to Shannon: Defender traffic that hits a path Shannon proved
vulnerable opens a critical incident, which can only close once the finding is resolved (re-tested)
unless someone overrides it; every open finding gets a path-scoped Cloudflare and AWS WAF rule.

Responses: sign out everywhere, force a password change, disable/enable, remove/restore an inbox
rule, revoke/restore an app's access, block an address. Disable, rule removal, app revocation and
blocking can be undone; Google cannot re-grant a revoked app token. Autopilot is off by default and
is chosen per action. Guard stores alerts and per-person baselines, never the raw logs. The AI
analyst ("Explain") uses the organization's own Anthropic key; the built-in summary needs none.

### Guard Phase 2: endpoint agent, ransomware, malware sandbox

Apply `supabase/migrations/20261114120000_guard_endpoint.sql`. The agent (`packages/guard-agent`,
see its README) talks to `/api/endpoint-agent/v1/*` with its own credential; the dashboard's
self-defense skips that path because agents upload attack command lines as evidence. Agent alerts
join the same Guard incidents, autopilot and alert integrations; isolate/stop/quarantine actions
are queued for the machine and complete when it confirms (normally within 10 seconds).

**Getting the agent onto a machine.** `Dockerfile.dashboard` builds the agent in its first stage
(Linux as one static binary that runs on any distribution, Windows cross-compiled) and puts both
in the image, so the agent a customer installs always matches the server. **Add a machine** on the
Guard page shows one command per platform that downloads the binary from
`/api/endpoint-agent/v1/download/<linux|windows>`, checks its SHA-256 against this server's build
and installs it as a service. That download needs no sign-in, so a server without a browser can
fetch it with `curl`; the program is open source and does nothing until it is enrolled with an
organization's token. The first build of a new agent version adds roughly two minutes to the image
build; after that the stage is cached until `packages/guard-agent` changes.

Servers have no Documents folder, so list their data folders under **Protection settings → Extra
folders to watch** (on a Docker host, the folders mounted into containers). Machines start watching
a new folder at their next check-in. Isolating a Linux machine also closes its forward path, so
containers and virtual machines on it lose the network too and published ports stop answering.

| Env var | Set to | What it does |
|---|---|---|
| `SHANNON_CAPE_URL` | your CAPE v2 server | Optional. Files from agents are detonated there and scored; a malicious verdict blocks that hash on every customer's machines (hash, family and verdict only are shared). Without it, files are recorded but not analysed. |
| `SHANNON_CAPE_TOKEN` | CAPE API token | Sent as `Authorization: Token …`. |
| `SHANNON_CAPE_TIMEOUT_SEC` | (unset = 180) | Analysis time per file. |
| `SHANNON_GUARD_AGENT_DIR` | folder with agent binaries | Optional. Serve agent builds from this folder instead of the ones built into the image (`securovix-guard-linux-x86_64`, `securovix-guard-windows-x86_64.exe`), for example signed binaries. |

CAPE needs its own KVM host with analysis VMs and cannot run on Railway. The sandbox verdict is a
logistic regression over the CAPE report (malscore, signatures, YARA, family, dropped files,
recovery tampering) with hand-set starting weights; `fitWeights` / `evaluate` in
`guard/sandbox.mjs` retrain and measure it on your labelled reports — do that before relying on
the ">95% accuracy" goal. Machines that stop checking in for 10 minutes raise a medium "agent
stopped" alert; queued commands expire after 24 hours.

### Pricing, credits and payments (all optional — off by default)

While `SHANNON_COMMERCE_ENABLED` is unset, Securovix is **free during beta**: `/pricing` shows launch
prices, the in-app **Billing** page shows usage and prices, and every purchase answers
`503 COMMERCE_DISABLED`. Prices live only in `packages/dashboard/commerce.mjs`.

| Env var | Purpose |
|---|---|
| `SHANNON_COMMERCE_ENABLED=1` | Opens purchases of fixed-price scan offers and credit packs. |
| `STRIPE_SECRET_KEY` + `STRIPE_WEBHOOK_SECRET` | Enables card payments (one-off Stripe Checkout). Point the Stripe webhook at `/api/billing/webhook` and send `checkout.session.completed` and `checkout.session.async_payment_succeeded`. Add `STRIPE_PRO_MONTHLY_PRICE_ID` (and optional `STRIPE_PRO_YEARLY_PRICE_ID`) to also sell the Pro subscription. |
| `SHANNON_PAY_CRYPTO_WALLETS` | Crypto by manual review, e.g. `BTC=bc1q...;ETH=0x...;USDT=T...`. Addresses are shown only to a buyer with an open order. |
| `SHANNON_PAY_QR_IMAGE_URL` (+ `SHANNON_PAY_QR_LABEL`) | Regional QR payment by manual review. An `https://` URL or a path under `public/`. |
| `SHANNON_PAY_BANK_DETAILS` | Bank transfer by manual review (free text). |
| `SHANNON_PLATFORM_ADMINS` | Comma-separated emails that see the **Payment review queue** on the Billing page and approve or reject manual payments. |

Manual payments: the buyer creates an order, pays using the order reference, then submits the
transaction hash / reference. An admin approves it and the credits are added. Credits last 90 days, are
used automatically after the daily allowance runs out, and spend soonest-expiring first. Apply
`supabase/migrations/20261102120000_commerce_credits.sql` before enabling commerce on Supabase.

### Security assistant, research reports, developer API, share links

Apply `supabase/migrations/20261102130000_assistant_api_share.sql` before using these on Supabase.

- **Assistant** (sidebar → Assistant): chat about the organization's findings and scans, with
  organization **memory** (notes, or `/remember …` in chat), **research reports** (a full assessment
  of a verified domain, written in the background; costs one agent run) and **shared links**.
  It calls Claude with the organization's own Anthropic key. Model: `claude-opus-5-5` by default;
  override with `SHANNON_ASSISTANT_MODEL`. Server-side refusal fallbacks are enabled for models
  that support them. Scan data sent to the model is wrapped as data, not instructions.
- **Developer API** (sidebar → Developer API): owners/admins create keys
  (`Authorization: Bearer svx_…`) with scopes `scans:read`, `scans:write`, `findings:read`. Routes:
  `GET /api/v1/me`, `GET /api/v1/scans`, `GET /api/v1/scans/:id`, `GET /api/v1/scans/:id/report`
  (`?format=md|sarif`), `POST /api/v1/scans`, `GET /api/v1/findings`. A key acts as its creator in
  its organization; domain verification, the `authorized` attestation and daily limits still apply.
  `/api/v1` accepts keys only (no browser cookies). Only a hash of each key is stored.
- **Share links** (`/share/<token>`): read-only, `noindex`, expire after 1–30 days, revocable, with a
  view count. Research and conversation pages are rendered with raw HTML escaped; shared scan
  reports are served under a `sandbox` Content-Security-Policy.

Public marketing pages: `/pricing`, `/security-testing` and one page per area
(`/security-testing/web-application-security`, `api-security`, `llm-security`, `tls-ssl`,
`subdomain-takeover`, `cloud-storage-exposure`, `network-services`), plus `/sitemap.xml` and `/robots.txt`.

## Option A — Railway / Render / Fly / any Node host (simplest)

- **Start command:** `node packages/dashboard/server.mjs`
- Install: `npm install` inside `packages/dashboard` (its deps: express, marked, @anthropic-ai/sdk, yaml).
- Set the env vars above. Done — this is how it runs today.

## Option B — Docker (host anywhere)

Build from the **repo root** (the dashboard imports sibling engine modules):

```bash
docker build -f packages/dashboard/Dockerfile -t shannon-dashboard .
docker run -p 3000:3000 -e SHANNON_SESSION_SECRET=change-me shannon-dashboard
```

Deployable to any container host (Fly.io, Render, ECS, a VPS, Kubernetes). **This is plain app
packaging — it does not need a Docker socket or privileged mode.**

## Code sandbox (optional — the "Exploit sandbox" panel)

The AI-writes-code sandbox runs each snippet in a **hardened, network-isolated Docker container**
(`--network none · --cap-drop=ALL · --read-only · non-root · memory/cpu/pids limits · timeout`). It's
**off unless Docker is reachable by the dashboard process** — otherwise the panel just says so.

To enable it:

1. **Give the dashboard access to Docker** — the `docker` CLI on `PATH` and the daemon socket. On a
   VM/VPS that's automatic; in a container, mount the socket and add the CLI (as the broker image does):
   `-v /var/run/docker.sock:/var/run/docker.sock`.
2. **Build & host the sandbox image** (guarantees the interpreters + offline libs):
   ```bash
   sh packages/dashboard/sandbox/build.sh                 # → shannon-sandbox:local
   # or push a registry tag:
   sh packages/dashboard/sandbox/build.sh ghcr.io/you/shannon-sandbox:1 --push
   ```
3. **Point the dashboard at it:** `SHANNON_SANDBOX_IMAGE=shannon-sandbox:local` (or the pushed tag).
   If unset, it falls back to the public `python:3-slim` / `node:20-slim` images (pulled on first use).

The sandboxed code has **no network of its own** — Shannon fetches the target (SSRF-guarded) and hands
the response in via `SX_INPUT`. Matches are labeled **potential** leads, never confirmed. For code that
must reach the target over a *scope-enforced* network, use the tool-broker (below), which adds a proxy.

## Note on the multi-agent broker (legacy, optional — NOT needed here)

The older `packages/tool-broker` + `packages/worker` path runs LLM agents + real external tools inside
hardened **Docker-in-Docker** sandboxes. That one genuinely needs a Docker-socket host (Fly machine,
a VM, ECS with the daemon) **plus** Anthropic credits **plus** the GPL sign-off for bundling 3rd-party
tools. It is a separate deployment and is **not required** for the AI Agent — the pure-Node engine
covers the substance. Host the dashboard (above) for people to use; reach for the broker only if you
specifically want sandboxed external-tool execution.
