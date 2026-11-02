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
