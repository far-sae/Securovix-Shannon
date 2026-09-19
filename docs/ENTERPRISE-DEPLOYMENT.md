# Enterprise deployment: Railway + Supabase

This deployment separates the HTTP dashboard from durable background workers. Supabase is the shared system of record and private artifact store, so scans survive web deploys and any available worker can claim them.

## 1. Create and migrate Supabase

Create a Supabase project, keep the service-role key server-side, then apply the migrations:

```bash
supabase link --project-ref YOUR_PROJECT_REF
supabase db push
```

The enterprise migration creates the job queue, atomic job-claim and token-consumption functions, identities, integrations, delivery history, operational events, and the private `shannon-artifacts` Storage bucket. Row-level security is enabled with no anonymous policies; Railway services use the service-role key.

Enable Supabase point-in-time recovery for production and regularly test a restore.

## 2. Create the Railway web service

Deploy the repository with `railway.json`. It builds `Dockerfile.dashboard`, starts `packages/dashboard/server.mjs`, and checks `/readyz`.
The production image includes Playwright and Chromium, and sets `SHANNON_HEADLESS=1`, so JavaScript-heavy
crawling and browser-backed XSS proof do not silently fall back to HTTP-only analysis.

Set every production variable from [`.env.example`](../.env.example), especially:

- `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY`
- unique random `SHANNON_SESSION_SECRET` and `SHANNON_ENCRYPTION_KEY`
- `SHANNON_PUBLIC_URL` set to the public Railway domain
- `SHANNON_DURABLE_JOBS=1` and `SHANNON_REQUIRE_EMAIL_VERIFICATION=1`
- an email provider (`RESEND_API_KEY` plus `SHANNON_EMAIL_FROM`, or the HTTPS relay variables)
- `SHANNON_METRICS_TOKEN`

Never expose the Supabase service-role key or either Shannon secret in browser variables, build arguments, logs, or source control.

## 3. Create the Railway worker service

Create a second service from the same repository. Select `railway.worker.json` as its config file, or override its start command with:

```bash
node packages/dashboard/worker.mjs
```

Copy the same Supabase, encryption, LLM, email, and retention variables to it. Do not attach a public domain. Scale this service horizontally for more scan throughput. PostgreSQL row locks with `SKIP LOCKED` ensure one worker claims each job. Stale leases recover automatically after a worker crash.

The worker exposes `/healthz` and `/readyz` on Railway's injected `PORT`; `railway.worker.json` uses
the readiness endpoint during deployment. It also writes a heartbeat to Supabase every minute, which
appears in the dashboard's **Settings → Production readiness** panel.

The same Worker schedules continuous-defense cycles. After applying
`20260919120000_continuous_defense.sql`, owners/admins/engineers can enable the loop from **Defender
Operations**, choose a cadence (24 hours by default), and run an immediate cycle. The PostgreSQL
claim function uses `FOR UPDATE SKIP LOCKED`, so horizontally scaled workers do not schedule the
same due organization concurrently.

`SHANNON_WORKER_CONCURRENCY` controls child scans per worker. Start with `1` or `2`; increase only after watching Railway memory and CPU. Artifact uploads are private and downloads use short-lived signed URLs after organization RBAC checks.

The web service refreshes its authorization cache from Supabase using `SHANNON_CACHE_REFRESH_MS` (default five seconds), allowing multiple web replicas to converge on account, role, project, finding, and scan-owner changes. Keep this low for rapid revocation and monitor Supabase load when scaling web replicas.

## 4. Create the Defender Edge service

Create a third Railway service from the same repository and select `railway.edge.json`. This builds
the minimal `Dockerfile.edge`, starts the public reverse proxy, and checks `/__edge/health`.

Set these variables on the Edge service:

- `SHANNON_DASHBOARD_URL=https://YOUR-DASHBOARD-DOMAIN`
- `SHANNON_EDGE_PLATFORM_TOKEN=` a new 32-byte random token, set to the same value on the Dashboard and Edge services
- `SHANNON_EDGE_REFRESH_MS=60000`
- optionally `SHANNON_EDGE_ROUTES=[]` as a static recovery floor

Attach a public Railway domain to Edge. Do not use a customer's SDK key for the shared service:
`SHANNON_EDGE_API_KEY` is retained only for
legacy single-organization deployments. The Edge service uses `Dockerfile.edge`. Start every route in monitor mode, verify telemetry, and
only then switch that route to enforce.

## 5. Identity and provisioning

- OIDC: owners/admins configure each organization separately. Its start URL is `/auth/sso/org/ORG_ID/start`; register `/auth/sso/org/callback` with the provider. Global `OIDC_*` variables are legacy fallback only.
- SCIM: owners/admins create/rotate a separate bearer token for each organization. Its base URL is `/scim/v2/orgs/ORG_ID`. Global `SHANNON_SCIM_*` variables are legacy fallback only.
- MFA: users enable TOTP from the MFA profile control and receive one-time recovery codes.
- Invitations, verification, and password-reset links require a working email provider in production.

## 6. Integrations and operations

Owners and admins can configure generic webhooks, SIEM HTTP, Slack, Teams, Jira Cloud, and Linear from Team Workspace. Connector credentials are encrypted at rest. Deliveries use the durable queue, exponential-backoff retries, and dead-letter status after exhaustion.

Defender SDK detections and incident status changes use the same durable integration pipeline. Use
the Defender Operations page to triage incidents, rotate the organization-scoped SDK credential,
export evidence, and control durable edge routes. Keep edge routes in monitor mode until their
telemetry has been reviewed, then promote individual routes to enforce.

### Continuous-defense asset coverage

- Add verified web/domain/API assets and connect them to an Edge route or Defender SDK.
- Add a verified CIDR only after the IP-range ownership challenge succeeds.
- Cloud, repository, identity, network, and endpoint entries begin as **inventory only**. They become
  covered only while an authorized customer collector sends an organization-scoped heartbeat to
  `POST /api/defender/sensors/heartbeat` with `{ "assetId": "..." }` and a current Defender SDK key.
- Send collector detections through `POST /api/defender/report`. Do not give a collector the
  Supabase service-role key, Edge platform token, session secret, or encryption key.
- Sensor coverage expires from the defense model after 15 minutes without a heartbeat. A cycle
  learns priorities from outcomes and false-positive dispositions, but cannot change enforcement.

The loop is orchestration, not a universal agent by itself. Private network traffic, cloud audit
logs, identity events, repository events, and endpoint telemetry need appropriate customer-side
collectors. Do not market an inventory-only asset as monitored or protected.

Monitoring endpoints:

- `GET /healthz`: process liveness
- `GET /readyz`: Supabase and durable-runtime readiness
- `GET /metrics` with `Authorization: Bearer $SHANNON_METRICS_TOKEN`: Prometheus metrics
- `GET /api/system/readiness` while authenticated as an owner/admin: configuration and live worker/edge status

Alert on readiness failures, dead-letter jobs, growing queue depth, and expired worker leases. Retention runs at worker startup; completed jobs, tokens, delivery logs, operational logs, and artifacts use the configurable retention-day variables.

Use [Production operations and incident response](./PRODUCTION-OPERATIONS.md) for backup restore tests,
Railway alerts/log retention, incident handling, Sandbox Runner release evidence, and independent review.

## Billing and organization limits

Daily limits are enforced atomically per organization in Supabase. To enable paid Pro checkout, set
`STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRO_MONTHLY_PRICE_ID`, and optionally
`STRIPE_PRO_YEARLY_PRICE_ID`, then register `https://YOUR_DOMAIN/api/billing/webhook` in Stripe.
Until all required values are present, paid checkout stays disabled and no paid entitlement is granted.

The arbitrary-code AI sandbox deliberately remains unavailable on standard Railway because Railway
does not expose a Docker daemon to application containers. Use the bounded custom-check workflow on
Railway unless you deploy the separate runner described in [Production sandbox runner](#production-sandbox-runner).
Never mount Docker into, or execute LLM-authored code directly inside, the Dashboard container.

## Production sandbox runner

The runner is a separate service under `packages/sandbox-runner`. It accepts authenticated requests
from the Dashboard and is the *only* process allowed to talk to Docker. Each job is a disposable,
network-disabled, non-root, read-only container with CPU, memory, process, and time limits.

1. Provision a dedicated Linux VM (not Railway and not the Dashboard host), install Docker Engine and
   clone this repository there.
2. Create `packages/sandbox-runner/.env` from the following values. Use a newly generated secret of
   at least 32 characters; do not reuse a session, encryption, Supabase, or Defender key.

   ```env
   SANDBOX_RUNNER_DOMAIN=sandbox-runner.yourdomain.com
   SHANNON_SANDBOX_RUNNER_TOKEN=YOUR_NEW_LONG_RANDOM_SECRET
   SHANNON_SANDBOX_MAX_CONCURRENT=2
   ```

3. Create a DNS record for `sandbox-runner.yourdomain.com` pointing to the VM public IP, then run:

   ```bash
   cd packages/sandbox-runner
   docker compose up -d --build
   ```

   Caddy obtains the TLS certificate and exposes HTTPS; port 8080 remains private inside Docker.
   Firewall the VM to TCP 80/443 only. Do not expose Docker's port or `/var/run/docker.sock`.
4. On the Railway **Dashboard** service only, set:

   ```env
   SHANNON_SANDBOX_RUNNER_URL=https://sandbox-runner.yourdomain.com
   SHANNON_SANDBOX_RUNNER_TOKEN=THE_SAME_NEW_LONG_RANDOM_SECRET
   ```

   Redeploy Dashboard. The Settings readiness card changes the sandbox to **Ready** only after the
   authenticated runner health check confirms Docker is available.

The runner accepts only Python and Node jobs, caps source/input sizes, fixes execution to at most 20
seconds, does not accept arbitrary image names or Docker arguments, and does not log code or input.
Use a dedicated VM and keep it patched; treat the runner token as a production secret.

## 7. Release checklist

1. Run the complete test suite and production dependency audits.
2. Apply migrations before deploying code that uses them.
3. Deploy the worker, dashboard, and (when required) Defender Edge as separate services.
4. Open **Settings → Production readiness**, verify required checks are green, enqueue a test connector delivery, and run an authorized test scan.
5. Send a staging Defender SDK detection, triage it, rotate the key, and confirm the previous key is rejected.
6. Confirm the scan and Defender incident survive a web restart and the report downloads from Supabase Storage.
7. Test invitation, password reset, MFA recovery, OIDC, SCIM deactivation, backup restore, and secret rotation in staging.
