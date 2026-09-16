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

`SHANNON_WORKER_CONCURRENCY` controls child scans per worker. Start with `1` or `2`; increase only after watching Railway memory and CPU. Artifact uploads are private and downloads use short-lived signed URLs after organization RBAC checks.

The web service refreshes its authorization cache from Supabase using `SHANNON_CACHE_REFRESH_MS` (default five seconds), allowing multiple web replicas to converge on account, role, project, finding, and scan-owner changes. Keep this low for rapid revocation and monitor Supabase load when scaling web replicas.

## 4. Create the Defender Edge service

Create a third Railway service from the same repository and select `railway.edge.json`. This builds
the minimal `Dockerfile.edge`, starts the public reverse proxy, and checks `/__edge/health`.

Set these variables on the Edge service:

- `SHANNON_DASHBOARD_URL=https://YOUR-DASHBOARD-DOMAIN`
- `SHANNON_EDGE_API_KEY=` the organization SDK key shown on the Defender page
- `SHANNON_EDGE_REFRESH_MS=60000`
- optionally `SHANNON_EDGE_ROUTES=[]` as a static recovery floor

Attach a public Railway domain to Edge. Keep the dashboard and worker on `Dockerfile.dashboard`; only
the Edge service uses `Dockerfile.edge`. Start every route in monitor mode, verify telemetry, and
only then switch that route to enforce.

## 5. Identity and provisioning

- OIDC: configure `OIDC_ISSUER`, client credentials, callback URL `https://YOUR_DOMAIN/auth/sso/callback`, and optional allowed domains.
- SCIM: configure a random `SHANNON_SCIM_TOKEN` and `SHANNON_SCIM_ORG_ID`. The base URL is `https://YOUR_DOMAIN/scim/v2`.
- MFA: users enable TOTP from the MFA profile control and receive one-time recovery codes.
- Invitations, verification, and password-reset links require a working email provider in production.

## 6. Integrations and operations

Owners and admins can configure generic webhooks, SIEM HTTP, Slack, Teams, Jira Cloud, and Linear from Team Workspace. Connector credentials are encrypted at rest. Deliveries use the durable queue, exponential-backoff retries, and dead-letter status after exhaustion.

Defender SDK detections and incident status changes use the same durable integration pipeline. Use
the Defender Operations page to triage incidents, rotate the organization-scoped SDK credential,
export evidence, and control durable edge routes. Keep edge routes in monitor mode until their
telemetry has been reviewed, then promote individual routes to enforce.

Monitoring endpoints:

- `GET /healthz`: process liveness
- `GET /readyz`: Supabase and durable-runtime readiness
- `GET /metrics` with `Authorization: Bearer $SHANNON_METRICS_TOKEN`: Prometheus metrics
- `GET /api/system/readiness` while authenticated as an owner/admin: configuration and live worker/edge status

Alert on readiness failures, dead-letter jobs, growing queue depth, and expired worker leases. Retention runs at worker startup; completed jobs, tokens, delivery logs, operational logs, and artifacts use the configurable retention-day variables.

The arbitrary-code AI sandbox deliberately remains unavailable on standard Railway because Railway
does not expose a Docker daemon to application containers. Use the bounded custom-check workflow on
Railway. Enable the sandbox only on a dedicated Docker-capable runner; never weaken it to execute
LLM-authored code directly inside the dashboard container.

## 7. Release checklist

1. Run the complete test suite and production dependency audits.
2. Apply migrations before deploying code that uses them.
3. Deploy the worker, dashboard, and (when required) Defender Edge as separate services.
4. Open **Settings → Production readiness**, verify required checks are green, enqueue a test connector delivery, and run an authorized test scan.
5. Send a staging Defender SDK detection, triage it, rotate the key, and confirm the previous key is rejected.
6. Confirm the scan and Defender incident survive a web restart and the report downloads from Supabase Storage.
7. Test invitation, password reset, MFA recovery, OIDC, SCIM deactivation, backup restore, and secret rotation in staging.
