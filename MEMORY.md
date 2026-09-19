# Securovix Shannon — Project Memory

Last updated: 2026-09-19

## Product mission

Securovix Shannon is an authorized defensive-security platform for companies, security teams, and
eventually individual users. It discovers and verifies security weaknesses, helps defenders
investigate them, recommends fixes, and can monitor or block selected web attacks.

The primary product direction is organization-wide continuous defense: inventory the customer's
websites, APIs, networks, cloud accounts, repositories, identities, and endpoint groups; collect
telemetry from installed Edge/SDK/sensor integrations; detect and contain approved high-confidence
threats; learn from analyst dispositions and recurrence; and repeat on a durable schedule. An asset
listed in inventory is not described as protected until a live sensor or matching Edge route proves
coverage.

Shannon is not an autonomous offensive-attack service. Active testing must remain limited to systems
the user owns or has written permission to test. AI may help reason, prioritize, explain, and prepare
safe checks, but technical controls—not trust in the model—must prevent it from attacking unrelated
people or infrastructure.

## Current production architecture

- `securovix.com`: main company website.
- `origin.securovix.com`: Shannon Dashboard public URL.
- `defender.securovix.com`: public Defender Edge service.
- Railway: Dashboard, Worker, and Defender Edge hosting.
- Supabase: production database and private artifact storage.
- Hetzner: intended host for the isolated Sandbox Runner; deployment and independent live testing
  must be completed before it is offered to customers.
- GitHub repository: `far-sae/Securovix-Shannon`.
- Production-readiness baseline commit before the continuous-defense work: `ad7652e`.

Important environment relationships:

- Dashboard: `SHANNON_PUBLIC_URL=https://origin.securovix.com`.
- Defender Edge: `SHANNON_DASHBOARD_URL=https://origin.securovix.com`.
- Dashboard and shared Edge use the same strong `SHANNON_EDGE_PLATFORM_TOKEN`.
- Customer Defender SDK keys remain organization-specific and must not be placed on the shared Edge.
- Dashboard and Worker must share the same stable `SHANNON_ENCRYPTION_KEY` where both decrypt job
  secrets. Never rotate it without a planned secret-reencryption procedure.
- Platform AI fallback keys are disabled in production with `SHANNON_ALLOW_PLATFORM_AI_KEYS=0`;
  customers normally provide their own organization AI keys.

## What has been built

### Accounts and sessions

- Email/password authentication, verification, reset flow, signed HttpOnly session cookies, Google
  sign-in, MFA with TOTP and recovery codes, and role-based access controls.
- Production refuses missing or weak session/encryption secrets.
- Cookies, login URLs, usernames, and passwords are never put in EventSource/streaming URLs.
- Authenticated agent scans use encrypted, exact-origin-bound, five-minute, single-use grants.
- Non-durable scanner authentication files are private temporary files and are deleted after exit.

### Organizations and secrets

- Organization workspaces, memberships, roles, projects, findings, audit events, integrations, and
  scan ownership are tenant-scoped.
- Customer AI keys are encrypted in the organization secret store. They are not stored in browser
  `localStorage` and are never returned to the browser after saving.
- Organization OIDC and SCIM secrets are encrypted. OIDC requires an email domain the configuring
  administrator has verified, and its issuer/endpoints must be public HTTPS origins.
- Tenant-scoped SCIM deactivation removes the affected organization membership instead of disabling
  the user across every organization.

### Security products

- Authorized website scanning with ownership verification, deterministic proof checks, reports,
  remediation guidance, monitoring, and optional network checks.
- AI Agent understanding, investigation, multi-agent runs, history, findings, and reporting.
- Source Code Scan with quick scan, project scan, provider selection, and multi-agent review.
- Personal Security Shield first slice: authenticated, rate-limited, deterministic analysis of
  suspicious messages and links for phishing, credential theft, payment pressure, impersonation,
  dangerous attachments, suspicious URL properties, and prompt-injection language. It does not open
  links, execute content, call an AI model, or persist the submitted content.
- Defender SDK credentials, detection events, incident states, monitor/enforce modes, and self-defense.
- A shared multi-tenant Defender Edge that fetches all routes with a platform credential and derives
  organization identity from the stored hostname mapping—not from an organization ID supplied by the
  Edge request.
- A tenant-scoped continuous-defense foundation: organization asset inventory, verified domain/CIDR
  gates, sensor heartbeats, durable scheduled/manual defense cycles, coverage scoring, incident and
  finding backlog analysis, recurring-attack prioritization, integration escalation, and explicit
  false-positive feedback. Learning cannot silently change enforcement rules.
- A dedicated Sandbox Runner design that executes bounded Python or Node code inside disposable,
  network-disabled, read-only, non-root Docker containers with CPU, memory, process, timeout, output,
  request-size, and concurrency limits.

### Commercial and operational controls

- Stripe checkout, signed webhook verification, customer portal access, durable entitlements, daily
  organization usage counters, free/pro limits, and per-user rate limiting.
- Stripe checkout completion does not grant Pro unless payment is paid or no payment is required;
  inactive, canceled, or expired subscriptions fall back to Free limits.
- Public Terms, Privacy Policy, retention rules, and security/contact page.
- Supabase backup/restore, Railway alert/log, incident-response, Sandbox Runner test, and independent
  penetration-test procedures are documented.
- Reports use evidence-based language. Framework mappings are informational and are not certification
  or compliance claims. Do not claim ISO 27001, SOC 2, PCI DSS, or a passed independent pentest until
  the applicable assessment is formally completed and current.

### Verification status

- 239 automated tests passed after adding the continuous-defense loop and SDK heartbeat coverage.
- Typecheck, build, JavaScript syntax, and diff checks passed.
- Production dependency audits reported no known vulnerabilities at the recorded test time.
- Repository-wide lint has a large pre-existing baseline and is not yet a clean release gate.
- Docker was unavailable on the development laptop, so the deployed Hetzner runner has not been
  independently tested from an external host.

See `docs/SECURITY-VERIFICATION.md`, `docs/PRODUCTION-OPERATIONS.md`, and
`docs/ENTERPRISE-DEPLOYMENT.md` for the detailed evidence and procedures.

## External work that is not complete merely because code exists

The following must never be presented as completed until real evidence is recorded:

1. Apply every pending migration through
   `supabase/migrations/20260919120000_continuous_defense.sql` to production.
2. Confirm Railway deployed the intended commit and all required secrets are set on the correct
   services.
3. Deploy the Sandbox Runner on the dedicated Hetzner VM, configure TLS/firewalling, and perform the
   external isolation/cleanup/token-rotation tests.
4. Enable the appropriate Supabase backup/PITR option and successfully restore into a separate test
   project.
5. Configure and test Railway/on-call alerts and record the real log-retention period.
6. Complete a live Stripe checkout, webhook, renewal/cancellation, and failed-payment test.
7. Test customer OIDC and SCIM against real customer identity providers.
8. Commission an independent penetration test and remediate/retest all high and critical findings.
9. Have qualified legal/privacy counsel review the public policies for the actual company, customers,
   subprocessors, jurisdictions, and commercial terms.

## Primary product direction: Organization-wide continuous defense

The control loop is:

1. **Inventory:** register assets in the correct organization. Domain and CIDR assets require
   ownership verification.
2. **Observe:** receive Edge, SDK, and customer-operated sensor telemetry. A heartbeat proves current
   sensor coverage; inventory alone does not.
3. **Detect and protect:** deterministic Edge/SDK policy may block only when an authorized operator
   explicitly enables enforcement. Other signals create incidents and integrations.
4. **Investigate:** analysts record open, investigating, contained, closed, or false-positive
   outcomes and remediate related findings.
5. **Learn:** each durable cycle measures recurrence, unresolved threats, false positives, coverage
   gaps, failed automation, and finding backlog. This changes priority and recommendations, not
   firewall rules or target scope.
6. **Repeat:** the Worker atomically schedules the next organization cycle (daily by default), so
   multiple replicas cannot run the same scheduled slot twice.

The present implementation directly protects HTTP applications through Edge/SDK. Private networks,
cloud control planes, identity systems, repositories, and endpoint fleets require an installed or
connected collector that sends heartbeats and detections. Building and hardening those individual
collectors remains product work; merely adding those assets to inventory does not protect them.

## Secondary product direction: Personal Security Shield

The next major direction is to protect a person's accounts, messages, browser activity, devices, and
private data from conventional hackers and AI-enabled attacks. The read-only suspicious-message/link
analyzer is now the first implemented slice; the remaining capabilities below are roadmap items, not
current product claims.

### Recommended capabilities

1. **Phishing and scam protection**
   - Analyze suspicious links, email text, QR codes, attachments, and messages.
   - Explain the evidence and risk in plain language.
   - Detect impersonation, urgency/payment scams, credential harvesting, and AI-generated social
     engineering patterns.
   - Never automatically open an untrusted link from the user's normal browser session.

2. **Identity and account protection**
   - Security checklist for MFA, passkeys, recovery methods, reused passwords, and active sessions.
   - Optional breach/exposure monitoring through a legitimate licensed provider.
   - Guided response for account takeover: isolate, revoke sessions, rotate credentials, preserve
     evidence, and contact the provider.
   - Never collect or store a user's plaintext passwords.

3. **Personal privacy monitoring**
   - Show which connected services can access sensitive data and why.
   - Detect accidental secret, document, location, or personal-information exposure.
   - Provide user-controlled retention and deletion with clear export/delete actions.
   - Prefer local processing for sensitive personal content whenever practical.

4. **AI attack protection**
   - Detect prompt injection, malicious instructions hidden in webpages/documents, data-exfiltration
     attempts, unsafe tool requests, and poisoned retrieved content.
   - Treat website, email, document, and tool output as untrusted data—not as system instructions.
   - Put an authorization gateway between every AI decision and every external tool/action.
   - Redact secrets and personal data before model calls unless the user explicitly needs and approves
     that data transfer.

5. **Safe personal incident assistant**
   - Help users investigate alerts, understand risk, and follow a recovery checklist.
   - Require explicit confirmation before changing accounts, blocking access, deleting data, sending
     messages, spending money, or contacting third parties.
   - Keep an understandable audit trail of what the assistant suggested and what the user approved.

## AI safety boundaries — “the AI will not attack us”

No responsible product should promise that a model can never produce a harmful idea. Shannon must
instead make harmful execution technically unavailable or tightly controlled:

- **Authorization first:** active checks require authentication, permission, explicit authorization,
  and verified domain/CIDR ownership.
- **Scope binding:** credentials and grants are bound to one user, organization, target origin, and
  short expiry; they are single-use where possible.
- **No open-ended network access:** AI-written code runs only in the isolated sandbox with networking
  disabled. Network security tools use separately scoped, deterministic brokers.
- **Least privilege:** AI never receives platform service-role keys, encryption keys, session-signing
  keys, Edge platform tokens, or unrelated customer secrets.
- **Deterministic enforcement:** the model may propose or prioritize; conservative deterministic
  controls decide whether a Defender request is blocked.
- **Human approval:** consequential actions require a person with the correct organization role.
- **Untrusted-content separation:** content collected from targets cannot override system policy,
  permissions, scope, or tool constraints.
- **Bounded resources:** time, memory, CPU, process count, body size, output size, concurrency, daily
  usage, and retry limits must apply before expensive or dangerous work.
- **Tenant isolation:** every secret, finding, event, route, usage record, identity configuration, and
  artifact must be resolved through the authenticated organization context.
- **Auditability and revocation:** privileged actions are logged; customer, SCIM, sandbox, and Edge
  credentials can be rotated or revoked.
- **Safe failure:** Defender inspection errors fail open so customer availability is preserved, while
  authentication, tenancy, billing, and secret-access errors fail closed.

## Suggested implementation order

1. Finish and independently test the existing production deployment gates.
2. Build a threat model and privacy/data-flow map for Personal Security Shield.
3. Implement a read-only suspicious-message/link analyzer with local redaction and no automatic
   navigation.
4. Add an AI prompt-injection/content-trust gateway shared by all agents and future personal tools.
5. Add user-consent receipts, per-connector permissions, action previews, and approval gates.
6. Add licensed exposure monitoring and incident recovery workflows.
7. Perform privacy review, abuse testing, red-team testing, and an independent penetration test before
   offering the personal product publicly.

## Rules for future development

- Do not call a mocked screen, placeholder, or configured-but-untested integration “working.”
- Do not expose credentials in URLs, logs, analytics, browser storage, reports, or error messages.
- Do not add offensive capability without the same or stronger ownership, authorization, scope, and
  audit controls used by the current scanner.
- Do not let AI output directly trigger destructive or externally visible actions.
- Do not weaken multi-tenant isolation for convenience.
- Do not claim legal compliance, certification, perfect detection, or zero false positives.
- Update this file whenever architecture, deployment domains, security boundaries, verified test
  counts, or major roadmap decisions change.
