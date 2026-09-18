# Production operations and incident response

This is the operator checklist for a Railway + Supabase deployment. A control is not complete merely
because code exists: record the owner, completion date, test evidence, and next review date for every
item below.

## Supabase backups and restore tests

1. In Supabase, open **Project Settings → Add-ons/Backups** and enable the backup/PITR option suitable
   for the business recovery objective. Record the actual retention shown by Supabase.
2. Restrict production project access, require MFA for administrators, and keep the service-role key
   only in Railway service variables.
3. Once per quarter, restore the newest backup into a separate non-production project. Never restore
   over production for a test.
4. Run the migrations, start a staging Dashboard against the restored project, and verify users,
   organizations, memberships, encrypted secrets, scan records, findings, Defender events, and a
   private artifact download. Store the test date, duration, and any missing data in the change log.
5. Delete the temporary restore after evidence is approved. A backup that has not been restored and
   checked is not considered tested.

## Railway alerts and logs

Configure Railway alerts for every Dashboard, Worker, and Edge service, and an external uptime alert
for the Hetzner Sandbox Runner:

- deployment failure or crash loop;
- `/readyz` failing for five minutes (Dashboard/Worker) or `/__edge/health` failing (Edge);
- CPU above 85%, memory above 85%, or disk above 80% for 15 minutes;
- worker heartbeat older than three minutes, dead-letter jobs, or a growing queue;
- Edge route count unexpectedly dropping to zero;
- unusual 401/403/429 rate, quota exhaustion, and repeated authentication failures.

Send alerts to an on-call destination that is tested monthly. Railway logs are operational telemetry,
not the sole audit archive. Set the Railway retention/export option available on the selected plan and
document its real duration. Shannon's database defaults are: operational events 30 days, completed
jobs 30 days, delivery history 90 days, artifacts 90 days, and expired auth tokens 7 days. Adjust the
`SHANNON_*_RETENTION_DAYS` variables to match the published Privacy Policy, then verify the worker
actually purges records in staging.

## Incident procedure

1. **Triage:** acknowledge the alert, open an incident record, record UTC time, reporter, affected
   organizations, systems, suspected data, and incident commander.
2. **Contain:** rotate the relevant credential (session secret only as a platform-wide emergency
   reset), revoke organization SDK/SCIM/OIDC/API keys, disable affected accounts, place Edge routes in
   monitor mode if enforcement is contributing to impact, and isolate the Sandbox Runner if involved.
3. **Preserve evidence:** export application/audit/Defender events, Railway deployment logs, Supabase
   database logs, affected release SHA, and infrastructure configuration. Store read-only copies with
   access logging. Do not copy customer secrets into tickets or chat.
4. **Eradicate and recover:** patch through review, test in staging, restore if necessary, deploy with
   rollback ready, and verify health, tenant isolation, authentication, queues, and telemetry.
5. **Notify:** involve legal/privacy leads immediately. Assess contractual and regulatory notification
   deadlines based on facts and jurisdiction; do not promise a deadline this runbook cannot guarantee.
6. **Review:** within five business days, record root cause, timeline, impact, corrective actions,
   owners, due dates, and whether customer-facing documents must change.

Security contact: `security@securovix.com`. Privacy contact: `privacy@securovix.com`.

## Sandbox Runner release test

Before enabling it for customers, independently test the deployed Hetzner URL from a host that is not
the VM or Railway:

1. Confirm anonymous `/health` and `/v1/run` requests are rejected and the authenticated health
   response reports Docker available.
2. Run one Python and one Node job and confirm expected output.
3. Attempt DNS/network access, filesystem writes outside the job temp area, process forking, oversized
   source/input, an unsupported language, and a timeout. Each must be blocked or terminated.
4. Inspect `docker ps -a` after the tests: no job container may remain. Confirm the VM firewall exposes
   only TCP 80/443 and Docker's socket/daemon is not remotely reachable.
5. Rotate the runner token and confirm the previous token immediately fails. Save commands, timestamps,
   responses, VM image/version, Docker version, and reviewer name as release evidence.

## Independent security review

Commission a tester who did not implement the system. Scope the public Dashboard, shared Edge,
organization boundaries, auth/MFA/session recovery, OIDC/SCIM, billing webhooks, Supabase policies,
private artifacts, Worker queue, and Sandbox Runner. Require authenticated cross-tenant testing and a
retest of every high/critical finding. Keep the signed report and retest letter privately; publish only
an approved summary. Dependency scanning and internal review help, but do not replace this test.

Do not claim ISO 27001 certification, SOC 2 attestation, PCI DSS compliance, or a “passed pentest” until
the relevant independent work is complete and current.
