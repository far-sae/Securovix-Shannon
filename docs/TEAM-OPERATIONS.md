# Team Operations

Shannon's dashboard supports organization-scoped security workspaces. A new account automatically
receives a personal organization; owners can create additional organizations and add existing
Securovix users from **Team Workspace**.

## Roles

| Role | Main permissions |
|---|---|
| Owner | Organization, members, projects, scans, findings, Defender and settings |
| Admin | Members, projects, scans, findings, Defender and settings |
| Engineer | Projects, active scans, triage, remediation and Defender |
| Analyst | Read scans, triage/assign findings, risk decisions and audit history |
| Developer | Read scans and work remediation/retest states |
| Viewer | Read-only scans, findings and audit history |

Organization selection is stored in an HttpOnly `shannon_org` cookie. Every team API validates the
current membership on every request; resource identifiers alone never grant access.

## Finding lifecycle

Confirmed agent and pentest findings are deduplicated into the active organization's shared queue.
The supported states are:

`new -> triaged -> assigned -> in-progress -> ready-for-retest -> resolved`

`risk-accepted` requires a reason and a future expiry. `false-positive` requires a reason. Every
membership, project, scan, finding, Defender, and remediation mutation writes an audit event.

## Production setup

1. Apply all repository migrations with `supabase db push`. The Defender enterprise migration adds
   revocable SDK credentials and the durable incident workflow.
2. Set a stable `SHANNON_SESSION_SECRET`.
3. Set `SHANNON_PLATFORM_ADMINS` to a comma-separated list of operator emails. Only these users can
   control process-wide dashboard self-defense and reset the global provider leaderboard.
4. Use HTTPS. Production cookies are emitted with `Secure`, `HttpOnly`, and `SameSite=Lax`.
5. Deploy the dashboard and public Defender edge independently. Generate the edge API key from the
   Defender page after selecting the owning organization.

Edge routes and Defender SDK detections are durable. Routes require verified ownership of both the
public hostname and origin hostname. The dashboard and edge independently reject origins resolving
to loopback, link-local, private, or carrier-grade NAT addresses.

## Defender operations

The **Defender** workspace provides organization-level posture metrics, attack-class trends, edge
route controls, and an incident queue. Runtime detections are severity-ranked and move through
`open`, `investigating`, `contained`, and `closed`. Status changes, SDK key rotations, and edge route
changes are audited. New detections and incident changes are also sent through enabled chat,
ticketing, webhook, and SIEM integrations using the durable delivery queue.

Start every deployment in monitor mode. Promote an SDK service or edge route to enforce only after
reviewing its observed traffic. The SDK key can be rotated from the Defender page; rotation
immediately rejects the old key, so update all applications that use it. Exported Defender evidence
is a point-in-time JSON copy of the visible incident queue.

## External integrations

Ticketing, chat, SSO/SCIM, and SIEM destinations require customer-specific credentials and are not
enabled implicitly. Integrate them through organization-scoped service credentials and preserve the
same permission and audit requirements. Never store provider or repository tokens in finding data or
audit metadata.

## Operational limitations

- Locally connected loopback Defender proxies are process-bound. Use the durable public Defender edge
  or the in-app SDK for production traffic.
- Scan artifacts still require persistent object storage when the hosting filesystem is ephemeral.
- The scheduler is single-process. Multi-instance deployments should move scheduled work and scan
  execution to a durable queue before horizontal scaling.
