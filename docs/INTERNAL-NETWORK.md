# Shannon for an internal company network

How to run Shannon **inside** your organisation's network to find provable
security issues in internal web apps, APIs, AI features, and a few exposed
services continuously, with confirmed and unverified results kept in separate confidence tiers.

> **Scope and authorisation first.** Only scan systems your organisation owns and
> you are authorised to test. Get that authorisation in writing. On the command
> line Shannon trusts the operator (you); the dashboard additionally enforces a
> domain- and IP-ownership gate. Shannon's probes are benign and read-only by
> design, but scanning still generates real traffic against real systems.

Shannon covers the **application and AI layer** of internal defence. It is not a
host/OS vulnerability scanner, a port scanner, EDR, IDS, or SIEM — pair it with
those (nmap, Nessus/OpenVAS, EDR) for full internal coverage.

---

## 1. Prerequisites

- **Node.js 20+** on a machine that can reach the internal targets. No Docker
  required; the engine is pure Node and runs on Windows, macOS, and Linux.
- Clone the repo and install root deps (`npm install` at the repo root). The
  engine's detection modules need no external packages; only the dashboard needs
  its own `npm install` (Express etc.).
- No API key is needed for detection (35 of 36 classes plus the LLM and team
  modules run offline). An `ANTHROPIC_API_KEY` only adds optional LLM narration.

Place the machine on a network segment (or VLAN) that can route to the internal
apps you intend to test.

---

## 2. Quick check that it works (no target, no network)

```bash
node purple-engine.mjs --selftest
```

This spins up an in-process vulnerable app and runs the whole loop, including the
new prompt-injection classes. Use it to confirm your install is healthy.

---

## 3. Scan one internal app (command line)

Point `--target` at an internal URL (hostname or IP), reachable from this machine:

```bash
node purple-engine.mjs --target http://intranet.corp.local/ --label intranet
node purple-engine.mjs --target http://10.20.1.15:8080/ --label billing-app
```

Common options (all real flags):

| Flag | Purpose |
|------|---------|
| `--label <name>` | Names the run and its report folder under `workspaces/`. |
| `--max-pages N` | How many pages to crawl (default 40). |
| `--headless` | Use a headless browser crawl for SPAs (needs Playwright). |
| `--no-crawl` | Probe the single target URL only, skip crawling. |
| `--network-scan` | Also check the target's host for exposed Redis / Memcached / Elasticsearch / anonymous FTP (see §6). |
| `--monitor` | Baseline-diff mode: report only newly-appeared exposures (see §7). |

### Scanning an app behind a login

```bash
# Session cookie you already hold:
node purple-engine.mjs --target http://intranet.corp.local/ --cookie "session=abc123"

# Or let Shannon log in first, then crawl+probe behind the session:
node purple-engine.mjs --target http://intranet.corp.local/ \
  --login-url http://intranet.corp.local/login --username tester --password '••••'
```

Add a custom header (e.g. an API token) with `--header "Authorization: Bearer …"`.

### Broken access control (IDOR / BOLA / BFLA)

Give Shannon a second identity (and optionally an admin) and it will test whether
one user can reach another user's or an admin's data. Resources are discovered
automatically by crawling as each identity.

```bash
node purple-engine.mjs --target http://intranet.corp.local/ \
  --cookie "session=ALICE" \
  --user2-cookie "session=BOB" \
  --admin-cookie "session=ADMIN"
```

`--user2-login-url/--user2-username/--user2-password` (and the `--admin-*`
equivalents) work too if you prefer form login over cookies.

### Testing internal AI / LLM features

Any internal chat, "summarize", assistant, or copilot feature is covered by the
prompt-injection classes automatically during a normal scan. To focus on it,
point `--target` at the page or endpoint that fronts the model.

---

## 4. Scan many internal hosts (batch)

Keep a list of internal targets in a file and loop over them.

**Linux/macOS (bash):**

```bash
while read -r url; do
  [ -n "$url" ] && node purple-engine.mjs --target "$url" --label "$(echo "$url" | sed 's#[^a-zA-Z0-9]#_#g')"
done < internal-targets.txt
```

**Windows (PowerShell):**

```powershell
Get-Content internal-targets.txt | Where-Object { $_ } | ForEach-Object {
  node purple-engine.mjs --target $_ --label ($_ -replace '[^a-zA-Z0-9]','_')
}
```

Reports land under `workspaces/<label>-<id>/` (Markdown + JSON + SARIF).

---

## 5. Dashboard mode (multi-user, with the ownership gate)

For a team, run the dashboard (`packages/dashboard`) inside the network. It adds
sign-in, saved runs, the AI Agent page, and the **Security Team** panel, and it
**enforces authorisation** before any scan:

1. **Verify each internal domain** you will scan (the Domains page).
2. **Verify internal IP ranges** you own. The server issues a per-user token
   derived from `SHANNON_SESSION_SECRET` (`ipVerifyToken`) and gives you
   verification instructions (`verificationInstructions`) — a control check
   confirms you operate the range before scans against those IPs are allowed.
3. Set a strong `SHANNON_SESSION_SECRET` (32-byte hex) in the dashboard `.env`.
   Keep the dashboard on an internal address; do not expose it to the internet.

Then use the **AI Agent** page to run the autonomous agent, or the **Security
Team** panel to run the blackboard-coordinated team (recon → exploit pool →
remediation → report) against an internal target, and watch the live graph.

> On the CLI there is no gate — it trusts you. The dashboard is where the
> domain/IP-ownership gate is enforced, which is what you want for a shared,
> multi-user internal deployment.

---

## 6. Exposed unauthenticated services (opt-in)

`--network-scan` additionally checks the **target's own host** (not a whole
range) for unauthenticated Redis, Memcached, Elasticsearch, and anonymous FTP —
a common internal misconfiguration.

```bash
node purple-engine.mjs --target http://10.20.1.15:8080/ --network-scan
```

In the dashboard this requires an explicit authorised flag on the request, tied
to the verified host.

---

## 7. Continuous monitoring + alerts

Run with `--monitor` on a schedule. Shannon diffs against the last baseline and
reports only **newly-appeared** exposures, so you get signal, not noise. Wire
alerts by setting a webhook (Slack / Discord / generic) in the environment.

**Linux (cron), every night at 02:00:**

```cron
0 2 * * * cd /opt/shannon && /usr/bin/node purple-engine.mjs \
  --target http://intranet.corp.local/ --label intranet --monitor >> /var/log/shannon.log 2>&1
```

**Windows (Task Scheduler):** create a Basic Task that runs daily and starts
`node.exe` with arguments
`purple-engine.mjs --target http://intranet.corp.local/ --label intranet --monitor`,
with "Start in" set to the repo folder.

For several targets, schedule the batch loop from §4 with `--monitor` added.

---

## 8. Feed results into your pipeline

- Every run writes **SARIF** — import it into GitHub code scanning or any SARIF
  consumer, or into a SIEM that accepts it.
- The Markdown/JSON reports include CVSS, OWASP (Web Top 10 and the new LLM Top
  10), CWE, and MITRE mappings for each confirmed finding.
- Findings are labeled **confirmed** (zero-FP, proven) versus **potential leads**
  (unproven, for manual review) — keep that distinction when you triage.

---

## 9. What Shannon does NOT do (pair accordingly)

- Broad host discovery / port scanning across a subnet → use **nmap**.
- OS / patch / host CVE scanning → use **Nessus / OpenVAS / Qualys**.
- Endpoint protection, IDS/IPS, firewalling, log aggregation → use **EDR / IDS /
  SIEM**.
- Active Directory, identity, lateral movement, phishing, packet capture.

Shannon is the **application- and AI-layer** scanner in that stack: it proves
real vulnerabilities in internal apps, APIs, AI features, and a few exposed
services, continuously and without false-positive noise.
```
