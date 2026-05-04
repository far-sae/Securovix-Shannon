# Securovix-Shannon

Autonomous white-box penetration testing framework powered by LLM agents. Zero false positives — every finding comes with a working proof-of-concept exploit.

> **Windows note**: Native Windows is not supported. Use WSL2.

---

## Prerequisites

| Tool | Version | Why |
|------|---------|-----|
| Node.js | >= 18 | Runtime |
| pnpm | >= 9 | Package manager |
| Docker | >= 24 | Containers for Temporal + worker |
| Docker Compose | v2 | Orchestration |
| Git | any | Workspace checkpoints |

### Install prerequisites (Ubuntu/WSL2)

```bash
# Node.js 18+
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# pnpm
npm install -g pnpm@9

# Docker (if not already installed)
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```

---

## Quick Start (Local Development Mode)

### 1. Clone and install

```bash
cd shannon
pnpm install
pnpm build
```

### 2. Set your LLM provider

Create a `.env` file in the project root:

```bash
# Pick exactly ONE provider:

# Option A: Anthropic direct (recommended)
ANTHROPIC_API_KEY=sk-ant-api03-xxxxx

# Option B: AWS Bedrock
# AWS_BEDROCK_REGION=us-east-1
# AWS_ACCESS_KEY_ID=xxxxx
# AWS_SECRET_ACCESS_KEY=xxxxx

# Option C: GCP Vertex AI
# VERTEX_PROJECT_ID=my-project
# VERTEX_REGION=us-central1

# Option D: Custom proxy
# SHANNON_LLM_BASE_URL=https://proxy.example.com/v1
# SHANNON_LLM_API_KEY=xxxxx
```

### 3. Create a scan config

Copy the example and edit it:

```bash
cp shannon.example.yaml my-target.yaml
```

Edit `my-target.yaml`:

```yaml
target:
  url: https://your-target-app.com
  repoPath: /path/to/target/source/code    # optional, for white-box
  urls:
    focus:
      - /api/
      - /admin/
    avoid:
      - /docs/
      - /static/

authentication:
  type: form
  loginUrl: https://your-target-app.com/login
  username: testuser
  password: testpassword
  # totpSecret: JBSWY3DPEHPK3PXP    # uncomment for TOTP 2FA

pipeline:
  retryPreset: default       # default | fast | subscription
  maxConcurrentPipelines: 5  # 1-5

loginInstructions: |
  Navigate to /login, enter username and password, click "Sign In".
```

### 4. Run the scan

```bash
# Set local development mode
export SHANNON_LOCAL=1

# Source your API key
source .env

# Run the scan
node packages/cli/dist/index.js scan --config my-target.yaml
```

This will:
1. Start a Temporal server via Docker Compose
2. Build the worker Docker image locally
3. Mount prompts live (editable during scan)
4. Store all results in `./workspaces/<scan-id>/`

### 5. Check results

```bash
# Scan status
node packages/cli/dist/index.js status

# Results are in the workspace directory:
ls workspaces/<scan-id>/
```

Output structure:
```
workspaces/<scan-id>/
  session.json                    # Scan metadata, agent metrics
  pre-recon/                      # nmap, subfinder, whatweb, source analysis
  recon/
    exploration.md                # Browser exploration report
    api-map.json                  # Discovered API endpoints
    deception-verdicts.json       # Honeypot/canary detection results
  vuln/
    sqli/analysis.md              # SQL injection findings
    sqli/exploitation-queue.json
    xss/...
    auth-bypass/...
    authz-bypass/...
    ssrf/...
    business-logic/...            # State machine logic flaws
  exploit/
    sqli/exploit-report.md        # Working POC exploits
    sqli/poc.md                   # Copy-paste ready exploits
    xss/...
    ...
  chain-analysis/
    graph.md                      # Attack surface graph
    chains.json                   # Discovered kill chains
    execution-plan.md             # Highest-scoring chain steps
    chain-exploit-report.md       # Chain exploitation results
  war-room/
    verdicts.json                 # Agent debate verdicts
    transcript.md                 # Full debate transcript
    summary.md                    # False positives eliminated
  report.md                       # Final penetration test report
  forensic-package/
    manifest.json                 # SHA-256 hash-chained evidence
    integrity-report.md           # Chain verification
    timeline.md                   # Chronological evidence
    chain-of-custody.md           # Legal attestation
  audit/
    workflow.log                  # Human-readable audit log
    *.log                         # Per-agent logs
    prompts/                      # Prompt snapshots
  evidence.db                     # SQLite forensic evidence chain
  evasion-profile.json            # Learned WAF evasion strategies
```

---

## NPX Mode (Production)

For running without cloning the repo:

### 1. Setup credentials

```bash
mkdir -p ~/.shannon
cat > ~/.shannon/config.toml << 'EOF'
[anthropic]
api_key = "sk-ant-api03-xxxxx"
EOF
```

### 2. Run via npx

```bash
npx @keygraph/shannon scan --config my-target.yaml
```

This pulls the prebuilt worker image from Docker Hub and stores results in `~/.shannon/workspaces/`.

---

## Resume a Failed/Interrupted Scan

```bash
# Resumes from where it left off, skipping completed agents
node packages/cli/dist/index.js scan --config my-target.yaml --resume

# Or specify a specific workspace to resume
node packages/cli/dist/index.js scan --config my-target.yaml --resume --workspace ./workspaces/abc123
```

Resume will:
- Read `session.json` to find completed agents
- Validate their deliverables still exist on disk
- Restore git checkpoints
- Skip finished agents, continue from the next one

---

## Pipeline Phases

```
Phase 1    Pre-Recon         nmap, subfinder, whatweb, source code analysis
Phase 2    Recon             Live browser exploration + API mapping
Phase 2.5  Counter-Deception Honeypot/canary/tarpit detection
Phase 3+4  Vuln + Exploit    6 categories in parallel (SQLi, XSS, auth bypass,
                             authz bypass, SSRF, business logic)
Phase 3.5  Chain Analysis    Graph-based kill chain discovery + exploitation
Phase 4.5  War Room          3-agent adversarial debate per finding
Phase 5    Report            Final markdown report with war room verdicts
Phase 5.5  Forensic Package  SHA-256 evidence chain + custody documents
```

---

## Configuration Reference

### Retry Presets

| Preset | Max Attempts | Initial Backoff | Max Backoff | Use Case |
|--------|-------------|-----------------|-------------|----------|
| `default` | 50 | 5 min | 30 min | Production scans |
| `fast` | 5 | 10 sec | 2 min | Testing/development |
| `subscription` | 100 | 5 min | 6 hours | Anthropic rate limit windows |

### Model Tiers

Override per-agent model selection via environment variables:

```bash
SHANNON_MODEL_SMALL=claude-haiku-4-5-20251001    # pre-recon, forensic
SHANNON_MODEL_MEDIUM=claude-sonnet-4-6            # recon, report, skeptic
SHANNON_MODEL_LARGE=claude-opus-4-6               # vuln agents, exploit agents, war room lead
```

### Authentication Types

```yaml
# Form-based login
authentication:
  type: form
  loginUrl: https://app.com/login
  username: admin
  password: secret
  totpSecret: JBSWY3DPEHPK3PXP     # optional TOTP 2FA

# SSO
authentication:
  type: sso
  loginUrl: https://app.com/login
  ssoProvider: okta

# API Key
authentication:
  type: api-key
  apiKey: sk-xxxxx
  customHeaders:
    X-API-Key: sk-xxxxx

# HTTP Basic
authentication:
  type: http-basic
  username: admin
  password: secret
```

---

## Development

### Project Structure

```
shannon/
  packages/
    cli/              @keygraph/shannon (published to npm)
    worker/           Private, runs in Docker container
  prompts/            Plain text prompt templates
  config/             JSON Schema for config validation
  scripts/            Container utilities (entrypoint, TOTP, save-deliverable)
  docker-compose.yml  Temporal server
  Dockerfile          Two-stage Wolfi-based worker image
```

### Build

```bash
pnpm install
pnpm build          # Builds both CLI (tsdown) and worker (tsc)
pnpm typecheck      # Type-check without emitting
pnpm lint           # Biome lint + format check
pnpm lint:fix       # Auto-fix lint issues
```

### Edit prompts live

In local mode (`SHANNON_LOCAL=1`), prompts are mounted into the container. Edit files in `prompts/` and they take effect immediately on the next agent run.

Prompt variables:
- `{{TARGET_URL}}` — target application URL
- `{{REPO_PATH}}` — path to source code
- `{{CONFIG_CONTEXT}}` — JSON config context
- `{{LOGIN_INSTRUCTIONS}}` — authentication instructions
- `{{>partial-name}}` — includes from `prompts/partials/`

### Docker manual build

```bash
# Build worker image
docker build -t shannon-worker:local .

# Run Temporal
docker compose up -d temporal

# Run worker manually
docker run --rm \
  --network shannon_default \
  -e TEMPORAL_ADDRESS=temporal:7233 \
  -e TEMPORAL_TASK_QUEUE=shannon-scan-test \
  -e SHANNON_TARGET=https://target.com \
  -e ANTHROPIC_API_KEY=sk-ant-xxxxx \
  -v $(pwd)/workspaces/test:/workspace \
  -v $(pwd)/prompts:/app/prompts \
  shannon-worker:local
```

### Stop Temporal

```bash
docker compose down
# To also remove the SQLite volume:
docker compose down -v
```

---

## Troubleshooting

### "No LLM provider configured"
Set exactly ONE of: `ANTHROPIC_API_KEY`, `AWS_BEDROCK_REGION`, `VERTEX_PROJECT_ID`, or `SHANNON_LLM_BASE_URL`.

### "Exactly one LLM provider must be configured"
You have multiple providers set. Unset the ones you don't want.

### Docker connection errors
Make sure Docker is running: `docker info`. On WSL2, ensure Docker Desktop has WSL integration enabled.

### Rate limiting (429 errors)
Switch to `subscription` retry preset in your config:
```yaml
pipeline:
  retryPreset: subscription
```

### Temporal UI
Access the Temporal dashboard at http://localhost:8080 to monitor workflow execution.

### Agent timeout
Default is 2 hours per agent. For large applications, this may not be enough. The activity will be retried per the retry preset.

---

## License

MIT
