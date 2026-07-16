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

## Note on the multi-agent broker (legacy, optional — NOT needed here)

The older `packages/tool-broker` + `packages/worker` path runs LLM agents + real external tools inside
hardened **Docker-in-Docker** sandboxes. That one genuinely needs a Docker-socket host (Fly machine,
a VM, ECS with the daemon) **plus** Anthropic credits **plus** the GPL sign-off for bundling 3rd-party
tools. It is a separate deployment and is **not required** for the AI Agent — the pure-Node engine
covers the substance. Host the dashboard (above) for people to use; reach for the broker only if you
specifically want sandboxed external-tool execution.
