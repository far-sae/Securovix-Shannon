# Securovix Shannon — dashboard + pure-Node AI Agent.
#
# This containerizes the HOSTABLE web app so anyone can run it — NO Docker-in-Docker, NO external tools.
# (The AI Agent runs the proof engine in-process; only the LEGACY multi-agent broker needs a Docker
# socket, and that is a separate, optional deployment — see DEPLOY.md.)
#
# The dashboard imports the sibling engine modules from the repo root, so build from the REPO ROOT:
#   docker build -f packages/dashboard/Dockerfile -t shannon-dashboard .
#   docker run -p 3000:3000 \
#     -e SHANNON_SESSION_SECRET=change-me \
#     -e SUPABASE_URL=... -e SUPABASE_SERVICE_ROLE_KEY=...   # optional: persistence across restarts
#     shannon-dashboard
FROM node:20-slim
WORKDIR /app

# Copy the whole repo (the dashboard imports ../../crawler.mjs, ../../purple-engine.mjs, etc.).
COPY . .

# Install only the dashboard's runtime deps (express, marked, @anthropic-ai/sdk, yaml). The engine
# modules use global fetch + node builtins, so they need nothing extra.
WORKDIR /app/packages/dashboard
RUN npm install --omit=dev --no-audit --no-fund

ENV PORT=3000 NODE_ENV=production
EXPOSE 3000
CMD ["node", "server.mjs"]
