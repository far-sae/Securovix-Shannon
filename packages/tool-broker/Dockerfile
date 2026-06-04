# Tool-broker sidecar image. Build from the REPO ROOT so it can see the base tsconfig:
#   docker build -f packages/tool-broker/Dockerfile -t shannon-tool-broker:local .
# The broker has no runtime npm deps (only Node built-ins), so the runtime stage is tiny.
# It needs the Docker CLI to launch per-tool sandbox containers via the mounted host socket.

FROM node:22-bookworm-slim AS build
WORKDIR /repo
COPY tsconfig.json ./tsconfig.json
COPY packages/tool-broker/package.json packages/tool-broker/tsconfig.json ./packages/tool-broker/
COPY packages/tool-broker/src ./packages/tool-broker/src
RUN npm install -g typescript@5.6 \
 && cd packages/tool-broker \
 && tsc -p tsconfig.json

FROM node:22-bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends docker.io \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY packages/tool-broker/package.json ./package.json
COPY --from=build /repo/packages/tool-broker/dist ./dist
EXPOSE 8443
# Runs as root because it drives the host Docker socket; the SANDBOXED tools it launches
# are the ones hardened (cap-drop, non-root, read-only, egress-controlled).
CMD ["node", "dist/server-main.js"]
