# Tool-broker sidecar image. Build from the REPO ROOT so it can see the base tsconfig:
#   docker build -f packages/tool-broker/Dockerfile -t shannon-tool-broker:local .
# The broker has no runtime npm deps (only Node built-ins), so the runtime stage is tiny.
# It needs the Docker CLI to launch per-tool sandbox containers via the mounted host socket.

FROM node:22-bookworm-slim AS build
WORKDIR /repo
COPY tsconfig.json ./tsconfig.json
COPY packages/tool-broker/package.json packages/tool-broker/tsconfig.json ./packages/tool-broker/
COPY packages/tool-broker/src ./packages/tool-broker/src
# Install the broker's devDeps (typescript + @types/node) so tsc has Node's ambient types
# (the broker has NO runtime npm deps — only Node built-ins — so the runtime stage stays tiny).
RUN cd packages/tool-broker \
 && npm install --no-audit --no-fund \
 && npx tsc -p tsconfig.json

FROM node:22-bookworm-slim
# Install a CURRENT static Docker CLI (just the client binary). Debian's `docker.io`
# package ships an old CLI (API 1.41) that modern daemons (>=29, min API 1.44) reject —
# the broker MUST be able to drive the host socket to launch sandbox containers.
ARG DOCKER_CLI_VERSION=27.3.1
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && curl -fsSL "https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_CLI_VERSION}.tgz" -o /tmp/docker.tgz \
 && tar -xzf /tmp/docker.tgz -C /tmp \
 && mv /tmp/docker/docker /usr/local/bin/docker \
 && chmod +x /usr/local/bin/docker \
 && rm -rf /tmp/docker /tmp/docker.tgz \
 && apt-get purge -y curl && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY packages/tool-broker/package.json ./package.json
COPY --from=build /repo/packages/tool-broker/dist ./dist
EXPOSE 8443
# Runs as root because it drives the host Docker socket; the SANDBOXED tools it launches
# are the ones hardened (cap-drop, non-root, read-only, egress-controlled).
CMD ["node", "dist/server-main.js"]
