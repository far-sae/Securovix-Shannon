# Stage 1: Build
FROM cgr.dev/chainguard/wolfi-base:latest AS builder

RUN apk add --no-cache \
    nodejs-18 \
    npm \
    python-3 \
    py3-pip \
    go \
    ruby \
    build-base \
    git

WORKDIR /build

# Install pnpm
RUN npm install -g pnpm@9

# Copy package files
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml* ./
COPY packages/worker/package.json packages/worker/
COPY packages/cli/package.json packages/cli/

# Install dependencies
RUN pnpm install --frozen-lockfile || pnpm install

# Install worker dependencies separately (worker is excluded from workspace)
RUN cd packages/worker && npm install

# Copy source
COPY tsconfig.json turbo.json biome.json ./
COPY packages/worker/ packages/worker/

# Build worker
RUN cd packages/worker && npx tsc

# Install Python tools
RUN pip install schemathesis==4.13.0

# Install Go tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Stage 2: Runtime
FROM cgr.dev/chainguard/wolfi-base:latest AS runtime

RUN apk add --no-cache \
    nodejs-18 \
    npm \
    python-3 \
    py3-pip \
    ruby \
    ruby-dev \
    build-base \
    nmap \
    chromium \
    git \
    go \
    bash \
    coreutils

# Install whatweb from source
RUN git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb && \
    ln -s /opt/whatweb/whatweb /usr/local/bin/whatweb

WORKDIR /app

# Copy built worker — flatten so dist/index.js can resolve deps from /app/node_modules
COPY --from=builder /build/packages/worker/dist ./dist
COPY --from=builder /build/packages/worker/package.json ./
COPY --from=builder /build/packages/worker/node_modules ./node_modules

# Copy Go binaries
COPY --from=builder /root/go/bin/subfinder /usr/local/bin/

# Copy Python tools
COPY --from=builder /usr/lib/python3*/site-packages /usr/lib/python3*/site-packages
COPY --from=builder /usr/bin/st /usr/local/bin/schemathesis

# Copy prompts
COPY prompts/ /app/prompts/

# Copy scripts
COPY scripts/save-deliverable.sh /usr/local/bin/save-deliverable
COPY scripts/totp.py /usr/local/bin/totp-generator
COPY scripts/entrypoint.sh /entrypoint.sh

RUN chmod +x /usr/local/bin/save-deliverable \
    /usr/local/bin/totp-generator \
    /entrypoint.sh

# Install Playwright browsers
RUN npx playwright install chromium --with-deps 2>/dev/null || true

# Set environment
ENV PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium-browser
ENV NODE_ENV=production

ENTRYPOINT ["/entrypoint.sh"]
CMD ["node", "dist/index.js"]
