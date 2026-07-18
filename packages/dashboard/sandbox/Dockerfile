# Securovix Shannon — hardened code-sandbox image.
#
# The RUNNER (sandbox.mjs) already locks the container down hard at run time
# (--network none, --cap-drop=ALL, --read-only, non-root, memory/cpu/pids limits, timeout). This image
# just guarantees the interpreters are present and ships a few OFFLINE analysis libraries so common
# tasks (JWT decode, hashing, encoding, parsing) work out of the box. There is NO network at run time,
# so only pure/offline libraries are useful here.
#
# Build + host:
#   docker build -t shannon-sandbox:local -f packages/dashboard/sandbox/Dockerfile packages/dashboard/sandbox
#   # or push to a registry:
#   docker tag shannon-sandbox:local ghcr.io/<you>/shannon-sandbox:1 && docker push ghcr.io/<you>/shannon-sandbox:1
# Then point the dashboard at it:
#   SHANNON_SANDBOX_IMAGE=shannon-sandbox:local   (or the pushed tag)
FROM python:3.12-slim

# Node too, so JS snippets run in the same image (distro build; fine for offline analysis).
RUN apt-get update \
 && apt-get install -y --no-install-recommends nodejs \
 && rm -rf /var/lib/apt/lists/*

# Offline analysis helpers (pure-python, no network needed at run time).
RUN pip install --no-cache-dir pyjwt==2.8.0

# Sensible defaults; the runner also forces --user 65534 and a writable tmpfs at /tmp.
WORKDIR /tmp
USER 65534:65534
