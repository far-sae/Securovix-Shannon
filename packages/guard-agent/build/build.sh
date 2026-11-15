#!/usr/bin/env sh
# Builds and tests the Guard agent inside Docker; binaries land in packages/guard-agent/dist/.
#   sh packages/guard-agent/build/build.sh
# The production dashboard image builds the same two binaries itself (Dockerfile.dashboard), so
# this script is for local testing only.
set -eu
HERE="$(cd "$(dirname "$0")/.." && pwd)"
docker build -t securovix-guard-build "$HERE/build"
docker run --rm \
  -v "$HERE:/src" \
  -v securovix-guard-cargo:/usr/local/cargo/registry \
  -v securovix-guard-target:/src/target \
  securovix-guard-build sh -c '
    set -e
    cargo test --release
    cargo build --release --target x86_64-unknown-linux-musl
    cargo build --release --target x86_64-pc-windows-gnu
    mkdir -p dist
    cp target/x86_64-unknown-linux-musl/release/securovix-guard dist/securovix-guard-linux-x86_64
    cp target/x86_64-pc-windows-gnu/release/securovix-guard.exe dist/securovix-guard-windows-x86_64.exe
    cd dist && sha256sum securovix-guard-* > SHA256SUMS && ls -l
  '
