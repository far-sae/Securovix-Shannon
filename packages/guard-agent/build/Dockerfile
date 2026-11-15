# Build environment for the Guard agent: Linux (static, musl) and Windows (MinGW cross-compile).
# The Linux build is fully static so one binary runs on every distribution, old or new.
# macOS binaries need Apple's SDK and are built on a Mac: `cargo build --release`.
FROM rust:1-bookworm
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc-mingw-w64-x86-64 musl-tools \
 && rm -rf /var/lib/apt/lists/* \
 && rustup target add x86_64-pc-windows-gnu x86_64-unknown-linux-musl
WORKDIR /src
