# Build environment for the Guard agent: Linux (native) and Windows (MinGW cross-compile).
# macOS binaries need Apple's SDK and are built on a Mac: `cargo build --release`.
FROM rust:1-bookworm
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc-mingw-w64-x86-64 \
 && rm -rf /var/lib/apt/lists/* \
 && rustup target add x86_64-pc-windows-gnu
WORKDIR /src
