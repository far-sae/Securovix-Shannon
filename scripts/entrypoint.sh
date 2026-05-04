#!/bin/bash
set -e

# Ensure workspace directory is writable
if [ -d /workspace ]; then
  chmod -R 777 /workspace 2>/dev/null || true
fi

# Run the command directly
exec "$@"
