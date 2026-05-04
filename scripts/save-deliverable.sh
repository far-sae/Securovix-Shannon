#!/bin/bash
# save-deliverable: Save a file to the workspace with size validation
# Usage: save-deliverable <source-path> <dest-name>

set -e

MAX_SIZE=$((2 * 1024 * 1024))  # 2MB limit for Temporal protobuf

SOURCE="$1"
DEST_NAME="$2"
WORKSPACE="${WORKSPACE_DIR:-/workspace}"

if [ -z "$SOURCE" ] || [ -z "$DEST_NAME" ]; then
  echo "Usage: save-deliverable <source-path> <dest-name>" >&2
  exit 1
fi

if [ ! -f "$SOURCE" ]; then
  echo "Error: Source file not found: $SOURCE" >&2
  exit 1
fi

FILE_SIZE=$(stat -c%s "$SOURCE" 2>/dev/null || stat -f%z "$SOURCE" 2>/dev/null)

if [ "$FILE_SIZE" -gt "$MAX_SIZE" ]; then
  echo "Warning: File exceeds 2MB limit ($FILE_SIZE bytes). Truncating..." >&2
  head -c "$MAX_SIZE" "$SOURCE" > "${WORKSPACE}/${DEST_NAME}"
  echo "" >> "${WORKSPACE}/${DEST_NAME}"
  echo "[TRUNCATED - original size: ${FILE_SIZE} bytes]" >> "${WORKSPACE}/${DEST_NAME}"
else
  cp "$SOURCE" "${WORKSPACE}/${DEST_NAME}"
fi

echo "Saved: ${WORKSPACE}/${DEST_NAME} (${FILE_SIZE} bytes)"
