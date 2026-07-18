#!/usr/bin/env sh
# Build (and optionally push) the Shannon code-sandbox image, then tell the dashboard to use it.
#
#   ./build.sh                              # builds shannon-sandbox:local
#   ./build.sh ghcr.io/you/shannon-sandbox:1 --push   # builds + pushes a registry tag
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGE="${1:-shannon-sandbox:local}"

docker build -t "$IMAGE" -f "$DIR/Dockerfile" "$DIR"

if [ "$2" = "--push" ]; then
  docker push "$IMAGE"
fi

echo ""
echo "Built: $IMAGE"
echo "Point the dashboard at it with:  export SHANNON_SANDBOX_IMAGE=$IMAGE"
