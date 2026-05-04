#!/bin/bash
# Shannon - Quick Setup Script
# Run: bash setup.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}Shannon - Autonomous Penetration Testing Framework${NC}"
echo "=================================================="
echo ""

# Check prerequisites
echo -e "${BLUE}Checking prerequisites...${NC}"

check_cmd() {
  if command -v "$1" &>/dev/null; then
    echo -e "  ${GREEN}[OK]${NC} $1 found: $(command -v "$1")"
    return 0
  else
    echo -e "  ${RED}[MISSING]${NC} $1 not found"
    return 1
  fi
}

MISSING=0
check_cmd node || MISSING=1
check_cmd pnpm || MISSING=1
check_cmd docker || MISSING=1
check_cmd git || MISSING=1

if [ "$MISSING" -eq 1 ]; then
  echo ""
  echo -e "${RED}Missing prerequisites. Install them first:${NC}"
  echo "  Node.js 18+: https://nodejs.org/"
  echo "  pnpm:        npm install -g pnpm@9"
  echo "  Docker:      https://docs.docker.com/get-docker/"
  echo "  Git:         https://git-scm.com/"
  exit 1
fi

# Check Node version
NODE_VERSION=$(node -v | sed 's/v//' | cut -d. -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
  echo -e "${RED}Node.js 18+ required (found v$NODE_VERSION)${NC}"
  exit 1
fi

# Check Docker is running
if ! docker info &>/dev/null; then
  echo -e "${RED}Docker is not running. Start Docker first.${NC}"
  exit 1
fi
echo -e "  ${GREEN}[OK]${NC} Docker is running"

echo ""

# Install dependencies
echo -e "${BLUE}Installing dependencies...${NC}"
pnpm install

# Build
echo -e "${BLUE}Building packages...${NC}"
pnpm build

echo ""
echo -e "${GREEN}Setup complete!${NC}"
echo ""
echo "Next steps:"
echo ""
echo "  1. Create a .env file with your LLM provider API key:"
echo "     echo 'ANTHROPIC_API_KEY=sk-ant-xxxxx' > .env"
echo ""
echo "  2. Create a scan config:"
echo "     cp shannon.example.yaml my-target.yaml"
echo "     # Edit my-target.yaml with your target details"
echo ""
echo "  3. Run your first scan:"
echo "     export SHANNON_LOCAL=1"
echo "     source .env"
echo "     node packages/cli/dist/index.js scan --config my-target.yaml"
echo ""
echo "  4. Monitor in Temporal UI:"
echo "     http://localhost:8080"
echo ""
