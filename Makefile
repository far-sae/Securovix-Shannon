.PHONY: setup build clean scan resume status up down logs lint typecheck

# Quick setup
setup:
	pnpm install
	pnpm build

# Build all packages
build:
	pnpm build

# Type-check
typecheck:
	pnpm typecheck

# Lint
lint:
	pnpm lint

lint-fix:
	pnpm lint:fix

# Clean build artifacts
clean:
	pnpm clean

# Start Temporal server
up:
	docker compose up -d temporal temporal-ui
	@echo "Temporal UI: http://localhost:8080"

# Stop Temporal server
down:
	docker compose down

# Stop and remove data
down-clean:
	docker compose down -v

# Build worker Docker image locally
docker-build:
	docker build -t shannon-worker:local .

# Run a scan (requires CONFIG=path/to/config.yaml and .env sourced)
scan: up
	SHANNON_LOCAL=1 node packages/cli/dist/index.js scan --config $(CONFIG)

# Resume a scan
resume: up
	SHANNON_LOCAL=1 node packages/cli/dist/index.js scan --config $(CONFIG) --resume

# Check scan status
status:
	node packages/cli/dist/index.js status

# View Temporal logs
logs:
	docker compose logs -f temporal

# View worker logs for a workspace
audit:
	@if [ -z "$(WORKSPACE)" ]; then echo "Usage: make audit WORKSPACE=./workspaces/abc123"; exit 1; fi
	cat $(WORKSPACE)/audit/workflow.log
