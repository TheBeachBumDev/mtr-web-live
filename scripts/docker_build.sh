#!/usr/bin/env bash
# Run mandatory Docker context checks, then docker compose build for the given services.
# Does NOT recreate containers — use scripts/rebuild_services.sh for build + up -d.
#
# Usage:
#   bash scripts/docker_build.sh whatsapp_signups
#   bash scripts/docker_build.sh --no-cache backhauls monitoring
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

bash scripts/preflight_docker_context.sh

ENV_FILE=".env.compose"
if [[ -f "$ROOT_DIR/$ENV_FILE" ]]; then
  exec docker compose -f docker-compose.yml --env-file "$ROOT_DIR/$ENV_FILE" build "$@"
else
  exec docker compose -f docker-compose.yml build "$@"
fi
