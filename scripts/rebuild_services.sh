#!/usr/bin/env bash
# Rebuild Docker image(s) from the project tree and recreate container(s).
# Always runs Docker context preflight first (unless --skip-preflight).
#
# Usage:
#   bash scripts/rebuild_services.sh backhauls
#   bash scripts/rebuild_services.sh --no-cache whatsapp_signups monitoring
#   bash scripts/rebuild_services.sh --restart-only backhauls    # no image rebuild; bounce containers
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ENV_FILE=".env.compose"
if [[ -f "$ROOT_DIR/$ENV_FILE" ]]; then
  DC=(docker compose -f docker-compose.yml --env-file "$ROOT_DIR/$ENV_FILE")
else
  DC=(docker compose -f docker-compose.yml)
fi

SKIP_PREFLIGHT=0
RESTART_ONLY=0
BUILD_ARGS=()
SERVICES=()

usage() {
  cat <<EOF
Usage: $(basename "$0") [options] <compose-service> [service ...]

  Rebuild images (docker compose build) and recreate containers (up -d).

Options:
  --no-cache          Pass through to docker compose build
  --skip-preflight    Do not run scripts/preflight_docker_context.sh (not recommended)
  --restart-only      Only restart containers (docker compose restart); no build

Examples:
  bash scripts/rebuild_services.sh backhauls
  bash scripts/rebuild_services.sh --no-cache core
  bash scripts/rebuild_services.sh --restart-only monitoring

Compose file: docker-compose.yml (with ${ENV_FILE} when present).
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --skip-preflight)
      SKIP_PREFLIGHT=1
      shift
      ;;
    --restart-only)
      RESTART_ONLY=1
      shift
      ;;
    --no-cache)
      BUILD_ARGS+=(--no-cache)
      shift
      ;;
    -*)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
    *)
      SERVICES+=("$1")
      shift
      ;;
  esac
done

if [[ ${#SERVICES[@]} -eq 0 ]]; then
  usage >&2
  exit 1
fi

if [[ "$SKIP_PREFLIGHT" -eq 0 && "$RESTART_ONLY" -eq 0 ]]; then
  bash "$ROOT_DIR/scripts/preflight_docker_context.sh"
fi

if [[ "$RESTART_ONLY" -eq 1 ]]; then
  echo "== restart only (no build): ${SERVICES[*]} =="
  "${DC[@]}" restart "${SERVICES[@]}"
  exit 0
fi

echo "== docker compose build ${BUILD_ARGS[*]:-} ${SERVICES[*]} =="
"${DC[@]}" build "${BUILD_ARGS[@]}" "${SERVICES[@]}"

echo "== docker compose up -d ${SERVICES[*]} =="
"${DC[@]}" up -d "${SERVICES[@]}"

echo "== status =="
"${DC[@]}" ps "${SERVICES[@]}"
