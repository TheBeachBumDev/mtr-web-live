#!/usr/bin/env bash
# Invoked by scripts/dr_runner.py from the UI "Promote Standby" action (core container, cwd=/app).
# Re-enables live behaviour that full-clone standby turns off, then applies env via compose.
set -euo pipefail

if [[ "${1:-}" != "PROMOTE STANDBY" ]]; then
  echo "Usage: $0 PROMOTE STANDBY" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "PHASE write dr_mode.json"
mkdir -p data
PROMOTED="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
printf '{"role":"primary","promoted_at":"%s"}\n' "$PROMOTED" > data/dr_mode.json

echo "PHASE write .env.compose.standby (monitoring, location sync nightly, clone scheduler on)"
cat > .env.compose.standby << 'EOF'
MONITORING_SAMPLING_ENABLED=1
LOCATION_SYNC_SCHEDULER_ENABLED=1
CLONE_SCHEDULER_ENABLED=1
EOF

if [[ "${DR_PROMOTE_SKIP_COMPOSE:-0}" == "1" ]]; then
  echo "PHASE skip docker compose (DR_PROMOTE_SKIP_COMPOSE=1) — recreate stack yourself so env applies."
  exit 0
fi

echo "PHASE docker compose up -d (apply env; recreate containers as needed)"
if [[ ! -f docker-compose.yml ]]; then
  echo "docker-compose.yml not found in ${ROOT}" >&2
  exit 3
fi

ENV_ARGS=( -f docker-compose.yml )
if [[ -f .env.compose ]]; then
  ENV_ARGS+=( --env-file .env.compose )
fi
if [[ -f .env.compose.clone.override ]]; then
  ENV_ARGS+=( --env-file .env.compose.clone.override )
fi
ENV_ARGS+=( --env-file .env.compose.standby )

docker compose "${ENV_ARGS[@]}" up -d

echo "PHASE promote complete"
