#!/usr/bin/env bash
set -euo pipefail

# Safe asset restore for shared host-mounted web assets.
# - Never deletes live dirs first.
# - Restores into temp dirs and atomically swaps into place.
# - Keeps timestamped backups for rollback/forensics.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

IMAGE="${1:-mtr-web-live-core}"
TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="$ROOT_DIR/backups/recovery-assets-$TS"
TMP_BASE="$ROOT_DIR/.restore-assets-$TS"

echo "== Safe asset restore =="
echo "Root:    $ROOT_DIR"
echo "Image:   $IMAGE"
echo "Backup:  $BACKUP_DIR"
echo "Tmp:     $TMP_BASE"

mkdir -p "$BACKUP_DIR" "$TMP_BASE"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "ERROR: image not found: $IMAGE"
  exit 1
fi

TMP_CID="$(docker create "$IMAGE")"
cleanup() {
  docker rm "$TMP_CID" >/dev/null 2>&1 || true
  rm -rf "$TMP_BASE"
}
trap cleanup EXIT

echo "-- Exporting assets from image..."
docker cp "$TMP_CID":/app/templates "$TMP_BASE/templates"
docker cp "$TMP_CID":/app/static "$TMP_BASE/static"

if [[ ! -f "$TMP_BASE/templates/home.html" || ! -f "$TMP_BASE/templates/base.html" || ! -f "$TMP_BASE/static/style.css" ]]; then
  echo "ERROR: exported assets missing required files; aborting."
  exit 1
fi

echo "-- Backing up current live dirs..."
if [[ -d "$ROOT_DIR/templates" ]]; then
  mv "$ROOT_DIR/templates" "$BACKUP_DIR/templates"
fi
if [[ -d "$ROOT_DIR/static" ]]; then
  mv "$ROOT_DIR/static" "$BACKUP_DIR/static"
fi

echo "-- Promoting restored dirs atomically..."
mv "$TMP_BASE/templates" "$ROOT_DIR/templates"
mv "$TMP_BASE/static" "$ROOT_DIR/static"

echo "-- Restarting app services to refresh bind mounts..."
docker compose -f "$ROOT_DIR/docker-compose.yml" --env-file "$ROOT_DIR/.env.compose" up -d --force-recreate \
  core location_sync whatsapp_signups monitoring purchase_orders stock_management routers backhauls mtr_live download_test fieldtech ipam

echo "-- Post-restore checks..."
docker compose -f "$ROOT_DIR/docker-compose.yml" --env-file "$ROOT_DIR/.env.compose" ps
docker exec mtr-core ls -la /app/templates/home.html /app/templates/base.html /app/static/style.css >/dev/null

echo "SUCCESS: assets restored safely."
echo "Rollback source kept at: $BACKUP_DIR"
