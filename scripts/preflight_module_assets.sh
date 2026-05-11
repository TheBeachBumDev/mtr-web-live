#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SERVICE="${1:-}"
if [[ -z "$SERVICE" ]]; then
  echo "Usage: bash scripts/preflight_module_assets.sh <compose-service>"
  echo "Example: bash scripts/preflight_module_assets.sh whatsapp_signups"
  exit 1
fi

base_check='test -f /app/templates/base.html && test -f /app/static/style.css'
template_for_service() {
  case "$1" in
    core) echo "/app/templates/home.html" ;;
    monitoring) echo "/app/templates/monitoring.html" ;;
    location_sync) echo "/app/templates/location_sync.html" ;;
    routers) echo "/app/templates/routers.html" ;;
    backhauls) echo "/app/templates/backhauls.html" ;;
    stock_management) echo "/app/templates/stock_management.html" ;;
    purchase_orders) echo "/app/templates/purchase_orders.html" ;;
    whatsapp_signups) echo "/app/templates/whatsapp_signups.html" ;;
    mtr_live) echo "/app/templates/index.html" ;;
    download_test) echo "/app/templates/traffic.html" ;;
    fieldtech) echo "/app/templates/fieldtech.html" ;;
    ipam) echo "/app/templates/ipam.html" ;;
    *)
      # New modules: default page name matches compose service key (e.g. whatsapp_signups → whatsapp_signups.html).
      echo "/app/templates/${1}.html"
      ;;
  esac
}

tmpl="$(template_for_service "$SERVICE")"

echo "== Asset preflight: $SERVICE =="
docker compose -f "$ROOT_DIR/docker-compose.yml" --env-file "$ROOT_DIR/.env.compose" ps "$SERVICE" >/dev/null
docker compose -f "$ROOT_DIR/docker-compose.yml" --env-file "$ROOT_DIR/.env.compose" exec -T "$SERVICE" sh -lc "$base_check && test -f '$tmpl'"
echo "OK: base assets and module template present in $SERVICE"
