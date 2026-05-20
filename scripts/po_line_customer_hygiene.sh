#!/usr/bin/env bash
# PO line customer_id hygiene — audit or apply legacy customer_item rows missing customer_id.
#
# Run from repo root after git pull and rebuild purchase_orders (script must exist in the image).
#
#   bash scripts/po_line_customer_hygiene.sh
#   PO_HYGIENE_CONFIRM=YES bash scripts/po_line_customer_hygiene.sh --apply
#
# Env:
#   PO_HYGIENE_CONTAINER   purchase_orders container name (default: mtr-purchase-orders)
#   PO_HYGIENE_CONFIRM=YES required for --apply
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTAINER="${PO_HYGIENE_CONTAINER:-mtr-purchase-orders}"

die() { echo "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker CLI not found"

if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
  die "Container $CONTAINER not found. Rebuild/start purchase_orders first: bash scripts/rebuild_services.sh purchase_orders"
fi

exec docker exec "$CONTAINER" python3 /app/scripts/po_line_customer_hygiene.py "$@"
