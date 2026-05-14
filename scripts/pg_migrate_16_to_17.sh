#!/usr/bin/env bash
# Migrate PostgreSQL 16 → 17 using dump/restore into a NEW Docker volume.
# Safe: old volume (postgres_data) is left untouched for rollback.
#
# Preconditions:
#   - Run from repo root (directory with docker-compose.yml and .env.compose).
#   - mtr-postgres must be postgres:16-alpine using volume postgres_data (default in this repo).
#   - Enough disk for a compressed dump under ./backups/
#
# Usage:
#   PG_MIGRATE_CONFIRM=YES bash scripts/pg_migrate_16_to_17.sh
#
# Rollback (if something fails after compose edit, before you delete the old volume):
#   - Restore docker-compose.yml from the .premigrate-* backup this script creates.
#   - docker compose -f docker-compose.yml --env-file .env.compose up -d postgres
#   - Point postgres service back to postgres_data and postgres:16-alpine.
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ "${PG_MIGRATE_CONFIRM:-}" != "YES" ]]; then
  echo "Refusing to run: set PG_MIGRATE_CONFIRM=YES to proceed (short downtime)." >&2
  exit 2
fi

ENV_FILE=".env.compose"
if [[ -f "$ROOT_DIR/$ENV_FILE" ]]; then
  DC=(docker compose -f docker-compose.yml --env-file "$ROOT_DIR/$ENV_FILE")
else
  DC=(docker compose -f docker-compose.yml)
fi

POSTGRES_CONTAINER="${POSTGRES_CONTAINER_NAME:-mtr-postgres}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
DUMP_DIR="$ROOT_DIR/backups"
DUMP_PATH="$DUMP_DIR/pg16_to_17_${TS}.dump"
COMPOSE_BAK="$ROOT_DIR/docker-compose.yml.premigrate-${TS}"

die() { echo "$*" >&2; exit 1; }

[[ -f docker-compose.yml ]] || die "docker-compose.yml missing in $ROOT_DIR"
command -v docker >/dev/null 2>&1 || die "docker CLI not found"

img="$(docker inspect "$POSTGRES_CONTAINER" --format '{{.Config.Image}}' 2>/dev/null || true)"
[[ "$img" == "postgres:16-alpine" ]] || die "Expected $POSTGRES_CONTAINER image postgres:16-alpine; got: ${img:-not running}"

grep -q 'postgres:16-alpine' docker-compose.yml || die "docker-compose.yml does not reference postgres:16-alpine (already migrated or edited?)"
grep -q 'postgres_data:/var/lib/postgresql/data' docker-compose.yml || die "Expected postgres_data volume mount in docker-compose.yml"

mkdir -p "$DUMP_DIR"

APP_SERVICES=(
  core mtr_live download_test fieldtech ipam monitoring location_sync routers
  backhauls stock_management purchase_orders whatsapp_signups
)

echo "== Phase 1: stop app containers (postgres keeps running) =="
"${DC[@]}" stop "${APP_SERVICES[@]}" 2>/dev/null || true

echo "== Phase 2: logical dump (custom format) =="
docker exec "$POSTGRES_CONTAINER" pg_dump -U "${POSTGRES_USER:-mtr}" -d "${POSTGRES_DB:-mtr}" -Fc >"$DUMP_PATH"
[[ -s "$DUMP_PATH" ]] || die "Dump is empty: $DUMP_PATH"

echo "== Phase 3: stop postgres =="
"${DC[@]}" stop postgres

echo "== Phase 4: patch docker-compose.yml (16→17, new volume postgres_data_17) =="
cp -a docker-compose.yml "$COMPOSE_BAK"
if ! grep -q '^  postgres_data_17:' docker-compose.yml; then
  # Named volume for PG17 data (PG16 data stays in postgres_data).
  sed -i '/^  postgres_data:$/a\  postgres_data_17:' docker-compose.yml
fi
grep -q '^  postgres_data_17:' docker-compose.yml || die "Could not add postgres_data_17: to volumes: in docker-compose.yml"
sed -i 's|image: postgres:16-alpine|image: postgres:17-alpine|' docker-compose.yml
sed -i 's|postgres_data:/var/lib/postgresql/data|postgres_data_17:/var/lib/postgresql/data|' docker-compose.yml

echo "== Phase 5: start Postgres 17 on empty postgres_data_17 =="
"${DC[@]}" up -d postgres

echo "== Phase 6: wait for postgres healthy =="
# Do not pass -d ${POSTGRES_DB}: during first init the DB may not exist yet; pg_isready -U only is enough.
sleep 3
for _i in $(seq 1 120); do
  if docker exec "$POSTGRES_CONTAINER" pg_isready -U "${POSTGRES_USER:-mtr}" -q 2>/dev/null; then
    break
  fi
  sleep 1
done
docker exec "$POSTGRES_CONTAINER" pg_isready -U "${POSTGRES_USER:-mtr}" -q || die "postgres did not become ready"

ver="$(docker exec "$POSTGRES_CONTAINER" psql -U "${POSTGRES_USER:-mtr}" -d "${POSTGRES_DB:-mtr}" -tAc 'show server_version;' | tr -d '[:space:]')"
echo "Postgres reports version: $ver"
[[ "$ver" == 17.* ]] || die "Expected server_version 17.x, got: $ver"

echo "== Phase 7: restore dump into new cluster =="
docker cp "$DUMP_PATH" "${POSTGRES_CONTAINER}:/tmp/migrate.dump"
set +e
docker exec -e PGPASSWORD="${POSTGRES_PASSWORD:-}" "$POSTGRES_CONTAINER" pg_restore \
  --clean \
  --if-exists \
  --no-owner \
  --no-acl \
  -U "${POSTGRES_USER:-mtr}" \
  -d "${POSTGRES_DB:-mtr}" \
  /tmp/migrate.dump
grc=$?
set -e
docker exec "$POSTGRES_CONTAINER" rm -f /tmp/migrate.dump
# pg_restore often returns 1 for non-fatal warnings
if [[ "$grc" -ne 0 && "$grc" -ne 1 ]]; then
  die "pg_restore failed with exit code $grc"
fi

echo "== Phase 8: start all application services =="
"${DC[@]}" up -d

echo "== Done =="
echo "Dump saved at: $DUMP_PATH"
echo "Compose backup: $COMPOSE_BAK"
echo "Old Docker volume postgres_data (PG16) is UNTOUCHED — keep until you verify prod, then remove with care:"
echo "  docker volume rm <project>_postgres_data   # only after a fresh backup and explicit approval"
echo "Next: verify the site, then commit and push the updated docker-compose.yml so Git matches this host."
