#!/usr/bin/env bash
# Push this repo tree + PostgreSQL + /app/data overlay to a standby host over SSH/rsync,
# layer standby-only env (.env.compose.standby), then docker compose pull && up -d --build.
#
# Invoked only by scripts/clone_runner.py (admin Clone UI / API). Emits lines starting with
# "PHASE …" so the runner can surface progress.
#
# Requirements on the standby: Docker Engine + Compose v2 plugin, rsync, same compose layout.
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TARGET_HOST=""
TARGET_USER="root"
TARGET_PORT="22"
TARGET_DIR=""
CONFIRM=""
RUN_ID=""
SSH_KEY=""
DRY_RUN=0
OVERRIDE_FILE=""
HOST_FINGERPRINT=""
PROFILE="full"
SERVICES_CSV=""
POSTGRES_CONTAINER="${POSTGRES_CONTAINER_NAME:-mtr-postgres}"

usage() {
  cat <<EOF
Usage: clone_rebuild.sh --target-host HOST --target-user USER --target-port PORT \\
  --target-dir DIR --confirm 'CLONE HOST' --run-id ID [--ssh-key PATH] [--dry-run] \\
  [--override-file PATH] [--host-fingerprint SHA] [--profile full] [--services a,b]

Internal use: clone_runner.py only. (--profile / --services kept for API compatibility.)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target-host) TARGET_HOST="${2:-}"; shift 2 ;;
    --target-user) TARGET_USER="${2:-}"; shift 2 ;;
    --target-port) TARGET_PORT="${2:-}"; shift 2 ;;
    --target-dir) TARGET_DIR="${2:-}"; shift 2 ;;
    --confirm) CONFIRM="${2:-}"; shift 2 ;;
    --run-id) RUN_ID="${2:-}"; shift 2 ;;
    --ssh-key) SSH_KEY="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --override-file) OVERRIDE_FILE="${2:-}"; shift 2 ;;
    --host-fingerprint) HOST_FINGERPRINT="${2:-}"; shift 2 ;;
    --profile) PROFILE="${2:-full}"; shift 2 ;;
    --services) SERVICES_CSV="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

die() { echo "$*" >&2; exit 1; }

[[ -n "$TARGET_HOST" ]] || die "--target-host is required"
[[ -n "$TARGET_DIR" ]] || die "--target-dir is required"
[[ -n "$CONFIRM" ]] || die "--confirm is required"
[[ -n "$RUN_ID" ]] || die "--run-id is required"

EXPECTED="CLONE ${TARGET_HOST}"
if [[ "$CONFIRM" != "$EXPECTED" ]]; then
  die "Confirmation mismatch (expected exactly: ${EXPECTED})"
fi

POSTGRES_USER="${POSTGRES_USER:-mtr}"
POSTGRES_DB="${POSTGRES_DB:-mtr}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-}"

SSH_OPTS=( -p "${TARGET_PORT}" -o BatchMode=yes -o ConnectTimeout=30 )
if [[ -n "${SSH_KEY}" ]]; then
  SSH_OPTS+=( -i "${SSH_KEY}" )
fi
SSH_OPTS+=( -o StrictHostKeyChecking=accept-new )
if [[ -n "${HOST_FINGERPRINT}" ]]; then
  echo "PHASE ssh fingerprint (stored — verification limited on standby)" >&2
  :
fi

export RSYNC_RSH="ssh ${SSH_OPTS[*]}"

REMOTE="${TARGET_USER}@${TARGET_HOST}"
CLONE_DIR="${ROOT_DIR}/.clone-transfer-${RUN_ID}"
DUMP_LOCAL="${CLONE_DIR}/postgres.dump"

cleanup_local_clone_artifacts() {
  rm -rf "${CLONE_DIR:-}"
}
trap cleanup_local_clone_artifacts EXIT

echo "PHASE preflight local (${RUN_ID}) profile=${PROFILE}${SERVICES_CSV:+ services=${SERVICES_CSV}}"
if [[ ! -f "${ROOT_DIR}/docker-compose.yml" ]]; then
  die "docker-compose.yml missing under ${ROOT_DIR} — cannot clone"
fi

if ! command -v docker >/dev/null 2>&1; then
  die "docker CLI not found — clone runs from mtr-core (needs /var/run/docker.sock)."
fi

RSYNC_EXCLUDES=(
  --exclude '.git/'
  --exclude 'venv/'
  --exclude '.venv/'
  --exclude '**/__pycache__/'
  --exclude '.cursor/'
  --exclude '.clone-transfer-*/'
  --exclude 'logs/'
  --exclude 'backups/'
  --exclude '.deploy-state/'
  --exclude 'node_modules/'
)

RSYNC_FLAGS=( -az )
if [[ "$DRY_RUN" -eq 1 ]]; then
  RSYNC_FLAGS+=( --dry-run )
fi

SCP_BASE=( -P "${TARGET_PORT}" -o BatchMode=yes -o ConnectTimeout=30 -o StrictHostKeyChecking=accept-new )
[[ -n "${SSH_KEY}" ]] && SCP_BASE+=( -i "${SSH_KEY}" )

# --- 1) Logical dump of primary Postgres (full DB state for monitoring, IPAM, etc.) ---
if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "PHASE pg_dump primary postgres ([dry-run] skipped)"
else
  echo "PHASE pg_dump primary postgres (${POSTGRES_CONTAINER})"
  if ! docker ps --format '{{.Names}}' | grep -qx "${POSTGRES_CONTAINER}"; then
    die "Container ${POSTGRES_CONTAINER} is not running — start compose on primary before clone."
  fi
  mkdir -p "${CLONE_DIR}"
  set +e
  docker exec -e "PGPASSWORD=${POSTGRES_PASSWORD}" "${POSTGRES_CONTAINER}" \
    pg_dump -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -Fc > "${DUMP_LOCAL}"
  dumph_rc=$?
  set -e
  if [[ "${dumph_rc}" -ne 0 ]]; then
    die "pg_dump failed (rc=${dumph_rc}). Check POSTGRES_* env in mtr-core and postgres health."
  fi
  if [[ ! -s "${DUMP_LOCAL}" ]]; then
    die "pg_dump produced an empty file — aborting."
  fi
fi

echo "PHASE mkdir target dir on standby"
ssh "${SSH_OPTS[@]}" "${REMOTE}" "mkdir -p $(printf '%q' "${TARGET_DIR}")"

TRANSFER_REMOTE="${TARGET_DIR}/.clone-transfer-${RUN_ID}"
if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "PHASE scp postgres dump to standby ([dry-run] skipped)"
else
  echo "PHASE scp postgres dump to standby"
  ssh "${SSH_OPTS[@]}" "${REMOTE}" "mkdir -p $(printf '%q' "${TRANSFER_REMOTE}")"
  scp "${SCP_BASE[@]}" "${DUMP_LOCAL}" "${REMOTE}:${TRANSFER_REMOTE}/postgres.dump"
fi

echo "PHASE rsync tree + data/ to ${REMOTE}:${TARGET_DIR}"
# Trailing slashes: sync contents into target dir (includes live /app/data from the primary volume).
rsync "${RSYNC_FLAGS[@]}" "${RSYNC_EXCLUDES[@]}" "${ROOT_DIR}/" "${REMOTE}:${TARGET_DIR}/"

if [[ -n "${OVERRIDE_FILE}" && -f "${OVERRIDE_FILE}" ]]; then
  echo "PHASE copy compose env override"
  REMOTE_OVERRIDE="${TARGET_DIR}/.env.compose.clone.override"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[dry-run] would scp override to ${REMOTE}:${REMOTE_OVERRIDE}"
  else
    scp "${SCP_BASE[@]}" "${OVERRIDE_FILE}" "${REMOTE}:${REMOTE_OVERRIDE}"
  fi
fi

echo "PHASE remote restore postgres + compose + volume data merge"

DRY_EXPORT=0
[[ "$DRY_RUN" -eq 1 ]] && DRY_EXPORT=1

# shellcheck disable=SC2090
ssh "${SSH_OPTS[@]}" "${REMOTE}" \
  env \
    TARGET_DIR="${TARGET_DIR}" \
    DRY_RUN_FLAG="${DRY_EXPORT}" \
    RUN_ID="${RUN_ID}" \
    TRANSFER_REMOTE="${TRANSFER_REMOTE}" \
    POSTGRES_CONTAINER="${POSTGRES_CONTAINER}" \
  bash -s <<'REMOTE_EOF'
set -euo pipefail
cd "$TARGET_DIR"
set -a
[[ -f .env.compose ]] && . ./.env.compose
[[ -f .env.compose.clone.override ]] && . ./.env.compose.clone.override
set +a
POSTGRES_USER="${POSTGRES_USER:-mtr}"
POSTGRES_DB="${POSTGRES_DB:-mtr}"

if [[ ! -f docker-compose.yml ]]; then
  echo "docker-compose.yml missing on standby after rsync" >&2
  exit 2
fi

# Standby-only env layer (loaded after .env.compose per docker-compose.yml).
if [[ "${DRY_RUN_FLAG:-0}" != "1" ]]; then
  cat > .env.compose.standby << 'STANDBY_ENV'
MONITORING_SAMPLING_ENABLED=0
LOCATION_SYNC_SCHEDULER_ENABLED=0
STANDBY_ENV
fi

ENV_ARGS=( -f docker-compose.yml )
if [[ -f .env.compose ]]; then
  ENV_ARGS+=( --env-file .env.compose )
fi
if [[ -f .env.compose.clone.override ]]; then
  ENV_ARGS+=( --env-file .env.compose.clone.override )
fi

APP_SERVICES=(
  core mtr_live download_test fieldtech ipam monitoring location_sync routers
  backhauls stock_management purchase_orders whatsapp_signups
)

if [[ "${DRY_RUN_FLAG:-0}" == "1" ]]; then
  echo "[dry-run] would write .env.compose.standby, restore Postgres, compose pull/up, merge app_data"
  if [[ -f scripts/preflight_docker_context.sh ]]; then
    echo "[dry-run] would run scripts/preflight_docker_context.sh"
  fi
  echo "[dry-run] docker compose ${ENV_ARGS[*]} pull"
  echo "[dry-run] docker compose ${ENV_ARGS[*]} up -d --build"
  exit 0
fi

if [[ -f scripts/preflight_docker_context.sh ]]; then
  bash scripts/preflight_docker_context.sh
fi

DUMP_R="${TRANSFER_REMOTE}/postgres.dump"
[[ -f "$DUMP_R" ]] || { echo "missing transfer dump at $DUMP_R" >&2; exit 3; }

# Stop app containers so pg_restore can rewrite the DB safely.
docker compose "${ENV_ARGS[@]}" stop "${APP_SERVICES[@]}" 2>/dev/null || true

docker compose "${ENV_ARGS[@]}" up -d postgres

echo "PHASE remote wait for postgres"
for _i in $(seq 1 90); do
  if docker exec "$POSTGRES_CONTAINER" pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
if ! docker exec "$POSTGRES_CONTAINER" pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB" >/dev/null 2>&1; then
  echo "postgres did not become ready on standby" >&2
  exit 4
fi

docker cp "$DUMP_R" "${POSTGRES_CONTAINER}:/tmp/clone_pg.dump"

set +e
docker exec -e "PGPASSWORD=${POSTGRES_PASSWORD}" "${POSTGRES_CONTAINER}" \
  pg_restore \
    --clean \
    --if-exists \
    --no-owner \
    --no-acl \
    -U "${POSTGRES_USER}" \
    -d "${POSTGRES_DB}" \
    /tmp/clone_pg.dump
grc=$?
set -e
docker exec "${POSTGRES_CONTAINER}" rm -f /tmp/clone_pg.dump

if [[ "$grc" -ne 0 && "$grc" -ne 1 ]]; then
  echo "pg_restore failed with exit code ${grc}" >&2
  exit "$grc"
fi

echo "PHASE remote docker compose (pull + up -d --build)"
docker compose "${ENV_ARGS[@]}" pull
docker compose "${ENV_ARGS[@]}" up -d --build

echo "PHASE merge synced host data/ into app_data volume"
if [[ -d "${TARGET_DIR}/data" ]] && [[ -n "$(ls -A "${TARGET_DIR}/data" 2>/dev/null)" ]]; then
  docker compose "${ENV_ARGS[@]}" run --rm --no-deps \
    -v "${TARGET_DIR}/data:/clone_data:ro" \
    core \
    sh -c 'set -e; cp -a /clone_data/. /app/data/'
else
  echo "(no ${TARGET_DIR}/data content to merge — skipping)"
fi

echo "PHASE redis flush on standby (avoid stale sessions/cache from old volume)"
docker compose "${ENV_ARGS[@]}" exec -T redis redis-cli FLUSHALL 2>/dev/null || true

rm -rf "${TRANSFER_REMOTE}"

echo "PHASE remote clone transfer cleaned"
REMOTE_EOF

echo "PHASE completed clone run ${RUN_ID}"
exit 0
