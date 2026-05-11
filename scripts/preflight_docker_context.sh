#!/usr/bin/env bash
# Fail fast before `docker compose build` when the checkout is incomplete.
# Every app service shares context "." and Dockerfile COPY requirements.txt + COPY . /app.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

err() {
  echo "preflight_docker_context: ERROR: $*" >&2
}

die() {
  err "$@"
  echo >&2
  echo "Recovery: restore a complete project tree (see docs/AI_SYSTEM_CONTEXT.md)." >&2
  echo "  docker cp mtr-core:/app/requirements.txt ./requirements.txt" >&2
  echo "  docker cp mtr-core:/app/Dockerfile ./Dockerfile" >&2
  echo "  # …sync full /app from a healthy container or backup so COPY . /app is complete." >&2
  exit 1
}

[[ -f Dockerfile ]] || die "missing Dockerfile in ${ROOT_DIR}"

[[ -f docker-compose.yml ]] || die "missing docker-compose.yml"

[[ -f requirements.txt ]] || die "missing requirements.txt (Dockerfile COPY step requires it)"

[[ -f main.py ]] || die "missing main.py (shared monolith entry; image COPY expects full tree)"

if [[ ! -f .dockerignore ]]; then
  err "missing .dockerignore — builds will be slow and may leak junk into the image context"
  exit 1
fi

# Warn if huge local trees would be sent as context (common footgun).
if [[ -d venv ]] && ! grep -q '^venv' .dockerignore 2>/dev/null; then
  err "directory ./venv exists but is not excluded in .dockerignore — add 'venv/'"
  exit 1
fi
if [[ -d .venv ]] && ! grep -q '\.venv' .dockerignore 2>/dev/null; then
  err "directory ./.venv exists but is not excluded in .dockerignore — add a '.venv/' line"
  exit 1
fi

python3 <<'PY'
import re
import sys
from pathlib import Path

root = Path(".").resolve()
compose = root / "docker-compose.yml"
text = compose.read_text(encoding="utf-8")
# All uvicorn module entrypoints declared in compose (main_<role>:app).
mods = sorted(set(re.findall(r"main_[a-z0-9_]+(?=:app)", text)))
missing = [m for m in mods if not (root / f"{m}.py").exists()]
if missing:
    print("preflight_docker_context: ERROR: missing Python entrypoints for compose uvicorn commands:", ", ".join(missing), file=sys.stderr)
    print("Add main_<service>.py for each new module service, or fix docker-compose.yml.", file=sys.stderr)
    sys.exit(1)
if not mods:
    print("preflight_docker_context: ERROR: no main_*:app uvicorn commands found in docker-compose.yml", file=sys.stderr)
    sys.exit(1)
print(f"preflight_docker_context: OK ({len(mods)} uvicorn entrypoints, Dockerfile + requirements.txt present)")
PY
