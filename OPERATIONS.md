# MTR Operations Runbook

## Docker build context (mandatory before any image build)

Every app service uses the **same** build context (`.`): `Dockerfile` runs `COPY requirements.txt` then `COPY . /app`.  
If `Dockerfile`, `requirements.txt`, `main.py`, or a `main_<service>.py` entrypoint is missing on disk, **`docker compose build <anything>` fails** — not a single-module bug.

### Canonical: rebuild image **and** recreate container(s)

From the repo root (uses `.env.compose` when present):

```bash
cd /home/wibernetdev/mtr-web-live
bash scripts/rebuild_services.sh backhauls
bash scripts/rebuild_services.sh --no-cache whatsapp_signups
```

Restart **without** rebuilding the image (config/env bounce only):

```bash
bash scripts/rebuild_services.sh --restart-only monitoring
```

Build-only (no `up -d`): `bash scripts/docker_build.sh <service>` — prefer **`rebuild_services.sh`** for normal deploys.

Preflight alone (optional):

```bash
bash scripts/preflight_docker_context.sh
```

Incomplete directory recovery (when the build folder is missing files — restore from disk backup or container copy; version control is optional operator tooling):

```bash
docker cp mtr-core:/app/requirements.txt ./requirements.txt
docker cp mtr-core:/app/main.py ./main.py
# Prefer restoring the **full** `/app` tree from a known-good image or backup so `COPY . /app` is complete.
```

See **`docs/AI_SYSTEM_CONTEXT.md`** for how builds and roles fit together.

Keep `.dockerignore` in the repo so contexts stay small (exclude `venv/`, `.venv/`, `data/`, etc.).

### Checklist: adding a new Compose module service

1. Add `main_<service>.py` and wire `command: ["uvicorn", "main_<service>:app", ...]` in `docker-compose.yml`.
2. Add `templates/<service>.html` unless you match an existing naming exception (see `preflight_module_assets.sh`).
3. Run `bash scripts/preflight_docker_context.sh`, then `bash scripts/docker_build.sh <service>`.
4. Run `bash scripts/preflight_module_assets.sh <service>` after the container exists.
5. Update nginx / `server_resources` routing docs as you already do for new upstreams.

## Module Fault Isolation (Standard)

Runtime app services now use image-baked `templates`/`static` assets (no shared host bind mount for those paths).  
This prevents one broken module asset tree from taking down unrelated modules.

Required deploy preflight for any module change:

```bash
cd /home/wibernetdev/mtr-web-live
bash scripts/preflight_module_assets.sh core
bash scripts/preflight_module_assets.sh monitoring
bash scripts/preflight_module_assets.sh location_sync
bash scripts/preflight_module_assets.sh whatsapp_signups
```

Use the same command for any specific module service being deployed.

## Safe Asset Restore (Templates / Static)

Use this when UI pages fail with missing template/static errors (for example `TemplateNotFound`, missing `style.css`, or cross-module UI failures caused by shared bind mounts).

Always use the safe script below; do not manually delete live `templates/` or `static/`.

```bash
cd /home/wibernetdev/mtr-web-live
bash scripts/safe_restore_assets.sh
```

Optional explicit image source:

```bash
cd /home/wibernetdev/mtr-web-live
bash scripts/safe_restore_assets.sh mtr-web-live-core
```

What the script guarantees:
- restore into temporary directories first
- validate required files before cutover
- move current live dirs into timestamped backup under `backups/`
- atomically swap restored dirs into place
- force-recreate app services so bind mounts refresh cleanly

Post-restore verification:

```bash
cd /home/wibernetdev/mtr-web-live
docker compose -f docker-compose.yml --env-file .env.compose ps
curl -k -I https://mtr.wibernet.co.za/
curl -k -I https://mtr.wibernet.co.za/monitoring
curl -k -I https://mtr.wibernet.co.za/location-sync
curl -k -I https://mtr.wibernet.co.za/whatsapp-signups
```
