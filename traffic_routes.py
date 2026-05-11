# v1.0.7-hotfix11
# Download Test routes (isolated module)

import os
import time
from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.security import HTTPBasicCredentials

# Imported from main.py at runtime
# - security
# - require_login
# - RUN_LOG_PATH

from templates_env import templates

router = APIRouter()

TRAFFIC_FILE_DEFAULT_MB = int(os.getenv("TRAFFIC_FILE_DEFAULT_MB", "200"))
TRAFFIC_FILE_MAX_MB = int(os.getenv("TRAFFIC_FILE_MAX_MB", "1024"))


@router.get("/download-test", response_class=HTMLResponse)
def download_test_page(request: Request, credentials: HTTPBasicCredentials = Depends(lambda: None)):
    # Auth is enforced by main's session middleware; credentials dependency is a no-op placeholder.
    username = request.state.username if hasattr(request.state, "username") else "unknown"
    return templates.TemplateResponse(
        "traffic.html",
        {
            "request": request,
            "username": username,
            "active_tab": "download_test",
            "title": "Download Test",
            "run_log_path": os.getenv("RUN_LOG_PATH", "mtr_runs.log"),
        },
    )


@router.get("/api/traffic/download")
def traffic_download(size_mb: int = TRAFFIC_FILE_DEFAULT_MB, rate_mbps: float = 0.0, credentials: HTTPBasicCredentials = Depends(lambda: None)):
    # Auth is enforced by main's session middleware; credentials dependency is a no-op placeholder.
    try:
        size_mb = int(size_mb)
    except Exception:
        size_mb = TRAFFIC_FILE_DEFAULT_MB
    size_mb = max(1, min(TRAFFIC_FILE_MAX_MB, size_mb))
    total_bytes = size_mb * 1024 * 1024

    import secrets as _secrets

    def gen():
        remaining = total_bytes
        chunk = 1024 * 1024
        while remaining > 0:
            n = chunk if remaining >= chunk else remaining
            remaining -= n
            yield _secrets.token_bytes(n)
            if rate_mbps and rate_mbps > 0:
                # crude server-side throttle (Mbps)
                time.sleep((n * 8) / (rate_mbps * 1_000_000))

    headers = {
        "Content-Disposition": f'attachment; filename="wibernet-download-test-{size_mb}MB.bin"',
        "Cache-Control": "no-store",
    }
    return StreamingResponse(gen(), media_type="application/octet-stream", headers=headers)



@router.post("/api/traffic/upload")
async def traffic_upload(request: Request, credentials: HTTPBasicCredentials = Depends(lambda: None)):
    # Discard uploaded bytes (used for controlled upstream load tests).
    # Optional client-side rate limiting should be applied by the browser/app.
    n = 0
    async for chunk in request.stream():
        if chunk:
            n += len(chunk)
        # hard safety limit: 2GB per request
        if n > (2 * 1024 * 1024 * 1024):
            break
    return {"received_bytes": n}
