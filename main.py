# v1.0.6
import asyncio
import base64
import logging
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import time
import math
from fnmatch import fnmatch
from datetime import datetime, timedelta
from pathlib import Path
import subprocess
import tarfile
import ipam
import monitoring
from access_control import require_admin, require_login
from app_config import APP_ROLE
import edge_routers
import location_sync
import location_cross_ref
import backhauls
import stock_management
import purchase_orders
import whatsapp_signups
import server_resources
import compose_control
import auth_users
import audit_log
import push_notifications
import firewall_ops
import db_runtime
from scripts import clone_runner
from scripts import clone_schedule
from scripts import dr_runner
from notifications.service import dispatch_due_notifications, _hydrate_po_email_notification
from po_email_actions import execute_email_action, get_email_action_context, render_email_action_page
from po_pdf import build_purchase_order_pdf, purchase_order_pdf_filename
import po_quote_import
from urllib.parse import parse_qs, quote, urlparse
import html
from dataclasses import dataclass, field
from collections import deque
from typing import Any, Dict, Literal, Optional, List, Set, Tuple
try:
    import redis.asyncio as redis_async
except Exception:
    redis_async = None
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, Depends, HTTPException, status, Body, UploadFile, File, Query, Form
from fastapi.exceptions import RequestValidationError
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
# --- Python 3.8 OpenSSL hashlib compatibility ------------------------------
# Some packages call md5/openssl_md5/new(..., usedforsecurity=False). Python 3.8 OpenSSL backend errors.
# We drop that kwarg across hashlib and _hashlib to prevent crashes in PDF generation dependencies.
import hashlib as _hashlib_public  # noqa: E402

def _drop_usedforsecurity(_kwargs):
    try:
        _kwargs.pop("usedforsecurity", None)
    except Exception:
        pass
    return _kwargs

_real_md5 = _hashlib_public.md5
def _md5_compat(data=b"", *args, **kwargs):
    _drop_usedforsecurity(kwargs)
    return _real_md5(data, *args, **kwargs)
_hashlib_public.md5 = _md5_compat

if hasattr(_hashlib_public, "openssl_md5"):
    _real_omd5 = _hashlib_public.openssl_md5
    def _omd5_compat(data=b"", *args, **kwargs):
        _drop_usedforsecurity(kwargs)
        return _real_omd5(data, *args, **kwargs)
    _hashlib_public.openssl_md5 = _omd5_compat

_real_new = _hashlib_public.new
def _new_compat(name, data=b"", *args, **kwargs):
    _drop_usedforsecurity(kwargs)
    return _real_new(name, data, *args, **kwargs)
_hashlib_public.new = _new_compat

try:
    import _hashlib as _hashlib_private  # noqa: E402
    if hasattr(_hashlib_private, "openssl_md5"):
        _real_pomd5 = _hashlib_private.openssl_md5
        def _pomd5_compat(data=b"", *args, **kwargs):
            _drop_usedforsecurity(kwargs)
            return _real_pomd5(data, *args, **kwargs)
        _hashlib_private.openssl_md5 = _pomd5_compat
except Exception:
    pass
# ---------------------------------------------------------------------------

ModeProto = Literal["icmp", "tcp", "udp"]

# -------------------- App Auth --------------------
security = HTTPBasic()


def require_login(credentials: HTTPBasicCredentials) -> str:
    user = (credentials.username or "").strip()
    if verify_user_password(user, credentials.password or ""):
        return user

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized",
        headers={"WWW-Authenticate": "Basic"},
    )



# -------------------- Session Login (no external deps) --------------------
SESSION_COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "mtr_session")
PENDING_2FA_COOKIE_NAME = os.getenv("PENDING_2FA_COOKIE_NAME", "mtr_2fa_pending")
SESSION_SECRET = os.getenv("SESSION_SECRET", "").encode("utf-8")
# If SESSION_SECRET is unset, session and WS tokens use this (local dev only; set SESSION_SECRET in production).
_SIGNKEY_FALLBACK_DEV = b"mtr-web-live-dev-session-signing-key-not-for-production"


def _session_hmac_key() -> bytes:
    return SESSION_SECRET if SESSION_SECRET else _SIGNKEY_FALLBACK_DEV


SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "43200"))  # 12h
PENDING_2FA_TTL_SECONDS = int(os.getenv("PENDING_2FA_TTL_SECONDS", "600"))  # 10m
SESSION_HTTPS_ONLY = os.getenv("SESSION_HTTPS_ONLY", "0").strip() == "1"

# Behind nginx/caddy TLS termination the app often sees scheme=http; trust X-Forwarded-Proto.
TRUST_PROXY_HEADERS = os.getenv("TRUST_PROXY_HEADERS", "0").strip() == "1"
# Redirect HTTP→HTTPS at the app layer (usually prefer doing this in the reverse proxy instead).
FORCE_HTTPS = os.getenv("FORCE_HTTPS", "0").strip() == "1"
SKIP_FORCE_HTTPS_LOCALHOST = os.getenv("SKIP_FORCE_HTTPS_LOCALHOST", "1").strip() == "1"
BACKUP_DIR = os.getenv("BACKUP_DIR", "/app/data/backups")
# HSTS (only sent when the request is considered HTTPS). 0 disables.
SECURITY_HSTS_MAX_AGE = max(0, min(63072000, int(os.getenv("SECURITY_HSTS_MAX_AGE", "0"))))


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_dec(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def _sign(data: bytes) -> str:
    return _b64u(hmac.new(_session_hmac_key(), data, hashlib.sha256).digest())


def _make_session_token(username: str, ttl_seconds: int = SESSION_TTL_SECONDS) -> str:
    exp = int(time.time()) + int(ttl_seconds)
    nonce = secrets.token_urlsafe(12)
    payload = f"{username}|{exp}|{nonce}".encode("utf-8")
    sig = _sign(payload)
    return _b64u(payload) + "." + sig


def _make_pending_2fa_token(username: str, next_path: str, ttl_seconds: int = PENDING_2FA_TTL_SECONDS) -> str:
    exp = int(time.time()) + int(ttl_seconds)
    nonce = secrets.token_urlsafe(12)
    payload = f"{username}|{exp}|{nonce}|{safe_redirect_path(next_path, '/')}".encode("utf-8")
    sig = _sign(payload)
    return _b64u(payload) + "." + sig


def _verify_session_token(token: str):
    try:
        if not token or "." not in token:
            return None
        payload_b64, sig = token.split(".", 1)
        payload = _b64u_dec(payload_b64)
        if not secrets.compare_digest(_sign(payload), sig):
            return None
        parts = payload.decode("utf-8").split("|")
        if len(parts) < 3:
            return None
        username, exp_s, _nonce = parts[0], parts[1], parts[2]
        if int(exp_s) < int(time.time()):
            return None
        return username
    except Exception:
        return None


def _verify_pending_2fa_token(token: str):
    try:
        if not token or "." not in token:
            return None
        payload_b64, sig = token.split(".", 1)
        payload = _b64u_dec(payload_b64)
        if not secrets.compare_digest(_sign(payload), sig):
            return None
        parts = payload.decode("utf-8").split("|")
        if len(parts) < 4:
            return None
        username, exp_s, _nonce, next_path = parts[0], parts[1], parts[2], parts[3]
        if int(exp_s) < int(time.time()):
            return None
        return {"username": username, "next": safe_redirect_path(next_path, "/")}
    except Exception:
        return None


def _user_requires_2fa(username: str, row: Optional[Dict[str, Any]] = None) -> bool:
    """Every account must enroll in 2FA and complete TOTP at login (password alone is never enough)."""
    return bool((username or "").strip())


def _request_is_https(request: Request) -> bool:
    if (request.url.scheme or "").lower() == "https":
        return True
    if TRUST_PROXY_HEADERS:
        xf = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip().lower()
        if xf == "https":
            return True
    return False


def _effective_cookie_secure(request: Request) -> bool:
    """Secure session cookies when TLS is used (directly or via trusted reverse proxy)."""
    if SESSION_HTTPS_ONLY:
        return True
    if _request_is_https(request):
        return True
    return False


def _https_url_for_request(request: Request) -> str:
    host = (request.headers.get("host") or request.url.netloc or "").strip()
    if not host:
        host = "localhost"
    path = request.url.path or "/"
    if request.url.query:
        return f"https://{host}{path}?{request.url.query}"
    return f"https://{host}{path}"


def _should_force_https_redirect(request: Request) -> bool:
    if not FORCE_HTTPS:
        return False
    if _request_is_https(request):
        return False
    path = request.url.path or ""
    if path.startswith("/.well-known/"):
        return False
    if SKIP_FORCE_HTTPS_LOCALHOST:
        h = (request.headers.get("host") or "").split(":")[0].lower()
        if h in ("localhost", "127.0.0.1", "::1"):
            return False
    return True


def safe_redirect_path(raw: Optional[str], default: str = "/") -> str:
    """
    Only same-site path redirects (prevents open redirects after login).
    Allows /foo and / but rejects //evil.com, http:, newlines, etc.
    """
    if not raw:
        return default
    s = str(raw).strip()
    if len(s) > 2048:
        return default
    if any(c in s for c in ("\n", "\r", "\0")):
        return default
    if not s.startswith("/"):
        return default
    if s.startswith("//"):
        return default
    if "://" in s:
        return default
    try:
        p = urlparse(s)
        if p.netloc:
            return default
    except Exception:
        return default
    return s


def _apply_security_headers(request: Request, response: Response) -> None:
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Permissions-Policy",
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), "
        "microphone=(), payment=(), usb=()",
    )
    if SECURITY_HSTS_MAX_AGE > 0 and _request_is_https(request):
        response.headers.setdefault(
            "Strict-Transport-Security",
            f"max-age={SECURITY_HSTS_MAX_AGE}; includeSubDomains",
        )


def verify_user_password(username: str, password: str) -> bool:
    if not (username or "").strip():
        return False
    return auth_users.verify_password((username or "").strip(), password or "")


def _basic_auth_user(request: Request) -> str:
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth:
        return ""
    if not auth.lower().startswith("basic "):
        return ""
    try:
        raw = base64.b64decode(auth.split(" ", 1)[1].strip()).decode("utf-8")
        if ":" not in raw:
            return ""
        u, p = raw.split(":", 1)
        return u if verify_user_password(u, p) else ""
    except Exception:
        return ""

# -------------------- Runtime Config --------------------
MTR_BIN = os.getenv("MTR_BIN", "mtr")
USE_SUDO = os.getenv("USE_SUDO", "0") == "1"

DEFAULT_FREQ_SEC = float(os.getenv("DEFAULT_FREQ_SEC", "1.0"))
MIN_FREQ_SEC = 0.25
MAX_FREQ_SEC = 10.0

TARGET_RE = re.compile(r"^[a-zA-Z0-9\.\-:]+$")

WARMUP_PINGS = 5

WS_TOKEN_TTL_SEC = 60 * 30
_WS_SECRET_RAW = os.getenv("WS_SECRET", "").strip()
WS_SECRET = _WS_SECRET_RAW.encode("utf-8") if _WS_SECRET_RAW else _session_hmac_key()

RUN_LOG_PATH = os.getenv("RUN_LOG_PATH", "mtr_runs.log")

# -------------------- Active Tests (In-Memory) --------------------
# Tracks currently running WebSocket tests so the UI can show who is running what.
# Keyed by a per-connection id.
ACTIVE_RUNS: Dict[str, Dict[str, Any]] = {}
ACTIVE_LOCK = asyncio.Lock()


def clamp_freq(freq: Any) -> float:
    try:
        f = float(freq)
    except Exception:
        f = DEFAULT_FREQ_SEC
    return max(MIN_FREQ_SEC, min(MAX_FREQ_SEC, f))


def make_ws_token(username: str) -> str:
    ts = str(int(time.time()))
    payload = f"{ts}|{username}"
    sig = hmac.new(WS_SECRET, payload.encode(), hashlib.sha256).hexdigest()
    raw = f"{payload}|{sig}".encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def verify_ws_token(token: str) -> Optional[str]:
    try:
        padded = token + "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode(padded.encode()).decode()
        ts_s, username, sig = raw.split("|", 2)
        ts = int(ts_s)

        if abs(time.time() - ts) > WS_TOKEN_TTL_SEC:
            return None

        payload = f"{ts_s}|{username}"
        expected = hmac.new(WS_SECRET, payload.encode(), hashlib.sha256).hexdigest()
        if not secrets.compare_digest(sig, expected):
            return None

        return username
    except Exception:
        return None


def append_run_log(line: str) -> None:
    """
    Append a single log line. Any errors are printed so they appear in journalctl.
    """
    try:
        os.makedirs(os.path.dirname(RUN_LOG_PATH) or ".", exist_ok=True)
        with open(RUN_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line.rstrip("\n") + "\n")
            f.flush()
            os.fsync(f.fileno())
        print(f"[RUNLOG] appended to {RUN_LOG_PATH}")
    except Exception as e:
        print(f"[RUNLOG] FAILED append to {RUN_LOG_PATH}: {e!r}")


def parse_run_log_line(line: str) -> Optional[dict]:
    line = (line or "").strip()
    if not line:
        return None

    parts = line.split()
    if len(parts) < 2:
        return None

    out: Dict[str, Any] = {"ts": parts[0]}
    for token in parts[1:]:
        if "=" not in token:
            continue
        k, v = token.split("=", 1)
        out[k.strip()] = v.strip()

    return out


def iso_z_to_epoch_utc(ts: str) -> Optional[int]:
    try:
        import calendar

        t = time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
        return int(calendar.timegm(t))
    except Exception:
        return None


def read_runs_last_days(days: int = 30) -> List[dict]:
    try:
        days = int(days)
    except Exception:
        days = 30
    days = max(1, min(365, days))

    if not os.path.exists(RUN_LOG_PATH):
        return []

    cutoff = int(time.time()) - (days * 24 * 60 * 60)

    out: List[dict] = []
    try:
        with open(RUN_LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                d = parse_run_log_line(ln)
                if not d:
                    continue

                ts = str(d.get("ts", ""))
                epoch = iso_z_to_epoch_utc(ts)
                if epoch is None or epoch < cutoff:
                    continue                # Run History should include runs that were stopped manually.
                # We keep the list clean using the sanity checks below (dst present + at least one send).
                # Minimal sanity: require destination and at least one send.
                # (avg/loss/snt_eff may be missing if stopped during warmup)
                dst = str(d.get("dst", "-"))
                # Prefer effective sent count when present
                snt = str(d.get("snt_eff") or d.get("snt") or "0")

                if dst in ("-", "", "None"):
                    continue
                if snt in ("-", "", "None", "0", "0.0"):
                    continue

                out.append(d)
    except Exception as e:
        print(f"[RUNLOG] FAILED read {RUN_LOG_PATH}: {e!r}")
        return []

    out.sort(key=lambda x: x.get("ts", ""), reverse=True)
    return out


# -------------------- Hop Statistics --------------------
@dataclass
class HopStats:
    hop: int
    host: str = ""
    ip: str = ""

    sent: int = 0
    rcvd: int = 0

    last_ms: Optional[float] = None
    best_ms: Optional[float] = None
    worst_ms: Optional[float] = None
    sum_ms: float = 0.0

    sent_eff: int = 0
    rcvd_eff: int = 0
    last_eff_ms: Optional[float] = None
    best_eff_ms: Optional[float] = None
    worst_eff_ms: Optional[float] = None
    sum_eff_ms: float = 0.0

    # Store effective latency samples for percentile/jitter (bounded).
    eff_samples: Any = field(default_factory=lambda: deque(maxlen=5000))  # deque[float]
    _prev_eff_ms: Optional[float] = None
    _jitter_abs_sum: float = 0.0
    _jitter_abs_n: int = 0

    warmup_done: bool = False

    def on_sent(self) -> None:
        self.sent += 1

        if self.sent < WARMUP_PINGS:
            return

        if self.sent == WARMUP_PINGS and not self.warmup_done:
            self.warmup_done = True
            self.sent_eff = 0
            self.rcvd_eff = 0
            self.last_eff_ms = None
            self.best_eff_ms = None
            self.worst_eff_ms = None
            self.sum_eff_ms = 0.0
            try:
                self.eff_samples.clear()
            except Exception:
                self.eff_samples = deque(maxlen=5000)
            self._prev_eff_ms = None
            self._jitter_abs_sum = 0.0
            self._jitter_abs_n = 0
            return

        if self.warmup_done:
            self.sent_eff += 1

    def on_reply(self, ms: float) -> None:
        self.rcvd += 1
        self.last_ms = ms
        self.sum_ms += ms
        if self.best_ms is None or ms < self.best_ms:
            self.best_ms = ms
        if self.worst_ms is None or ms > self.worst_ms:
            self.worst_ms = ms

        if not self.warmup_done:
            return

        self.rcvd_eff += 1
        self.last_eff_ms = ms
        self.sum_eff_ms += ms
        if self.best_eff_ms is None or ms < self.best_eff_ms:
            self.best_eff_ms = ms
        if self.worst_eff_ms is None or ms > self.worst_eff_ms:
            self.worst_eff_ms = ms

        # Capture samples for percentiles + jitter (effective only)
        try:
            self.eff_samples.append(ms)
        except Exception:
            self.eff_samples = deque(maxlen=5000)
            self.eff_samples.append(ms)

        if self._prev_eff_ms is not None:
            self._jitter_abs_sum += abs(ms - self._prev_eff_ms)
            self._jitter_abs_n += 1
        self._prev_eff_ms = ms

    def avg_eff(self) -> Optional[float]:
        if self.rcvd_eff == 0:
            return None
        return self.sum_eff_ms / self.rcvd_eff

    def loss_eff(self) -> Optional[float]:
        if self.sent_eff == 0:
            return None
        lost = self.sent_eff - self.rcvd_eff
        if lost < 0:
            lost = 0
        return (lost / self.sent_eff) * 100.0


    def jitter_eff(self) -> Optional[float]:
        if self._jitter_abs_n <= 0:
            return None
        return self._jitter_abs_sum / float(self._jitter_abs_n)

    def pctl_eff(self, p: float) -> Optional[float]:
        """Percentile over effective latency samples (p in [0,100])."""
        if not self.eff_samples:
            return None
        try:
            arr = sorted(self.eff_samples)
        except Exception:
            return None
        if not arr:
            return None
        p = max(0.0, min(100.0, float(p)))
        if len(arr) == 1:
            return float(arr[0])
        # Nearest-rank with interpolation
        k = (p / 100.0) * (len(arr) - 1)
        f = int(math.floor(k))
        c = int(math.ceil(k))
        if f == c:
            return float(arr[f])
        return float(arr[f] + (arr[c] - arr[f]) * (k - f))


def _configure_request_logging() -> None:
    """Ensure uvicorn + app logs show tracebacks for 500s (docker logs / journal)."""
    fmt = "%(asctime)s %(levelname)s [%(name)s] %(message)s"
    raw_level = (os.getenv("MTR_LOG_LEVEL", "") or "INFO").strip().upper()
    level = getattr(logging, raw_level, logging.INFO)
    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(level=level, format=fmt)
    else:
        root.setLevel(level)
    for name in ("mtr.web", "mtr.backhauls", "uvicorn", "uvicorn.error", "uvicorn.access", "fastapi"):
        logging.getLogger(name).setLevel(level)


_configure_request_logging()
LOG = logging.getLogger("mtr.web")


# -------------------- FastAPI Setup --------------------
app = FastAPI()

# Local IPAM + monitoring store
if db_runtime.is_postgres():
    db_runtime.init_postgres_schema()
ipam.init_db()
auth_users.init_db()
audit_log.init_db()
push_notifications.init_db()
if APP_ROLE == "core":
    location_sync.init_db()
if APP_ROLE == "whatsapp_signups":
    whatsapp_signups.init_db()
if APP_ROLE == "stock_management":
    stock_management.init_db()
if APP_ROLE == "purchase_orders":
    purchase_orders.init_db()
if APP_ROLE == "monitoring":
    monitoring.init_db()
if APP_ROLE == "backhauls":
    backhauls.init_db()
# Static assets (CSS/JS)
os.makedirs("static", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

LOG.info("FastAPI app initialized APP_ROLE=%s", APP_ROLE)


@app.middleware("http")
async def log_unhandled_exceptions_middleware(request: Request, call_next):
    """Log traceback for server errors; safe passthrough for HTTP / validation responses."""
    try:
        return await call_next(request)
    except HTTPException:
        raise
    except RequestValidationError:
        raise
    except Exception:
        LOG.exception(
            "Unhandled exception %s %s",
            request.method,
            request.url.path,
        )
        raise


@app.get("/sw.js", include_in_schema=False)
def service_worker():
    p = os.path.join("static", "sw.js")
    if not os.path.isfile(p):
        raise HTTPException(404, "Service worker missing")
    return FileResponse(
        p,
        media_type="application/javascript; charset=utf-8",
        headers={"Service-Worker-Allowed": "/"},
    )


# -------------------- Local IPAM API --------------------
@app.get("/api/ipam/locations")
def api_ipam_locations():
    return {"ok": True, "locations": ipam.list_locations()}

@app.post("/api/ipam/locations")
def api_ipam_create_location(request: Request, payload: Dict[str, Any] = Body(...)):
    name = (payload or {}).get("name")
    if not name:
        raise HTTPException(status_code=400, detail="Missing name")
    loc_id = ipam.create_location(str(name).strip())
    audit_log.record_request(
        request,
        "ipam.location.create",
        target_type="location_id",
        target_id=str(loc_id),
        detail={"name": str(name).strip()[:120]},
    )
    # Keep both response shapes for UI/backward compatibility.
    return {"ok": True, "location": loc_id, "location_id": loc_id}

@app.post("/api/ipam/location")
def api_ipam_location_alias(request: Request, payload: dict):
    """Backward-compatible alias for older UI: use /api/ipam/locations"""
    return api_ipam_create_location(request, payload)

@app.post("/api/ipam/network")
def api_ipam_network_alias(request: Request, payload: dict):
    """Backward-compatible alias for older UI: use /api/ipam/networks"""
    return api_ipam_create_network(request, payload)


@app.get("/api/ipam/networks")
def api_ipam_networks(location_id: int):
    return {"ok": True, "networks": ipam.list_networks(location_id)}

@app.get("/api/ipam/ips")
def api_ipam_ips(network_id: int):
    """List IPs for a given network, marking available/used/reserved."""
    try:
        return ipam.list_ips_for_network(int(network_id))
    except Exception as e:
        return {"ok": False, "detail": str(e)}


@app.post("/api/ipam/networks")
def api_ipam_create_network(request: Request, payload: Dict[str, Any] = Body(...)):
    location_id = (payload or {}).get("location_id")
    cidr = (payload or {}).get("cidr")
    if not location_id or not cidr:
        raise HTTPException(status_code=400, detail="Missing location_id or cidr")
    net_id = ipam.create_network(int(location_id), str(cidr).strip())
    audit_log.record_request(
        request,
        "ipam.network.create",
        target_type="network_id",
        target_id=str(net_id),
        detail={"location_id": int(location_id), "cidr": str(cidr).strip()[:64]},
    )
    # Keep both response shapes for UI/backward compatibility.
    return {"ok": True, "network": net_id, "network_id": net_id}

@app.get("/api/ipam/next")
def api_ipam_next(location_id: int):
    network_id, net_cidr, ip_addr = ipam.next_free_for_location(location_id)
    return {"ok": True, "network_id": network_id, "ip": ip_addr, "network_cidr": net_cidr}

@app.post("/api/ipam/use")
def api_ipam_use(request: Request, payload: Dict[str, Any] = Body(...)):
    customer_id = (payload or {}).get("customer_id")
    location_id = (payload or {}).get("location_id")
    if not customer_id or not location_id:
        raise HTTPException(status_code=400, detail="Missing customer_id or location_id")
    res = ipam.assign_next_ip(int(customer_id), int(location_id))
    audit_log.record_request(
        request,
        "ipam.ip.assign_next",
        target_type="customer_id",
        target_id=str(int(customer_id)),
        detail={"location_id": int(location_id), "result_keys": list((res or {}).keys())[:12] if isinstance(res, dict) else []},
    )
    return {"ok": True, "result": res}

@app.get("/api/ipam/customer/{customer_id}")
def api_ipam_customer(customer_id: int):
    ip_addr = ipam.get_customer_ip(customer_id)
    return {"ok": True, "customer_id": customer_id, "ip": ip_addr}

def _clone_scheduler_allowed() -> bool:
    """When false (standby .env.compose.standby): no nightly clone, no clone API — avoids DR host cloning itself."""
    v = (os.getenv("CLONE_SCHEDULER_ENABLED") or "1").strip().lower()
    return v not in ("0", "false", "no", "off")


def _standby_banner_message() -> str:
    """DR standby (clone) layers .env.compose.standby — show a global heads-up in the UI."""
    loc = (os.getenv("LOCATION_SYNC_SCHEDULER_ENABLED") or "1").strip().lower()
    clone_on = _clone_scheduler_allowed()
    if loc not in ("0", "false", "no") and clone_on:
        return ""
    parts: List[str] = []
    if loc in ("0", "false", "no"):
        parts.append(
            "Standby / DR mode: automatic Location Sync is disabled (scheduled Splynx pull does not run; data reflects the last clone)."
        )
    if not clone_on:
        parts.append(
            "Standby / DR mode: clone scheduler is disabled (no nightly clone; clone API off — avoids standby copying to itself)."
        )
    mon = (os.getenv("MONITORING_SAMPLING_ENABLED") or "1").strip().lower()
    if mon in ("0", "false", "no"):
        parts.append(
            "Monitoring ICMP sampling and SNMP probes to network gear are off on this host."
        )
    if parts:
        parts.append("Re-enable after Promote Standby or by editing .env.compose.")
    return " ".join(parts)


_po_event_subscribers: List[asyncio.Queue] = []
# Event loop that owns _po_event_subscribers' asyncio.Queue instances (SSE runs here).
_po_events_loop: Optional[asyncio.AbstractEventLoop] = None
_po_events_redis_client: Optional[Any] = None
_po_events_redis_task: Optional[asyncio.Task] = None
_PO_EVENTS_CHANNEL = os.getenv("PO_EVENTS_CHANNEL", "mtr:po_events")


def _po_put_or_drop_subscriber(q: asyncio.Queue, evt: Dict[str, Any]) -> None:
    """Must run on the asyncio loop that owns `q` (thread-safe for that queue)."""
    try:
        q.put_nowait(evt)
    except Exception:
        try:
            _po_event_subscribers.remove(q)
        except ValueError:
            pass


def _po_broadcast_local(evt: Dict[str, Any]) -> None:
    for q in list(_po_event_subscribers):
        _po_put_or_drop_subscriber(q, evt)


async def _po_publish_redis(evt: Dict[str, Any]) -> None:
    if _po_events_redis_client is None:
        return
    try:
        await _po_events_redis_client.publish(_PO_EVENTS_CHANNEL, json.dumps(evt, ensure_ascii=True))
    except Exception:
        pass


async def _po_redis_subscriber_loop() -> None:
    if _po_events_redis_client is None:
        return
    pubsub = _po_events_redis_client.pubsub()
    await pubsub.subscribe(_PO_EVENTS_CHANNEL)
    try:
        while True:
            msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=5.0)
            if not msg:
                await asyncio.sleep(0.05)
                continue
            raw = msg.get("data")
            if raw in (None, ""):
                continue
            try:
                if isinstance(raw, (bytes, bytearray)):
                    raw = raw.decode("utf-8", errors="ignore")
                evt = json.loads(str(raw))
            except Exception:
                continue
            if not isinstance(evt, dict):
                continue
            _po_broadcast_local(evt)
    except asyncio.CancelledError:
        raise
    finally:
        try:
            await pubsub.unsubscribe(_PO_EVENTS_CHANNEL)
        except Exception:
            pass
        try:
            await pubsub.close()
        except Exception:
            pass


def _publish_po_event(po_id: int, action: str) -> None:
    """Notify all PO EventSource clients. Safe when called from sync route thread pool."""
    evt = {"po_id": int(po_id), "action": str(action or "updated"), "ts": datetime.utcnow().isoformat(timespec="seconds") + "Z"}
    loop = _po_events_loop
    if loop is None or not loop.is_running():
        return
    # Redis bridge for multi-worker fanout.
    if _po_events_redis_client is not None:
        try:
            loop.call_soon_threadsafe(lambda: asyncio.create_task(_po_publish_redis(evt)))
        except RuntimeError:
            pass
        return
    # Local in-process fallback (single worker / Redis unavailable).
    try:
        loop.call_soon_threadsafe(_po_broadcast_local, evt)
    except RuntimeError:
        pass

# -------------------- Auth Middleware + Login Routes --------------------
PUBLIC_PATHS = {"/login", "/login/2fa", "/2fa/setup", "/logout", "/health", "/favicon.ico", "/sw.js", "/api/whatsapp-signups/webhook"}


def _path_to_page_key(url_path: str) -> Optional[str]:
    """Maps URL path to a coarse page key for RBAC; None means no granular rule (unused)."""
    p = (url_path or "/").split("?", 1)[0]
    if len(p) > 1 and p.endswith("/"):
        p = p[:-1] or "/"

    if p.startswith("/api/users") or p == "/users":
        return "users_admin"
    if p.startswith("/api/audit") or p == "/audit-log":
        return "users_admin"

    if p.startswith("/api/ipam") or p == "/ipam":
        return "ipam"
    if p.startswith("/api/routers") or p == "/routers":
        return "routers"
    if p.startswith("/api/backhauls") or p == "/backhauls":
        return "backhauls"
    if p.startswith("/api/firewall") or p == "/firewall":
        return "firewall"
    if p.startswith("/api/backups") or p == "/backups":
        return "backups"
    if p.startswith("/api/location-sync") or p == "/location-sync":
        return "location_sync"
    if p.startswith("/api/monitoring") or p == "/monitoring":
        return "monitoring"
    if p.startswith("/api/push"):
        return "monitoring"
    if p.startswith("/api/resources") or p == "/resources":
        return "resources"
    if p.startswith("/api/compose"):
        return "resources"
    if p.startswith("/api/stock/sales-log") or p == "/sales-log":
        return "sales_log"
    if p.startswith("/api/stock") or p == "/stock-management":
        return "stock_management"
    if p.startswith("/api/po") or p == "/purchase-orders":
        return "purchase_orders"
    if p.startswith("/api/whatsapp-signups") or p == "/whatsapp-signups":
        return "whatsapp_signups"
    if p.startswith("/api/clone") or p.startswith("/api/dr"):
        return "resources"
    if p.startswith("/api/fieldtech") or p == "/fieldtech":
        return "fieldtech"

    if p.startswith("/download-test"):
        return "download_test"
    if p.startswith("/fieldtech"):
        return "fieldtech"

    if p.startswith("/api/traffic"):
        return None  # allowed if mtr_live or download_test (see auth_session_middleware)

    if p.startswith("/ws/mtr"):
        return "mtr_live"
    if p.startswith("/api/runs") or p.startswith("/api/active") or p.startswith("/api/pdf_summary"):
        return "mtr_live"

    if p == "/mtr-live" or p.startswith("/mtr-live/"):
        return "mtr_live"

    if p == "/":
        return "home"

    return None


def _access_denied(request: Request, path: str) -> Response:
    accept = (request.headers.get("accept") or "").lower()
    wants_json = path.startswith("/api/") or path.startswith("/ws") or "application/json" in accept
    if wants_json:
        return JSONResponse({"ok": False, "error": "forbidden"}, status_code=403)
    return HTMLResponse(
        "<!doctype html><html><body style='font-family:system-ui;padding:2rem'>"
        "<h1>Forbidden</h1><p>You do not have access to this page.</p>"
        "<p><a href='/'>Home</a></p></body></html>",
        status_code=403,
    )


def _admin_portable_ui_path(path: str) -> bool:
    """
    Paths that were historically exempt from APP_ROLE edge filtering when combined with admin.
    Admins now bypass the edge list entirely (see auth_session_middleware); kept for reference.
    """
    p = (path or "/").split("?", 1)[0]
    if len(p) > 1 and p.endswith("/"):
        p = p[:-1] or "/"
    if p in ("/users", "/audit-log"):
        return True
    if p.startswith("/api/users") or p.startswith("/api/audit"):
        return True
    if p.startswith("/resources") or p == "/resources":
        return True
    if p.startswith("/api/resources") or p.startswith("/api/compose"):
        return True
    if p.startswith("/api/clone") or p.startswith("/api/dr"):
        return True
    return False


def _edge_allowed_path(path: str) -> bool:
    p = (path or "/").split("?", 1)[0]
    common_allow = (
        "/",
        "/login",
        "/logout",
        "/health",
        "/favicon.ico",
        "/sw.js",
        "/static/*",
        "/api/push/vapid-public-key",
    )
    role_allow = {
        "core": (
            "/",
            "/users*",
            "/firewall*",
            "/backups*",
            "/resources*",
            "/api/users*",
            "/api/firewall*",
            "/api/backups*",
            "/api/resources*",
            "/api/compose*",
            "/api/clone*",
            "/api/dr*",
            "/audit-log*",
            "/api/audit*",
        ),
        "mtr_live": (
            "/mtr-live*",
            "/api/traffic*",
            "/api/runs*",
            "/api/active*",
            "/api/pdf_summary*",
            "/ws/mtr*",
        ),
        "download_test": (
            "/download-test*",
            "/download/purchase-orders-user-guide*",
            "/api/traffic*",
        ),
        "fieldtech": (
            "/fieldtech*",
            "/api/fieldtech*",
        ),
        "ipam": (
            "/ipam*",
            "/api/ipam*",
        ),
        "monitoring": (
            "/monitoring*",
            "/api/monitoring*",
            "/api/push*",
        ),
        "location_sync": (
            "/location-sync*",
            "/api/location-sync*",
            "/api/routers*",
        ),
        "routers": (
            "/routers*",
            "/api/routers*",
        ),
        "backhauls": (
            "/backhauls*",
            "/api/backhauls*",
            "/api/routers*",
        ),
        "stock_management": (
            "/stock-management*",
            "/sales-log*",
            "/api/stock*",
        ),
        "purchase_orders": (
            "/purchase-orders*",
            "/api/po*",
        ),
        "whatsapp_signups": (
            "/whatsapp-signups*",
            "/api/whatsapp-signups*",
        ),
        # Backward compatibility for previous edge role.
        "edge": (
            "/routers*",
            "/backhauls*",
            "/api/routers*",
            "/api/backhauls*",
        ),
    }
    allow_patterns = common_allow + role_allow.get(APP_ROLE, role_allow["core"])
    return any(fnmatch(p, pat) for pat in allow_patterns)


# `home` maps to `/` (default landing). RBAC stays page keys in Users (`pages_json`).
# Edge path prefixes stay stable; extra upstreams are added in host nginx when services split.

def _nav_items_for_request(request: Request) -> List[Dict[str, str]]:
    """Ordered links for bottom sheet + home dropdown (mirrors former sidebar rules)."""
    raw_ap = getattr(request.state, "allowed_pages", None)
    ap = set(raw_ap or [])
    # Match session_permissions: implicit grants (e.g. home → mtr_live) for nav building.
    for sources, grants in auth_users.IMPLICIT_PAGE_GRANTS:
        if ap.intersection(sources):
            ap.update(grants)
    is_adm = bool(getattr(request.state, "is_admin", False))
    kl = dict(auth_users.PAGE_DEFINITIONS)
    out: List[Dict[str, str]] = []
    seen: Set[str] = set()

    def add_key(key: str) -> None:
        if key in seen:
            return
        if key in ("users", "audit_log"):
            if not is_adm:
                return
            seen.add(key)
            if key == "users":
                out.append({"key": "users", "label": "Users", "href": "/users"})
            else:
                out.append({"key": "audit_log", "label": "Audit log", "href": "/audit-log"})
            return
        if key not in kl:
            return
        if not is_adm and key not in ap:
            return
        if key == "sales_log" and not is_adm and "sales_log" not in ap:
            return
        seen.add(key)
        out.append({"key": key, "label": kl[key], "href": auth_users.page_landing_path(key)})

    # Admin should always see every app page regardless of current module/container context.
    if is_adm:
        for key, _label in auth_users.PAGE_DEFINITIONS:
            add_key(key)
        add_key("users")
        add_key("audit_log")
        return out

    for key in (
        "home",
        "mtr_live",
        "download_test",
        "fieldtech",
        "ipam",
        "monitoring",
        "backhauls",
        "stock_management",
        "purchase_orders",
        "whatsapp_signups",
    ):
        add_key(key)

    if is_adm or ("sales_log" in ap):
        add_key("sales_log")

    if (not is_adm) and ("location_sync" in ap):
        add_key("location_sync")

    if not is_adm:
        for key in ("firewall", "backups", "routers", "resources"):
            add_key(key)

    # Last resort: still empty but RBAC lists pages (legacy keys / ordering gaps).
    if not out and ap and not is_adm:
        for key, _label in auth_users.PAGE_DEFINITIONS:
            if key in ("users", "audit_log"):
                continue
            add_key(key)

    return out


def _client_hostname_for_nav(request: Request) -> str:
    raw = (request.headers.get("host") or "").split(",")[0].strip()
    if not raw:
        return (request.url.hostname or "").strip()
    if raw.startswith("["):
        end = raw.find("]")
        if end > 1:
            return raw[1:end].strip()
    if ":" in raw:
        host_part, port_part = raw.rsplit(":", 1)
        if port_part.isdigit():
            return host_part.strip()
    return raw


def _host_for_url(hostname: str) -> str:
    """Bracket IPv6 literals for use in http(s)://… URLs."""
    if not hostname:
        return hostname
    if ":" in hostname and not hostname.startswith("["):
        return f"[{hostname}]"
    return hostname


def _nav_with_published_ports(request: Request, items: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """
    When the stack is reached via per-service ports (no path-based reverse proxy), root-relative
    /purchase-orders etc. would hit the wrong container. Rewrite nav hrefs to scheme://host:port/path.
    Enable with MTR_NAV_USE_PUBLISHED_PORTS=1 in .env.compose (clone / dev laptops).
    """
    flag = (os.getenv("MTR_NAV_USE_PUBLISHED_PORTS", "") or "").strip().lower()
    if flag not in ("1", "true", "yes", "on"):
        return items
    hostname = _client_hostname_for_nav(request)
    if not hostname:
        return items
    scheme = (request.url.scheme or "http").strip() or "http"
    cur_port = request.url.port
    if cur_port is None:
        cur_port = 443 if scheme == "https" else 80
    core_port = server_resources.published_port_for_compose_service("core")
    out: List[Dict[str, str]] = []
    host_u = _host_for_url(hostname)
    for it in items:
        key = str(it.get("key") or "")
        href = str(it.get("href") or "/")
        label = str(it.get("label") or "")
        svc = server_resources.PAGE_KEY_COMPOSE_SERVICE.get(key, "core")
        port = server_resources.published_port_for_compose_service(svc)
        if port is None:
            out.append(it)
            continue
        h = href if href.startswith("/") else f"/{href}"
        if svc == "core":
            if core_port is not None and cur_port != core_port:
                out.append({"key": key, "label": label, "href": f"{scheme}://{host_u}:{core_port}{h}"})
            else:
                out.append({"key": key, "label": label, "href": href})
            continue
        if port == cur_port:
            out.append({"key": key, "label": label, "href": href})
        else:
            out.append({"key": key, "label": label, "href": f"{scheme}://{host_u}:{port}{h}"})
    return out


def _compose_service_name_for_app_role() -> str:
    r = (APP_ROLE or "").strip().lower()
    if r == "edge":
        return "routers"
    return r


def _maybe_cross_service_port_redirect(request: Request, path: str) -> Optional[RedirectResponse]:
    """
    If the browser opened a compose publish port directly (e.g. :9002/core) but the path belongs to
    another service, bounce GET (non-API) requests to the correct host:port. Skips standard 80/443 so
    reverse-proxy entrypoints are unchanged.
    """
    raw = (os.getenv("MTR_NAV_CROSS_SERVICE_REDIRECT", "1") or "1").strip().lower()
    if raw in ("0", "false", "no", "off"):
        return None
    if request.method != "GET":
        return None
    p0 = path or "/"
    if p0.startswith("/api/") or p0.startswith("/ws"):
        return None
    if _edge_allowed_path(p0):
        return None
    pub = server_resources.compose_published_ports()
    scheme = (request.url.scheme or "http").strip() or "http"
    if _request_is_https(request):
        scheme = "https"
    cur_req_port = request.url.port
    if cur_req_port is None:
        cur_req_port = 443 if scheme == "https" else 80
    cur_role = _compose_service_name_for_app_role()
    cur_pub = server_resources.published_port_for_compose_service(cur_role)
    if cur_pub is None:
        return None
    if int(cur_req_port) not in pub or int(cur_req_port) != int(cur_pub):
        return None
    p = p0.split("?", 1)[0]
    if len(p) > 1 and p.endswith("/"):
        p = p[:-1] or "/"
    pk = _path_to_page_key(p)
    if not pk:
        return None
    is_adm = bool(getattr(request.state, "is_admin", False))
    if pk == "users_admin":
        if not is_adm:
            return None
        target_svc = "core"
    else:
        if not is_adm:
            allowed = set(getattr(request.state, "allowed_pages", None) or [])
            if pk not in allowed:
                return None
        target_svc = server_resources.PAGE_KEY_COMPOSE_SERVICE.get(pk) or "core"
    target_port = server_resources.published_port_for_compose_service(target_svc)
    if target_port is None or int(target_port) == int(cur_req_port):
        return None
    hostname = _client_hostname_for_nav(request)
    if not hostname:
        return None
    host_u = _host_for_url(hostname)
    qs = ("?" + request.url.query) if request.url.query else ""
    p_start = p if p.startswith("/") else "/" + p
    dest = f"{scheme}://{host_u}:{target_port}{p_start}{qs}"
    return RedirectResponse(url=dest, status_code=302)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    try:
        _apply_security_headers(request, response)
    except Exception:
        pass
    return response


@app.middleware("http")
async def auth_session_middleware(request: Request, call_next):
    path = request.url.path or "/"

    if path.startswith("/po/email-action"):
        return await call_next(request)

    if path in PUBLIC_PATHS:
        return await call_next(request)
    if path.startswith("/static/"):
        return await call_next(request)

    token = request.cookies.get(SESSION_COOKIE_NAME, "")
    username = _verify_session_token(token) if token else None
    came_from_basic = False
    auth_via_basic = False

    if not username:
        u = _basic_auth_user(request)
        if u:
            username = u
            came_from_basic = True
            auth_via_basic = True

    if not username:
        if path.startswith("/api/"):
            return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
        next_url = quote(path)
        return RedirectResponse(url=f"/login?next={next_url}", status_code=302)

    request.state.username = username
    is_adm, allowed = auth_users.session_permissions(username)
    urow = auth_users.get_user_by_username(username)
    requires_2fa = _user_requires_2fa(username, urow)
    twofa_enabled = bool((urow or {}).get("twofa_enabled"))
    # HTTP Basic proves password only; after 2FA enrollment it must not bypass TOTP.
    if auth_via_basic and requires_2fa and twofa_enabled:
        if path.startswith("/api/"):
            return JSONResponse({"ok": False, "error": "session_required_after_2fa"}, status_code=401)
        next_q = quote(path)
        msg_q = quote("Sign in through the web login and enter your authenticator code.")
        return RedirectResponse(url=f"/login?next={next_q}&msg={msg_q}", status_code=302)
    if requires_2fa and (not twofa_enabled):
        if path not in {"/2fa/setup", "/logout"}:
            if path.startswith("/api/"):
                return JSONResponse({"ok": False, "error": "2fa_setup_required"}, status_code=403)
            return RedirectResponse(url="/2fa/setup", status_code=302)
    request.state.user_id = int((urow or {}).get("id") or 0)
    request.state.is_admin = is_adm
    request.state.po_admin = bool((urow or {}).get("po_admin"))
    request.state.allowed_pages = allowed
    request.state.standby_banner = _standby_banner_message()
    request.state.nav_items = _nav_with_published_ports(request, _nav_items_for_request(request))

    if path.startswith("/api/traffic") and not is_adm:
        if "mtr_live" not in allowed and "download_test" not in allowed:
            return _access_denied(request, path)

    pk = _path_to_page_key(path)
    if pk == "users_admin":
        if not is_adm:
            return _access_denied(request, path)
    elif pk and not is_adm and pk not in allowed:
        return _access_denied(request, path)

    if not _edge_allowed_path(path):
        redir = _maybe_cross_service_port_redirect(request, path)
        if redir is not None:
            return redir
        if getattr(request.state, "is_admin", False) and APP_ROLE != "core":
            # Non-core roles: admins may use portable ops paths outside this container's tab subset.
            pass
        elif path == "/":
            landing = {
                "monitoring": "/monitoring",
                "location_sync": "/location-sync",
                "routers": "/routers",
                "backhauls": "/backhauls",
                "edge": "/routers",
            }.get(APP_ROLE, "/")
            return RedirectResponse(url=landing, status_code=302)
        else:
            return _access_denied(request, path)

    response = await call_next(request)

    if came_from_basic:
        try:
            response.set_cookie(
                SESSION_COOKIE_NAME,
                _make_session_token(username),
                httponly=True,
                samesite="lax",
                secure=_effective_cookie_secure(request),
                path="/",
            )
        except Exception:
            pass

    return response


@app.middleware("http")
async def force_https_middleware(request: Request, call_next):
    if _should_force_https_redirect(request):
        return RedirectResponse(url=_https_url_for_request(request), status_code=301)
    return await call_next(request)


LOGIN_PAGE_HTML = """<!doctype html>
<html lang="en" data-theme="light">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Business Management Platform</title>
    <link rel="stylesheet" href="/static/style.css?v=20260513-login-brand" />
    <script>
      (function() {
        try {
          var t = localStorage.getItem('theme');
          if (t === 'dark' || t === 'light') document.documentElement.setAttribute('data-theme', t);
        } catch (e) {}
      })();
    </script>
  </head>
  <body>
    <button class="theme-toggle" id="themeToggle" type="button" aria-label="Toggle theme">🌙</button>

    <div class="wrap">
      <div class="container">
        <div class="login-brand">
          <img
            src="/static/Wibernet-logo.png"
            alt="Wibernet"
            class="home-hero__logo"
            width="280"
            height="auto"
            decoding="async"
          />
          <h1 class="title login-brand__title">Business Management Platform</h1>
        </div>

        <div class="card">
          <form method="post" action="/login">
            <input type="hidden" name="next" value="{{NEXT}}" />
            <label for="u">Username</label>
            <input id="u" name="username" autocomplete="username" required />
            <label for="p">Password</label>
            <input id="p" name="password" type="password" autocomplete="current-password" required />
            <button class="btn" type="submit">Sign in</button>
            {{MSG}}
          </form>
        </div>
      </div>
    </div>

    <script>
      (function() {
        var btn = document.getElementById('themeToggle');
        function applyLabel(theme) { btn.textContent = theme === 'dark' ? '☀️' : '🌙'; }
        function getTheme() {
          var t = document.documentElement.getAttribute('data-theme');
          return (t === 'dark' || t === 'light') ? t : 'light';
        }
        applyLabel(getTheme());
        btn.addEventListener('click', function() {
          var next = getTheme() === 'dark' ? 'light' : 'dark';
          document.documentElement.setAttribute('data-theme', next);
          try { localStorage.setItem('theme', next); } catch (e) {}
          applyLabel(next);
        });
      })();
    </script>
  </body>
</html>
"""

LOGIN_2FA_PAGE_HTML = """<!doctype html>
<html lang="en" data-theme="light"><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" /><title>MTR 2FA</title><link rel="stylesheet" href="/static/style.css" /></head>
<body><div class="wrap"><div class="container"><h1 class="title">Two-Factor Verification</h1><div class="card">
<form method="post" action="/login/2fa">
<input type="hidden" name="next" value="{{NEXT}}" />
<label for="c">6-digit code / backup code</label>
<input id="c" name="code" autocomplete="one-time-code" required />
<button class="btn" type="submit">Verify</button>
{{MSG}}
</form></div></div></div></body></html>"""

SETUP_2FA_PAGE_HTML = """<!doctype html>
<html lang="en" data-theme="light"><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" /><title>Setup 2FA</title><link rel="stylesheet" href="/static/style.css" /></head>
<body><div class="wrap"><div class="container"><h1 class="title">Setup Two-Factor Authentication</h1><div class="card">
<div style="display:flex;justify-content:center;margin:8px 0 14px;"><img src="{{QR_DATA_URI}}" alt="2FA QR code" style="max-width:220px;max-height:220px;border:1px solid var(--border);padding:6px;border-radius:8px;background:white;" /></div>
<p class="hint">Add this secret to your authenticator app: <code class="mono">{{SECRET}}</code></p>
<p class="hint">Or use otpauth URL: <code class="mono">{{OTPAUTH}}</code></p>
<form method="post" action="/2fa/setup">
<label for="c">Enter 6-digit verification code</label>
<input id="c" name="code" autocomplete="one-time-code" required />
<button class="btn" type="submit">Enable 2FA</button>
{{MSG}}
</form></div></div></div></body></html>"""


def _make_qr_data_uri(text: str) -> str:
    try:
        import qrcode
        img = qrcode.make(text or "")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")
    except Exception:
        fallback_svg = (
            "<svg xmlns='http://www.w3.org/2000/svg' width='220' height='220'>"
            "<rect width='100%' height='100%' fill='white' stroke='#d0d7de'/>"
            "<text x='50%' y='48%' dominant-baseline='middle' text-anchor='middle' "
            "font-family='Arial, sans-serif' font-size='14' fill='#444'>QR unavailable</text>"
            "<text x='50%' y='58%' dominant-baseline='middle' text-anchor='middle' "
            "font-family='Arial, sans-serif' font-size='11' fill='#666'>Use manual secret below</text>"
            "</svg>"
        )
        return "data:image/svg+xml;base64," + base64.b64encode(fallback_svg.encode("utf-8")).decode("ascii")


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, next: str = "/"):
    msg = request.query_params.get("msg", "")
    msg_html = f'<div class="err">{html.escape(msg)}</div>' if msg else ""
    safe_next = safe_redirect_path(next, "/")
    page = LOGIN_PAGE_HTML.replace("{{NEXT}}", html.escape(safe_next, quote=True)).replace("{{MSG}}", msg_html)
    return HTMLResponse(page)


@app.post("/login")
async def login_submit(request: Request):
    body = (await request.body()).decode("utf-8", errors="ignore")
    form = parse_qs(body)
    username = (form.get("username", [""])[0] or "").strip()
    password = form.get("password", [""])[0] or ""
    # Product rule: always land on Home after successful login.
    next_url = "/"
    _lip = audit_log.client_ip_from_request(request)
    _lua = (request.headers.get("user-agent") or "")[:512]

    if verify_user_password(username, password):
        row = auth_users.get_user_by_username(username) or {}
        uid = int(row["id"]) if row.get("id") is not None else None
        if bool(row.get("twofa_enabled")):
            audit_log.record(
                event_type="auth.login.password_ok_pending_2fa",
                actor_username=username,
                actor_user_id=uid,
                success=True,
                target_type="user",
                target_id=username,
                detail={},
                client_ip=_lip,
                user_agent=_lua,
                request_path="/login",
            )
            resp = RedirectResponse(url=f"/login/2fa?next={quote(next_url)}", status_code=302)
            resp.set_cookie(
                PENDING_2FA_COOKIE_NAME,
                _make_pending_2fa_token(username, next_url),
                httponly=True,
                samesite="lax",
                secure=_effective_cookie_secure(request),
                path="/",
            )
            return resp
        if _user_requires_2fa(username, row):
            audit_log.record(
                event_type="auth.login.password_ok_pending_2fa_setup",
                actor_username=username,
                actor_user_id=uid,
                success=True,
                target_type="user",
                target_id=username,
                detail={},
                client_ip=_lip,
                user_agent=_lua,
                request_path="/login",
            )
            resp = RedirectResponse(url=f"/2fa/setup?next={quote(next_url)}", status_code=302)
            resp.set_cookie(
                PENDING_2FA_COOKIE_NAME,
                _make_pending_2fa_token(username, next_url),
                httponly=True,
                samesite="lax",
                secure=_effective_cookie_secure(request),
                path="/",
            )
            return resp
        audit_log.record(
            event_type="auth.login.success",
            actor_username=username,
            actor_user_id=uid,
            success=True,
            target_type="user",
            target_id=username,
            detail={"via": "password_only"},
            client_ip=_lip,
            user_agent=_lua,
            request_path="/login",
        )
        resp = RedirectResponse(url=next_url, status_code=302)
        resp.set_cookie(
            SESSION_COOKIE_NAME,
            _make_session_token(username),
            httponly=True,
            samesite="lax",
            secure=_effective_cookie_secure(request),
            path="/",
        )
        return resp

    audit_log.record(
        event_type="auth.login.failure",
        actor_username=username,
        success=False,
        target_type="user",
        target_id=username,
        detail={"reason": "invalid_credentials"},
        client_ip=_lip,
        user_agent=_lua,
        request_path="/login",
    )
    return RedirectResponse(url=f"/login?msg=Invalid%20credentials&next={quote(next_url)}", status_code=302)


@app.get("/login/2fa", response_class=HTMLResponse)
async def login_2fa_page(request: Request, next: str = "/"):
    token = request.cookies.get(PENDING_2FA_COOKIE_NAME, "")
    pending = _verify_pending_2fa_token(token) if token else None
    if not pending:
        return RedirectResponse(url="/login?msg=Session%20expired", status_code=302)
    safe_next = safe_redirect_path(next or pending.get("next") or "/", "/")
    msg = request.query_params.get("msg", "")
    msg_html = f'<div class="err">{html.escape(msg)}</div>' if msg else ""
    page = LOGIN_2FA_PAGE_HTML.replace("{{NEXT}}", html.escape(safe_next, quote=True)).replace("{{MSG}}", msg_html)
    return HTMLResponse(page)


@app.post("/login/2fa")
async def login_2fa_submit(request: Request):
    token = request.cookies.get(PENDING_2FA_COOKIE_NAME, "")
    pending = _verify_pending_2fa_token(token) if token else None
    if not pending:
        return RedirectResponse(url="/login?msg=Session%20expired", status_code=302)
    body = (await request.body()).decode("utf-8", errors="ignore")
    form = parse_qs(body)
    code = (form.get("code", [""])[0] or "").strip()
    # Product rule: always land on Home after successful login.
    next_url = "/"
    row = auth_users.get_user_by_username(str(pending.get("username") or "")) or {}
    ok = auth_users.verify_totp_code(str(row.get("twofa_secret") or ""), code, window=1)
    if not ok:
        ok = auth_users.consume_user_backup_code(int(row.get("id") or 0), code)
    if not ok:
        audit_log.record(
            event_type="auth.2fa.failure",
            actor_username=str(row.get("username") or ""),
            actor_user_id=int(row["id"]) if row.get("id") is not None else None,
            success=False,
            target_type="user",
            target_id=str(row.get("username") or ""),
            detail={},
            client_ip=audit_log.client_ip_from_request(request),
            user_agent=(request.headers.get("user-agent") or "")[:512],
            request_path="/login/2fa",
        )
        return RedirectResponse(url=f"/login/2fa?msg=Invalid%20code&next={quote(next_url)}", status_code=302)
    audit_log.record(
        event_type="auth.login.success",
        actor_username=str(row.get("username") or ""),
        actor_user_id=int(row["id"]) if row.get("id") is not None else None,
        success=True,
        target_type="user",
        target_id=str(row.get("username") or ""),
        detail={"via": "totp"},
        client_ip=audit_log.client_ip_from_request(request),
        user_agent=(request.headers.get("user-agent") or "")[:512],
        request_path="/login/2fa",
    )
    resp = RedirectResponse(url=next_url, status_code=302)
    resp.set_cookie(
        SESSION_COOKIE_NAME,
        _make_session_token(str(row.get("username") or "")),
        httponly=True,
        samesite="lax",
        secure=_effective_cookie_secure(request),
        path="/",
    )
    resp.delete_cookie(
        PENDING_2FA_COOKIE_NAME,
        path="/",
        secure=_effective_cookie_secure(request),
        httponly=True,
        samesite="lax",
    )
    return resp


@app.get("/2fa/setup", response_class=HTMLResponse)
async def setup_2fa_page(request: Request, next: str = "/"):
    token = request.cookies.get(PENDING_2FA_COOKIE_NAME, "")
    pending = _verify_pending_2fa_token(token) if token else None
    username = str((pending or {}).get("username") or "")
    if not username:
        username = str(getattr(request.state, "username", "") or "")
    if not username:
        return RedirectResponse(url="/login?msg=Sign%20in%20first", status_code=302)
    row = auth_users.get_user_by_username(username) or {}
    if bool(row.get("twofa_enabled")):
        return RedirectResponse(url=safe_redirect_path(next or "/", "/"), status_code=302)
    secret = str(row.get("twofa_temp_secret") or "")
    if not secret:
        secret = auth_users.generate_totp_secret()
        auth_users.set_user_twofa_temp_secret(int(row.get("id") or 0), secret)
    issuer = quote("MTR Web")
    label = quote(username)
    otpauth = f"otpauth://totp/{issuer}:{label}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
    msg = request.query_params.get("msg", "")
    msg_html = f'<div class="err">{html.escape(msg)}</div>' if msg else ""
    page = (
        SETUP_2FA_PAGE_HTML.replace("{{SECRET}}", html.escape(secret))
        .replace("{{OTPAUTH}}", html.escape(otpauth))
        .replace("{{QR_DATA_URI}}", _make_qr_data_uri(otpauth))
        .replace("{{MSG}}", msg_html)
    )
    return HTMLResponse(page)


@app.post("/2fa/setup")
async def setup_2fa_submit(request: Request):
    token = request.cookies.get(PENDING_2FA_COOKIE_NAME, "")
    pending = _verify_pending_2fa_token(token) if token else None
    username = str((pending or {}).get("username") or "")
    if not username:
        username = str(getattr(request.state, "username", "") or "")
    if not username:
        return RedirectResponse(url="/login?msg=Sign%20in%20first", status_code=302)
    row = auth_users.get_user_by_username(username) or {}
    secret = str(row.get("twofa_temp_secret") or "")
    if not secret:
        return RedirectResponse(url="/2fa/setup?msg=Setup%20secret%20missing", status_code=302)
    body = (await request.body()).decode("utf-8", errors="ignore")
    form = parse_qs(body)
    code = (form.get("code", [""])[0] or "").strip()
    if not auth_users.verify_totp_code(secret, code, window=1):
        return RedirectResponse(url="/2fa/setup?msg=Invalid%20verification%20code", status_code=302)
    backup_codes = [secrets.token_hex(4).upper() for _ in range(8)]
    auth_users.enable_user_twofa(int(row.get("id") or 0), secret, backup_codes)
    audit_log.record(
        event_type="auth.2fa.enrolled",
        actor_username=username,
        actor_user_id=int(row.get("id") or 0) or None,
        success=True,
        target_type="user",
        target_id=username,
        detail={"backup_codes_issued": len(backup_codes)},
        client_ip=audit_log.client_ip_from_request(request),
        user_agent=(request.headers.get("user-agent") or "")[:512],
        request_path="/2fa/setup",
    )
    # Product rule: always land on Home after sign-in / 2FA enrollment.
    next_url = "/"
    codes_html = "".join(f"<li><code class='mono'>{html.escape(c)}</code></li>" for c in backup_codes)
    done_html = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8' /><meta name='viewport' content='width=device-width, initial-scale=1' />"
        "<title>2FA Enabled</title><link rel='stylesheet' href='/static/style.css' /></head><body>"
        "<div class='wrap'><div class='container'><h1 class='title'>2FA Enabled</h1><div class='card'>"
        "<p class='hint'>Save these backup codes in a safe place. Each code can be used once.</p>"
        f"<ul>{codes_html}</ul>"
        f"<p><a class='btn' href='{html.escape(next_url, quote=True)}'>Continue</a></p>"
        "</div></div></div></body></html>"
    )
    resp = HTMLResponse(done_html)
    resp.set_cookie(
        SESSION_COOKIE_NAME,
        _make_session_token(username),
        httponly=True,
        samesite="lax",
        secure=_effective_cookie_secure(request),
        path="/",
    )
    resp.delete_cookie(
        PENDING_2FA_COOKIE_NAME,
        path="/",
        secure=_effective_cookie_secure(request),
        httponly=True,
        samesite="lax",
    )
    return resp


@app.post("/logout")
async def logout_post(request: Request):
    return await logout(request)

@app.get("/logout")
async def logout(request: Request):
    tok = request.cookies.get(SESSION_COOKIE_NAME, "")
    sess_user = _verify_session_token(tok) if tok else None
    if sess_user:
        row = auth_users.get_user_by_username(sess_user) or {}
        audit_log.record(
            event_type="auth.logout",
            actor_username=sess_user,
            actor_user_id=int(row["id"]) if row.get("id") is not None else None,
            success=True,
            target_type="session",
            target_id=sess_user,
            detail={},
            client_ip=audit_log.client_ip_from_request(request),
            user_agent=(request.headers.get("user-agent") or "")[:512],
            request_path="/logout",
        )
    resp = RedirectResponse(url="/login?msg=Logged%20out", status_code=302)
    resp.delete_cookie(
        SESSION_COOKIE_NAME,
        path="/",
        secure=_effective_cookie_secure(request),
        httponly=True,
        samesite="lax",
    )
    resp.delete_cookie(
        PENDING_2FA_COOKIE_NAME,
        path="/",
        secure=_effective_cookie_secure(request),
        httponly=True,
        samesite="lax",
    )
    return resp


# -------------------- Field Tech: Splynx Customer Info --------------------
# This integration is optional and disabled unless SPLYNX_API_BASE, SPLYNX_API_KEY and SPLYNX_API_SECRET are set.
# We intentionally keep credentials server-side and only return the minimum info needed by the Field Tech tab.

SPLYNX_API_BASE = os.getenv("SPLYNX_API_BASE", "").strip().rstrip("/")
SPLYNX_API_KEY = os.getenv("SPLYNX_API_KEY", "").strip()
SPLYNX_API_SECRET = os.getenv("SPLYNX_API_SECRET", "").strip()
SPLYNX_TIMEOUT_SEC = float(os.getenv("SPLYNX_TIMEOUT_SEC", "10").strip() or "10")

def _splynx_enabled() -> bool:
    return bool(SPLYNX_API_BASE and SPLYNX_API_KEY and SPLYNX_API_SECRET)

def _splynx_auth_header_basic() -> str:
    # Many deployments use "Basic base64(key:secret)" for API access (see community examples).
    token = base64.b64encode(f"{SPLYNX_API_KEY}:{SPLYNX_API_SECRET}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"

def _http_get_json(url: str, headers: Dict[str, str], timeout: float) -> Any:
    import json as _json
    import urllib.request
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read().decode("utf-8", errors="replace")
        return _json.loads(data) if data else None

def splynx_get(path: str, params: Optional[Dict[str, Any]] = None) -> Any:
    if not _splynx_enabled():
        raise HTTPException(status_code=503, detail="Splynx integration not configured on this server.")
    from urllib.parse import urlencode
    import urllib.error
    p = path.lstrip("/")
    url = f"{SPLYNX_API_BASE}/{p}"
    if params:
        url = f"{url}?{urlencode(params, doseq=True)}"
    headers = {
        "Authorization": _splynx_auth_header_basic(),
        "Accept": "application/json",
        "User-Agent": "MTR-Web-UI",
    }
    try:
        return _http_get_json(url, headers=headers, timeout=SPLYNX_TIMEOUT_SEC)
    except urllib.error.HTTPError as e:
        # Preserve upstream HTTP status (e.g. 404 endpoint mismatch, 401 auth).
        detail = f"Splynx HTTP {getattr(e, 'code', '?')} for {p}"
        try:
            body = e.read().decode("utf-8", errors="replace").strip()
            if body:
                detail = f"{detail}: {body[:400]}"
        except Exception:
            pass
        raise HTTPException(status_code=int(getattr(e, "code", 502) or 502), detail=detail)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Splynx request failed: {e}")


def _splynx_get_first_ok(candidates: List[Tuple[str, Optional[Dict[str, Any]]]]) -> Any:
    """
    Try candidate Splynx GET endpoints in order.
    Continue on 404s (common across different Splynx versions/path layouts),
    but fail fast on auth/transport errors.
    """
    last_404: Optional[str] = None
    for path, params in candidates:
        try:
            return splynx_get(path, params=params)
        except HTTPException as e:
            if int(e.status_code) == 404:
                last_404 = str(e.detail)
                continue
            raise
    raise HTTPException(
        status_code=404,
        detail=last_404 or "Customer not found in Splynx."
    )


def _pick_customer_from_payload(payload: Any, customer_id: int) -> Optional[Dict[str, Any]]:
    """Normalize various Splynx customer payload shapes to one customer dict."""
    if isinstance(payload, dict):
        # Direct customer object.
        try:
            pid = int(payload.get("id")) if payload.get("id") is not None else None
        except Exception:
            pid = None
        if pid == int(customer_id):
            return payload
        # Some endpoints wrap lists in data/items.
        for key in ("data", "items", "customers", "rows"):
            if key in payload:
                return _pick_customer_from_payload(payload.get(key), customer_id)
        return None
    if isinstance(payload, list):
        for row in payload:
            if not isinstance(row, dict):
                continue
            try:
                rid = int(row.get("id")) if row.get("id") is not None else None
            except Exception:
                rid = None
            if rid == int(customer_id):
                return row
    return None


def _splynx_get_customer_by_id(customer_id: int) -> Dict[str, Any]:
    """
    Resolve one customer with minimal latency.
    Prefer filter/list endpoints first so missing IDs return quickly as "not found"
    instead of waiting on slower per-id routes.
    """
    fast_candidates: List[Tuple[str, Optional[Dict[str, Any]]]] = [
        ("admin/customers/customer", {"id": customer_id}),
        ("admin/customers/customer", {"customer_id": customer_id}),
        ("admin/customers/customer", {"main_attributes[id]": customer_id}),
    ]
    for path, params in fast_candidates:
        try:
            payload = splynx_get(path, params=params)
        except HTTPException as e:
            if int(e.status_code) in (404,):
                continue
            # If one variant fails (timeout/5xx), try the next variant before failing.
            continue
        picked = _pick_customer_from_payload(payload, customer_id)
        if picked:
            return picked
        # Endpoint worked but did not return this id -> definitive not found.
        raise HTTPException(status_code=404, detail=f"Customer {customer_id} not found in Splynx.")

    # Fallbacks for older/newer path shapes.
    fallback_payload = _splynx_get_first_ok(
        [
            (f"admin/customers/customer/{customer_id}", None),
            (f"admin/customers/{customer_id}", None),
        ]
    )
    picked = _pick_customer_from_payload(fallback_payload, customer_id)
    if picked:
        return picked
    raise HTTPException(status_code=404, detail=f"Customer {customer_id} not found in Splynx.")
# ---------------------------------------------------------------------------

# -------------------- Field Tech: Location IPv4 availability helpers --------------------
# Goal: Given a customer_id, derive location_id and list free IPv4 addresses in 172.16.0.0/16
# based on configured "Network IPv4" ranges for that location.

from ipaddress import ip_network, IPv4Network

FIELDTECH_PRIVATE_SUPERNET = ip_network(os.getenv("FIELDTECH_PRIVATE_SUPERNET", "172.16.0.0/16"))

# Candidate endpoints differ between Splynx versions/customizations; we try a short list.
SPLYNX_IPV4_NETWORK_ENDPOINTS = [
    p.strip().lstrip("/") for p in os.getenv(
        "SPLYNX_IPV4_NETWORK_ENDPOINTS",
        "admin/network/ipv4,admin/networking/ipv4,admin/ip/ipv4,admin/network/ipv4-networks,admin/networking/ipv4-networks"
    ).split(",") if p.strip()
]

SPLYNX_SERVICES_ENDPOINTS = [
    p.strip().lstrip("/") for p in os.getenv(
        "SPLYNX_INTERNET_SERVICES_ENDPOINTS",
        "admin/customers/internet-services,admin/customers/services/internet"
    ).split(",") if p.strip()
]

FIELDTECH_MAX_IP_OPTIONS = int(os.getenv("FIELDTECH_MAX_IP_OPTIONS", "5000"))

def _safe_int(v: Any) -> Optional[int]:
    try:
        if v is None:
            return None
        if isinstance(v, bool):
            return None
        return int(v)
    except Exception:
        return None

def _extract_location_id(customer: Dict[str, Any], service: Optional[Dict[str, Any]]) -> Optional[int]:
    # Common field names seen in Splynx installations
    candidates = [
        customer.get("location_id"),
        customer.get("locationId"),
        customer.get("location"),
        customer.get("locationID"),
    ]
    if service and isinstance(service, dict):
        candidates.extend([
            service.get("location_id"),
            service.get("locationId"),
            service.get("location"),
            service.get("locationID"),
        ])
    for c in candidates:
        li = _safe_int(c)
        if li and li > 0:
            return li
    return None

def _parse_ipv4_ranges(value: Any) -> List[IPv4Network]:
    # Accept:
    # - CIDR strings: "172.16.10.0/24"
    # - multiple CIDRs separated by comma/space/newline
    # - lists of strings
    nets: List[IPv4Network] = []
    parts: List[str] = []
    if isinstance(value, str):
        parts = re.split(r"[\s,;]+", value.strip())
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                parts.extend(re.split(r"[\s,;]+", item.strip()))
    for p in parts:
        if not p:
            continue
        try:
            n = ip_network(p.strip(), strict=False)
            if isinstance(n, IPv4Network):
                nets.append(n)
        except Exception:
            continue
    return nets

def _get_record_location_id(rec: Dict[str, Any]) -> Optional[int]:
    for k in ("location_id", "locationId", "location", "locationID"):
        li = _safe_int(rec.get(k))
        if li and li > 0:
            return li
    return None

def splynx_list_location_ipv4_networks(location_id: int) -> Tuple[List[IPv4Network], Optional[str]]:
    """Return IPv4 networks configured for a location, filtered to FIELDTECH_PRIVATE_SUPERNET.
    Also returns an optional hint string for UI/debugging."""
    last_err: Optional[str] = None
    for ep in SPLYNX_IPV4_NETWORK_ENDPOINTS:
        try:
            data = splynx_get(ep) or []
            if not isinstance(data, list):
                # Some endpoints return dicts with 'data' or similar
                if isinstance(data, dict):
                    data = data.get("data") or data.get("items") or []
            if not isinstance(data, list):
                continue

            nets: List[IPv4Network] = []
            for rec in data:
                if not isinstance(rec, dict):
                    continue
                if _get_record_location_id(rec) != location_id:
                    continue

                # Candidate field names for network ranges
                rng = (
                    rec.get("network_ipv4")
                    or rec.get("network")
                    or rec.get("ipv4")
                    or rec.get("range")
                    or rec.get("cidr")
                    or rec.get("net")
                )
                for n in _parse_ipv4_ranges(rng):
                    # Only ranges that overlap our private supernet
                    try:
                        if n.overlaps(FIELDTECH_PRIVATE_SUPERNET):
                            nets.append(n)
                    except Exception:
                        continue

            # De-duplicate
            uniq = []
            seen = set()
            for n in nets:
                s = str(n)
                if s in seen:
                    continue
                seen.add(s)
                uniq.append(n)
            return uniq, None
        except HTTPException as he:
            last_err = str(he.detail)
        except Exception as e:
            last_err = str(e)

    return [], (last_err or "No IPv4 network endpoint returned data.")

def splynx_list_used_ipv4_by_location(location_id: int) -> Tuple[set, Optional[str]]:
    """Try to list internet services for the location and return used IPv4 set."""
    last_err: Optional[str] = None
    for ep in SPLYNX_SERVICES_ENDPOINTS:
        # Prefer server-side filtering by location_id where supported
        for params in ({"location_id": location_id}, {"locationId": location_id}, None):
            try:
                data = splynx_get(ep, params=params) if params else splynx_get(ep)
                data = data or []
                if not isinstance(data, list):
                    if isinstance(data, dict):
                        data = data.get("data") or data.get("items") or []
                if not isinstance(data, list):
                    continue

                used = set()
                for s in data:
                    if not isinstance(s, dict):
                        continue
                    # If server didn't filter, double-check record location
                    rec_li = _safe_int(s.get("location_id") or s.get("locationId") or s.get("location"))
                    if rec_li and rec_li != location_id and params is None:
                        continue
                    ip = s.get("ipv4") or s.get("ip") or s.get("ip_address")
                    if isinstance(ip, str) and ip.strip():
                        used.add(ip.strip())
                return used, None
            except HTTPException as he:
                last_err = str(he.detail)
            except Exception as e:
                last_err = str(e)

    return set(), (last_err or "Could not load used IPv4 services for this location.")
# ---------------------------------------------------------------------------


# -------------------- Download Test + Jinja HTML pages (modular routers) --------------------
from traffic_routes import router as download_test_router
from routes.web_html import router as web_html_router

app.include_router(download_test_router)
app.include_router(web_html_router)


@app.get("/api/routers")
def api_routers_list():
    return {"ok": True, "routers": edge_routers.list_routers()}


@app.post("/api/routers")
def api_routers_add(payload: Dict[str, Any] = Body(...)):
    p = payload or {}
    location_raw = p.get("location_id")
    host = p.get("router_host") or p.get("ip") or p.get("host")
    ssh_user = p.get("ssh_user") or p.get("user")
    ssh_password = p.get("ssh_password") or p.get("password")
    ssh_port = p.get("ssh_port")
    try:
        location_id = int(location_raw)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid or missing location_id")
    try:
        rid = edge_routers.add_router(
            location_id,
            str(host or ""),
            str(ssh_user or ""),
            str(ssh_password if ssh_password is not None else ""),
            ssh_port,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True, "id": rid}


@app.post("/api/routers/import")
def api_routers_import(payload: Dict[str, Any] = Body(...)):
    """Bulk-create routers from multi-line text (see edge_routers._parse_router_import_row)."""
    p = payload or {}
    location_raw = p.get("location_id")
    text = p.get("text")
    if text is None:
        text = ""
    default_location_id = None
    if location_raw is not None and location_raw != "":
        try:
            default_location_id = int(location_raw)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="Invalid location_id")
    ssh_user = p.get("ssh_user")
    ssh_password = p.get("ssh_password")
    ssh_port_raw = p.get("ssh_port")
    ssh_port = None
    if ssh_port_raw is not None and ssh_port_raw != "":
        try:
            ssh_port = int(ssh_port_raw)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="Invalid ssh_port")
    try:
        result = edge_routers.import_routers_bulk(
            str(text),
            str(ssh_user or ""),
            str(ssh_password if ssh_password is not None else ""),
            ssh_port,
            default_location_id,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True, "import": result}


@app.delete("/api/routers/{router_id}")
def api_routers_delete(router_id: int):
    if not edge_routers.delete_router(router_id):
        raise HTTPException(status_code=404, detail="Not found")
    return {"ok": True}


@app.get("/api/backhauls")
def api_backhauls_list():
    return {"ok": True, "backhauls": backhauls.list_backhauls()}


@app.get("/api/backhauls/overview")
def api_backhauls_overview():
    en = monitoring.is_monitoring_sampling_enabled()
    return {
        "ok": True,
        "live_probing_enabled": en,
        "sampling_enabled": en,
        "backhauls": backhauls.overview_live(),
    }


@app.get("/api/backhauls/routers/{router_id}/interfaces")
def api_backhauls_router_interfaces(router_id: int):
    en = monitoring.is_monitoring_sampling_enabled()
    items, err = backhauls.list_router_interfaces_filtered(router_id)
    return {"ok": True, "live_probing_enabled": en, "sampling_enabled": en, "interfaces": items, "warning": err}


@app.post("/api/backhauls")
def api_backhauls_add(payload: Dict[str, Any] = Body(...)):
    p = payload or {}
    try:
        bid = backhauls.add_backhaul(
            str(p.get("name") or ""),
            int(p.get("router_a_id")),
            int(p.get("router_b_id")),
            str(p.get("iface_a") or ""),
            str(p.get("iface_b") or ""),
            p.get("max_mbps"),
        )
    except (TypeError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True, "id": bid}


@app.patch("/api/backhauls/{backhaul_id}")
def api_backhauls_patch(backhaul_id: int, payload: Dict[str, Any] = Body(...)):
    p = payload or {}
    if p.get("max_mbps") is None:
        raise HTTPException(status_code=400, detail="max_mbps required")
    try:
        ok = backhauls.update_max_mbps(backhaul_id, p.get("max_mbps"))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not ok:
        raise HTTPException(status_code=404, detail="Not found")
    return {"ok": True}


@app.delete("/api/backhauls/{backhaul_id}")
def api_backhauls_delete(backhaul_id: int):
    if not backhauls.delete_backhaul(backhaul_id):
        raise HTTPException(status_code=404, detail="Not found")
    return {"ok": True}


@app.get("/api/backhauls/radios")
def api_backhauls_radios(live: bool = True):
    en = monitoring.is_monitoring_sampling_enabled()
    if live:
        return {
            "ok": True,
            "live_probing_enabled": en,
            "sampling_enabled": en,
            "radios": backhauls.radios_overview_live(),
        }
    return {"ok": True, "live_probing_enabled": en, "sampling_enabled": en, "radios": backhauls.list_radios()}


@app.post("/api/backhauls/radios")
def api_backhauls_radios_add(payload: Dict[str, Any] = Body(...)):
    try:
        rid = backhauls.add_radio(payload or {})
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True, "id": rid}


@app.patch("/api/backhauls/radios/{radio_id}")
def api_backhauls_radio_patch(radio_id: int, payload: Dict[str, Any] = Body(...)):
    p = payload or {}
    if p.get("name") is None:
        raise HTTPException(status_code=400, detail="name required")
    try:
        ok = backhauls.update_radio_name(radio_id, str(p.get("name") or ""))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not ok:
        raise HTTPException(status_code=404, detail="Not found")
    return {"ok": True}


@app.post("/api/backhauls/radios/{radio_id}/oids")
def api_backhauls_radio_oids_append(radio_id: int, payload: Dict[str, Any] = Body(...)):
    try:
        n = backhauls.append_radio_oids(radio_id, (payload or {}).get("oids"))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True, "added": n}


@app.patch("/api/backhauls/radios/{radio_id}/oids/{row_id}")
def api_backhauls_radio_oid_label_patch(radio_id: int, row_id: int, payload: Dict[str, Any] = Body(...)):
    try:
        ok = backhauls.update_radio_oid_label(radio_id, row_id, str((payload or {}).get("label") or ""))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not ok:
        raise HTTPException(status_code=404, detail="Not found")
    return {"ok": True}


@app.delete("/api/backhauls/radios/{radio_id}/oids/{row_id}")
def api_backhauls_radio_oid_delete(radio_id: int, row_id: int):
    if not backhauls.delete_radio_oid(radio_id, row_id):
        raise HTTPException(status_code=404, detail="OID row not found")
    return {"ok": True}


@app.post("/api/backhauls/radios/snmp-ping")
def api_backhauls_snmp_ping(payload: Dict[str, Any] = Body(...)):
    """Quick snmpget sysDescr from server — confirms UI uses same network path as manual snmpwalk."""
    try:
        out = backhauls.snmp_ping(payload or {})
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True, **out}


@app.post("/api/backhauls/radios/snmp-walk")
def api_backhauls_radios_snmp_walk(payload: Dict[str, Any] = Body(...)):
    """Starts walk in a background thread; client polls GET snmp-walk-jobs/{job_id} (short requests avoid nginx 504)."""
    try:
        job_id = backhauls.snmp_walk_job_submit(payload or {})
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True, "job_id": job_id}


@app.get("/api/backhauls/radios/snmp-walk-jobs/{job_id}")
def api_backhauls_snmp_walk_job(job_id: str):
    try:
        st = backhauls.snmp_walk_job_status(job_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return {"ok": True, **st}


@app.get("/api/backhauls/radios/snmp-mibs")
def api_backhauls_snmp_mibs_list():
    flat, detail = backhauls.scan_uploaded_mibs_enterprise_roots()
    return {
        "ok": True,
        "mibs": backhauls.list_snmp_user_mibs(),
        "dir": backhauls.snmp_user_mib_dir_resolved(),
        "suggested_base_oids": flat,
        "suggested_base_oids_by_file": detail,
    }


@app.post("/api/backhauls/radios/snmp-mibs")
async def api_backhauls_snmp_mibs_upload(request: Request, upload: UploadFile = File(...)):
    require_admin(request)
    blob = await upload.read()
    try:
        meta = backhauls.save_snmp_user_mib(upload.filename or "vendor.mib", blob)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    flat, detail = backhauls.scan_uploaded_mibs_enterprise_roots()
    return {
        "ok": True,
        **meta,
        "suggested_base_oids": flat,
        "suggested_base_oids_by_file": detail,
    }


@app.delete("/api/backhauls/radios/snmp-mibs/{name}")
def api_backhauls_snmp_mibs_delete(request: Request, name: str):
    require_admin(request)
    try:
        ok = backhauls.delete_snmp_user_mib(name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not ok:
        raise HTTPException(status_code=404, detail="MIB file not found")
    return {"ok": True}


@app.delete("/api/backhauls/radios/{radio_id}")
def api_backhauls_radios_delete(radio_id: int):
    if not backhauls.delete_radio(radio_id):
        raise HTTPException(status_code=404, detail="Not found")
    return {"ok": True}


@app.get("/api/backhauls/radios/{radio_id}/history")
def api_backhauls_radio_history(radio_id: int, hours: float = 12.0):
    if hours < 0.1 or hours > 168:
        raise HTTPException(status_code=400, detail="hours must be between 0.1 and 168")
    data = backhauls.fetch_radio_history(int(radio_id), hours=hours)
    if data is None:
        raise HTTPException(status_code=404, detail="Radio not found")
    return {"ok": True, "hours": hours, **data}


@app.get("/api/location-sync/status")
def api_location_sync_status():
    return {"ok": True, **location_sync.get_status()}


@app.get("/api/location-sync/customers")
def api_location_sync_customers(
    offset: int = 0,
    limit: int = 500,
    search: str = "",
):
    rows, total = location_sync.list_cached(
        offset=offset,
        limit=limit,
        search=search or None,
    )
    return {
        "ok": True,
        "customers": rows,
        "total": total,
        "offset": offset,
        "limit": limit,
    }


@app.get("/api/location-sync/directory")
def api_location_sync_directory(
    offset: int = 0,
    limit: int = 200,
    search: str = "",
):
    rows, total = location_sync.list_customer_directory(
        offset=offset,
        limit=limit,
        search=search or None,
    )
    return {
        "ok": True,
        "customers": rows,
        "total": total,
        "offset": offset,
        "limit": limit,
    }


@app.get("/api/location-sync/directory/{customer_id}")
def api_location_sync_directory_customer(customer_id: int):
    row = location_sync.get_cached_customer(int(customer_id))
    if not row:
        raise HTTPException(status_code=404, detail="Customer not found in Location Sync cache")
    return {"ok": True, "customer": row}


@app.post("/api/location-sync/run")
async def api_location_sync_run():
    if not _splynx_enabled():
        raise HTTPException(
            status_code=503,
            detail="Splynx integration not configured on this server.",
        )
    loop = asyncio.get_running_loop()
    ok, msg = await loop.run_in_executor(
        None,
        lambda: location_sync.run_full_sync(splynx_get),
    )
    return {"ok": ok, "message": msg, "detail": msg}


@app.get("/api/location-sync/cross-ref/vendors")
def api_location_sync_cross_ref_vendors():
    return {"ok": True, "vendors": location_cross_ref.list_vendors()}


@app.post("/api/location-sync/cross-ref/run")
async def api_location_sync_cross_ref_run(payload: Dict[str, Any] = Body(...)):
    p = payload or {}
    try:
        router_id = int(p.get("router_id"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="router_id required")
    vendor = str(p.get("vendor") or "").strip().lower()
    if not vendor:
        raise HTTPException(status_code=400, detail="vendor required")
    loop = asyncio.get_running_loop()
    ok, msg, stats = await loop.run_in_executor(
        None,
        location_cross_ref.run_cross_reference,
        router_id,
        vendor,
    )
    out: Dict[str, Any] = {"ok": ok, "message": msg, "detail": msg}
    if stats is not None:
        out["stats"] = stats
    return out


@app.post("/api/routers/{router_id}/test-ssh")
async def api_routers_test_ssh(router_id: int):
    loop = asyncio.get_running_loop()
    ok, msg = await loop.run_in_executor(
        None,
        edge_routers.test_ssh_connection,
        int(router_id),
    )
    if ok:
        return {"ok": True, "message": msg}
    return {"ok": False, "detail": msg}


@app.get("/api/stock/sales-log")
def api_stock_sales_log(start: str = "", end: str = "", product: str = ""):
    s = str(start or "").strip()
    e = str(end or "").strip()
    if not s or not e:
        today = datetime.utcnow().date()
        e = today.isoformat()
        s = (today - timedelta(days=29)).isoformat()
    try:
        data = stock_management.sales_log_series(s, e, str(product or ""))
    except ValueError as ex:
        raise HTTPException(status_code=400, detail=str(ex))
    return {"ok": True, "start": s, "end": e, "days": data.get("days", []), "products": data.get("products", [])}


@app.get("/api/whatsapp-signups")
def api_whatsapp_signups_list(q: str = "", page: int = 1, page_size: int = 10):
    p = max(1, int(page))
    ps = max(1, min(50, int(page_size)))
    off = (p - 1) * ps
    total = whatsapp_signups.count_events(search=q or "")
    items = whatsapp_signups.list_events(search=q or "", limit=ps, offset=off)
    return {"ok": True, "items": items, "total": total, "page": p, "page_size": ps}


@app.get("/api/whatsapp-signups/records")
def api_whatsapp_signups_records(request: Request, q: str = "", limit: int = 200, offset: int = 0):
    require_admin(request)
    return {"ok": True, "items": whatsapp_signups.list_records(search=q or "", limit=limit, offset=offset)}


@app.put("/api/whatsapp-signups/records/{record_id}")
def api_whatsapp_signups_record_update(record_id: int, request: Request, payload: Dict[str, Any] = Body(...)):
    require_admin(request)
    p = payload or {}
    try:
        ok = whatsapp_signups.update_record_details(
            record_id=record_id,
            address_line=str(p.get("address_line") or ""),
            suburb=str(p.get("suburb") or ""),
            notes=str(p.get("notes") or ""),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not ok:
        raise HTTPException(status_code=404, detail="Record not found")
    return {"ok": True}


@app.post("/api/whatsapp-signups/records/{record_id}/push-splynx")
def api_whatsapp_signups_record_push_splynx(record_id: int, request: Request):
    require_admin(request)
    try:
        result = whatsapp_signups.push_record_to_splynx(int(record_id))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    audit_log.record_request(
        request,
        "whatsapp.signup.splynx.push",
        target_type="whatsapp_signup_record_id",
        target_id=str(int(record_id)),
        detail={"mode": str(result.get("mode") or ""), "status": str(result.get("status") or "")},
    )
    return {"ok": True, "result": result}


@app.get("/api/whatsapp-signups/records/{record_id}/splynx-pushes")
def api_whatsapp_signups_record_splynx_pushes(record_id: int, request: Request, limit: int = 20):
    require_admin(request)
    return {"ok": True, "items": whatsapp_signups.list_splynx_push_attempts(record_id=int(record_id), limit=limit)}


@app.get("/api/whatsapp-signups/health")
def api_whatsapp_signups_health(request: Request):
    require_admin(request)
    return whatsapp_signups.webhook_health()


@app.get("/api/whatsapp-signups/config")
def api_whatsapp_signups_config(request: Request):
    require_admin(request)
    return {"ok": True, "config": whatsapp_signups.get_settings()}


@app.put("/api/whatsapp-signups/config")
def api_whatsapp_signups_config_save(request: Request, payload: Dict[str, Any] = Body(...)):
    require_admin(request)
    saved = whatsapp_signups.save_settings(payload or {})
    audit_log.record_request(
        request,
        "whatsapp.signup.config.update",
        target_type="module",
        target_id="whatsapp_signups",
        detail={"keys": sorted(list((payload or {}).keys()))[:20]},
    )
    return {"ok": True, "config": saved}


@app.get("/api/whatsapp-signups/qr")
def api_whatsapp_signups_qr(request: Request, campaign: str = "default"):
    require_admin(request)
    try:
        data = whatsapp_signups.generate_qr(campaign=campaign or "default")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True, **data}


@app.get("/api/whatsapp-signups/campaigns")
def api_whatsapp_signups_campaigns(request: Request, page: int = 1, page_size: int = 10):
    require_admin(request)
    p = max(1, int(page))
    ps = max(1, min(50, int(page_size)))
    off = (p - 1) * ps
    total = whatsapp_signups.count_campaigns()
    items = whatsapp_signups.list_campaigns(limit=ps, offset=off)
    return {"ok": True, "items": items, "total": total, "page": p, "page_size": ps}


@app.get("/api/whatsapp-signups/campaign-defs")
def api_whatsapp_signups_campaign_defs(request: Request):
    require_admin(request)
    return {"ok": True, "items": whatsapp_signups.list_campaign_defs()}


@app.post("/api/whatsapp-signups/campaign-defs")
def api_whatsapp_signups_campaign_defs_save(request: Request, payload: Dict[str, Any] = Body(...)):
    require_admin(request)
    p = payload or {}
    try:
        result = whatsapp_signups.save_campaign_def(
            campaign_code=str(p.get("campaign_code") or ""),
            trigger_text=str(p.get("trigger_text") or ""),
            welcome_text=str(p.get("welcome_text") or ""),
            success_text=str(p.get("success_text") or ""),
            flow=p.get("flow") if isinstance(p.get("flow"), list) else [],
            active=bool(p.get("active", True)),
            campaign_id=int(p.get("id") or 0),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    audit_log.record_request(
        request,
        "whatsapp.signup.campaign.save",
        target_type="campaign_code",
        target_id=str(result.get("campaign_code") or ""),
        detail={"campaign_id": int(result.get("id") or 0)},
    )
    return {"ok": True, "result": result}


@app.post("/api/whatsapp-signups/test")
def api_whatsapp_signups_test(request: Request, payload: Dict[str, Any] = Body(...)):
    require_admin(request)
    p = payload or {}
    to_phone = str(p.get("to_phone") or "")
    message = str(p.get("message") or "Wibernet WhatsApp config test")
    result = whatsapp_signups.send_test_message(
        to_phone=to_phone,
        message=message,
        use_template=True,
        template_name="hello_world",
        template_language="en_US",
    )
    if not bool(result.get("ok")):
        detail = str(result.get("detail") or "Test failed")
        body = str(result.get("body") or "").strip()
        if body:
            detail = f"{detail}: {body[:1200]}"
        raise HTTPException(status_code=400, detail=detail)
    return {"ok": True, "result": result}


@app.get("/api/whatsapp-signups/webhook")
def api_whatsapp_signups_webhook_verify(
    hub_mode: str = Query(default="", alias="hub.mode"),
    hub_challenge: str = Query(default="", alias="hub.challenge"),
    hub_verify_token: str = Query(default="", alias="hub.verify_token"),
):
    cfg = whatsapp_signups.get_settings()
    expected = str(cfg.get("verify_token") or "")
    mode = (hub_mode or "").strip().lower()
    if mode == "subscribe" and expected and (hub_verify_token or "") == expected:
        return Response(content=(hub_challenge or ""), media_type="text/plain")
    raise HTTPException(status_code=403, detail="Webhook verification failed")


@app.post("/api/whatsapp-signups/webhook")
def api_whatsapp_signups_webhook_ingest(payload: Dict[str, Any] = Body(...)):
    result = whatsapp_signups.ingest_webhook(payload or {})
    return {"ok": True, **result}


@app.get("/api/stock/suppliers")
def api_stock_suppliers():
    return {"ok": True, "suppliers": stock_management.list_suppliers()}


@app.get("/api/stock/lookups")
def api_stock_lookups():
    users = auth_users.list_users()
    technicians = [
        {"id": int(u["id"]), "username": str(u["username"])}
        for u in users
    ]
    return {"ok": True, "technicians": technicians}


@app.get("/api/stock/customer/{customer_id}")
def api_stock_customer(customer_id: int):
    cached = location_sync.get_cached_customer(int(customer_id)) or {}
    if cached:
        return {
            "ok": True,
            "customer": {
                "id": int(cached.get("customer_id") or customer_id),
                "name": str(cached.get("customer_name") or ""),
                "address": str(cached.get("address_text") or ""),
                "status": str(cached.get("status") or ""),
                "source": "location_sync_cache",
            },
        }
    customer = _splynx_get_customer_by_id(int(customer_id))
    addr_parts = []
    for key in ("street_1", "street_2", "city", "state", "zip_code", "country"):
        val = customer.get(key)
        if val not in (None, ""):
            addr_parts.append(str(val).strip())
    address = ", ".join([v for v in addr_parts if v])
    return {
        "ok": True,
        "customer": {
            "id": int(customer.get("id") or customer_id),
            "name": str(customer.get("name") or customer.get("login") or ""),
            "address": address,
            "source": "splynx_live",
        },
    }


@app.get("/api/stock/assigned")
def api_stock_assigned():
    return {"ok": True, "items": stock_management.list_assigned_stock_items()}


@app.get("/api/stock/misc-assignable")
def api_stock_misc_assignable():
    return {"ok": True, "items": stock_management.list_misc_products_for_assignment()}


@app.get("/api/stock/ipam-locations")
def api_stock_ipam_locations():
    return {"ok": True, "locations": stock_management.list_ipam_locations()}


@app.get("/api/stock/scrapped")
def api_stock_scrapped(limit: int = 200):
    return {"ok": True, "items": stock_management.list_scrapped_log(limit=limit)}


@app.post("/api/stock/suppliers")
def api_stock_add_supplier(request: Request, payload: Dict[str, Any] = Body(...)):
    name = str((payload or {}).get("name") or "")
    try:
        sid = stock_management.add_supplier(name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    audit_log.record_request(request, "stock.supplier.create", target_type="supplier_id", target_id=str(sid), detail={"name": name[:120]})
    return {"ok": True, "id": sid}


@app.post("/api/stock/suppliers/{supplier_id}/vendors")
def api_stock_add_vendor(request: Request, supplier_id: int, payload: Dict[str, Any] = Body(...)):
    name = str((payload or {}).get("name") or "")
    is_misc = bool((payload or {}).get("is_misc"))
    try:
        vid = stock_management.add_vendor(supplier_id, name, is_misc=is_misc)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    audit_log.record_request(
        request,
        "stock.vendor.create",
        target_type="vendor_id",
        target_id=str(vid),
        detail={"supplier_id": supplier_id, "name": name[:120], "is_misc": is_misc},
    )
    return {"ok": True, "id": vid}


@app.post("/api/stock/vendors/{vendor_id}/products")
def api_stock_add_product(request: Request, vendor_id: int, payload: Dict[str, Any] = Body(...)):
    name = str((payload or {}).get("name") or "")
    try:
        pid = stock_management.add_product(vendor_id, name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    audit_log.record_request(
        request,
        "stock.product.create",
        target_type="product_id",
        target_id=str(pid),
        detail={"vendor_id": vendor_id, "name": name[:120]},
    )
    return {"ok": True, "id": pid}


@app.post("/api/stock/products/{product_id}/items")
def api_stock_add_product_item(request: Request, product_id: int, payload: Dict[str, Any] = Body(...)):
    serial_number = str((payload or {}).get("serial_number") or "")
    try:
        iid = stock_management.add_product_item(product_id, serial_number)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    audit_log.record_request(
        request,
        "stock.item.create",
        target_type="item_id",
        target_id=str(iid),
        detail={"product_id": product_id, "serial_suffix": serial_number[-8:] if serial_number else ""},
    )
    return {"ok": True, "id": iid}


@app.post("/api/stock/products/{product_id}/items/batch")
def api_stock_add_product_items_batch(request: Request, product_id: int, payload: Dict[str, Any] = Body(...)):
    p = payload or {}
    invoice_number = str(p.get("invoice_number") or "")
    items = p.get("items") if isinstance(p.get("items"), list) else []
    try:
        ids = stock_management.add_product_items_batch(
            product_id=product_id,
            batch_invoice_number=invoice_number,
            items=items,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    audit_log.record_request(
        request,
        "stock.item.batch_create",
        target_type="product_id",
        target_id=str(product_id),
        detail={"invoice_number": invoice_number[:80], "count": len(ids), "item_ids_head": [int(x) for x in ids[:8]]},
    )
    return {"ok": True, "ids": ids}


@app.post("/api/stock/products/{product_id}/misc-lots")
def api_stock_add_misc_lot(request: Request, product_id: int, payload: Dict[str, Any] = Body(...)):
    p = payload or {}
    invoice_number = str(p.get("invoice_number") or "")
    quantity = p.get("quantity")
    date_in_stock = str(p.get("date_in_stock") or "")
    value_ex_vat = p.get("value_ex_vat")
    try:
        lid = stock_management.add_misc_product_lot(
            product_id=product_id,
            invoice_number=invoice_number,
            quantity=float(quantity),
            date_in_stock=date_in_stock,
            value_ex_vat=value_ex_vat,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    audit_log.record_request(
        request,
        "stock.misc_lot.create",
        target_type="misc_lot_id",
        target_id=str(lid),
        detail={"product_id": product_id, "invoice_number": invoice_number[:80], "quantity": quantity},
    )
    return {"ok": True, "id": lid}


@app.post("/api/stock/items/{item_id}/assign")
def api_stock_assign_item(request: Request, item_id: int, payload: Dict[str, Any] = Body(...)):
    p = payload or {}
    assignment_target = str(p.get("assignment_target") or "customer").strip().lower()
    location_id = p.get("location_id")
    customer_id = int(p.get("customer_id") or 0)
    customer_name = str(p.get("customer_name") or "")
    customer_address = str(p.get("customer_address") or "")
    customer_invoice_number = str(p.get("customer_invoice_number") or "")
    try:
        if assignment_target == "pre_allocate":
            stock_management.pre_allocate_item_to_customer(
                item_id=int(item_id),
                customer_id=customer_id,
                customer_name=customer_name,
                customer_address=customer_address,
                customer_invoice_number=customer_invoice_number,
            )
        else:
            stock_management.assign_item_to_customer(
                item_id=int(item_id),
                customer_id=customer_id,
                customer_name=customer_name,
                customer_address=customer_address,
                customer_invoice_number=customer_invoice_number,
                assignment_target=assignment_target,
                location_id=int(location_id) if location_id not in (None, "") else None,
            )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    audit_action = "stock.item.pre_allocate" if assignment_target == "pre_allocate" else "stock.item.assign"
    audit_log.record_request(
        request,
        audit_action,
        target_type="item_id",
        target_id=str(item_id),
        detail={
            "customer_id": customer_id,
            "customer_invoice_number": customer_invoice_number[:80],
            "customer_name": customer_name[:80],
            "assignment_target": assignment_target,
            "location_id": int(location_id) if location_id not in (None, "") else None,
        },
    )
    return {"ok": True}


@app.post("/api/stock/misc/assign")
def api_stock_assign_misc(request: Request, payload: Dict[str, Any] = Body(...)):
    p = payload or {}
    assignment_target = str(p.get("assignment_target") or "customer").strip().lower()
    location_id = p.get("location_id")
    try:
        assignment_id = stock_management.assign_misc_item_to_customer(
            product_name=str(p.get("product_name") or ""),
            quantity=float(p.get("quantity") or 0),
            customer_id=int(p.get("customer_id") or 0),
            customer_name=str(p.get("customer_name") or ""),
            customer_address=str(p.get("customer_address") or ""),
            customer_invoice_number=str(p.get("customer_invoice_number") or ""),
            comment=str(p.get("comment") or ""),
            assignment_target=assignment_target,
            location_id=int(location_id) if location_id not in (None, "") else None,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    audit_log.record_request(
        request,
        "stock.misc.assign",
        target_type="assignment_id",
        target_id=str(assignment_id),
        detail={
            "product_name": str(p.get("product_name") or "")[:120],
            "customer_id": int(p.get("customer_id") or 0),
            "quantity": p.get("quantity"),
            "assignment_target": assignment_target,
            "location_id": int(location_id) if location_id not in (None, "") else None,
        },
    )
    return {"ok": True, "assignment_id": assignment_id}


@app.post("/api/stock/items/{item_id}/return")
def api_stock_return_item(request: Request, item_id: int):
    try:
        stock_management.return_item_to_stock(int(item_id))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    audit_log.record_request(request, "stock.item.return", target_type="item_id", target_id=str(item_id), detail={})
    return {"ok": True}


@app.post("/api/stock/items/{item_id}/release-pre-allocation")
def api_stock_release_pre_allocation(request: Request, item_id: int):
    try:
        stock_management.release_pre_allocated_item(int(item_id))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    audit_log.record_request(
        request,
        "stock.item.release_pre_allocation",
        target_type="item_id",
        target_id=str(item_id),
        detail={},
    )
    return {"ok": True}


@app.post("/api/stock/items/{item_id}/scrap")
def api_stock_scrap_item(request: Request, item_id: int, payload: Dict[str, Any] = Body(None)):
    p = payload or {}
    try:
        stock_management.scrap_assigned_item(int(item_id), reason=str(p.get("reason") or ""))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    audit_log.record_request(
        request,
        "stock.item.scrap",
        target_type="item_id",
        target_id=str(item_id),
        detail={"reason_len": len(str(p.get("reason") or ""))},
    )
    return {"ok": True}


@app.post("/api/stock/items/{item_id}/rma")
def api_stock_rma_item(request: Request, item_id: int):
    try:
        stock_management.mark_item_rma(int(item_id))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    audit_log.record_request(request, "stock.item.rma", target_type="item_id", target_id=str(item_id), detail={})
    return {"ok": True, "message": "RMA placeholder logged"}


@app.patch("/api/stock/suppliers/{supplier_id}")
def api_stock_rename_supplier(request: Request, supplier_id: int, payload: Dict[str, Any] = Body(...)):
    require_admin(request)
    name = str((payload or {}).get("name") or "")
    try:
        stock_management.rename_supplier(supplier_id, name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    audit_log.record_request(request, "stock.supplier.rename", target_type="supplier_id", target_id=str(supplier_id), detail={"name": name[:120]})
    return {"ok": True}


@app.patch("/api/stock/vendors/{vendor_id}")
def api_stock_rename_vendor(request: Request, vendor_id: int, payload: Dict[str, Any] = Body(...)):
    require_admin(request)
    name = str((payload or {}).get("name") or "")
    try:
        stock_management.rename_vendor(vendor_id, name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    audit_log.record_request(request, "stock.vendor.rename", target_type="vendor_id", target_id=str(vendor_id), detail={"name": name[:120]})
    return {"ok": True}


@app.patch("/api/stock/products/{product_id}")
def api_stock_rename_product(request: Request, product_id: int, payload: Dict[str, Any] = Body(...)):
    require_admin(request)
    name = str((payload or {}).get("name") or "")
    try:
        stock_management.rename_product(product_id, name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    audit_log.record_request(request, "stock.product.rename", target_type="product_id", target_id=str(product_id), detail={"name": name[:120]})
    return {"ok": True}


@app.patch("/api/stock/items/{item_id}")
def api_stock_rename_item(request: Request, item_id: int, payload: Dict[str, Any] = Body(...)):
    require_admin(request)
    serial_number = str((payload or {}).get("serial_number") or "")
    try:
        stock_management.rename_item(item_id, serial_number)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    audit_log.record_request(
        request,
        "stock.item.rename",
        target_type="item_id",
        target_id=str(item_id),
        detail={"serial_suffix": serial_number[-8:] if serial_number else ""},
    )
    return {"ok": True}


@app.get("/api/po/lookups")
def api_po_lookups():
    return {
        "ok": True,
        "suppliers": purchase_orders.list_suppliers(),
        "departments": purchase_orders.list_departments(),
    }


@app.get("/api/po/suppliers/{supplier_id}/products")
def api_po_supplier_products(supplier_id: int):
    return {
        "ok": True,
        "products": stock_management.list_product_names_for_supplier(int(supplier_id)),
    }


@app.get("/api/po/suppliers/{supplier_id}/product-catalog")
def api_po_supplier_product_catalog(supplier_id: int):
    return {
        "ok": True,
        "products": stock_management.list_product_catalog_for_supplier(int(supplier_id)),
    }


@app.post("/api/po/departments")
def api_po_add_department(payload: Dict[str, Any] = Body(...), request: Request = None):
    require_admin(request)
    name = str((payload or {}).get("name") or "")
    try:
        dep_id = purchase_orders.add_department(name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True, "id": dep_id}


@app.get("/api/po/rules")
def api_po_rules(request: Request):
    require_admin(request)
    return {
        "ok": True,
        "rules": purchase_orders.list_approval_rules(),
        "approvers": purchase_orders.list_approver_users(),
        "departments": purchase_orders.list_departments(),
        "role_assignments": purchase_orders.list_role_assignments(),
    }


@app.post("/api/po/rules")
def api_po_add_rule(payload: Dict[str, Any] = Body(...), request: Request = None):
    require_admin(request)
    p = payload or {}
    try:
        rid = purchase_orders.add_approval_rule(
            name=str(p.get("name") or "Rule"),
            min_total=float(p.get("min_total") or 0),
            max_total=float(p["max_total"]) if p.get("max_total") not in (None, "") else None,
            department_id=int(p["department_id"]) if p.get("department_id") not in (None, "") else None,
            category=str(p.get("category") or ""),
            step_number=int(p.get("step_number") or 1),
            step_name=str(p.get("step_name") or ""),
            approver_user_id=int(p.get("approver_user_id") or 0),
            backup_approver_user_id=int(p["backup_approver_user_id"]) if p.get("backup_approver_user_id") not in (None, "") else None,
            active=bool(p.get("active", True)),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True, "id": rid}


@app.delete("/api/po/rules/{rule_id}")
def api_po_delete_rule(rule_id: int, request: Request):
    require_admin(request)
    if not purchase_orders.delete_approval_rule(rule_id):
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"ok": True}


@app.get("/api/po/role-assignments")
def api_po_role_assignments(request: Request, department_id: int = 0):
    require_admin(request)
    return {
        "ok": True,
        "assignments": purchase_orders.list_role_assignments(int(department_id) if int(department_id or 0) > 0 else None),
        "approvers": purchase_orders.list_approver_users(),
        "departments": purchase_orders.list_departments(),
    }


@app.put("/api/po/role-assignments")
def api_po_set_role_assignments(payload: Dict[str, Any] = Body(...), request: Request = None):
    require_admin(request)
    p = payload or {}
    department_id = int(p.get("department_id") or 0)
    if department_id <= 0:
        raise HTTPException(status_code=400, detail="department_id is required")
    try:
        for rk in ("manager", "finance", "director"):
            block = p.get(rk) or {}
            uid = int(block.get("user_id") or 0)
            if uid <= 0:
                continue
            bkup = int(block.get("backup_user_id")) if block.get("backup_user_id") not in (None, "", 0) else None
            purchase_orders.set_role_assignment(rk, uid, bkup, department_id=department_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True, "assignments": purchase_orders.list_role_assignments(department_id=department_id)}


def _break_glass_po_force(request: Request) -> bool:
    """Legacy: global admin with username ``admin`` may act on a pending step without being the named approver."""
    if not bool(getattr(request.state, "is_admin", False)):
        return False
    return str(getattr(request.state, "username", "") or "").strip().lower() == "admin"


def _po_can_read(request: Request, po: Dict[str, Any]) -> bool:
    if bool(getattr(request.state, "is_admin", False)):
        return True
    if bool(getattr(request.state, "po_admin", False)):
        return True
    uid = int(getattr(request.state, "user_id", 0) or 0)
    return int(po.get("requested_by_user_id") or 0) == uid


@app.get("/api/po/list")
def api_po_list(
    request: Request,
    status: str = "",
    q: str = "",
    page: int = 1,
    page_size: int = 10,
):
    username = getattr(request.state, "username", "unknown")
    user_id = int(getattr(request.state, "user_id", 0) or 0)
    is_admin = bool(getattr(request.state, "is_admin", False))
    po_admin = bool(getattr(request.state, "po_admin", False))
    page = max(1, int(page))
    page_size = max(1, min(50, int(page_size)))
    offset = (page - 1) * page_size
    search = (q or "").strip()
    see_all = is_admin or po_admin
    total = purchase_orders.count_pos(see_all_pos=see_all, user_id=user_id, status=status, search=search)
    rows = purchase_orders.list_pos(
        username=username,
        see_all_pos=see_all,
        user_id=user_id,
        status=status,
        limit=page_size,
        offset=offset,
        search=search,
    )
    return {
        "ok": True,
        "purchase_orders": rows,
        "total": total,
        "page": page,
        "page_size": page_size,
    }


def _api_po_postpone_impl(po_id: int, payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    require_login(request)
    user_id = int(getattr(request.state, "user_id", 0) or 0)
    p = payload or {}
    comments = str(p.get("comments") or "")
    resume_at = str(p.get("resume_at") or "")
    if not comments.strip():
        raise HTTPException(status_code=400, detail="Comments are required when postponing a PO")
    if not str(resume_at).strip():
        raise HTTPException(status_code=400, detail="Resume date is required")
    try:
        purchase_orders.postpone_po(
            po_id,
            user_id,
            comments,
            resume_at,
            force_admin=_break_glass_po_force(request),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    dispatch = {"total": 0, "processed": 0, "failed": 0}
    try:
        dispatch = dispatch_due_notifications(limit=100)
    except Exception:
        pass
    _publish_po_event(po_id, "postponed")
    return {"ok": True, "dispatch": dispatch}


@app.post("/api/po/action/postpone")
@app.post("/api/po/postpone")
def api_po_postpone_body(payload: Dict[str, Any] = Body(...), request: Request = None):
    """POST body includes po_id — registered before /api/po/{po_id} so routing/proxies cannot confuse this path."""
    p = payload or {}
    raw = p.get("po_id", p.get("purchase_order_id", 0))
    try:
        po_id = int(raw)
    except (TypeError, ValueError):
        po_id = 0
    if po_id <= 0:
        raise HTTPException(status_code=400, detail="po_id is required")
    return _api_po_postpone_impl(po_id, p, request)


@app.post("/api/po/{po_id}/postpone")
def api_po_postpone(po_id: int, payload: Dict[str, Any] = Body(...), request: Request = None):
    return _api_po_postpone_impl(po_id, payload or {}, request)


@app.get("/api/po/{po_id}")
def api_po_detail(po_id: int, request: Request):
    try:
        po = purchase_orders.get_po(po_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    if not _po_can_read(request, po):
        raise HTTPException(status_code=403, detail="Forbidden")
    return {"ok": True, "purchase_order": po}


@app.get("/api/po/events/stream")
async def api_po_stream(request: Request):
    q: asyncio.Queue = asyncio.Queue(maxsize=200)
    _po_event_subscribers.append(q)

    async def event_gen():
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    evt = await asyncio.wait_for(q.get(), timeout=25.0)
                    yield "event: po_update\n" + "data: " + json.dumps(evt, ensure_ascii=True) + "\n\n"
                except asyncio.TimeoutError:
                    yield "event: heartbeat\ndata: {}\n\n"
        finally:
            try:
                _po_event_subscribers.remove(q)
            except ValueError:
                pass

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={
            # SSE must not be buffered by reverse proxies (e.g. Nginx), or events appear only on refresh.
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/po/events/health")
def api_po_events_health():
    loop = _po_events_loop
    task = _po_events_redis_task
    redis_url = (os.getenv("REDIS_URL") or "").strip()
    return {
        "ok": True,
        "app_role": APP_ROLE,
        "pid": os.getpid(),
        "sse_loop_bound": bool(loop is not None and loop.is_running()),
        "sse_subscribers_local": len(_po_event_subscribers),
        "redis_client_available": bool(_po_events_redis_client is not None),
        "redis_configured": bool(redis_url),
        "redis_module_available": bool(redis_async is not None),
        "redis_subscriber_running": bool(task is not None and not task.done()),
        "channel": _PO_EVENTS_CHANNEL,
    }


@app.post("/api/po/quote/parse")
async def api_po_quote_parse(request: Request, upload: UploadFile = File(...)):
    if not int(getattr(request.state, "user_id", 0) or 0):
        raise HTTPException(status_code=401, detail="Unauthorized")
    blob = await upload.read()
    try:
        parsed = po_quote_import.parse_quote_upload(
            upload.filename or "quote",
            upload.content_type or "",
            blob,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True, **parsed}


@app.post("/api/po")
def api_po_create(payload: Dict[str, Any] = Body(...), request: Request = None):
    p = payload or {}
    user_id = int(getattr(request.state, "user_id", 0) or 0)
    try:
        po_id = purchase_orders.create_draft(
            requested_by_user_id=user_id,
            supplier_id=int(p.get("supplier_id")) if p.get("supplier_id") else None,
            department_id=int(p.get("department_id")) if p.get("department_id") else None,
            category=str(p.get("category") or ""),
            notes=str(p.get("notes") or ""),
            request_type=str(p.get("request_type") or ""),
            customer_id=int(p.get("customer_id")) if p.get("customer_id") not in (None, "") else None,
            payment_status=str(p.get("payment_status") or ""),
            date_required=str(p.get("date_required") or ""),
            urgency=str(p.get("urgency") or ""),
            items=list(p.get("items") or []),
            tax_override=float(p["tax"]) if p.get("tax") not in (None, "") else None,
            department_name=str(p.get("department_name") or ""),
            supplier_name=str(p.get("supplier_name") or ""),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    _publish_po_event(po_id, "created")
    return {"ok": True, "id": po_id}


@app.put("/api/po/{po_id}")
def api_po_update(po_id: int, payload: Dict[str, Any] = Body(...), request: Request = None):
    p = payload or {}
    user_id = int(getattr(request.state, "user_id", 0) or 0)
    try:
        purchase_orders.update_draft(
            po_id=po_id,
            actor_user_id=user_id,
            supplier_id=int(p.get("supplier_id")) if p.get("supplier_id") else None,
            department_id=int(p.get("department_id")) if p.get("department_id") else None,
            category=str(p.get("category") or ""),
            notes=str(p.get("notes") or ""),
            request_type=str(p.get("request_type") or ""),
            customer_id=int(p.get("customer_id")) if p.get("customer_id") not in (None, "") else None,
            payment_status=str(p.get("payment_status") or ""),
            date_required=str(p.get("date_required") or ""),
            urgency=str(p.get("urgency") or ""),
            items=list(p.get("items") or []),
            tax_override=float(p["tax"]) if p.get("tax") not in (None, "") else None,
            department_name=str(p.get("department_name") or ""),
            supplier_name=str(p.get("supplier_name") or ""),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    _publish_po_event(po_id, "updated")
    return {"ok": True}


@app.post("/api/po/{po_id}/submit")
def api_po_submit(po_id: int, request: Request):
    user_id = int(getattr(request.state, "user_id", 0) or 0)
    try:
        purchase_orders.submit_po(po_id, user_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    # Create a submission-time PDF snapshot so users can view/download immediately.
    try:
        po = purchase_orders.get_po(po_id)
        pdf_bytes = build_purchase_order_pdf(po)
        version = purchase_orders.next_document_version(po_id)
        out_dir = Path("/app/data/po-docs") / str(int(po_id))
        out_dir.mkdir(parents=True, exist_ok=True)
        out_name = f"v{version}.pdf"
        out_path = out_dir / out_name
        out_path.write_bytes(pdf_bytes)
        purchase_orders.save_po_pdf(po_id, user_id, purchase_order_pdf_filename(po), str(out_path), pdf_bytes)
    except Exception:
        pass
    dispatch = {"total": 0, "processed": 0, "failed": 0}
    try:
        dispatch = dispatch_due_notifications(limit=100)
    except Exception:
        pass
    _publish_po_event(po_id, "submitted")
    return {"ok": True, "dispatch": dispatch}


@app.post("/api/po/{po_id}/approve")
def api_po_approve(po_id: int, payload: Dict[str, Any] = Body(...), request: Request = None):
    require_login(request)
    user_id = int(getattr(request.state, "user_id", 0) or 0)
    comments = str((payload or {}).get("comments") or "")
    try:
        new_status = purchase_orders.approve_step(po_id, user_id, comments, force_admin=_break_glass_po_force(request))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    dispatch = {"total": 0, "processed": 0, "failed": 0}
    try:
        dispatch = dispatch_due_notifications(limit=100)
    except Exception:
        pass
    _publish_po_event(po_id, "approved")
    return {"ok": True, "status": new_status, "dispatch": dispatch}


@app.post("/api/po/{po_id}/reject")
def api_po_reject(po_id: int, payload: Dict[str, Any] = Body(...), request: Request = None):
    require_login(request)
    user_id = int(getattr(request.state, "user_id", 0) or 0)
    comments = str((payload or {}).get("comments") or "")
    if not comments.strip():
        raise HTTPException(status_code=400, detail="Comments are required when declining a PO")
    try:
        purchase_orders.reject_po(po_id, user_id, comments, force_admin=_break_glass_po_force(request))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    dispatch = {"total": 0, "processed": 0, "failed": 0}
    try:
        dispatch = dispatch_due_notifications(limit=100)
    except Exception:
        pass
    _publish_po_event(po_id, "rejected")
    return {"ok": True, "dispatch": dispatch}


@app.post("/api/po/{po_id}/changes")
def api_po_changes(po_id: int, payload: Dict[str, Any] = Body(...), request: Request = None):
    require_login(request)
    user_id = int(getattr(request.state, "user_id", 0) or 0)
    comments = str((payload or {}).get("comments") or "")
    if not comments.strip():
        raise HTTPException(status_code=400, detail="Comments are required when putting a PO on hold")
    try:
        purchase_orders.request_changes(po_id, user_id, comments, force_admin=_break_glass_po_force(request))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    dispatch = {"total": 0, "processed": 0, "failed": 0}
    try:
        dispatch = dispatch_due_notifications(limit=100)
    except Exception:
        pass
    _publish_po_event(po_id, "on_hold")
    return {"ok": True, "dispatch": dispatch}


@app.post("/api/po/{po_id}/status")
def api_po_status(po_id: int, payload: Dict[str, Any] = Body(...), request: Request = None):
    user_id = int(getattr(request.state, "user_id", 0) or 0)
    target_status = str((payload or {}).get("status") or "")
    comments = str((payload or {}).get("comments") or "")
    if target_status == "cancelled" and not bool(getattr(request.state, "is_admin", False)):
        raise HTTPException(status_code=403, detail="Only admin can cancel a PO")
    try:
        purchase_orders.update_lifecycle_status(po_id, user_id, target_status, comments)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    _publish_po_event(po_id, "status_update")
    return {"ok": True}


@app.delete("/api/po/{po_id}")
def api_po_delete(po_id: int, request: Request):
    is_admin = bool(getattr(request.state, "is_admin", False))
    user_id = int(getattr(request.state, "user_id", 0) or 0)
    try:
        if is_admin:
            purchase_orders.delete_po(po_id, user_id, force=False)
        else:
            po = purchase_orders.get_po(po_id)
            if int(po.get("requested_by_user_id") or 0) != int(user_id):
                raise HTTPException(status_code=403, detail="Only requester can delete this draft")
            if str(po.get("status") or "") != "draft":
                raise HTTPException(status_code=400, detail="Only draft POs can be deleted")
            purchase_orders.delete_po(po_id, user_id, force=False)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    _publish_po_event(po_id, "deleted")
    return {"ok": True, "force": False}


@app.post("/api/po/{po_id}/attachments")
async def api_po_attachment(po_id: int, request: Request, upload: UploadFile = File(...)):
    user_id = int(getattr(request.state, "user_id", 0) or 0)
    is_admin = bool(getattr(request.state, "is_admin", False))
    try:
        po = purchase_orders.get_po(po_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    if not _po_can_read(request, po):
        raise HTTPException(status_code=403, detail="Forbidden")
    if not is_admin and int(po.get("requested_by_user_id") or 0) != int(user_id):
        raise HTTPException(status_code=403, detail="Only the requester can add attachments to this PO")
    safe_name = os.path.basename(upload.filename or "attachment.bin")
    target_dir = Path("/app/data/po-attachments") / str(int(po_id))
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / safe_name
    blob = await upload.read()
    target.write_bytes(blob)
    try:
        aid = purchase_orders.add_attachment(po_id, user_id, safe_name, str(target), str(upload.content_type or "application/octet-stream"))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True, "id": aid}


@app.get("/api/po/{po_id}/document/{version_no}")
def api_po_document(po_id: int, version_no: int, request: Request):
    try:
        po = purchase_orders.get_po(po_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    if not _po_can_read(request, po):
        raise HTTPException(status_code=403, detail="Forbidden")
    if str(po.get("status") or "").lower() != "sent_to_supplier":
        raise HTTPException(status_code=400, detail="PDF is only available after the PO is placed (ordered)")
    doc = next((d for d in po.get("documents", []) if int(d.get("version_no") or 0) == int(version_no)), None)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    # One-time template uplift for legacy PDFs:
    # if stored doc hash differs from current renderer output, save a new current version and serve it.
    try:
        rendered = build_purchase_order_pdf(po)
        rendered_sha = hashlib.sha256(rendered).hexdigest()
        current_sha = str(doc.get("sha256") or "").strip().lower()
        if rendered and rendered_sha and current_sha != rendered_sha:
            next_version = purchase_orders.next_document_version(po_id)
            out_dir = Path("/app/data/po-docs") / str(int(po_id))
            out_dir.mkdir(parents=True, exist_ok=True)
            out_name = f"v{next_version}.pdf"
            out_path = out_dir / out_name
            out_path.write_bytes(rendered)
            download_name = purchase_order_pdf_filename(po)
            purchase_orders.save_po_pdf(po_id, user_id, download_name, str(out_path), rendered)
            return FileResponse(path=str(out_path), filename=download_name, media_type="application/pdf")
    except Exception:
        pass
    p = str(doc.get("file_path") or "")
    if not p or not os.path.isfile(p):
        raise HTTPException(status_code=404, detail="File missing")
    return FileResponse(
        path=p,
        filename=str(doc.get("file_name") or purchase_order_pdf_filename(po)),
        media_type="application/pdf",
    )


@app.post("/api/po/{po_id}/generate-pdf")
def api_po_generate_pdf(po_id: int, request: Request):
    require_admin(request)
    user_id = int(getattr(request.state, "user_id", 0) or 0)
    try:
        po = purchase_orders.get_po(po_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    if str(po.get("status") or "").lower() != "sent_to_supplier":
        raise HTTPException(status_code=400, detail="PDF is only available after the PO is placed (ordered)")
    pdf_bytes = build_purchase_order_pdf(po)
    version = purchase_orders.next_document_version(po_id)
    out_dir = Path("/app/data/po-docs") / str(int(po_id))
    out_dir.mkdir(parents=True, exist_ok=True)
    out_name = f"v{version}.pdf"
    out_path = out_dir / out_name
    out_path.write_bytes(pdf_bytes)
    download_name = purchase_order_pdf_filename(po)
    purchase_orders.save_po_pdf(po_id, user_id, download_name, str(out_path), pdf_bytes)
    return {"ok": True, "version": version, "path": str(out_path)}


@app.post("/api/po/{po_id}/place-order")
def api_po_place_order(po_id: int, request: Request):
    user_id = int(getattr(request.state, "user_id", 0) or 0)
    is_admin = bool(getattr(request.state, "is_admin", False))
    try:
        po = purchase_orders.get_po(po_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    requested_by_user_id = int(po.get("requested_by_user_id") or 0)
    if not is_admin and int(user_id) != requested_by_user_id:
        raise HTTPException(status_code=403, detail="Only the requester (or admin) can place this order")
    status = str(po.get("status") or "").lower()
    if status not in ("approved", "sent_to_supplier"):
        raise HTTPException(status_code=400, detail="PO must be approved before placing order")
    pdf_bytes = build_purchase_order_pdf(po)
    version = purchase_orders.next_document_version(po_id)
    out_dir = Path("/app/data/po-docs") / str(int(po_id))
    out_dir.mkdir(parents=True, exist_ok=True)
    out_name = f"v{version}.pdf"
    out_path = out_dir / out_name
    out_path.write_bytes(pdf_bytes)
    download_name = purchase_order_pdf_filename(po)
    purchase_orders.save_po_pdf(po_id, user_id, download_name, str(out_path), pdf_bytes)
    if status != "sent_to_supplier":
        purchase_orders.update_lifecycle_status(po_id, user_id, "sent_to_supplier", "Placed order")
    _publish_po_event(po_id, "placed")
    return {
        "ok": True,
        "version": version,
        "path": str(out_path),
        "document_url": f"/api/po/{po_id}/document/{version}",
    }


@app.post("/api/po/notifications/dispatch")
def api_po_dispatch_notifications(request: Request, payload: Dict[str, Any] = Body(None)):
    require_admin(request)
    limit = int((payload or {}).get("limit") or 100)
    return {"ok": True, "result": dispatch_due_notifications(limit=limit)}


@app.get("/api/po/notifications/settings")
def api_po_notification_settings(request: Request):
    require_admin(request)
    return {
        "ok": True,
        "timing": purchase_orders.get_notification_settings(),
        "users": purchase_orders.list_user_notification_preferences(),
    }


@app.put("/api/po/notifications/settings")
def api_po_notification_settings_update(request: Request, payload: Dict[str, Any] = Body(...)):
    require_admin(request)
    p = payload or {}
    purchase_orders.set_notification_settings(
        reminder_4h_sec=int(p.get("reminder_4h_sec") or 14400),
        escalation_24h_sec=int(p.get("escalation_24h_sec") or 86400),
        backup_48h_sec=int(p.get("backup_48h_sec") or 172800),
    )
    return {"ok": True, "timing": purchase_orders.get_notification_settings()}


@app.put("/api/po/notifications/users/{user_id}")
def api_po_notification_user_update(user_id: int, request: Request, payload: Dict[str, Any] = Body(...)):
    require_admin(request)
    p = payload or {}
    purchase_orders.set_user_notification_preference(
        user_id=int(user_id),
        notify_app=bool(p.get("notify_app", True)),
        notify_email=bool(p.get("notify_email", True)),
        notify_whatsapp=bool(p.get("notify_whatsapp", False)),
        email=str(p.get("email") or ""),
        whatsapp_number=str(p.get("whatsapp_number") or ""),
    )
    return {"ok": True}


@app.post("/api/po/notifications/test")
def api_po_notification_test(request: Request, payload: Dict[str, Any] = Body(...)):
    require_admin(request)
    p = payload or {}
    user_id = int(p.get("user_id") or 0)
    if user_id <= 0:
        raise HTTPException(status_code=400, detail="user_id required")
    nid, preview = purchase_orders.enqueue_test_notification(
        user_id=user_id,
        channel=str(p.get("channel") or "app"),
        actor_username=str(getattr(request.state, "username", "admin")),
    )
    if str(p.get("channel") or "").strip().lower() == "email":
        enriched = _hydrate_po_email_notification(
            {
                "id": int(nid),
                "user_id": user_id,
                "purchase_order_id": None,
                "event_type": "test_po_approval",
                "title": preview.get("title") or "",
                "message": preview.get("message") or "",
                "action_url": preview.get("action_url") or "",
                "channel": "email",
            }
        )
        preview = {
            key: enriched.get(key)
            for key in ("title", "message", "action_url", "html_body")
            if enriched.get(key) is not None
        }
    result = dispatch_due_notifications(limit=50)
    return {"ok": True, "notification_id": nid, "preview": preview, "dispatch": result}


@app.get("/po/email-action/{token}", response_class=HTMLResponse)
def po_email_action_get(token: str):
    ctx, err = get_email_action_context(token)
    if err:
        return HTMLResponse(
            f"<!doctype html><html><body style='font-family:system-ui;padding:2rem'><h1>Link unavailable</h1><p>{html.escape(err)}</p></body></html>",
            status_code=400,
        )
    row = ctx["token_row"]
    return HTMLResponse(render_email_action_page(token, ctx["po"], row["action"]))


@app.post("/po/email-action/{token}", response_class=HTMLResponse)
def po_email_action_post(
    token: str,
    comments: str = Form(""),
    resume_at: str = Form(""),
    confirm: str = Form(""),
):
    ctx, err = get_email_action_context(token)
    if err:
        return HTMLResponse(
            f"<!doctype html><html><body style='font-family:system-ui;padding:2rem'><h1>Link unavailable</h1><p>{html.escape(err)}</p></body></html>",
            status_code=400,
        )
    row = ctx["token_row"]
    po = ctx["po"]
    action = str(row.get("action") or "")
    if not str(confirm or "").strip():
        return HTMLResponse(render_email_action_page(token, po, action, error="Confirmation is required."))
    ok, message, evt = execute_email_action(
        token,
        {"comments": comments, "resume_at": resume_at},
    )
    if ok:
        try:
            dispatch_due_notifications(limit=100)
        except Exception:
            pass
        if evt:
            try:
                _publish_po_event(int(po.get("id") or 0), evt)
            except Exception:
                pass
        return HTMLResponse(render_email_action_page(token, po, action, message=message))
    return HTMLResponse(render_email_action_page(token, po, action, error=message), status_code=400)


@app.get("/download/purchase-orders-user-guide")
def download_purchase_orders_user_guide(request: Request):
    p = os.path.abspath("PURCHASE_ORDERS_USER_GUIDE.md")
    if not os.path.isfile(p):
        raise HTTPException(status_code=404, detail="Guide not found")
    return FileResponse(
        path=p,
        filename="PURCHASE_ORDERS_USER_GUIDE.md",
        media_type="text/markdown; charset=utf-8",
    )


def _ensure_backup_dir() -> Path:
    p = Path(BACKUP_DIR)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _pg_conn_parts() -> Dict[str, str]:
    return {
        "host": os.getenv("POSTGRES_HOST", "postgres"),
        "port": os.getenv("POSTGRES_PORT", "5432"),
        "db": os.getenv("POSTGRES_DB", "mtr"),
        "user": os.getenv("POSTGRES_USER", "mtr"),
        "password": os.getenv("POSTGRES_PASSWORD", "change-me"),
    }


def _run_pg_dump(target_file: Path) -> None:
    pg = _pg_conn_parts()
    env = os.environ.copy()
    env["PGPASSWORD"] = pg["password"]
    cmd = [
        "pg_dump",
        "-h",
        pg["host"],
        "-p",
        pg["port"],
        "-U",
        pg["user"],
        "-d",
        pg["db"],
        "-Fc",
        "-f",
        str(target_file),
    ]
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env, check=False)
    if p.returncode != 0:
        raise RuntimeError((p.stderr or p.stdout or "pg_dump failed").strip())


def _human_size(n: int) -> str:
    v = float(max(0, int(n)))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if v < 1024.0 or unit == "TB":
            return f"{v:.1f} {unit}" if unit != "B" else f"{int(v)} B"
        v /= 1024.0
    return f"{int(n)} B"


def _list_backup_files() -> List[Dict[str, Any]]:
    root = _ensure_backup_dir()
    out: List[Dict[str, Any]] = []
    for p in sorted(root.glob("*"), key=lambda x: x.stat().st_mtime, reverse=True):
        if not p.is_file():
            continue
        st = p.stat()
        out.append(
            {
                "name": p.name,
                "size": int(st.st_size),
                "size_text": _human_size(int(st.st_size)),
                "mtime": datetime.utcfromtimestamp(st.st_mtime).isoformat(timespec="seconds") + "Z",
            }
        )
    return out


@app.get("/api/backups")
def api_backups_list(request: Request):
    require_admin(request)
    return {"ok": True, "files": _list_backup_files()}


@app.get("/api/backups/download/{name}")
def api_backups_download(name: str, request: Request):
    require_admin(request)
    safe = os.path.basename(str(name or ""))
    if safe != name or not safe:
        raise HTTPException(status_code=400, detail="Invalid filename")
    p = _ensure_backup_dir() / safe
    if not p.is_file():
        raise HTTPException(status_code=404, detail="Backup not found")
    return FileResponse(str(p), filename=safe, media_type="application/octet-stream")


@app.post("/api/backups/db-only")
def api_backups_db_only(request: Request):
    require_admin(request)
    root = _ensure_backup_dir()
    stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    out = root / f"db-only-{stamp}.dump"
    _run_pg_dump(out)
    return {"ok": True, "file": out.name, "size": _human_size(out.stat().st_size)}


@app.post("/api/backups/full")
def api_backups_full(request: Request):
    require_admin(request)
    root = _ensure_backup_dir()
    stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    stage = root / f"full-{stamp}"
    stage.mkdir(parents=True, exist_ok=True)
    dump_path = stage / "postgres.dump"
    _run_pg_dump(dump_path)
    meta = {
        "created_at_utc": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "db_backend": os.getenv("DB_BACKEND", ""),
        "postgres": {k: v for k, v in _pg_conn_parts().items() if k != "password"},
    }
    (stage / "metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    for cfg in ("docker-compose.yml", ".env.compose", "OPERATIONS.md"):
        src = Path("/app") / cfg
        if src.is_file():
            (stage / cfg).write_bytes(src.read_bytes())
    out = root / f"full-backup-{stamp}.tar.gz"
    with tarfile.open(out, "w:gz") as tf:
        tf.add(stage, arcname=stage.name)
    for child in sorted(stage.glob("**/*"), reverse=True):
        if child.is_file():
            child.unlink(missing_ok=True)
        elif child.is_dir():
            child.rmdir()
    stage.rmdir()
    return {"ok": True, "file": out.name, "size": _human_size(out.stat().st_size)}


@app.get("/api/resources")
def api_resources_snapshot():
    return server_resources.snapshot()


@app.post("/api/compose/restart")
def api_compose_restart(request: Request, payload: Dict[str, Any] = Body(...)):
    require_admin(request)
    p = payload or {}
    try:
        svc = compose_control.restart_service_async(str(p.get("service") or ""))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    audit_log.record_request(
        request,
        "compose.restart",
        target_type="compose_service",
        target_id=svc,
        detail={},
    )
    return {"ok": True, "service": svc, "queued": True}


@app.post("/api/compose/rebuild")
def api_compose_rebuild(request: Request, payload: Dict[str, Any] = Body(...)):
    require_admin(request)
    p = payload or {}
    expected = "REBUILD STACK"
    if str(p.get("confirm_phrase") or "").strip() != expected:
        raise HTTPException(status_code=400, detail=f"Confirmation phrase must be: {expected}")
    try:
        compose_control.rebuild_stack_async()
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    audit_log.record_request(
        request,
        "compose.rebuild",
        target_type="compose",
        target_id="full",
        detail={},
    )
    return {"ok": True, "queued": True}


@app.get("/api/clone/runs")
def api_clone_runs(request: Request, limit: int = 20):
    require_admin(request)
    return {
        "ok": True,
        "active_run_id": clone_runner.active_run_id(),
        "runs": clone_runner.list_runs(limit=limit),
        # Where clone-*.json lives (default /app/data/clone-runs in Docker); helps verify volume mounts.
        "clone_state_dir": str(clone_runner.STATE_DIR.resolve()),
    }


@app.get("/api/clone/runs/{run_id}")
def api_clone_run_detail(run_id: str, request: Request):
    require_admin(request)
    row = clone_runner.get_run(run_id)
    if not row:
        raise HTTPException(status_code=404, detail="Clone run not found")
    return {"ok": True, "run": row}


@app.post("/api/clone/start")
def api_clone_start(request: Request, payload: Dict[str, Any] = Body(...)):
    require_admin(request)
    if not _clone_scheduler_allowed():
        raise HTTPException(
            status_code=403,
            detail="Clone runs are disabled on this host (CLONE_SCHEDULER_ENABLED=0, typical DR standby).",
        )
    p = payload or {}
    target_host = str(p.get("target_host") or "").strip()
    target_dir = str(p.get("target_dir") or "").strip()
    target_user = str(p.get("target_user") or "root").strip() or "root"
    ssh_key_path = str(p.get("ssh_key_path") or "").strip()
    confirm_phrase = str(p.get("confirm_phrase") or "").strip()
    dry_run = bool(p.get("dry_run"))
    override_text = str(p.get("override_text") or "")
    host_fingerprint = str(p.get("host_fingerprint") or "").strip()
    profile = "full"
    services: List[str] = []
    target_port = int(p.get("target_port") or 22)
    if not target_host:
        raise HTTPException(status_code=400, detail="target_host is required")
    if not target_dir:
        raise HTTPException(status_code=400, detail="target_dir is required")
    if target_port <= 0 or target_port > 65535:
        raise HTTPException(status_code=400, detail="target_port must be 1-65535")
    expected = f"CLONE {target_host}"
    if confirm_phrase != expected:
        raise HTTPException(status_code=400, detail=f"Confirmation phrase must be: {expected}")
    try:
        row = clone_runner.start_clone(
            target_host=target_host,
            target_user=target_user,
            target_port=target_port,
            target_dir=target_dir,
            ssh_key_path=ssh_key_path,
            confirm_phrase=confirm_phrase,
            dry_run=dry_run,
            override_text=override_text,
            host_fingerprint=host_fingerprint,
            profile=profile,
            services=services,
        )
    except RuntimeError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    audit_log.record_request(
        request,
        "clone.start",
        target_type="clone_run",
        target_id=str((row or {}).get("run_id") or ""),
        detail={
            "target_host": target_host,
            "target_dir": target_dir[:200],
            "profile": profile,
            "dry_run": dry_run,
            "has_override": bool((override_text or "").strip()),
            "services_count": len(services),
        },
    )
    return {"ok": True, "run": row}


@app.get("/api/clone/schedule")
def api_clone_schedule_get(request: Request):
    require_admin(request)
    return {
        "ok": True,
        "schedule": clone_schedule.get(),
        "clone_scheduler_allowed": _clone_scheduler_allowed(),
    }


@app.get("/api/clone/target")
def api_clone_target_get(request: Request):
    require_admin(request)
    cfg = clone_schedule.get()
    return {
        "ok": True,
        "target": {
            "target_host": str(cfg.get("target_host") or ""),
            "target_user": str(cfg.get("target_user") or "root"),
            "target_port": int(cfg.get("target_port") or 22),
            "target_dir": str(cfg.get("target_dir") or ""),
            "ssh_key_path": str(cfg.get("ssh_key_path") or ""),
            "host_fingerprint": str(cfg.get("host_fingerprint") or ""),
            "override_text": str(cfg.get("override_text") or ""),
        },
    }


@app.put("/api/clone/target")
def api_clone_target_put(request: Request, payload: Dict[str, Any] = Body(...)):
    require_admin(request)
    p = payload or {}
    curr = clone_schedule.get()
    curr.update(
        {
            "target_host": str(p.get("target_host") or "").strip(),
            "target_user": str(p.get("target_user") or "root").strip() or "root",
            "target_port": int(p.get("target_port") or 22),
            "target_dir": str(p.get("target_dir") or "").strip(),
            "ssh_key_path": str(p.get("ssh_key_path") or "").strip(),
            "host_fingerprint": str(p.get("host_fingerprint") or "").strip(),
            "override_text": str(p.get("override_text") or ""),
        }
    )
    cfg = clone_schedule.set_config(curr)
    audit_log.record_request(
        request,
        "clone.target.update",
        target_type="config",
        target_id="clone_target",
        detail={"target_host": str(cfg.get("target_host") or ""), "has_fingerprint": bool((cfg.get("host_fingerprint") or "").strip())},
    )
    return {"ok": True, "target": cfg}


@app.delete("/api/clone/target")
def api_clone_target_reset(request: Request):
    require_admin(request)
    curr = clone_schedule.get()
    curr.update(
        {
            "target_host": "",
            "target_user": "root",
            "target_port": 22,
            "target_dir": "",
            "ssh_key_path": "",
            "host_fingerprint": "",
            "override_text": "",
        }
    )
    cfg = clone_schedule.set_config(curr)
    audit_log.record_request(request, "clone.target.reset", target_type="config", target_id="clone_target", detail={})
    return {"ok": True, "target": cfg}


@app.put("/api/clone/schedule")
def api_clone_schedule_put(request: Request, payload: Dict[str, Any] = Body(...)):
    require_admin(request)
    p = payload or {}
    if not _clone_scheduler_allowed() and bool(p.get("enabled")):
        raise HTTPException(
            status_code=403,
            detail="Cannot enable nightly clone on this host (CLONE_SCHEDULER_ENABLED=0).",
        )
    cfg = clone_schedule.set_config(
        {
            "enabled": bool(p.get("enabled")),
            "hour": int(p.get("hour") or 0),
            "minute": int(p.get("minute") or 0),
            "profile": "full",
            "services": [],
            "target_host": str(p.get("target_host") or "").strip(),
            "target_user": str(p.get("target_user") or "root").strip() or "root",
            "target_port": int(p.get("target_port") or 22),
            "target_dir": str(p.get("target_dir") or "").strip(),
            "ssh_key_path": str(p.get("ssh_key_path") or "").strip(),
            "host_fingerprint": str(p.get("host_fingerprint") or "").strip(),
            "override_text": str(p.get("override_text") or ""),
        }
    )
    audit_log.record_request(
        request,
        "clone.schedule.update",
        target_type="config",
        target_id="clone_schedule",
        detail={"enabled": bool(cfg.get("enabled")), "profile": str(cfg.get("profile") or ""), "target_host": str(cfg.get("target_host") or "")},
    )
    return {"ok": True, "schedule": cfg}


@app.post("/api/clone/schedule/run-now")
def api_clone_schedule_run_now(request: Request):
    require_admin(request)
    if not _clone_scheduler_allowed():
        raise HTTPException(
            status_code=403,
            detail="Clone runs are disabled on this host (CLONE_SCHEDULER_ENABLED=0).",
        )
    cfg = clone_schedule.get()
    target_host = str(cfg.get("target_host") or "").strip()
    target_dir = str(cfg.get("target_dir") or "").strip()
    if not target_host or not target_dir:
        raise HTTPException(status_code=400, detail="Schedule target_host and target_dir are required")
    try:
        row = clone_runner.start_clone(
            target_host=target_host,
            target_user=str(cfg.get("target_user") or "root").strip() or "root",
            target_port=int(cfg.get("target_port") or 22),
            target_dir=target_dir,
            ssh_key_path=str(cfg.get("ssh_key_path") or "").strip(),
            confirm_phrase=f"CLONE {target_host}",
            dry_run=False,
            override_text=str(cfg.get("override_text") or ""),
            host_fingerprint=str(cfg.get("host_fingerprint") or "").strip(),
            profile="full",
            services=[],
        )
    except RuntimeError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    audit_log.record_request(
        request,
        "clone.schedule.run_now",
        target_type="clone_run",
        target_id=str((row or {}).get("run_id") or ""),
        detail={"target_host": target_host, "profile": "full"},
    )
    return {"ok": True, "run": row}


@app.get("/api/dr/status")
def api_dr_status(request: Request):
    require_admin(request)
    return {"ok": True, "mode": dr_runner.mode_status(), "active_run_id": dr_runner.active_run_id(), "latest_run": dr_runner.latest_run()}


@app.post("/api/dr/promote")
def api_dr_promote(request: Request, payload: Dict[str, Any] = Body(...)):
    require_admin(request)
    phrase = str((payload or {}).get("confirm_phrase") or "").strip()
    try:
        run = dr_runner.promote(phrase)
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))
    audit_log.record_request(request, "dr.promote", target_type="dr_run", target_id=str((run or {}).get("run_id") or ""), detail={})
    return {"ok": True, "run": run}


@app.get("/api/users")
def api_users_list(request: Request):
    require_admin(request)
    return {"ok": True, "users": auth_users.list_users(), "page_keys": list(auth_users.PAGE_KEYS)}


@app.post("/api/users")
def api_users_create(request: Request, payload: Dict[str, Any] = Body(...)):
    require_admin(request)
    p = payload or {}
    try:
        uid = auth_users.create_user(
            str(p.get("username") or ""),
            str(p.get("password") or ""),
            is_admin=bool(p.get("is_admin")),
            po_admin=bool(p.get("po_admin")) and not bool(p.get("is_admin")),
            pages=p.get("pages") if isinstance(p.get("pages"), list) else [],
            email=str(p.get("email") or ""),
            mobile=str(p.get("mobile") or ""),
        )
        try:
            purchase_orders.sync_user_notification_contact(
                uid,
                email=str(p.get("email") or ""),
                mobile=str(p.get("mobile") or ""),
            )
        except Exception:
            pass
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    audit_log.record_request(
        request,
        "user.create",
        target_type="user",
        target_id=str(p.get("username") or "").strip(),
        detail={"new_user_id": int(uid), "is_admin": bool(p.get("is_admin"))},
    )
    return {"ok": True, "id": uid}


@app.patch("/api/users/{user_id}")
def api_users_update(request: Request, user_id: int, payload: Dict[str, Any] = Body(...)):
    require_admin(request)
    p = payload or {}
    kw: Dict[str, Any] = {}
    if "password" in p:
        pw = str(p.get("password") or "")
        if len(pw) < 6:
            raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
        kw["password"] = pw
    if "is_admin" in p:
        kw["is_admin"] = bool(p.get("is_admin"))
    if "pages" in p:
        pg = p.get("pages")
        kw["pages"] = pg if isinstance(pg, list) else []
    if "email" in p:
        kw["email"] = str(p.get("email") or "")
    if "mobile" in p:
        kw["mobile"] = str(p.get("mobile") or "")
    if "twofa_exempt" in p:
        kw["twofa_exempt"] = bool(p.get("twofa_exempt"))
    if "po_admin" in p:
        kw["po_admin"] = bool(p.get("po_admin"))
    if "is_admin" in p and bool(p.get("is_admin")):
        kw["po_admin"] = False
    trow = auth_users.get_user_by_id(int(user_id))
    tun = str((trow or {}).get("username") or "")
    try:
        auth_users.update_user(int(user_id), **kw)
        if "email" in p or "mobile" in p:
            row = auth_users.get_user_by_id(int(user_id))
            if row:
                try:
                    purchase_orders.sync_user_notification_contact(
                        int(row["id"]),
                        email=str(row.get("email") or ""),
                        mobile=str(row.get("mobile") or ""),
                    )
                except Exception:
                    pass
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    chg = [k for k in ("password", "is_admin", "po_admin", "pages", "email", "mobile", "twofa_exempt") if k in p]
    udet: Dict[str, Any] = {"user_id": int(user_id), "fields": chg}
    if "password" in p:
        udet["password_changed"] = True
    audit_log.record_request(
        request,
        "user.update",
        target_type="user",
        target_id=tun or str(user_id),
        detail=udet,
    )
    return {"ok": True}


@app.post("/api/users/{user_id}/reset-2fa")
def api_users_reset_2fa(request: Request, user_id: int):
    require_admin(request)
    trow = auth_users.get_user_by_id(int(user_id))
    if not trow:
        raise HTTPException(status_code=404, detail="User not found")
    tun = str(trow.get("username") or "")
    if not auth_users.reset_user_twofa(int(user_id)):
        raise HTTPException(status_code=404, detail="User not found")
    audit_log.record_request(
        request,
        "user.2fa.reset",
        target_type="user",
        target_id=tun or str(user_id),
        detail={"user_id": int(user_id)},
    )
    return {"ok": True}


@app.get("/api/firewall/status")
def api_firewall_status(request: Request):
    require_admin(request)
    try:
        st = firewall_ops.status()
    except firewall_ops.FirewallError as e:
        raise HTTPException(status_code=500, detail=str(e))
    return {"ok": True, "status": st}


@app.post("/api/firewall/allow")
def api_firewall_allow(request: Request, payload: Dict[str, Any] = Body(...)):
    require_admin(request)
    p = payload or {}
    target = str(p.get("target") or "").strip()
    direction = str(p.get("direction") or "in").strip().lower()
    port = p.get("port") or "any"
    protocol = str(p.get("protocol") or "any").strip().lower()
    try:
        res = firewall_ops.allow(target, direction=direction, port=port, protocol=protocol)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except firewall_ops.FirewallError as e:
        raise HTTPException(status_code=500, detail=str(e))
    return {"ok": True, "result": res}


@app.post("/api/firewall/deny")
def api_firewall_deny(request: Request, payload: Dict[str, Any] = Body(...)):
    require_admin(request)
    p = payload or {}
    target = str(p.get("target") or "").strip()
    direction = str(p.get("direction") or "in").strip().lower()
    port = p.get("port") or "any"
    protocol = str(p.get("protocol") or "any").strip().lower()
    try:
        res = firewall_ops.deny(target, direction=direction, port=port, protocol=protocol)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except firewall_ops.FirewallError as e:
        raise HTTPException(status_code=500, detail=str(e))
    return {"ok": True, "result": res}


@app.delete("/api/firewall/rules/{number}")
def api_firewall_delete_rule(request: Request, number: int):
    require_admin(request)
    try:
        res = firewall_ops.delete_rule(int(number))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except firewall_ops.FirewallError as e:
        raise HTTPException(status_code=500, detail=str(e))
    return {"ok": True, "result": res}


@app.delete("/api/users/{user_id}")
def api_users_delete(request: Request, user_id: int):
    require_admin(request)
    trow = auth_users.get_user_by_id(int(user_id))
    tun = str((trow or {}).get("username") or "")
    ok, err = auth_users.delete_user(int(user_id))
    if not ok:
        raise HTTPException(status_code=400, detail=err or "Could not delete user")
    audit_log.record_request(
        request,
        "user.delete",
        target_type="user",
        target_id=tun or str(user_id),
        detail={"deleted_user_id": int(user_id)},
    )
    return {"ok": True}


@app.get("/api/audit/events")
def api_audit_events(
    request: Request,
    limit: int = 100,
    offset: int = 0,
    event_type: str = "",
    actor: str = "",
):
    require_admin(request)
    return {
        "ok": True,
        "events": audit_log.list_events(
            limit=limit,
            offset=offset,
            event_type_prefix=(event_type or "")[:120],
            actor_username=(actor or "")[:120],
        ),
    }


@app.get("/api/monitoring/status")
def api_monitoring_status():
    rows, down_events = monitoring.status_snapshot_and_down_events()
    rows = monitoring.annotate_down_ack(rows)
    if down_events:
        try:
            push_notifications.send_device_down_push(down_events)
        except Exception:
            pass
    tabs = monitoring.list_tabs()
    site_groups = monitoring.list_site_groups()
    transitions = monitoring.recent_transition_events()
    outages = monitoring.recent_outage_events()
    return {
        "ok": True,
        "sampling_enabled": monitoring.is_monitoring_sampling_enabled(),
        "tabs": tabs,
        "site_groups": site_groups,
        "devices": rows,
        "transitions": transitions,
        "outages": outages,
    }


@app.post("/api/monitoring/devices/{device_id}/ack")
def api_monitoring_ack_down(device_id: int, request: Request):
    username = str(getattr(request.state, "username", "") or "").strip()
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        result = monitoring.acknowledge_down(int(device_id), username)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return result


@app.get("/api/push/vapid-public-key")
def api_push_vapid_public_key():
    st = push_notifications.push_configuration_status()
    if not st.get("ok"):
        return {
            "ok": False,
            "detail": st.get("detail") or "Web push is not available.",
            "python_executable": st.get("python_executable"),
        }
    return {
        "ok": True,
        "public_key": push_notifications.get_vapid_public_key_b64url(),
        "python_executable": st.get("python_executable"),
    }


@app.post("/api/push/subscribe")
def api_push_subscribe(request: Request, payload: Dict[str, Any] = Body(...)):
    p = payload or {}
    sub: Dict[str, Any]
    push_po = True
    push_monitoring = True
    if isinstance(p.get("subscription"), dict):
        sub = dict(p["subscription"])
        push_po = bool(p.get("push_po", True))
        push_monitoring = bool(p.get("push_monitoring", True))
    else:
        sub = dict(p)
    try:
        push_notifications.save_subscription(
            request.state.username,
            sub,
            push_po=push_po,
            push_monitoring=push_monitoring,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True}


@app.post("/api/push/unsubscribe")
def api_push_unsubscribe(request: Request, payload: Dict[str, Any] = Body(...)):
    ep = str((payload or {}).get("endpoint") or "")
    push_notifications.delete_subscription_for_user(request.state.username, ep)
    return {"ok": True}


@app.post("/api/push/test-self")
def api_push_test_self(request: Request):
    username = str(getattr(request.state, "username", "") or "").strip()
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated")
    push_notifications.send_user_push(
        username=username,
        title="Monitoring push test",
        body="Background push is enabled for this browser profile.",
        tag="monitoring-push-test",
        url="/monitoring",
        require_push_po=None,
        require_push_monitoring=True,
    )
    return {"ok": True}


@app.get("/api/push/subscriptions/status")
def api_push_subscription_status(request: Request):
    require_admin(request)
    counts = push_notifications.subscription_user_counts()
    by_user = {str(r.get("username") or ""): int(r.get("subscription_count") or 0) for r in counts}
    users = auth_users.list_users()
    rows = []
    seen: set[str] = set()
    for u in users:
        uname = str(u.get("username") or "")
        seen.add(uname)
        rows.append(
            {
                "user_id": int(u.get("id") or 0),
                "username": uname,
                "subscription_count": int(by_user.get(uname, 0)),
                "has_subscription": int(by_user.get(uname, 0)) > 0,
            }
        )
    # Fallback: if auth user list is unavailable/empty on this role, still expose push users.
    for uname, cnt in by_user.items():
        if uname in seen:
            continue
        rows.append(
            {
                "user_id": 0,
                "username": uname,
                "subscription_count": int(cnt),
                "has_subscription": int(cnt) > 0,
            }
        )
        seen.add(uname)
    current_username = str(getattr(request.state, "username", "") or "").strip()
    if current_username and current_username not in seen:
        rows.append(
            {
                "user_id": 0,
                "username": current_username,
                "subscription_count": int(by_user.get(current_username, 0)),
                "has_subscription": int(by_user.get(current_username, 0)) > 0,
            }
        )
    return {"ok": True, "users": rows}


@app.post("/api/push/test-user")
def api_push_test_user(request: Request, payload: Dict[str, Any] = Body(...)):
    require_admin(request)
    p = payload or {}
    user_id = int(p.get("user_id") or 0)
    username = str(p.get("username") or "").strip()
    if not username and user_id > 0:
        row = auth_users.get_user_by_id(user_id) or {}
        username = str(row.get("username") or "").strip()
    if not username:
        raise HTTPException(status_code=400, detail="username or user_id is required")
    push_notifications.send_user_push(
        username=username,
        title="Monitoring push test",
        body=f"Push test sent by {str(getattr(request.state, 'username', 'admin') or 'admin')}",
        tag=f"monitoring-push-test-{user_id}",
        url="/monitoring",
        require_push_po=None,
        require_push_monitoring=True,
    )
    return {"ok": True, "username": username}


def _can_delete_monitoring_tabs(request: Request) -> bool:
    """Privileged monitoring edits: DB admin (is_admin) or AUTH_SUPER_ADMIN_USERS."""
    if bool(getattr(request.state, "is_admin", False)):
        return True
    un = str(getattr(request.state, "username", "") or "").strip()
    return auth_users.user_is_super_admin(un)


@app.post("/api/monitoring/tabs")
def api_monitoring_tabs_add(payload: Dict[str, Any] = Body(...)):
    p = payload or {}
    name = p.get("name")
    display_mode = str(p.get("display_mode") or monitoring.TAB_DISPLAY_FLAT).strip().lower()
    try:
        tab_id = monitoring.add_tab(str(name or ""), display_mode)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True, "id": tab_id}


@app.delete("/api/monitoring/tabs/{tab_id}")
def api_monitoring_tabs_delete(tab_id: int, request: Request):
    if not _can_delete_monitoring_tabs(request):
        raise HTTPException(status_code=403, detail="Admin or super-admin only")
    try:
        ok = monitoring.delete_tab(int(tab_id))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not ok:
        raise HTTPException(status_code=404, detail="Tab not found")
    return {"ok": True}


@app.post("/api/monitoring/site-groups")
def api_monitoring_site_groups_add(payload: Dict[str, Any] = Body(...)):
    p = payload or {}
    try:
        tid = int(p.get("tab_id") or 0)
        gid = monitoring.add_site_group(tid, str(p.get("name") or ""))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True, "id": gid}


@app.delete("/api/monitoring/site-groups/{group_id}")
def api_monitoring_site_groups_delete(group_id: int, request: Request):
    if not _can_delete_monitoring_tabs(request):
        raise HTTPException(status_code=403, detail="Admin or super-admin only")
    if not monitoring.delete_site_group(int(group_id)):
        raise HTTPException(status_code=404, detail="Not found")
    return {"ok": True}


@app.post("/api/monitoring/devices")
def api_monitoring_add_device(payload: Dict[str, Any] = Body(...)):
    name = (payload or {}).get("name")
    target = (payload or {}).get("target") or (payload or {}).get("ip")
    warn_raw = (payload or {}).get("warn_latency_ms")
    warn_latency_ms = None
    if warn_raw is not None and warn_raw != "":
        try:
            warn_latency_ms = float(warn_raw)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="Invalid warn_latency_ms")
    tab_raw = (payload or {}).get("tab_id")
    if tab_raw is None:
        raise HTTPException(status_code=400, detail="Missing tab_id")
    try:
        tab_id = int(tab_raw)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid tab_id")
    sg_raw = (payload or {}).get("site_group_id")
    site_group_id = None
    if sg_raw is not None and str(sg_raw).strip() != "":
        try:
            site_group_id = int(sg_raw)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="Invalid site_group_id")
    try:
        device_id = monitoring.add_device(
            str(name or ""),
            str(target or ""),
            warn_latency_ms,
            tab_id=tab_id,
            site_group_id=site_group_id,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True, "id": device_id}


@app.post("/api/monitoring/devices/import")
def api_monitoring_import_devices(payload: Dict[str, Any] = Body(...)):
    """Bulk-create devices from multi-line text; each line is one target (see monitoring.parse_import_line)."""
    tab_raw = (payload or {}).get("tab_id")
    if tab_raw is None:
        raise HTTPException(status_code=400, detail="Missing tab_id")
    try:
        tab_id = int(tab_raw)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid tab_id")
    text = (payload or {}).get("text")
    if text is None:
        text = ""
    warn_latency_ms = None
    warn_raw = (payload or {}).get("warn_latency_ms")
    if warn_raw is not None and warn_raw != "":
        try:
            warn_latency_ms = float(warn_raw)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="Invalid warn_latency_ms")
    try:
        result = monitoring.import_devices_bulk(tab_id, str(text), warn_latency_ms)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True, "import": result}


@app.delete("/api/monitoring/devices/{device_id}")
def api_monitoring_delete_device(device_id: int):
    if not monitoring.delete_device(device_id):
        raise HTTPException(status_code=404, detail="Not found")
    return {"ok": True}


@app.get("/api/monitoring/history/{device_id}")
def api_monitoring_history(device_id: int, hours: float = 12.0):
    if hours < 0.1 or hours > 168:
        raise HTTPException(status_code=400, detail="hours must be between 0.1 and 168")
    pts = monitoring.fetch_history(device_id, hours=hours)
    if pts is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return {"ok": True, "hours": hours, "points": pts}


async def _monitoring_sample_loop():
    await asyncio.sleep(2.0)
    loop = asyncio.get_running_loop()
    while True:
        try:
            if monitoring.is_monitoring_sampling_enabled():

                def _sample_and_push():
                    ev = monitoring.record_sample_cycle()
                    if ev:
                        try:
                            push_notifications.send_device_down_push(ev)
                        except Exception:
                            pass

                await loop.run_in_executor(None, _sample_and_push)
        except Exception:
            pass
        await asyncio.sleep(float(monitoring.SAMPLE_INTERVAL_SEC))


def _backhaul_radio_sampler_interval_sec() -> float:
    """Align background SNMP cadence with UI poll (BACKHAUL_RADIO_POLL_MS)."""
    try:
        ms = int(os.getenv("BACKHAUL_RADIO_POLL_MS", "30000") or 30000)
    except (TypeError, ValueError):
        ms = 30000
    sec = ms / 1000.0
    return max(5.0, min(3600.0, sec))


def _backhaul_radio_background_sampling_enabled() -> bool:
    """When true (default), backhauls container records radio SNMP on a timer without an open browser tab."""
    v = (os.getenv("BACKHAUL_RADIO_BACKGROUND_SAMPLING") or "1").strip().lower()
    return v not in ("0", "false", "no", "off")


async def _backhaul_radio_sample_loop():
    """Periodic SNMP polls for all radios — mirrors browser live=1 recording (see BACKHAUL_RADIO_POLL_MS)."""
    if APP_ROLE not in ("backhauls",):
        return
    await asyncio.sleep(8.0)
    loop = asyncio.get_running_loop()
    while True:
        interval = _backhaul_radio_sampler_interval_sec()
        try:
            if (
                _backhaul_radio_background_sampling_enabled()
                and monitoring.is_monitoring_sampling_enabled()
            ):
                await loop.run_in_executor(None, backhauls.radios_overview_live)
        except Exception:
            LOG.exception("backhaul radio background SNMP sample failed")
        await asyncio.sleep(interval)


@app.on_event("startup")
async def _start_backhaul_radio_background_sampler():
    if APP_ROLE not in ("backhauls",):
        return
    asyncio.create_task(_backhaul_radio_sample_loop())


@app.on_event("startup")
async def _po_events_capture_loop():
    """Bind PO SSE publishing + cross-worker Redis fanout to this process loop."""
    global _po_events_loop, _po_events_redis_client, _po_events_redis_task
    _po_events_loop = asyncio.get_running_loop()
    if redis_async is None:
        return
    redis_url = (os.getenv("REDIS_URL") or "").strip()
    if not redis_url:
        return
    cli = None
    try:
        cli = redis_async.from_url(redis_url, decode_responses=False)
        await cli.ping()
    except Exception:
        try:
            if cli is not None:
                await cli.close()
        except Exception:
            pass
        return
    _po_events_redis_client = cli
    _po_events_redis_task = asyncio.create_task(_po_redis_subscriber_loop())


@app.on_event("shutdown")
async def _po_events_shutdown():
    global _po_events_redis_task, _po_events_redis_client
    if _po_events_redis_task is not None:
        _po_events_redis_task.cancel()
        try:
            await _po_events_redis_task
        except Exception:
            pass
        _po_events_redis_task = None
    if _po_events_redis_client is not None:
        try:
            await _po_events_redis_client.close()
        except Exception:
            pass
        _po_events_redis_client = None


@app.on_event("startup")
async def _security_warnings():
    import logging

    log = logging.getLogger("uvicorn.error")
    if not SESSION_SECRET:
        log.warning(
            "SESSION_SECRET is not set; session and WS signing use an insecure dev-only key. "
            "Set SESSION_SECRET to a long random string in production."
        )


@app.on_event("startup")
async def _start_monitoring_sampler():
    if APP_ROLE not in ("monitoring",):
        return
    asyncio.create_task(_monitoring_sample_loop())


async def _location_sync_scheduler():
    await asyncio.sleep(10.0)
    loop = asyncio.get_running_loop()
    while True:
        # Run strictly at local midnight (00:00) every day.
        now = datetime.now()
        next_midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
        if next_midnight <= now:
            next_midnight = next_midnight + timedelta(days=1)
        sleep_for = max(1.0, (next_midnight - now).total_seconds())
        await asyncio.sleep(sleep_for)
        try:
            if _splynx_enabled():
                await loop.run_in_executor(
                    None,
                    lambda: location_sync.run_full_sync(splynx_get),
                )
        except Exception:
            pass


async def _po_notification_scheduler():
    await asyncio.sleep(10.0)
    while True:
        try:
            r = dispatch_due_notifications(limit=200)
            if int((r or {}).get("processed") or 0) > 0:
                # Refresh PO pages when scheduled/due notifications were just delivered (no HTTP submit).
                _publish_po_event(0, "notifications_dispatch")
            resumed = purchase_orders.resume_due_postponed_pos()
            for rid in resumed:
                _publish_po_event(int(rid), "postponed_resume")
        except Exception:
            pass
        await asyncio.sleep(float(os.getenv("PO_NOTIFICATION_POLL_SEC", "60")))


async def _nightly_clone_scheduler():
    if APP_ROLE not in ("core",):
        return
    if not _clone_scheduler_allowed():
        return
    await asyncio.sleep(15.0)
    while True:
        cfg = clone_schedule.get()
        env_enabled = os.getenv("CLONE_NIGHTLY_ENABLED", "0").strip() == "1"
        enabled = _clone_scheduler_allowed() and (bool(cfg.get("enabled")) or env_enabled)
        if not enabled:
            await asyncio.sleep(30.0)
            continue
        use_env_fallback = not bool(cfg.get("target_host") or cfg.get("target_dir"))
        target_host = str(cfg.get("target_host") or (os.getenv("CLONE_TARGET_HOST", "").strip() if use_env_fallback else "")).strip()
        target_dir = str(cfg.get("target_dir") or (os.getenv("CLONE_TARGET_DIR", "").strip() if use_env_fallback else "")).strip()
        if not target_host or not target_dir:
            await asyncio.sleep(30.0)
            continue
        target_user = str(cfg.get("target_user") or os.getenv("CLONE_TARGET_USER", "root")).strip() or "root"
        target_port = int(cfg.get("target_port") or os.getenv("CLONE_TARGET_PORT", "22") or 22)
        ssh_key = str(cfg.get("ssh_key_path") or os.getenv("CLONE_SSH_KEY_PATH", "")).strip()
        host_fp = str(cfg.get("host_fingerprint") or os.getenv("CLONE_TARGET_FINGERPRINT", "")).strip()
        override_text = str(cfg.get("override_text") or os.getenv("CLONE_OVERRIDE_TEXT", ""))
        hh = max(0, min(23, int(cfg.get("hour") if cfg.get("hour") is not None else os.getenv("CLONE_NIGHTLY_HOUR", "0"))))
        mm = max(0, min(59, int(cfg.get("minute") if cfg.get("minute") is not None else os.getenv("CLONE_NIGHTLY_MINUTE", "0"))))
        now = datetime.now()
        nxt = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
        if nxt <= now:
            nxt = nxt + timedelta(days=1)
        await asyncio.sleep(max(1.0, (nxt - now).total_seconds()))
        try:
            if dr_runner.mode_status().get("role") == "primary":
                # this node is already promoted standby; avoid pushing clones out from failover node
                continue
            clone_runner.start_clone(
                target_host=target_host,
                target_user=target_user,
                target_port=target_port,
                target_dir=target_dir,
                ssh_key_path=ssh_key,
                confirm_phrase=f"CLONE {target_host}",
                dry_run=False,
                override_text=override_text,
                host_fingerprint=host_fp,
                profile="full",
                services=[],
            )
        except Exception:
            pass


@app.on_event("startup")
async def _start_location_sync_scheduler():
    if APP_ROLE not in ("location_sync",):
        return
    if not location_sync.is_location_sync_scheduler_enabled():
        return
    asyncio.create_task(_location_sync_scheduler())


@app.on_event("startup")
async def _start_po_notification_scheduler():
    if APP_ROLE not in ("purchase_orders",):
        return
    asyncio.create_task(_po_notification_scheduler())


@app.on_event("startup")
def _standby_sanitize_clone_schedule_json():
    """Cloned data/ may carry enabled=true from production; clear it when standby disables clone."""
    if APP_ROLE != "core":
        return
    if not _clone_scheduler_allowed():
        try:
            cfg = clone_schedule.get()
            if cfg.get("enabled"):
                merged = dict(cfg)
                merged["enabled"] = False
                clone_schedule.set_config(merged)
        except Exception:
            pass


@app.on_event("startup")
async def _start_nightly_clone_scheduler():
    if APP_ROLE != "core":
        return
    if not _clone_scheduler_allowed():
        return
    asyncio.create_task(_nightly_clone_scheduler())


@app.get("/api/fieldtech/customer/{customer_id}")
def api_fieldtech_customer(customer_id: int, request: Request):
    """Return customer radio IP (ipv4) and PPPoE credentials (login/password) where available.
    Also returns:
      - location_id (if available)
      - available_ips: free IPv4 addresses within 172.16.0.0/16 for matching location's configured Network IPv4 ranges
    """
    if customer_id <= 0:
        raise HTTPException(status_code=400, detail="Invalid customer_id")

    customer = _splynx_get_customer_by_id(customer_id)
    try:
        services = _splynx_get_first_ok(
            [
                (f"admin/customers/customer/{customer_id}/internet-services", None),
                ("admin/customers/internet-services", {"customer_id": customer_id}),
                ("admin/customers/services/internet", {"customer_id": customer_id}),
            ]
        ) or []
    except HTTPException as e:
        if int(e.status_code) == 404:
            services = []
        else:
            raise

    # Prefer an active service if present
    service = None
    if isinstance(services, list) and services:
        for s in services:
            if str(s.get("status", "")).lower() == "active":
                service = s
                break
        if service is None:
            service = services[0]

    # Radio IP: use service ipv4 when available
    radio_ip = None
    if isinstance(service, dict):
        radio_ip = service.get("ipv4") or service.get("ip") or service.get("ip_address")

    # PPPoE credentials: usually come from customer login/password or service login/password
    pppoe_username = None
    pppoe_password = None

    if isinstance(service, dict):
        pppoe_username = service.get("login") or service.get("pppoe_login") or service.get("username")
        pppoe_password = service.get("password") or service.get("pppoe_password")

    if not pppoe_username:
        pppoe_username = customer.get("login") or customer.get("username")

    password_available = bool(pppoe_password)

    # -------- Location -> Available IP addresses (172.16.0.0/16) --------
    location_id = _extract_location_id(customer if isinstance(customer, dict) else {}, service if isinstance(service, dict) else None)
    available_ips: List[str] = []
    ip_meta = {"truncated": False, "available_count": 0, "used_count": 0, "net_count": 0}
    ip_hint: Optional[str] = None

    if location_id:
        nets, net_hint = splynx_list_location_ipv4_networks(location_id)
        used, used_hint = splynx_list_used_ipv4_by_location(location_id)

        ip_meta["used_count"] = len(used)
        ip_meta["net_count"] = len(nets)

        # Enumerate hosts, filter to private supernet, subtract used
        for n in nets:
            try:
                # Clip to our supernet intersection
                if not n.overlaps(FIELDTECH_PRIVATE_SUPERNET):
                    continue
                # Iterating .hosts() on very large nets can be heavy; cap overall options.
                for host in n.hosts():
                    h = str(host)
                    # Ensure within the supernet
                    try:
                        if host not in FIELDTECH_PRIVATE_SUPERNET:
                            continue
                    except Exception:
                        pass
                    if h in used:
                        continue
                    available_ips.append(h)
                    if len(available_ips) >= FIELDTECH_MAX_IP_OPTIONS:
                        ip_meta["truncated"] = True
                        break
                if ip_meta["truncated"]:
                    break
            except Exception:
                continue

        available_ips.sort(key=lambda s: tuple(int(x) for x in s.split(".")))
        ip_meta["available_count"] = len(available_ips)

        # Provide a lightweight hint if something couldn't be loaded
        if net_hint or used_hint:
            parts = []
            if net_hint:
                parts.append(f"networks: {net_hint}")
            if used_hint:
                parts.append(f"used-ips: {used_hint}")
            ip_hint = "; ".join(parts)[:300]

    # -------------------------------------------------------------------

    return JSONResponse(
        {
            "ok": True,
            "customer_id": customer_id,
            "customer_name": (customer.get("name") or customer.get("full_name") or "") if isinstance(customer, dict) else "",
            "radio_ip": radio_ip,
            "antenna_ip": ipam.get_customer_ip(customer_id),
            "pppoe_username": pppoe_username,
            "pppoe_password": pppoe_password if password_available else None,
            "password_available": password_available,
            "location_id": location_id,
            "available_ips": available_ips,
            "ip_meta": ip_meta,
            "ip_hint": ip_hint,
        }
    )


@app.get("/api/runs")
def api_runs(days: int = 30, request: Request = None):
    runs = read_runs_last_days(days=days)
    return JSONResponse({"ok": True, "days": days, "runs": runs})


@app.get("/api/active")
async def api_active(request: Request):
    async with ACTIVE_LOCK:
        now = time.time()
        active_list = []
        for k, v in ACTIVE_RUNS.items():
            start_ts = float(v.get("start_ts", now))
            elapsed = max(0.0, now - start_ts)
            active_list.append(
                {
                    "id": k,
                    "user": v.get("user", "-"),
                    "target": v.get("target", "-"),
                    "freq": v.get("freq", None),
                    "started_ts": v.get("started_ts", "-"),
                    "elapsed_s": round(elapsed, 1),
                    "status": v.get("status", "running"),
                }
            )
    # sort newest first
    active_list.sort(key=lambda x: x.get("started_ts", ""), reverse=True)
    return JSONResponse({"ok": True, "active": active_list})


# -------------------- MTR Command Builder --------------------
def build_mtr_raw_command(target: str, interval_sec: float) -> List[str]:
    cmd: List[str] = []
    if USE_SUDO:
        cmd += ["sudo", "-n"]

    cmd += [
        MTR_BIN,
        "--raw",
        "--no-dns",
        "-i",
        f"{interval_sec:.2f}",
        "-c",
        "999999",
        target,
    ]
    return cmd


def safe_float(x: Any) -> Optional[float]:
    try:
        return float(x)
    except Exception:
        return None


# -------------------- Streaming Engine --------------------
async def stream_mtr_raw(
    target: str,
    freq: float,
    websocket: WebSocket,
    state: Dict[str, Any],
) -> Tuple[float, Optional[dict]]:
    """
    Stream mtr stdout to websocket and update `state` so the WS handler can log reliably
    even on early disconnect/cancel.
    state keys:
      - last_hops: List[dict]
      - final_hop: Optional[dict]
      - last_err: str
      - seen_output: bool
    """
    cmd = build_mtr_raw_command(target, freq)

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    start_ts = time.time()

    hops: Dict[int, HopStats] = {}
    last_emit = 0.0
    emit_period = max(0.2, freq)

    state.setdefault("last_hops", [])
    state.setdefault("final_hop", None)
    state.setdefault("last_err", "")
    state.setdefault("seen_output", False)

    async def safe_send(payload: dict) -> bool:
        try:
            await websocket.send_json(payload)
            return True
        except Exception:
            return False

    def compute_hop_list() -> List[dict]:
        hop_list = []
        prev_ip = None

        for hop_id in sorted(hops.keys()):
            h = hops[hop_id]
            ip = (h.ip or "").strip()

            if ip and prev_ip == ip:
                continue
            if ip:
                prev_ip = ip

            warmup = h.sent < WARMUP_PINGS
            jitter = None
            p95 = None
            p99 = None

            if warmup:
                loss = None
                avg = None
                last = None
                best = None
                worst = None
            else:
                avg = h.avg_eff()
                loss = h.loss_eff()
                last = h.last_eff_ms
                best = h.best_eff_ms
                worst = h.worst_eff_ms
                jitter = h.jitter_eff()
                p95 = h.pctl_eff(95.0)
                p99 = h.pctl_eff(99.0)

            hop_list.append(
                {
                    "hop": hop_id,
                    "host": h.host,
                    "ip": h.ip,
                    "snt": h.sent,
                    "rcvd": h.rcvd,
                    "snt_eff": h.sent_eff,
                    "rcvd_eff": h.rcvd_eff,
                    "warmup": warmup,
                    "warmup_need": WARMUP_PINGS,
                    "warmup_have": h.sent,
                    "loss": round(loss, 2) if loss is not None else None,
                    "last": round(last, 2) if last is not None else None,
                    "avg": round(avg, 2) if avg is not None else None,
                    "best": round(best, 2) if best is not None else None,
                    "worst": round(worst, 2) if worst is not None else None,
                    "jitter": round(jitter, 2) if jitter is not None else None,
                    "p95": round(p95, 2) if p95 is not None else None,
                    "p99": round(p99, 2) if p99 is not None else None,
                }
            )
        return hop_list

    def update_state() -> None:
        try:
            hl = compute_hop_list()
            state["last_hops"] = hl
            state["final_hop"] = hl[-1] if hl else None
        except BaseException:
            pass

    async def emit_snapshot() -> bool:
        nonlocal last_emit
        now = time.time()
        last_emit = now

        hop_list = compute_hop_list()
        state["last_hops"] = hop_list
        state["final_hop"] = hop_list[-1] if hop_list else None
        state["seen_output"] = True

        return await safe_send(
            {
                "type": "snapshot",
                "ts": now,
                "ok": True,
                "target": target,
                "proto": "icmp",
                "port": None,
                "freq": freq,
                "hops": hop_list,
            }
        )

    async def pump_stderr() -> None:
        assert proc.stderr is not None
        while True:
            b = await proc.stderr.readline()
            if not b:
                break
            msg = b.decode(errors="ignore").strip()
            if not msg:
                continue
            state["last_err"] = msg
            await safe_send({"type": "error", "message": msg})

    stderr_task = asyncio.create_task(pump_stderr())

    try:
        assert proc.stdout is not None

        ok = await safe_send(
            {
                "type": "status",
                "message": f"Live MTR → {target} (ICMP) @ {freq:.2f}s (warm-up {WARMUP_PINGS} pings)",
            }
        )
        if not ok:
            update_state()
            return (time.time() - start_ts, state.get("final_hop"))

        ok = await emit_snapshot()
        if not ok:
            update_state()
            return (time.time() - start_ts, state.get("final_hop"))

        while True:
            line = await proc.stdout.readline()
            if not line:
                break

            s = line.decode(errors="ignore").strip()
            if not s:
                continue

            parts = s.split()
            tag = parts[0].lower()

            if tag == "h" and len(parts) >= 3:
                pos = int(parts[1])
                ip = parts[2]
                st = hops.get(pos) or HopStats(hop=pos)
                st.ip = ip
                st.host = ip
                hops[pos] = st

            elif tag == "x" and len(parts) >= 3:
                pos = int(parts[1])
                st = hops.get(pos) or HopStats(hop=pos)
                st.on_sent()
                hops[pos] = st

            elif tag == "p" and len(parts) >= 4:
                pos = int(parts[1])
                usec = safe_float(parts[2])
                if usec is not None:
                    ms = usec / 1000.0
                    st = hops.get(pos) or HopStats(hop=pos)
                    st.on_reply(ms)
                    hops[pos] = st

            now = time.time()
            if now - last_emit >= emit_period:
                ok = await emit_snapshot()
                if not ok:
                    break

    finally:
        # Termination: when running via sudo, the child PID is root-owned, so SIGTERM from
        # this user can raise PermissionError. Fall back to sudo kill.
        if proc.returncode is None:
            try:
                proc.terminate()
            except PermissionError:
                if USE_SUDO and proc.pid:
                    try:
                        k = await asyncio.create_subprocess_exec("sudo", "-n", "/usr/bin/kill", "-TERM", str(proc.pid))
                        await k.wait()
                    except Exception:
                        pass
            except Exception:
                pass

            try:
                await asyncio.wait_for(proc.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except PermissionError:
                    if USE_SUDO and proc.pid:
                        try:
                            k = await asyncio.create_subprocess_exec("sudo", "-n", "/usr/bin/kill", "-KILL", str(proc.pid))
                            await k.wait()
                        except Exception:
                            pass
                except Exception:
                    pass

        stderr_task.cancel()
        try:
            await stderr_task
        except BaseException:
            pass

        update_state()

    duration = time.time() - start_ts
    return (duration, state.get("final_hop"))


# -------------------- WebSocket Endpoint --------------------
@app.websocket("/ws/mtr")
async def ws_mtr(websocket: WebSocket):
    token = websocket.query_params.get("token", "")
    username = verify_ws_token(token)
    if not username:
        await websocket.close(code=1008)
        return

    await websocket.accept()

    conn_id = secrets.token_hex(8)

    target = ""
    freq = 1.0
    duration = 0.0
    final_hop: Optional[dict] = None

    run_state: Dict[str, Any] = {}
    run_start: Optional[float] = None

    try:
        try:
            msg = await websocket.receive_json()
        except Exception:
            await websocket.close(code=1008)
            return

        target = str(msg.get("target", "")).strip()
        if not target or len(target) > 255 or not TARGET_RE.match(target):
            await websocket.send_json({"type": "error", "message": "Invalid target."})
            await websocket.close(code=1008)
            return

        freq = clamp_freq(msg.get("freq", 1.0))

        # Register active run
        try:
            started_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            async with ACTIVE_LOCK:
                ACTIVE_RUNS[conn_id] = {
                    "user": username,
                    "target": target,
                    "freq": freq,
                    "start_ts": time.time(),
                    "started_ts": started_ts,
                    "status": "running",
                }
        except Exception:
            pass

        if not USE_SUDO and freq < 1.0:
            await websocket.send_json(
                {"type": "error", "message": "This server requires USE_SUDO=1 for intervals < 1.0s. Choose 1.0s."}
            )
            await websocket.close(code=1008)
            return

        run_start = time.monotonic()
        duration, final_hop = await stream_mtr_raw(target, freq, websocket, run_state)

        # Prefer WS-computed duration (works even if stream returns early)
        if run_start is not None:
            duration = max(0.0, time.monotonic() - run_start)
            # v1.0.4: avoid 0.0s display on extremely fast stops
            if 0.0 < duration < 0.05:
                duration = 0.1

        # Prefer state final hop if available
        final_hop = run_state.get("final_hop") or final_hop

    except WebSocketDisconnect:
        pass
    finally:
        # Mark run stopped (so /api/active updates fast)
        try:
            async with ACTIVE_LOCK:
                if conn_id in ACTIVE_RUNS:
                    ACTIVE_RUNS[conn_id]["status"] = "stopped"
        except Exception:
            pass

        # ✅ Always log stop events, but mark complete/incomplete.
        # v1.0.4: Improve stop logging so Run History rows have useful values even on very short runs.
        # Prefer the last known hop from run_state if final_hop is missing (e.g., stop before first hop snapshot).
        try:
            if not final_hop and isinstance(run_state, dict):
                lh = run_state.get("last_hops") or []
                if isinstance(lh, list) and lh:
                    final_hop = lh[-1]
        except Exception:
            pass

        try:
            ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

            # Debug reason and stderr (space-safe)
            reason = "-"
            if not target:
                reason = "no_target"
            elif not final_hop or (final_hop.get("ip") in (None, "", "-")):
                reason = "no_hops"
            elif bool(final_hop.get("warmup")):
                reason = "stopped_during_warmup"

            last_err = ""
            try:
                last_err = (run_state or {}).get("last_err", "") or ""
            except Exception:
                last_err = ""

            err_b64 = "-"
            if last_err:
                err_b64 = base64.urlsafe_b64encode(last_err.encode("utf-8", errors="ignore")).decode().rstrip("=")

            # Consider complete as soon as we have a hop with a real IP and at least one send.
            # Do NOT require warmup completion, otherwise many real runs get filtered out.
            complete = bool(
                target
                and final_hop
                and (final_hop.get("ip") not in (None, "", "-"))
                and ((final_hop.get("snt") or 0) > 0)
            )

            status_txt = "complete" if complete else "incomplete"

            dst_ip = ((final_hop.get("ip") or "").strip() if final_hop else "") or "-"
            hop_n = (final_hop.get("hop") if final_hop else "-") or "-"

            avg = final_hop.get("avg") if final_hop else None
            loss = final_hop.get("loss") if final_hop else None
            last = final_hop.get("last") if final_hop else None
            best = final_hop.get("best") if final_hop else None
            worst = final_hop.get("worst") if final_hop else None

            snt = final_hop.get("snt") if final_hop else None
            rcvd = final_hop.get("rcvd") if final_hop else None
            snt_eff = final_hop.get("snt_eff") if final_hop else None
            rcvd_eff = final_hop.get("rcvd_eff") if final_hop else None

            line = (
                f"{ts} "
                f"user={username} "
                f"target={target or '-'} "
                f"status={status_txt} "
                f"reason={reason} "
                f"err_b64={err_b64} "
                f"freq={freq:.2f}s "
                f"dur={duration:.1f}s "
                f"dst={dst_ip} "
                f"hop={hop_n} "
                f"avg={avg if avg is not None else '-'}ms "
                f"loss={loss if loss is not None else '-'}% "
                f"last={last if last is not None else '-'}ms "
                f"best={best if best is not None else '-'}ms "
                f"worst={worst if worst is not None else '-'}ms "
                f"snt={snt if snt is not None else '-'} "
                f"rcvd={rcvd if rcvd is not None else '-'} "
                f"snt_eff={snt_eff if snt_eff is not None else '-'} "
                f"rcvd_eff={rcvd_eff if rcvd_eff is not None else '-'}"
            )

            append_run_log(line)
            print(f"[RUNLOG] status={status_txt} target={target} dst={dst_ip} reason={reason}")
        except Exception as e:
            print(f"[RUNLOG] FAILED building log line: {e!r}")
        finally:
            # Remove from active runs
            try:
                async with ACTIVE_LOCK:
                    ACTIVE_RUNS.pop(conn_id, None)
            except Exception:
                pass



@app.post("/api/pdf_summary")
async def api_pdf_summary(request: Request):
    """Generate a 1-page management PDF summary (latency + packet loss)."""
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "invalid_json"}, status_code=400)

    user = str(data.get("user") or getattr(request.state, "username", "") or "")
    target = str(data.get("target") or "-")
    dest = str(data.get("destination_ip") or "-")
    freq_s = data.get("freq_s", None)

    avg_lat = data.get("avg_latency_ms", None)
    worst_lat = data.get("worst_latency_ms", None)
    avg_loss = data.get("avg_loss_pct", None)
    samples = data.get("samples", None)

    lat_series = data.get("latency_series_ms") or []
    loss_series = data.get("loss_series_pct") or []

    def _to_floats(xs, limit=900):
        out = []
        try:
            for v in xs[:limit]:
                try:
                    fv = float(v)
                    if fv == fv and fv not in (float("inf"), float("-inf")):
                        out.append(fv)
                except Exception:
                    continue
        except Exception:
            pass
        return out

    lat_series = _to_floats(lat_series)
    loss_series = _to_floats(loss_series)

    try:
        import io
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
        from reportlab.lib.units import mm
        from reportlab.lib import colors
        from reportlab.graphics.shapes import Drawing, Line, PolyLine, Polygon, String, Rect
        from reportlab.graphics import renderPDF

        buf = io.BytesIO()
        c = canvas.Canvas(buf, pagesize=A4)
        W, H = A4

        margin = 14 * mm
        x0 = margin
        y = H - margin

        c.setFont("Helvetica-Bold", 16)
        c.drawString(x0, y, "MTR Live — Executive Summary")
        y -= 18

        c.setFont("Helvetica", 9)
        c.setFillColor(colors.grey)
        meta = f"User: {user or '-'}   Target: {target}   Destination: {dest}   Frequency: {freq_s if freq_s is not None else '-'}s"
        c.drawString(x0, y, meta)
        c.setFillColor(colors.black)
        y -= 14

        card_w = (W - 2*margin - 2*8*mm) / 3.0
        card_h = 22 * mm
        gap = 8 * mm

        def fmt(v, d=1):
            try:
                if v is None:
                    return "—"
                return f"{float(v):.{d}f}"
            except Exception:
                return "—"

        def draw_card(ix, title, value, unit=""):
            cx = x0 + ix*(card_w + gap)
            cy = y - card_h
            c.setStrokeColor(colors.lightgrey)
            c.roundRect(cx, cy, card_w, card_h, 8, stroke=1, fill=0)
            c.setFont("Helvetica", 9)
            c.setFillColor(colors.grey)
            c.drawString(cx + 8, cy + card_h - 12, title)
            c.setFillColor(colors.black)
            c.setFont("Helvetica-Bold", 16)
            c.drawString(cx + 8, cy + 8, f"{value}{unit}")

        draw_card(0, "Avg Latency", fmt(avg_lat, 1), " ms")
        draw_card(1, "Worst Latency", fmt(worst_lat, 1), " ms")
        draw_card(2, "Avg Packet Loss", fmt(avg_loss, 2), " %")

        y -= card_h + 10*mm

        chart_w = W - 2*margin
        chart_h = 70 * mm

        c.setFont("Helvetica", 10)
        c.drawString(x0, y, "Latency (ms) over time — destination hop")
        y -= 6*mm

        d = Drawing(chart_w, chart_h)
        d.add(Rect(0, 0, chart_w, chart_h, strokeColor=colors.lightgrey, fillColor=colors.white, rx=10, ry=10))

        padL, padR, padT, padB = 28, 10, 14, 22
        px0, py0 = padL, padB
        pw, ph = chart_w - padL - padR, chart_h - padT - padB

        d.add(Line(px0, py0, px0+pw, py0, strokeColor=colors.lightgrey))
        d.add(Line(px0, py0, px0, py0+ph, strokeColor=colors.lightgrey))

        if len(lat_series) >= 2:
            mn = min(lat_series)
            mx = max(lat_series)
            if mn == mx:
                mn = max(0.0, mn - 1.0)
                mx = mx + 1.0
            span = (mx - mn) or 1.0

            for i in range(5):
                tv = mn + span * (i/4.0)
                yy = py0 + ph * ((tv - mn) / span)
                d.add(Line(px0, yy, px0+pw, yy, strokeColor=colors.whitesmoke))
                d.add(String(px0-4, yy-3, f"{tv:.0f}", fontSize=8, fillColor=colors.grey, textAnchor="end"))

            pts = []
            n = len(lat_series)
            for i, v in enumerate(lat_series):
                x = px0 + pw * (i/(n-1))
                yy = py0 + ph * ((v - mn)/span)
                pts.append((x, yy))

            orange = colors.Color(1.0, 0.549, 0.0)
            fill_pts = [(pts[0][0], py0)] + pts + [(pts[-1][0], py0)]
            # Polygon expects a flat point list: [x1, y1, x2, y2, ...]
            fill_flat = []
            for x, y_ in fill_pts:
                fill_flat.extend([x, y_])
            d.add(Polygon(fill_flat, strokeColor=None, fillColor=colors.Color(1.0, 0.549, 0.0, alpha=0.18)))
            d.add(PolyLine(pts, strokeColor=orange, strokeWidth=1.8))
        else:
            d.add(String(px0+10, py0+ph/2, "Not enough data to chart yet.", fontSize=10, fillColor=colors.grey))

        d.add(String(px0, 6, "Time →", fontSize=8, fillColor=colors.grey))
        d.add(String(8, chart_h-12, "ms", fontSize=8, fillColor=colors.grey))

        renderPDF.draw(d, c, x0, y - chart_h)
        y -= chart_h + 10*mm

        c.setFont("Helvetica", 8)
        c.setFillColor(colors.grey)
        c.drawString(x0, y, f"Samples (post-warmup): {samples if samples is not None else '-'}   Loss points: {len(loss_series)}")
        y -= 10
        c.drawString(x0, y, "Note: Summary is based on destination hop series as reported by the live UI. Warm-up excluded by design.")

        c.showPage()
        c.save()

        pdf_bytes = buf.getvalue()
        buf.close()
        return Response(content=pdf_bytes, media_type="application/pdf")
    except ModuleNotFoundError as e:
        return JSONResponse({"ok": False, "error": "reportlab_missing", "detail": str(e)}, status_code=500)
    except Exception as e:
        return JSONResponse({"ok": False, "error": "pdf_failed", "detail": repr(e)}, status_code=500)



