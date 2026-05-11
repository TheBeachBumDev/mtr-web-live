"""Authenticated HTML pages (Jinja). Router is included from main after WS/MTR helpers exist."""

import base64
import json
import logging
import os
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

import auth_users
import monitoring
import server_resources
from access_control import require_admin
from app_config import APP_ROLE
from templates_env import templates

router = APIRouter()


def _b64_json_utf8(obj: Any) -> str:
    """Embed JSON inside HTML without '<' sequences that can break <script> parsing."""
    raw = json.dumps(obj, default=str, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


@router.get("/", response_class=HTMLResponse)
def home_page(request: Request):
    if APP_ROLE in ("monitoring", "routers", "backhauls", "edge"):
        target = {
            "monitoring": "/monitoring",
            "routers": "/routers",
            "backhauls": "/backhauls",
            "edge": "/routers",
        }[APP_ROLE]
        return RedirectResponse(url=target, status_code=302)
    username = request.state.username if hasattr(request.state, "username") else "unknown"
    return templates.TemplateResponse(
        "home.html",
        {
            "request": request,
            "username": username,
            "active_tab": "home",
            "title": "Home",
        },
    )


@router.get("/mtr-live", response_class=HTMLResponse)
def mtr_live_page(request: Request):
    if APP_ROLE in ("monitoring", "routers", "backhauls", "edge"):
        target = {
            "monitoring": "/monitoring",
            "routers": "/routers",
            "backhauls": "/backhauls",
            "edge": "/routers",
        }[APP_ROLE]
        return RedirectResponse(url=target, status_code=302)
    # Import inside handler so routes.web_html never imports main at module load (avoids cycles).
    from main import (
        MIN_FREQ_SEC,
        RUN_LOG_PATH,
        USE_SUDO,
        WARMUP_PINGS,
        make_ws_token,
    )
    username = request.state.username if hasattr(request.state, "username") else "unknown"
    return templates.TemplateResponse("index.html", {
        "request": request,
        "username": username,
        "active_tab": "mtr_live",
        "title": "MTR Live",
        "default_freq": 1.0,
        "min_freq": MIN_FREQ_SEC,
        "warmup_pings": WARMUP_PINGS,
        "ws_token": make_ws_token(username),
        "use_sudo": USE_SUDO,
        "run_log_path": RUN_LOG_PATH,
    })


@router.get("/fieldtech", response_class=HTMLResponse)
def fieldtech_page(request: Request):
    username = request.state.username if hasattr(request.state, "username") else "unknown"
    return templates.TemplateResponse("fieldtech.html", {
        "request": request,
        "username": username,
        "active_tab": "fieldtech",
        "title": "Field Tech",
    })


@router.get("/stock-management", response_class=HTMLResponse)
def stock_management_page(request: Request):
    username = request.state.username if hasattr(request.state, "username") else "unknown"
    return templates.TemplateResponse(
        "stock_management.html",
        {
            "request": request,
            "username": username,
            "active_tab": "stock_management",
            "title": "Stock Management",
            "is_admin": bool(getattr(request.state, "is_admin", False)),
        },
    )


@router.get("/purchase-orders", response_class=HTMLResponse)
def purchase_orders_page(request: Request):
    username = request.state.username if hasattr(request.state, "username") else "unknown"
    return templates.TemplateResponse(
        "purchase_orders.html",
        {
            "request": request,
            "username": username,
            "active_tab": "purchase_orders",
            "title": "Purchase Orders",
            "is_admin": bool(getattr(request.state, "is_admin", False)),
        },
    )


@router.get("/whatsapp-signups", response_class=HTMLResponse)
def whatsapp_signups_page(request: Request):
    username = request.state.username if hasattr(request.state, "username") else "unknown"
    return templates.TemplateResponse(
        "whatsapp_signups.html",
        {
            "request": request,
            "username": username,
            "active_tab": "whatsapp_signups",
            "title": "Whatsapp Signups",
        },
    )


@router.get("/ipam", response_class=HTMLResponse)
def ipam_page(request: Request):
    username = request.state.username if hasattr(request.state, "username") else "unknown"
    return templates.TemplateResponse("ipam.html", {"request": request, "username": username, "active_tab": "ipam", "title": "IPAM"})


@router.get("/routers", response_class=HTMLResponse)
def routers_page(request: Request):
    username = request.state.username if hasattr(request.state, "username") else "unknown"
    return templates.TemplateResponse(
        "routers.html",
        {
            "request": request,
            "username": username,
            "active_tab": "routers",
            "title": "Routers",
        },
    )


@router.get("/backhauls", response_class=HTMLResponse)
def backhauls_page(request: Request):
    username = request.state.username if hasattr(request.state, "username") else "unknown"
    is_admin = bool(getattr(request.state, "is_admin", False))
    poll_ms = int(os.getenv("BACKHAUL_RADIO_POLL_MS", "30000"))
    poll_ms = max(5000, min(600000, poll_ms))
    return templates.TemplateResponse(
        "backhauls.html",
        {
            "request": request,
            "username": username,
            "is_admin": is_admin,
            "active_tab": "backhauls",
            "title": "Backhauls",
            "radio_poll_ms": poll_ms,
        },
    )


@router.get("/location-sync", response_class=HTMLResponse)
def location_sync_page(request: Request):
    username = request.state.username if hasattr(request.state, "username") else "unknown"
    return templates.TemplateResponse(
        "location_sync.html",
        {
            "request": request,
            "username": username,
            "active_tab": "location_sync",
            "title": "Location Sync",
        },
    )


@router.get("/monitoring", response_class=HTMLResponse)
def monitoring_page(request: Request):
    username = request.state.username if hasattr(request.state, "username") else "unknown"
    can_manage_push_tests = bool(getattr(request.state, "is_admin", False))
    return templates.TemplateResponse(
        "monitoring.html",
        {
            "request": request,
            "username": username,
            "is_admin": bool(getattr(request.state, "is_admin", False)),
            "can_manage_push_tests": can_manage_push_tests,
            "active_tab": "monitoring",
            "title": "Monitoring",
            "default_warn_ms": int(monitoring.DEFAULT_WARN_MS),
            "down_after_fails": int(monitoring.DOWN_AFTER_CONSECUTIVE_FAILS),
        },
    )


@router.get("/sales-log", response_class=HTMLResponse)
def sales_log_page(request: Request):
    username = request.state.username
    return templates.TemplateResponse(
        "sales_log.html",
        {
            "request": request,
            "username": username,
            "is_admin": bool(getattr(request.state, "is_admin", False)),
            "active_tab": "sales_log",
            "title": "Sales Log",
        },
    )


@router.get("/resources", response_class=HTMLResponse)
def resources_page(request: Request):
    username = request.state.username if hasattr(request.state, "username") else "unknown"
    # Same JSON as GET /api/resources, inlined so the dashboard fills even when fetch() fails
    # (reverse-proxy path mismatch, extensions, or offline tooling).
    try:
        resources_initial_snapshot = server_resources.snapshot()
    except Exception as e:
        logging.exception("resources_page: embedded snapshot failed")
        resources_initial_snapshot = {
            "ok": False,
            "error": str(e),
            "metrics": {},
            "module_topology": server_resources.MODULE_TOPOLOGY,
        }
    return templates.TemplateResponse(
        "resources.html",
        {
            "request": request,
            "username": username,
            "active_tab": "resources",
            "title": "Resources",
            "topology_bootstrap": server_resources.MODULE_TOPOLOGY,
            "topology_bootstrap_b64": _b64_json_utf8(server_resources.MODULE_TOPOLOGY),
            "resources_initial_snapshot": resources_initial_snapshot,
            "resources_initial_snapshot_b64": _b64_json_utf8(resources_initial_snapshot),
            "can_clone": bool(getattr(request.state, "is_admin", False)),
        },
    )


@router.get("/backups", response_class=HTMLResponse)
def backups_page(request: Request):
    username = getattr(request.state, "username", "unknown")
    return templates.TemplateResponse(
        "backups.html",
        {
            "request": request,
            "username": username,
            "active_tab": "backups",
            "title": "Backups",
        },
    )


@router.get("/firewall", response_class=HTMLResponse)
def firewall_page(request: Request):
    username = getattr(request.state, "username", "")
    return templates.TemplateResponse(
        "firewall.html",
        {
            "request": request,
            "username": username,
            "active_tab": "firewall",
            "title": "Firewall",
        },
    )


@router.get("/users", response_class=HTMLResponse)
def users_admin_page(request: Request):
    require_admin(request)
    username = getattr(request.state, "username", "unknown")
    return templates.TemplateResponse(
        "users.html",
        {
            "request": request,
            "username": username,
            "active_tab": "users",
            "title": "Users",
            "page_definitions": auth_users.PAGE_DEFINITIONS,
        },
    )


@router.get("/audit-log", response_class=HTMLResponse)
def audit_log_page(request: Request):
    require_admin(request)
    username = getattr(request.state, "username", "unknown")
    return templates.TemplateResponse(
        "audit_log.html",
        {
            "request": request,
            "username": username,
            "active_tab": "audit_log",
            "title": "Audit log",
        },
    )
