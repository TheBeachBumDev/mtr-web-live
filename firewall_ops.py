import ipaddress
import json
import os
import re
import urllib.error
import urllib.request
from typing import Any, Dict, List


FIREWALL_AGENT_URL = os.getenv("FIREWALL_AGENT_URL", "http://host.docker.internal:9191").strip().rstrip("/")
FIREWALL_AGENT_TOKEN = os.getenv("FIREWALL_AGENT_TOKEN", "").strip()
UFW_TIMEOUT_SEC = max(2, min(20, int(float(os.getenv("UFW_TIMEOUT_SEC", "10")))))
MAX_RANGE_CIDRS = max(1, min(2048, int(os.getenv("UFW_MAX_RANGE_CIDRS", "256"))))

_RULE_NUM_RE = re.compile(r"^\[\s*(\d+)\]\s*(.+)$")


class FirewallError(RuntimeError):
    pass


def _normalize_direction(direction: str) -> str:
    d = (direction or "in").strip().lower()
    if d not in ("in", "out"):
        raise ValueError("Direction must be 'in' or 'out'")
    return d


def _normalize_protocol(protocol: str) -> str:
    p = (protocol or "any").strip().lower()
    if p not in ("any", "tcp", "udp"):
        raise ValueError("Protocol must be any, tcp, or udp")
    return p


def _normalize_port(port: Any) -> str:
    s = str(port or "").strip().lower()
    if not s or s == "any":
        return "any"
    if not s.isdigit():
        raise ValueError("Port must be a number or 'any'")
    n = int(s)
    if n < 1 or n > 65535:
        raise ValueError("Port must be between 1 and 65535")
    return str(n)


def _normalize_rule_params(direction: str, port: Any, protocol: str) -> Dict[str, str]:
    d = _normalize_direction(direction)
    p = _normalize_port(port)
    proto = _normalize_protocol(protocol)
    if p != "any" and proto == "any":
        # Port-specific rules almost always intend TCP if unspecified.
        proto = "tcp"
    if p == "any" and proto != "any":
        raise ValueError("Protocol filter requires a specific port")
    return {"direction": d, "port": p, "protocol": proto}


def _agent_request(method: str, path: str, payload: Dict[str, Any] = None) -> Dict[str, Any]:
    if not FIREWALL_AGENT_URL:
        raise FirewallError("FIREWALL_AGENT_URL is not configured")
    if not FIREWALL_AGENT_TOKEN:
        raise FirewallError("FIREWALL_AGENT_TOKEN is not configured")

    url = f"{FIREWALL_AGENT_URL}{path}"
    body = None
    headers = {
        "X-Firewall-Token": FIREWALL_AGENT_TOKEN,
        "Accept": "application/json",
    }
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url=url, method=method, data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=UFW_TIMEOUT_SEC) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            data = json.loads(raw or "{}")
            if not data.get("ok", False):
                raise FirewallError(str(data.get("error") or "Firewall agent request failed"))
            return data
    except urllib.error.HTTPError as e:
        raw = ""
        try:
            raw = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        try:
            data = json.loads(raw or "{}")
            msg = data.get("error") or data.get("detail") or raw
        except Exception:
            msg = raw or str(e)
        raise FirewallError(f"Firewall agent error: {msg}")
    except urllib.error.URLError as e:
        raise FirewallError(f"Firewall agent unreachable at {FIREWALL_AGENT_URL}") from e
    except json.JSONDecodeError as e:
        raise FirewallError("Firewall agent returned invalid JSON") from e


def _normalize_target(spec: str) -> List[str]:
    raw = (spec or "").strip()
    if not raw:
        raise ValueError("Target is required")

    # Single IP or CIDR.
    try:
        if "/" in raw:
            net = ipaddress.ip_network(raw, strict=False)
            return [str(net)]
        ip = ipaddress.ip_address(raw)
        return [str(ip)]
    except ValueError:
        pass

    # Range: start-end
    if "-" in raw:
        a, b = [x.strip() for x in raw.split("-", 1)]
        start = ipaddress.ip_address(a)
        end = ipaddress.ip_address(b)
        if start.version != end.version:
            raise ValueError("Range endpoints must be same IP version")
        if int(start) > int(end):
            raise ValueError("Range start must be <= end")
        cidrs = [str(n) for n in ipaddress.summarize_address_range(start, end)]
        if len(cidrs) > MAX_RANGE_CIDRS:
            raise ValueError("Range expands to too many CIDRs; narrow it")
        return cidrs

    raise ValueError("Target must be IP, CIDR, or IP range (start-end)")


def status() -> Dict[str, Any]:
    data = _agent_request("GET", "/status")
    out = str(data.get("raw") or "")
    rules: List[Dict[str, Any]] = []
    for line in out.splitlines():
        m = _RULE_NUM_RE.match(line.strip())
        if not m:
            continue
        rules.append({"number": int(m.group(1)), "text": m.group(2).strip()})
    return {"raw": out, "rules": rules}


def allow(target_spec: str, direction: str = "in", port: Any = "any", protocol: str = "any") -> Dict[str, Any]:
    targets = _normalize_target(target_spec)
    params = _normalize_rule_params(direction, port, protocol)
    d = params["direction"]
    p = params["port"]
    proto = params["protocol"]
    data = _agent_request("POST", "/allow", {"targets": targets, "direction": d, "port": p, "protocol": proto})
    return {
        "action": "allow",
        "targets": data.get("targets") or targets,
        "direction": d,
        "port": p,
        "protocol": proto,
    }


def deny(target_spec: str, direction: str = "in", port: Any = "any", protocol: str = "any") -> Dict[str, Any]:
    targets = _normalize_target(target_spec)
    params = _normalize_rule_params(direction, port, protocol)
    d = params["direction"]
    p = params["port"]
    proto = params["protocol"]
    data = _agent_request("POST", "/deny", {"targets": targets, "direction": d, "port": p, "protocol": proto})
    return {
        "action": "deny",
        "targets": data.get("targets") or targets,
        "direction": d,
        "port": p,
        "protocol": proto,
    }


def delete_rule(number: int) -> Dict[str, Any]:
    n = int(number)
    if n <= 0:
        raise ValueError("Rule number must be positive")
    data = _agent_request("DELETE", f"/rules/{n}")
    return {"action": "delete", "number": int(data.get("number") or n)}
