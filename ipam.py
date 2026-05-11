# v1.0.7-hotfix4
# Local IPAM datastore helpers
import os
import sqlite3
import ipaddress
from datetime import datetime
from typing import Optional, Tuple, List, Dict, Any
import db_runtime

DB_PATH = os.getenv("IPAM_DB_PATH", os.path.join("data", "ipam.db"))

def _ensure_db_dir():
    d = os.path.dirname(DB_PATH)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)

def get_conn() -> sqlite3.Connection:
    return db_runtime.get_conn("ipam")

def init_db():
    db_runtime.init_postgres_schema()

def _now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"

def list_locations() -> List[Dict[str, Any]]:
    conn = get_conn()
    rows = conn.execute("SELECT id, name FROM ipam_locations ORDER BY name ASC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def create_location(name: str) -> int:
    name = (name or "").strip()
    if not name:
        raise ValueError("Location name required")
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO ipam_locations(name, created_at) VALUES(?,?)", (name, _now()))
    conn.commit()
    lid = cur.lastrowid
    conn.close()
    return int(lid)

def list_networks(location_id: int) -> List[Dict[str, Any]]:
    conn = get_conn()
    rows = conn.execute(
        "SELECT id, location_id, cidr, active FROM ipam_networks WHERE location_id=? ORDER BY cidr ASC",
        (int(location_id),),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def create_network(location_id: int, cidr: str) -> int:
    cidr = (cidr or "").strip()
    if not cidr:
        raise ValueError("CIDR required")
    net = ipaddress.ip_network(cidr, strict=False)
    if net.version != 4:
        raise ValueError("Only IPv4 is supported for antenna IPs")
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO ipam_networks(location_id, cidr, active, created_at) VALUES(?,?,1,?)",
        (int(location_id), str(net), _now()),
    )
    conn.commit()
    nid = cur.lastrowid
    conn.close()
    return int(nid)

def get_customer_ip(customer_id: int) -> Optional[Dict[str, Any]]:
    conn = get_conn()
    row = conn.execute(
        """
        SELECT a.ip, a.network_id, n.cidr as network_cidr, n.location_id, l.name as location_name,
               a.assigned_by, a.assigned_at
        FROM ipam_allocations a
        JOIN ipam_networks n ON n.id = a.network_id
        JOIN ipam_locations l ON l.id = n.location_id
        WHERE a.customer_id=?
        LIMIT 1
        """,
        (int(customer_id),),
    ).fetchone()
    conn.close()
    return dict(row) if row else None

def _used_ips_for_network(conn: sqlite3.Connection, network_id: int) -> set:
    rows = conn.execute("SELECT ip FROM ipam_allocations WHERE network_id=?", (int(network_id),)).fetchall()
    return {r["ip"] for r in rows}

def next_free_for_location(location_id: int) -> Tuple[Optional[int], Optional[str], Optional[str]]:
    """Return (network_id, network_cidr, ip) for the next free IP across active networks for a location."""
    conn = get_conn()
    nets = conn.execute(
        "SELECT id, cidr FROM ipam_networks WHERE location_id=? AND active=1 ORDER BY cidr ASC",
        (int(location_id),),
    ).fetchall()
    for r in nets:
        nid = int(r["id"])
        cidr = str(r["cidr"])
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except Exception:
            continue
        if net.version != 4:
            continue

        used = _used_ips_for_network(conn, nid)

        # Reserve gateway (.1) as requested (network + 1)
        try:
            gw = str(ipaddress.IPv4Address(int(net.network_address) + 1))
        except Exception:
            gw = None

        for host in net.hosts():
            ip_s = str(host)
            if gw and ip_s == gw:
                continue
            if ip_s in used:
                continue
            conn.close()
            return nid, cidr, ip_s

    conn.close()
    return None, None, None


def list_ips_for_network(network_id: int, limit_hosts: int = 4096) -> Dict[str, Any]:
    """Return a full IP list for a network, marking .1 reserved, used allocations, and available IPs.
    NOTE: For very large CIDRs this can be heavy; we cap host enumeration via limit_hosts.
    """
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT n.id, n.cidr, l.id, l.name
        FROM ipam_networks n
        JOIN ipam_locations l ON l.id = n.location_id
        WHERE n.id = ?
    """, (network_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return {"ok": False, "detail": "Network not found"}

    _nid, cidr, location_id, location_name = row
    net = ipaddress.ip_network(cidr, strict=False)

    # Avoid materializing very large host lists in memory.
    host_count = max(0, int(net.num_addresses) - 2) if net.version == 4 else int(net.num_addresses)
    if host_count > limit_hosts:
        conn.close()
        return {"ok": False, "detail": f"Network too large to enumerate safely ({host_count} hosts)."}

    # Fetch allocations for network
    cur.execute("""
        SELECT ip, customer_id, status, assigned_at, note
        FROM ipam_allocations
        WHERE network_id = ?
    """, (network_id,))
    alloc_rows = cur.fetchall()
    conn.close()

    alloc_map: Dict[str, Dict[str, Any]] = {}
    for ip, customer_id, status, assigned_at, note in alloc_rows:
        alloc_map[str(ip)] = {
            "ip": str(ip),
            "status": status or "used",
            "customer_id": customer_id,
            "assigned_at": assigned_at,
            "note": note,
        }

    out = []
    for h in net.hosts():
        ip_s = str(h)
        # reserve gateway .1 (only makes sense for IPv4; for v6 keep as available unless explicitly allocated)
        if net.version == 4 and ip_s.endswith(".1"):
            out.append({"ip": ip_s, "status": "reserved", "customer_id": None})
            continue
        if ip_s in alloc_map:
            d = alloc_map[ip_s]
            # Normalize status: used if customer_id present else keep status
            st = d.get("status") or "used"
            out.append({"ip": ip_s, "status": "used" if d.get("customer_id") is not None else st, "customer_id": d.get("customer_id")})
        else:
            out.append({"ip": ip_s, "status": "available", "customer_id": None})

    counts = {"available": 0, "used": 0, "reserved": 0}
    for r in out:
        counts[r["status"]] = counts.get(r["status"], 0) + 1

    return {
        "ok": True,
        "network_id": network_id,
        "cidr": cidr,
        "location_id": location_id,
        "location_name": location_name,
        "counts": counts,
        "ips": out,
    }
def assign_next_ip(customer_id: int, location_id: int, assigned_by: str = "unknown") -> Dict[str, Any]:
    """Atomically assign next free IP to customer. Returns allocation info."""
    customer_id = int(customer_id)
    location_id = int(location_id)
    assigned_by = (assigned_by or "unknown").strip()

    # If already assigned, return it
    existing = get_customer_ip(customer_id)
    if existing:
        return {"already_assigned": True, **existing}

    conn = get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE;")

        # Re-check inside transaction
        row = conn.execute(
            "SELECT ip FROM ipam_allocations WHERE customer_id=? LIMIT 1",
            (customer_id,),
        ).fetchone()
        if row:
            # Another tech assigned in the meantime
            conn.commit()
            conn.close()
            return {"already_assigned": True, **(get_customer_ip(customer_id) or {"ip": row["ip"]})}

        nets = conn.execute(
            "SELECT id, cidr FROM ipam_networks WHERE location_id=? AND active=1 ORDER BY cidr ASC",
            (location_id,),
        ).fetchall()

        for r in nets:
            nid = int(r["id"])
            cidr = str(r["cidr"])
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except Exception:
                continue
            if net.version != 4:
                continue

            used = _used_ips_for_network(conn, nid)
            try:
                gw = str(ipaddress.IPv4Address(int(net.network_address) + 1))
            except Exception:
                gw = None

            for host in net.hosts():
                ip_s = str(host)
                if gw and ip_s == gw:
                    continue
                if ip_s in used:
                    continue

                # Try to allocate
                try:
                    conn.execute(
                        """
                        INSERT INTO ipam_allocations(network_id, ip, customer_id, status, assigned_by, assigned_at, note)
                        VALUES(?,?,?,?,?,?,?)
                        """,
                        (nid, ip_s, customer_id, "used", assigned_by, _now(), "Antenna IP"),
                    )
                    conn.commit()
                    # Return full details
                    conn.close()
                    return {"already_assigned": False, **(get_customer_ip(customer_id) or {"ip": ip_s, "network_id": nid, "network_cidr": cidr})}
                except sqlite3.IntegrityError:
                    # Someone else grabbed it first; move on
                    used.add(ip_s)
                    continue

        conn.rollback()
        conn.close()
        raise ValueError("No free IPs available for this location")
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass
        raise
