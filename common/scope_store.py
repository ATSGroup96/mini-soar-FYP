"""
Effective scan/remediation scope, editable from the dashboard.

Where the scope comes from (SCOPE_SOURCE in .env):
  * "dashboard" (default): the single row in public.scope_config, set by an
    admin with a TOTP code on the Settings page. If that row is missing or
    Supabase is unreachable, the .env values are used instead.
  * "env": only .env (ALLOWED_RANGES / DENY_HOSTS / AUTHORIZED_LAB_ONLY).

Safety rules that the dashboard can NOT change (only .env can):
  * AUTHORIZED_LAB_ONLY=true in .env is still the master switch.
  * Every range must sit inside SCOPE_CEILING (default: private ranges only).
  * Every range must be /22 or smaller (max 1024 addresses).
  * The engine's own IP addresses are always denied.
"""
from __future__ import annotations

import ipaddress
import subprocess
import time
from datetime import datetime, timezone

from .config import get_settings, _get, _parse_cidrs

MIN_PREFIX = 22                     # /22 = 1024 addresses at most per range
_CACHE_SECONDS = 10
_cache: dict = {"t": 0.0, "v": None}


def scope_source() -> str:
    return (_get("SCOPE_SOURCE", "dashboard") or "dashboard").lower()


def ceiling() -> list:
    return _parse_cidrs(_get("SCOPE_CEILING", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"))


_WIN_PS = ("Get-NetIPAddress -AddressFamily IPv4 | ForEach-Object "
           "{ \"$($_.InterfaceAlias)|$($_.IPAddress)|$($_.PrefixLength)\" }")


def _parse_windows_ip_lines(text: str) -> list[dict]:
    """Lines 'alias|ip|prefix' from Get-NetIPAddress -> interface dicts.
    Skips loopback, link-local (169.254.x.x, adapter without DHCP) and the
    virtual switches of WSL / Hyper-V / Docker ('vEthernet ...')."""
    found = []
    for line in (text or "").splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 3:
            continue
        alias, ip, prefix = parts
        if alias.lower().startswith(("loopback", "vethernet")):
            continue
        try:
            itf = ipaddress.ip_interface(f"{ip}/{int(prefix)}")
        except ValueError:
            continue
        if itf.version != 4 or itf.ip.is_loopback or itf.ip.is_link_local:
            continue
        found.append({"iface": alias, "ip": str(itf.ip), "network": str(itf.network),
                      "private": itf.ip.is_private})
    return found


def _windows_interfaces() -> list[dict]:
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", _WIN_PS],
                             capture_output=True, text=True, timeout=15).stdout
    except Exception:
        return []
    return _parse_windows_ip_lines(out)


def engine_interfaces() -> list[dict]:
    """IPv4 interfaces of the engine machine.
    * Linux (Docker host networking or native): `ip addr`.
    * Windows native: PowerShell Get-NetIPAddress.
    * NAT mode (Docker Desktop): the container cannot see Windows' adapters,
      so the lab address comes from ENGINE_HOST_IPS in .env."""
    from .netmode import is_nat, is_windows, engine_host_interfaces
    if is_nat():
        return engine_host_interfaces()
    if is_windows():
        return _windows_interfaces()
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True,
                             text=True, timeout=5).stdout
    except Exception:
        return []
    found = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[2] != "inet":
            continue
        iface, cidr = parts[1], parts[3]
        if iface.startswith(("lo", "docker", "br-", "veth")):
            continue
        itf = ipaddress.ip_interface(cidr)
        found.append({"iface": iface, "ip": str(itf.ip), "network": str(itf.network),
                      "private": itf.ip.is_private})
    return found


def engine_ips() -> list[str]:
    from .netmode import engine_host_interfaces
    return sorted({i["ip"] for i in engine_interfaces()} |
                  {i["ip"] for i in engine_host_interfaces()})


def _inside_ceiling(net) -> bool:
    return any(net.version == c.version and net.subnet_of(c) for c in ceiling())


def validate(ranges: list[str], deny: list[str]) -> tuple[list, list[str]]:
    """Raise ValueError with a clear message if anything is not allowed."""
    nets = []
    for r in ranges:
        r = (r or "").strip()
        if not r:
            continue
        try:
            net = ipaddress.ip_network(r, strict=False)
        except ValueError:
            raise ValueError(f"'{r}' is not a valid network (example: 192.168.110.0/24)")
        if net.version != 4:
            raise ValueError(f"{net}: only IPv4 ranges are supported")
        if not net.is_private:
            raise ValueError(f"{net}: only private (lab) ranges are allowed")
        if net.prefixlen < MIN_PREFIX:
            raise ValueError(f"{net}: too big; use /{MIN_PREFIX} or smaller (e.g. /24)")
        if not _inside_ceiling(net):
            raise ValueError(f"{net}: outside SCOPE_CEILING set in .env")
        nets.append(net)
    if not nets:
        raise ValueError("give at least one allowed range")
    clean_deny = []
    for d in deny:
        d = (d or "").strip()
        if not d:
            continue
        try:
            clean_deny.append(str(ipaddress.ip_address(d)))
        except ValueError:
            raise ValueError(f"'{d}' is not a valid IP address for the deny list")
    return nets, clean_deny


def _db_row() -> dict | None:
    from .db import get_service_client
    client = get_service_client()
    if not client:
        return None
    rows = client.table("scope_config").select("*").eq("id", 1).execute().data
    return rows[0] if rows else None


def effective_scope(force: bool = False) -> dict:
    """{source, allowed_ranges [ip_network], deny_hosts [str], authorized, note, updated_at}"""
    now = time.time()
    if not force and _cache["v"] is not None and now - _cache["t"] < _CACHE_SECONDS:
        return _cache["v"]
    s = get_settings()
    v = {"source": "env", "allowed_ranges": list(s.allowed_ranges),
         "deny_hosts": list(s.deny_hosts), "authorized": s.authorized_lab_only,
         "note": "", "updated_at": None}
    if scope_source() == "dashboard":
        try:
            row = _db_row()
        except Exception:
            row = None                      # cloud down -> keep the .env scope
        if row and row.get("allowed_ranges"):
            nets = []
            for r in row["allowed_ranges"]:
                try:
                    n = ipaddress.ip_network(r, strict=False)
                except ValueError:
                    continue
                if n.version == 4 and n.prefixlen >= MIN_PREFIX and _inside_ceiling(n):
                    nets.append(n)
            v = {"source": "dashboard", "allowed_ranges": nets,
                 "deny_hosts": list(row.get("deny_hosts") or []),
                 # .env master switch AND the per-network authorization must both be on
                 "authorized": bool(row.get("authorized")) and s.authorized_lab_only,
                 "note": row.get("authorization_note") or "",
                 "updated_at": row.get("updated_at")}
    # the engine never scans or fixes itself
    v["deny_hosts"] = sorted(set(v["deny_hosts"]) | set(engine_ips()))
    _cache.update(t=now, v=v)
    return v


def save_scope(ranges: list[str], deny: list[str], authorized: bool, note: str,
               user_id: str) -> dict:
    nets, clean_deny = validate(ranges, deny)
    if authorized and len((note or "").strip()) < 5:
        raise ValueError("write who authorized this network (e.g. 'Own VirtualBox lab' "
                         "or 'Written permission from <name>, <date>')")
    from .db import get_service_client
    client = get_service_client()
    if not client:
        raise RuntimeError("Supabase not configured; set the scope in .env instead")
    client.table("scope_config").upsert({
        "id": 1, "allowed_ranges": [str(n) for n in nets], "deny_hosts": clean_deny,
        "authorized": bool(authorized), "authorization_note": (note or "").strip(),
        "updated_by": user_id, "updated_at": datetime.now(timezone.utc).isoformat(),
    }).execute()
    _cache.update(t=0.0, v=None)
    return effective_scope(force=True)
