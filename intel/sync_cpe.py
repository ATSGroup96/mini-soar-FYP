"""
Targeted NVD sync: download CVEs only for the software actually found in the lab.

Reads the distinct CPEs that nmap reported (Supabase `services.cpe`, or the CPEs
passed on the command line) and asks the NVD API for the CVEs matching each
vendor:product using `virtualMatchString`. Minutes instead of hours, and the
data is exactly what the CVE matcher needs.

  python -m intel.cli sync-cpe                       # CPEs from your scans
  python -m intel.cli sync-cpe cpe:/a:vsftpd:vsftpd  # explicit CPEs
"""
from __future__ import annotations

import time

from common.config import get_settings
from common.db import get_intel_db, get_service_client
from .db_init import init_db
from .sync_nvd import _get, _store

PAGE = 500
KEYWORD_MAX = 2000      # cap for the keyword fallback per product

# nmap and NVD sometimes disagree on the vendor name for the same product
VENDOR_ALIASES = {
    "vsftpd": ["vsftpd_project", "beasts"],
    "openssh": ["openbsd"],
    "proftpd": ["proftpd_project", "proftpd"],
    "unrealircd": ["unrealircd"],
    "samba": ["samba"],
    "netkit_rsh": ["netkit"],
    "netkit-rsh": ["netkit"],
}


def _to_match_string(cpe: str) -> str | None:
    """'cpe:/a:apache:http_server:2.2.8' -> 'cpe:2.3:a:apache:http_server'"""
    cpe = (cpe or "").strip()
    if cpe.startswith("cpe:2.3:"):
        parts = cpe.split(":")
        if len(parts) > 2 and parts[2] != "a":
            return None
        return ":".join(parts[:5]) if len(parts) >= 5 and parts[4] not in ("", "*") else None
    if cpe.startswith("cpe:/"):
        parts = cpe[5:].split(":")          # a, vendor, product, version...
        if parts and parts[0] != "a":
            return None                     # skip OS/hardware CPEs (e.g. linux_kernel)
        if len(parts) >= 3 and parts[1] and parts[2]:
            return f"cpe:2.3:{parts[0]}:{parts[1]}:{parts[2]}"
    return None


def cpes_from_scans() -> list[str]:
    client = get_service_client()
    if not client:
        print("Supabase not configured; pass CPEs on the command line.")
        return []
    rows = client.table("services").select("cpe").execute().data or []
    return sorted({r["cpe"] for r in rows if r.get("cpe")})


def _pull(conn, params: dict, headers: dict, throttle: float, cap: int | None = None) -> int:
    start, got = 0, 0
    while True:
        data = _get(dict(params, resultsPerPage=PAGE, startIndex=start), headers)
        vulns = data.get("vulnerabilities", [])
        got += _store(conn, vulns)
        conn.commit()
        total_results = data.get("totalResults", 0)
        start += len(vulns) or PAGE
        time.sleep(throttle)
        if start >= total_results or not vulns or (cap and start >= cap):
            break
    return got


def _candidates(match_string: str) -> list[str]:
    """vendor:product as nmap reports it, then known NVD vendor aliases."""
    parts = match_string.split(":")
    vendor, product = parts[3], parts[4]
    out = [match_string]
    for alias in VENDOR_ALIASES.get(product, []) + VENDOR_ALIASES.get(vendor, []):
        cand = f"cpe:2.3:a:{alias}:{product}"
        if cand not in out:
            out.append(cand)
    return out


def sync(cpes: list[str] | None = None) -> int:
    init_db()
    s = get_settings()
    headers = {"apiKey": s.nvd_api_key} if s.nvd_api_key else {}
    throttle = 1.0 if s.nvd_api_key else 6.5

    raw = cpes if cpes else cpes_from_scans()
    targets = sorted({m for m in (_to_match_string(c) for c in raw) if m})
    if not targets:
        print("No CPEs found. Run a scan first.")
        return 0
    print(f"Syncing CVEs for {len(targets)} products found in the lab:")

    conn = get_intel_db()
    total = 0
    try:
        for t in targets:
            got, used = 0, t
            for cand in _candidates(t):
                try:
                    got = _pull(conn, {"virtualMatchString": cand}, headers, throttle)
                except Exception as e:
                    print(f"  {cand}: NVD error ({e}); trying next option")
                    got = 0
                if got:
                    used = cand
                    break
            if not got:
                # last resort: keyword search on the product name. The matcher
                # later keeps only CVEs whose CPE product equals this product.
                product = t.split(":")[4]
                try:
                    got = _pull(conn, {"keywordSearch": product.replace("_", " ")},
                                headers, throttle, cap=KEYWORD_MAX)
                    used = f"keyword '{product}'"
                except Exception as e:
                    print(f"  keyword {product}: NVD error ({e})")
            print(f"  {t:45} {got} CVEs" + (f"  (via {used})" if used != t else ""))
            total += got
    finally:
        conn.close()
    print(f"Targeted NVD sync complete: {total} CVE records.")
    return total
