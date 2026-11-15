"""
Offline CVE matching.

Given a scanned host's services (product/version/CPE from nmap), find candidate
CVEs in the local SQLite store and enrich each with EPSS probability and CISA
KEV status. Also raises a watchlist hit when a matched CVE is on the team's
cve_watchlist (checked against the cloud table when available).

Matching strategy (offline, best-effort):
  1. normalize product name from nmap (e.g. "OpenSSH" -> "openssh")
  2. find cpe_match rows with the same product
  3. if a version is known, keep CVEs whose version range contains it;
     if unknown, keep as "version-unconfirmed" candidates (lower confidence)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from common.db import get_intel_db, get_service_client


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def _ver_tuple(v: str):
    nums = re.findall(r"\d+", v or "")
    return tuple(int(n) for n in nums[:4]) if nums else ()


def _in_range(version: str, start: str | None, end: str | None,
              exact: str | None) -> bool:
    vt = _ver_tuple(version)
    if not vt:
        return True  # unknown version -> can't exclude
    if exact and exact not in ("*", "-", ""):
        return _ver_tuple(exact) == vt
    ok = True
    if start:
        ok = ok and vt >= _ver_tuple(start)
    if end:
        ok = ok and vt <= _ver_tuple(end)
    return ok


def _other_branch(version: str, start: str | None, end: str | None) -> bool:
    """
    NVD often records a range as only "up to X.Y.Z" even when the flaw exists
    only in the X.Y branch (e.g. Apache 2.4 CVEs listed as <= 2.4.48 with no
    lower bound). A host on an older branch (Apache 2.2.8) technically falls in
    that range but is usually NOT affected. When a range has an upper bound and
    no lower bound, and the host's major.minor branch is older than the bound's
    branch, treat the match as unconfirmed (shown, but with lower confidence)
    instead of confirmed.
    """
    if start or not end:
        return False
    vt, et = _ver_tuple(version), _ver_tuple(end)
    if len(vt) < 2 or len(et) < 2:
        return False
    return vt[:2] < et[:2]


@dataclass
class VulnMatch:
    cve_id: str
    cvss_score: float | None
    cvss_vector: str | None
    severity: str | None
    epss_score: float | None
    epss_percentile: float | None
    in_kev: bool
    kev_due_date: str | None
    description: str
    port: int
    product: str
    version: str
    confidence: str = "version-confirmed"
    ml_risk_score: float | None = None
    ml_reasons: list = field(default_factory=list)


def _watchlist_cves() -> set[str]:
    client = get_service_client()
    if not client:
        return set()
    try:
        rows = client.table("cve_watchlist").select("cve_id").execute().data
        return {r["cve_id"] for r in rows}
    except Exception:
        return set()


def match_service(conn, product: str, version: str, port: int,
                  watch: set[str]) -> list[VulnMatch]:
    prod = _norm(product)
    if not prod:
        return []
    rows = conn.execute(
        "select distinct c.cve_id,c.cvss_score,c.cvss_vector,c.severity,"
        "c.description,m.version_start,m.version_end,m.version_exact "
        "from cpe_match m join cves c on c.cve_id=m.cve_id "
        "where replace(replace(lower(m.product),'_',''),'-','')=?",
        (prod,)).fetchall()

    matches: list[VulnMatch] = []
    for r in rows:
        confirmed = _in_range(version, r["version_start"], r["version_end"],
                              r["version_exact"])
        if _ver_tuple(version) and not confirmed:
            continue  # known version is outside this CVE's affected range
        if confirmed and _ver_tuple(version) and _other_branch(
                version, r["version_start"], r["version_end"]):
            confirmed = False  # in range only because of a missing lower bound
        epss = conn.execute("select epss,percentile from epss where cve_id=?",
                            (r["cve_id"],)).fetchone()
        kev = conn.execute("select due_date from kev where cve_id=?",
                           (r["cve_id"],)).fetchone()
        matches.append(VulnMatch(
            cve_id=r["cve_id"], cvss_score=r["cvss_score"],
            cvss_vector=r["cvss_vector"], severity=r["severity"],
            epss_score=(epss["epss"] if epss else None),
            epss_percentile=(epss["percentile"] if epss else None),
            in_kev=bool(kev), kev_due_date=(kev["due_date"] if kev else None),
            description=r["description"] or "", port=port,
            product=product, version=version,
            confidence=("version-confirmed" if confirmed else "version-unconfirmed"),
        ))
    # de-dupe by cve_id keeping confirmed over unconfirmed
    best: dict[str, VulnMatch] = {}
    for m in matches:
        cur = best.get(m.cve_id)
        if not cur or (m.confidence == "version-confirmed"
                       and cur.confidence != "version-confirmed"):
            best[m.cve_id] = m
    result = list(best.values())
    for m in result:
        if m.cve_id in watch:
            m.ml_reasons.append("on CVE watchlist")
    return result


def match_host(host_result: dict) -> list[dict]:
    """Match every service on a host; returns a list of vuln dicts."""
    conn = get_intel_db()
    watch = _watchlist_cves()
    out: list[dict] = []
    try:
        for svc in host_result.get("services", []):
            product = svc.get("product") or svc.get("service_name") or ""
            version = svc.get("version") or ""
            # Prefer nmap's CPE (e.g. cpe:/a:apache:http_server:2.2.8): its
            # product name is the one NVD uses, unlike the display product.
            cpe = svc.get("cpe") or ""
            if cpe.startswith("cpe:/"):
                parts = cpe.split(":")
                if len(parts) > 3 and parts[3]:
                    product = parts[3]
                if len(parts) > 4 and parts[4] and not version:
                    version = parts[4]
            seen = {o["cve_id"] for o in out if o.get("port") == svc.get("port")}
            for m in match_service(conn, product, version, svc.get("port"), watch):
                if m.cve_id not in seen:
                    out.append(vars(m))
    finally:
        conn.close()
    # sort: KEV first, then EPSS, then CVSS
    out.sort(key=lambda v: (v["in_kev"], v["epss_score"] or 0,
                            v["cvss_score"] or 0), reverse=True)
    return out
