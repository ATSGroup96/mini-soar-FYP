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
from ml.features import WATCHLIST_REASON


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


_VERSION = re.compile(r"^\D*(\d+(?:\.\d+)*)(.*)$")


def _ver_key(version: str | None):
    """
    Comparable form of a version string, or None when there is no number in it.

      "2.3.4"   -> ((2, 3, 4), 0)
      "2.4.0"   -> ((2, 4), 0)        trailing zeros dropped, so 2.4 == 2.4.0
      "4.7p1"   -> ((4, 7), 0)        OpenSSH "portable" tag is not a new version
      "1.0.2k"  -> ((1, 0, 2), 11)    a single letter is a patch level (a < b < ...)
    """
    m = _VERSION.match((version or "").strip())
    if not m:
        return None
    core = tuple(int(x) for x in m.group(1).split("."))
    while len(core) > 1 and core[-1] == 0:
        core = core[:-1]
    suffix = m.group(2).strip().lower()
    letter = ord(suffix) - ord("a") + 1 if len(suffix) == 1 and suffix.isalpha() else 0
    return core, letter


def _in_range(version: str, start: str | None, end: str | None, exact: str | None,
              start_excl: bool = False, end_excl: bool = False) -> bool | None:
    """
    Is `version` inside this CVE's affected versions?
    True / False when the host version is known, None when it is unknown.
    """
    vk = _ver_key(version)
    if vk is None:
        return None
    if exact and exact not in ("*", "-"):
        ek = _ver_key(exact)
        if ek is None:
            return False
        # NVD keeps a patch letter either in the version ("1.0.2k") or in the
        # separate update field ("5.0.51" + "a"); in the second case only the
        # numbers can be compared
        return vk[0] == ek[0] and (ek[1] == 0 or ek[1] == vk[1])
    if start:
        sk = _ver_key(start)
        if sk is not None and (vk <= sk if start_excl else vk < sk):
            return False
    if end:
        ek = _ver_key(end)
        if ek is not None and (vk >= ek if end_excl else vk > ek):
            return False
    return True


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
    vk, ek = _ver_key(version), _ver_key(end)
    if vk is None or ek is None:
        return False
    branch = lambda core: (core + (0, 0))[:2]      # noqa: E731  major.minor
    return branch(vk[0]) < branch(ek[0])


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
    on_watchlist: bool = False
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
        "c.description,m.version_start,m.version_end,m.version_exact,"
        "m.version_start_excl,m.version_end_excl "
        "from cpe_match m join cves c on c.cve_id=m.cve_id "
        "where replace(replace(lower(m.product),'_',''),'-','')=?",
        (prod,)).fetchall()

    matches: list[VulnMatch] = []
    for r in rows:
        inside = _in_range(version, r["version_start"], r["version_end"],
                           r["version_exact"], bool(r["version_start_excl"]),
                           bool(r["version_end_excl"]))
        if inside is False:
            continue  # known version is outside this CVE's affected range
        # unknown version -> a candidate only; a missing lower bound on another
        # branch -> also only a candidate
        confirmed = bool(inside) and not _other_branch(
            version, r["version_start"], r["version_end"])
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
            m.on_watchlist = True
            m.ml_reasons.append(WATCHLIST_REASON)
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
