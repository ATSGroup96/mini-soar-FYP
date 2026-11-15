"""
Sync CVE data from the NVD 2.0 API into the offline SQLite store.

  python -m intel.sync_nvd            # incremental (last NVD_SYNC_DAYS days)
  python -m intel.sync_nvd --full     # whole catalogue (needed for old software)

Robust for slow links: small pages, automatic retries with backoff, and a full
sync RESUMES from the last saved page if it is interrupted. An NVD API key
(free) makes it several times faster.
"""
from __future__ import annotations

import time
import argparse
from datetime import datetime, timedelta, timezone

import requests

from common.config import get_settings
from common.db import get_intel_db
from .db_init import init_db

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE = 1000          # smaller pages = faster responses, fewer timeouts
TIMEOUT = 180
RETRIES = 6


def _severity_from_cvss(score):
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _extract_cvss(metrics: dict):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            data = metrics[key][0]["cvssData"]
            return data.get("baseScore"), data.get("vectorString")
    return None, None


def _parse_cpe23(cpe23: str):
    parts = cpe23.split(":")
    vendor = parts[3] if len(parts) > 3 else ""
    product = parts[4] if len(parts) > 4 else ""
    return vendor, product


def _get(params: dict, headers: dict) -> dict:
    """GET with retries + exponential backoff (NVD is often slow / rate-limits)."""
    delay = 10
    for attempt in range(1, RETRIES + 1):
        try:
            r = requests.get(NVD_URL, params=params, headers=headers, timeout=TIMEOUT)
            if r.status_code in (403, 429, 500, 502, 503, 504):
                raise requests.HTTPError(f"HTTP {r.status_code}")
            r.raise_for_status()
            return r.json()
        except Exception as e:
            if attempt == RETRIES:
                raise
            print(f"  NVD request failed ({e}); retry {attempt}/{RETRIES - 1} in {delay}s...")
            time.sleep(delay)
            delay = min(delay * 2, 120)
    return {}


def _store(conn, vulns) -> int:
    n = 0
    for item in vulns:
        cve = item["cve"]
        cid = cve["id"]
        score, vector = _extract_cvss(cve.get("metrics", {}))
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        conn.execute(
            "insert or replace into cves(cve_id,cvss_score,cvss_vector,severity,"
            "description,published,last_modified) values(?,?,?,?,?,?,?)",
            (cid, score, vector, _severity_from_cvss(score), desc,
             cve.get("published"), cve.get("lastModified")))
        conn.execute("delete from cpe_match where cve_id=?", (cid,))
        for cfg in cve.get("configurations", []):
            for node in cfg.get("nodes", []):
                for m in node.get("cpeMatch", []):
                    cpe23 = m.get("criteria", "")
                    vendor, product = _parse_cpe23(cpe23)
                    parts = cpe23.split(":")
                    conn.execute(
                        "insert into cpe_match(cve_id,vendor,product,version_start,"
                        "version_end,version_exact,cpe23) values(?,?,?,?,?,?,?)",
                        (cid, vendor, product,
                         m.get("versionStartIncluding") or m.get("versionStartExcluding"),
                         m.get("versionEndIncluding") or m.get("versionEndExcluding"),
                         parts[5] if len(parts) > 5 else None, cpe23))
        n += 1
    return n


def sync(days: int | None = None, full: bool = False) -> int:
    init_db()
    s = get_settings()
    headers = {"apiKey": s.nvd_api_key} if s.nvd_api_key else {}
    throttle = 1.0 if s.nvd_api_key else 6.5   # NVD public rate limit

    end = datetime.now(timezone.utc)
    if full:
        params_base = {"resultsPerPage": PAGE}
        progress_key = "nvd_full_progress"
    else:
        start = end - timedelta(days=days or s.nvd_sync_days)
        params_base = {
            "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": PAGE,
        }
        progress_key = None

    conn = get_intel_db()
    total = 0
    start_index = 0
    if progress_key:
        row = conn.execute("select rows from meta where feed=?", (progress_key,)).fetchone()
        if row and row["rows"]:
            start_index = int(row["rows"])
            print(f"  Resuming full NVD sync from record {start_index}")
    try:
        while True:
            data = _get(dict(params_base, startIndex=start_index), headers)
            vulns = data.get("vulnerabilities", [])
            total += _store(conn, vulns)
            total_results = data.get("totalResults", 0)
            start_index += PAGE
            if progress_key:
                conn.execute("insert or replace into meta(feed,last_sync,rows) values(?,?,?)",
                             (progress_key, end.isoformat(), start_index))
            conn.commit()
            print(f"  NVD: {min(start_index, total_results)}/{total_results}")
            if start_index >= total_results or not vulns:
                break
            time.sleep(throttle)

        if progress_key:
            conn.execute("delete from meta where feed=?", (progress_key,))
        n_all = conn.execute("select count(*) c from cves").fetchone()["c"]
        conn.execute("insert or replace into meta(feed,last_sync,rows) values(?,?,?)",
                     ("nvd", end.isoformat(), n_all))
        conn.commit()
    finally:
        conn.close()
    print(f"NVD sync complete: {total} CVEs this run.")
    return total


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=None)
    ap.add_argument("--full", action="store_true")
    a = ap.parse_args()
    sync(a.days, a.full)
