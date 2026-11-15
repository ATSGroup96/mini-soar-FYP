"""
Sync EPSS (Exploit Prediction Scoring System) scores from FIRST.org.

EPSS gives each CVE a probability (0..1) of being exploited in the next 30 days
plus a percentile. Used for prioritization alongside CVSS and KEV.

Feed: https://epss.cyentia.com/epss_scores-current.csv.gz  (public, no key)
Run:  python -m intel.sync_epss
"""
from __future__ import annotations

import io
import gzip
import csv

import requests

from common.db import get_intel_db
from .db_init import init_db

EPSS_URLS = ["https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
             "https://epss.cyentia.com/epss_scores-current.csv.gz"]


def sync() -> int:
    init_db()
    r = None
    for url in EPSS_URLS:
        try:
            r = requests.get(url, timeout=120)
            r.raise_for_status()
            break
        except Exception as e:
            print(f"  EPSS source failed ({url}): {e}")
            r = None
    if r is None:
        raise RuntimeError("Could not download EPSS data from any source.")
    raw = gzip.decompress(r.content).decode("utf-8", "replace")

    conn = get_intel_db()
    total = 0
    try:
        reader = csv.reader(io.StringIO(raw))
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            if row[0] == "cve":  # header
                continue
            if len(row) < 3:
                continue
            cve_id, epss, pct = row[0], row[1], row[2]
            try:
                conn.execute(
                    "insert or replace into epss(cve_id,epss,percentile) values(?,?,?)",
                    (cve_id, float(epss), float(pct)))
                total += 1
            except ValueError:
                continue
            if total % 20000 == 0:
                conn.commit()
        conn.commit()
        from datetime import datetime, timezone
        conn.execute("insert or replace into meta(feed,last_sync,rows) values(?,?,?)",
                     ("epss", datetime.now(timezone.utc).isoformat(), total))
        conn.commit()
    finally:
        conn.close()
    print(f"EPSS sync complete: {total} scores.")
    return total


if __name__ == "__main__":
    sync()
