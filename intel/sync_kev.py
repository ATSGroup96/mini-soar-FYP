"""
Sync the CISA Known Exploited Vulnerabilities (KEV) catalog.

KEV lists CVEs that are confirmed exploited in the wild — the strongest single
prioritization signal. A match here should jump a finding to the top.

Feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
Run:  python -m intel.sync_kev
"""
from __future__ import annotations

import requests

from common.db import get_intel_db
from .db_init import init_db

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")


def sync() -> int:
    init_db()
    r = requests.get(KEV_URL, timeout=90)
    r.raise_for_status()
    data = r.json()

    conn = get_intel_db()
    total = 0
    try:
        conn.execute("delete from kev")
        for v in data.get("vulnerabilities", []):
            conn.execute(
                "insert or replace into kev(cve_id,vendor,product,name,"
                "date_added,due_date,known_ransomware) values(?,?,?,?,?,?,?)",
                (v.get("cveID"), v.get("vendorProject"), v.get("product"),
                 v.get("vulnerabilityName"), v.get("dateAdded"),
                 v.get("dueDate"), v.get("knownRansomwareCampaignUse")))
            total += 1
        from datetime import datetime, timezone
        conn.execute("insert or replace into meta(feed,last_sync,rows) values(?,?,?)",
                     ("kev", datetime.now(timezone.utc).isoformat(), total))
        conn.commit()
    finally:
        conn.close()
    print(f"KEV sync complete: {total} known-exploited CVEs.")
    return total


if __name__ == "__main__":
    sync()
