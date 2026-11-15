"""
Intel sync CLI.

  python -m intel.cli init          # create the SQLite schema
  python -m intel.cli sync-all      # NVD + EPSS + KEV
  python -m intel.cli sync-nvd [--days N]
  python -m intel.cli sync-epss
  python -m intel.cli sync-kev
  python -m intel.cli sync-lab      # KEV + EPSS + CVEs for the software found
                                    # in the lab (what the launcher runs)
  python -m intel.cli sync-new      # CVEs only for software not seen before
                                    # (exit 0 = got new records, 3 = nothing new)
  python -m intel.cli stats         # row counts + last sync times
"""
from __future__ import annotations

import argparse
import sys

from common.db import get_intel_db
from . import db_init, sync_nvd, sync_epss, sync_kev, sync_cpe


def intel_status() -> dict:
    """Row counts + last sync time per feed (used by the API /health)."""
    db_init.init_db()
    conn = get_intel_db()
    try:
        out = {t: conn.execute(f"select count(*) c from {t}").fetchone()["c"]
               for t in ("cves", "kev", "epss")}
        out["last_sync"] = {r["feed"]: r["last_sync"] for r in
                            conn.execute("select feed,last_sync from meta").fetchall()}
    finally:
        conn.close()
    return out


def sync_lab(cpes: list[str] | None = None) -> dict:
    """
    Everything a lab scan needs, in one go: CISA KEV, EPSS, and the NVD records
    for the software found by the scans. One feed failing (no internet, a slow
    server) does not stop the others; the result says what worked.
    """
    result: dict = {}
    for name, job in (("kev", sync_kev.sync), ("epss", sync_epss.sync),
                      ("cpe", lambda: sync_cpe.sync(cpes or []))):
        try:
            result[name] = {"ok": True, "rows": job()}
        except Exception as e:
            result[name] = {"ok": False, "error": str(e)[:200]}
            print(f"  {name} sync failed: {e}")
    return result


def _stats() -> int:
    conn = get_intel_db()
    try:
        for feed in ("nvd", "epss", "kev"):
            row = conn.execute("select last_sync,rows from meta where feed=?",
                               (feed,)).fetchone()
            if row:
                print(f"  {feed:5} rows={row['rows']:<8} last_sync={row['last_sync']}")
            else:
                print(f"  {feed:5} (never synced)")
        for t in ("cves", "cpe_match", "epss", "kev"):
            n = conn.execute(f"select count(*) c from {t}").fetchone()["c"]
            print(f"  table {t:10} = {n}")
    finally:
        conn.close()
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="intel")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    p_nvd = sub.add_parser("sync-nvd"); p_nvd.add_argument("--days", type=int); p_nvd.add_argument("--full", action="store_true")
    sub.add_parser("sync-epss")
    sub.add_parser("sync-kev")
    p_all = sub.add_parser("sync-all"); p_all.add_argument("--full", action="store_true")
    p_cpe = sub.add_parser("sync-cpe"); p_cpe.add_argument("cpes", nargs="*")
    p_lab = sub.add_parser("sync-lab"); p_lab.add_argument("cpes", nargs="*")
    sub.add_parser("sync-new")
    sub.add_parser("stats")
    args = ap.parse_args(argv)

    if args.cmd == "init":
        db_init.init_db(); print("ok")
    elif args.cmd == "sync-nvd":
        sync_nvd.sync(args.days, args.full)
    elif args.cmd == "sync-epss":
        sync_epss.sync()
    elif args.cmd == "sync-kev":
        sync_kev.sync()
    elif args.cmd == "sync-all":
        sync_kev.sync(); sync_epss.sync(); sync_nvd.sync(full=args.full)
    elif args.cmd == "sync-cpe":
        sync_cpe.sync(args.cpes)
    elif args.cmd == "sync-new":
        # exit code 0 = new CVE records arrived (a re-scan will now find more),
        # 3 = nothing new
        return 0 if sync_cpe.sync(only_missing=True) > 0 else 3
    elif args.cmd == "sync-lab":
        result = sync_lab(args.cpes)
        return 0 if all(r["ok"] for r in result.values()) else 1
    elif args.cmd == "stats":
        return _stats()
    return 0


if __name__ == "__main__":
    sys.exit(main())
