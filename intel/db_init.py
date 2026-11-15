"""
Initialize the offline intelligence SQLite database.

Tables:
  cves        — CVE id, CVSS, description, published, CPE match strings
  cpe_match   — normalized (vendor, product, version range) -> cve_id
  epss        — cve_id -> probability + percentile
  kev         — CISA Known Exploited Vulnerabilities
  meta        — last-sync timestamps per feed
"""
from __future__ import annotations

from common.db import get_intel_db


SCHEMA = """
create table if not exists cves (
    cve_id        text primary key,
    cvss_score    real,
    cvss_vector   text,
    severity      text,
    description   text,
    published     text,
    last_modified text
);

create table if not exists cpe_match (
    id            integer primary key autoincrement,
    cve_id        text not null,
    vendor        text,
    product       text,
    version_start text,
    version_end   text,
    version_exact text,
    cpe23         text,
    foreign key (cve_id) references cves(cve_id)
);
create index if not exists idx_cpe_product on cpe_match(product);
create index if not exists idx_cpe_vendor  on cpe_match(vendor);
create index if not exists idx_cpe_cve     on cpe_match(cve_id);

create table if not exists epss (
    cve_id     text primary key,
    epss       real,
    percentile real
);

create table if not exists kev (
    cve_id       text primary key,
    vendor       text,
    product      text,
    name         text,
    date_added   text,
    due_date     text,
    known_ransomware text
);

create table if not exists meta (
    feed       text primary key,
    last_sync  text,
    rows       integer
);
"""


def init_db() -> None:
    conn = get_intel_db()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
    print("Intel DB initialized.")
