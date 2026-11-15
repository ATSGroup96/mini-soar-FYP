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
    -- 1 when NVD gave the bound as "excluding" (e.g. "before 2.2.8": 2.2.8 is safe)
    version_start_excl integer not null default 0,
    version_end_excl   integer not null default 0,
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


# columns added after the first release: (table, column, definition)
_ADDED_COLUMNS = [
    ("cpe_match", "version_start_excl", "integer not null default 0"),
    ("cpe_match", "version_end_excl", "integer not null default 0"),
]


def _migrate(conn) -> None:
    """Add newer columns to a database created by an older version."""
    for table, column, definition in _ADDED_COLUMNS:
        have = {r["name"] for r in conn.execute(f"pragma table_info({table})")}
        if column not in have:
            conn.execute(f"alter table {table} add column {column} {definition}")


def init_db() -> None:
    conn = get_intel_db()
    try:
        conn.executescript(SCHEMA)
        _migrate(conn)
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
    print("Intel DB initialized.")
