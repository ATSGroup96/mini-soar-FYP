"""
Supabase client helpers + offline SQLite connection.

The engine uses the SERVICE ROLE key (trusted ingestor, bypasses RLS). The
dashboard uses the anon key in the browser. If Supabase is not configured the
engine still runs fully offline, writing results to the local SQLite store.

One client per THREAD: the API answers requests on several threads at once,
and one shared HTTP/2 connection used from two threads made Supabase drop it
("Server disconnected", seen as 500 errors on the Topology page).
"""
from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

from .config import get_settings

try:
    from supabase import create_client, Client
except Exception:  # library optional at import time
    create_client = None
    Client = object  # type: ignore

PAGE_SIZE = 1000          # Supabase returns at most 1000 rows per request

_local = threading.local()
_generation = [0]         # bumped by cache_clear(): every thread makes a new client


def _make_client():
    s = get_settings()
    if not (create_client and s.supabase_url and s.supabase_service_role_key):
        return None
    if "YOUR-PROJECT" in s.supabase_url:
        return None
    try:
        return create_client(s.supabase_url, s.supabase_service_role_key)
    except Exception:
        return None


def get_service_client():
    """Supabase client with the service role key, or None if not configured."""
    if getattr(_local, "generation", None) != _generation[0]:
        _local.client = _make_client()
        _local.generation = _generation[0]
    return _local.client


def _cache_clear() -> None:
    _generation[0] += 1


get_service_client.cache_clear = _cache_clear   # same API as the old lru_cache


def fetch_all(client, table: str, columns: str = "*", eq: dict | None = None,
              page: int = PAGE_SIZE) -> list[dict]:
    """Every row of a select, page by page (a plain select stops at 1000 rows)."""
    out: list[dict] = []
    start = 0
    while True:
        q = client.table(table).select(columns)
        for k, v in (eq or {}).items():
            q = q.eq(k, v)
        rows = q.range(start, start + page - 1).execute().data or []
        out += rows
        if len(rows) < page:
            return out
        start += page


def get_intel_db() -> sqlite3.Connection:
    """Connection to the offline NVD/EPSS/KEV SQLite database."""
    path = Path(get_settings().intel_db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn
