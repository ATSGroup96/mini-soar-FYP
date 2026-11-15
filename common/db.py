"""
Supabase client helpers + offline SQLite connection.

The engine uses the SERVICE ROLE key (trusted ingestor, bypasses RLS). The
dashboard uses the anon key in the browser. If Supabase is not configured the
engine still runs fully offline, writing results to the local SQLite store.
"""
from __future__ import annotations

import sqlite3
from functools import lru_cache
from pathlib import Path

from .config import get_settings

try:
    from supabase import create_client, Client
except Exception:  # library optional at import time
    create_client = None
    Client = object  # type: ignore


@lru_cache(maxsize=1)
def get_service_client():
    """Supabase client with the service role key, or None if not configured."""
    s = get_settings()
    if not (create_client and s.supabase_url and s.supabase_service_role_key):
        return None
    if "YOUR-PROJECT" in s.supabase_url:
        return None
    try:
        return create_client(s.supabase_url, s.supabase_service_role_key)
    except Exception:
        return None


def get_intel_db() -> sqlite3.Connection:
    """Connection to the offline NVD/EPSS/KEV SQLite database."""
    path = Path(get_settings().intel_db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn
