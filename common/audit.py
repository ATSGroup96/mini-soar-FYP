"""
Tamper-evident audit log (hash chain).

Each entry stores curr_hash = SHA256(prev_hash || canonical(entry)). Any later
edit/deletion of a row breaks every subsequent hash, which `verify_chain()`
detects. Entries are written locally (append-only JSONL) and, when a cloud DB
is configured, mirrored to public.audit_log.
"""
from __future__ import annotations

import os
import json
import time
import hashlib
from pathlib import Path

from .filelock import file_lock   # fcntl on Linux, msvcrt on Windows

_AUDIT_DIR = Path(os.environ.get("AUDIT_DIR", "./audit"))
_AUDIT_FILE = _AUDIT_DIR / "audit_chain.jsonl"
_GENESIS = "0" * 64


def _canonical(entry: dict) -> str:
    # deterministic serialization so the hash is reproducible
    return json.dumps(entry, sort_keys=True, separators=(",", ":"))


def _hash(prev_hash: str, entry: dict) -> str:
    return hashlib.sha256((prev_hash + _canonical(entry)).encode()).hexdigest()


def _last_hash() -> str:
    if not _AUDIT_FILE.exists():
        return _GENESIS
    last = _GENESIS
    with _AUDIT_FILE.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    last = json.loads(line)["curr_hash"]
                except (json.JSONDecodeError, KeyError):
                    continue
    return last


def log_event(actor: str, action: str, target: str = "",
              detail: dict | None = None, mirror_cloud: bool = True) -> dict:
    """Append one tamper-evident entry and return it."""
    _AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    body = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "actor": actor,
        "action": action,
        "target": target,
        "detail": json.loads(json.dumps(detail or {}, default=str)),
    }
    # scanner, worker and API run in separate processes/containers but share
    # this file: hold an exclusive lock while reading the last hash and
    # appending, so two writers can never fork the chain
    with file_lock(_AUDIT_DIR / ".lock"):
        prev = _last_hash()
        curr = _hash(prev, body)
        row = {**body, "prev_hash": prev, "curr_hash": curr}
        with _AUDIT_FILE.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    if mirror_cloud:
        try:
            from .db import get_service_client
            client = get_service_client()
            if client:
                client.table("audit_log").insert({
                    "actor": actor, "action": action, "target": target,
                    "detail": body["detail"], "prev_hash": prev,
                    "curr_hash": curr,
                }).execute()
        except Exception:
            pass  # cloud mirror is best-effort; local chain is source of truth
    return row


def verify_chain() -> tuple[bool, int, str]:
    """
    Recompute the whole chain. Returns (ok, entries_checked, message).
    ok=False means a row was altered/removed after it was written.
    """
    if not _AUDIT_FILE.exists():
        return True, 0, "No audit log yet."
    prev = _GENESIS
    n = 0
    with _AUDIT_FILE.open("r", encoding="utf-8") as fh:
        for i, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            n += 1
            row = json.loads(line)
            body = {k: row[k] for k in ("ts", "actor", "action", "target", "detail")}
            if row.get("prev_hash") != prev:
                return False, n, f"Broken link at entry {i}: prev_hash mismatch."
            if _hash(prev, body) != row.get("curr_hash"):
                return False, n, f"Tampered content at entry {i}: hash mismatch."
            prev = row["curr_hash"]
    return True, n, f"Chain intact: {n} entries verified."
