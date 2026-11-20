"""
In-memory stand-in for the Supabase client, used by the test suite.

It implements only the query-builder calls the engine really uses
(table().select/insert/update/upsert/delete + eq/neq/lt/gt/in_/order/limit +
execute()), with the column defaults and unique keys of supabase/schema.sql,
so whole flows (scan upload -> tickets -> approval -> worker) can run without
any network or cloud project.
"""
from __future__ import annotations

import copy
import uuid
from datetime import datetime, timezone


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# column defaults taken from supabase/schema.sql
DEFAULTS = {
    "assets": {"is_rogue": False, "is_authorized": False, "risk_grade": None,
               "risk_score": None},
    "services": {"protocol": "tcp", "has_default_cred": False},
    "vulnerabilities": {"status": "open", "in_kev": False, "ml_reasons": []},
    "tickets": {"status": "open", "escalated": False, "severity": "medium",
                "vuln_id": None},
    "remediations": {"status": "planned", "totp_verified": False,
                     "verified_fixed": None},
    "notifications": {"level": "info", "read": False},
    "profiles": {"role": "viewer", "totp_enrolled": False, "totp_secret": None},
}


class _Result:
    def __init__(self, data):
        self.data = data


class _Query:
    def __init__(self, db: "FakeSupabase", table: str):
        self._db, self._table = db, table
        self._op, self._payload, self._conflict = "select", None, None
        self._filters: list = []
        self._order: tuple | None = None
        self._limit: int | None = None
        self._range: tuple | None = None

    # ---- operations ---------------------------------------------------------
    def select(self, _cols: str = "*"):
        self._op = "select"
        return self

    def insert(self, payload):
        self._op, self._payload = "insert", payload
        return self

    def update(self, payload):
        self._op, self._payload = "update", payload
        return self

    def upsert(self, payload, on_conflict: str | None = None):
        self._op, self._payload, self._conflict = "upsert", payload, on_conflict
        return self

    def delete(self):
        self._op = "delete"
        return self

    # ---- filters ------------------------------------------------------------
    def eq(self, col, val):
        self._filters.append(lambda r: r.get(col) == val)
        return self

    def neq(self, col, val):
        self._filters.append(lambda r: r.get(col) != val)
        return self

    def lt(self, col, val):
        self._filters.append(lambda r: r.get(col) is not None and r.get(col) < val)
        return self

    def gt(self, col, val):
        self._filters.append(lambda r: r.get(col) is not None and r.get(col) > val)
        return self

    def in_(self, col, vals):
        vals = list(vals)
        self._filters.append(lambda r: r.get(col) in vals)
        return self

    def order(self, col, desc: bool = False):
        self._order = (col, desc)
        return self

    def limit(self, n: int):
        self._limit = n
        return self

    def range(self, start: int, end: int):
        self._range = (start, end)
        return self

    # ---- run ----------------------------------------------------------------
    def _match(self, row) -> bool:
        return all(f(row) for f in self._filters)

    def _new_row(self, payload: dict) -> dict:
        row = copy.deepcopy(DEFAULTS.get(self._table, {}))
        row.update(copy.deepcopy(payload))
        row.setdefault("id", str(uuid.uuid4()))
        row.setdefault("created_at", _now())
        return row

    def execute(self) -> _Result:
        self._db.calls.append((self._table, self._op))
        if self._table in self._db.fail_tables:
            raise RuntimeError(f"simulated Supabase failure on {self._table}")
        rows = self._db.tables.setdefault(self._table, [])

        if self._op == "select":
            out = [r for r in rows if self._match(r)]
            if self._order:
                col, desc = self._order
                out.sort(key=lambda r: (r.get(col) is None, r.get(col) or 0), reverse=desc)
            if self._limit is not None:
                out = out[: self._limit]
            if self._range is not None:
                out = out[self._range[0]: self._range[1] + 1]
            return _Result(copy.deepcopy(out))

        if self._op == "insert":
            payloads = self._payload if isinstance(self._payload, list) else [self._payload]
            new = [self._new_row(p) for p in payloads]
            rows.extend(new)
            return _Result(copy.deepcopy(new))

        if self._op == "update":
            hit = [r for r in rows if self._match(r)]
            for r in hit:
                r.update(copy.deepcopy(self._payload))
            return _Result(copy.deepcopy(hit))

        if self._op == "upsert":
            keys = [k.strip() for k in (self._conflict or "id").split(",")]
            payload = self._payload
            existing = None
            # like Postgres: a NULL in a unique key never conflicts
            if all(payload.get(k) is not None for k in keys):
                existing = next((r for r in rows
                                 if all(r.get(k) == payload.get(k) for k in keys)), None)
            if existing:
                existing.update(copy.deepcopy(payload))
                return _Result([copy.deepcopy(existing)])
            new = self._new_row(payload)
            rows.append(new)
            return _Result([copy.deepcopy(new)])

        if self._op == "delete":
            gone = [r for r in rows if self._match(r)]
            rows[:] = [r for r in rows if not self._match(r)]
            return _Result(copy.deepcopy(gone))

        raise AssertionError(f"unknown op {self._op}")


class FakeSupabase:
    def __init__(self):
        self.tables: dict[str, list[dict]] = {}
        self.calls: list[tuple[str, str]] = []
        self.fail_tables: set[str] = set()

    def table(self, name: str) -> _Query:
        return _Query(self, name)

    # ---- helpers for tests --------------------------------------------------
    def rows(self, name: str) -> list[dict]:
        return self.tables.get(name, [])

    def add(self, name: str, **row) -> dict:
        return self.table(name).insert(row).execute().data[0]


class FakeNmap:
    """Stand-in for nmap.PortScanner: returns a canned result per host."""

    def __init__(self, hosts: dict | None = None, raise_on_scan: Exception | None = None,
                 raw_xml: str = ""):
        self.hosts = hosts or {}
        self.raise_on_scan = raise_on_scan
        self.raw_xml = raw_xml
        self.calls: list[dict] = []
        self._scanned: list[str] = []

    def scan(self, hosts: str = "", arguments: str = ""):
        self.calls.append({"hosts": hosts, "arguments": arguments})
        if self.raise_on_scan:
            raise self.raise_on_scan
        self._scanned = [h for h in hosts.split() if h in self.hosts]

    def all_hosts(self):
        return list(self._scanned)

    def get_nmap_last_output(self):
        return self.raw_xml

    def __getitem__(self, ip):
        return _NmapHost(self.hosts[ip])


class _NmapHost(dict):
    def state(self):
        return self.get("status", {}).get("state", "up")

    def hostnames(self):
        return self.get("hostnames", [])
