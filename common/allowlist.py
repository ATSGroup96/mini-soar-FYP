"""
Allowlist guard — the single chokepoint for "is this target in scope?".

Every module that touches the network (discovery, port scan, service detect,
default-cred check, TLS check, SSH remediation) MUST route its targets through
`filter_targets()` or `assert_in_scope()`. Targets outside ALLOWED_RANGES, or
inside DENY_HOSTS, are dropped before any packet is sent. Fails closed.
"""
from __future__ import annotations

import ipaddress
from typing import Iterable

from .config import assert_authorized_to_run
from .scope_store import effective_scope


class ScopeError(RuntimeError):
    """A target was requested that is not inside the authorized scope."""


def _as_ip(addr: str) -> ipaddress._BaseAddress:
    return ipaddress.ip_address(str(addr).strip())


def is_in_scope(addr: str) -> bool:
    """True only if addr is inside an allowed range AND not in deny list."""
    s = effective_scope()
    try:
        ip = _as_ip(addr)
    except ValueError:
        return False

    # explicit deny wins
    for deny in s["deny_hosts"]:
        try:
            if ip == _as_ip(deny):
                return False
        except ValueError:
            continue

    return any(ip in net for net in s["allowed_ranges"])


def assert_in_scope(addr: str) -> None:
    if not is_in_scope(addr):
        raise ScopeError(
            f"Target {addr!r} is OUTSIDE the authorized allowlist. "
            f"Refusing to proceed."
        )


def filter_targets(addrs: Iterable[str]) -> list[str]:
    """
    Return only the in-scope addresses from `addrs`. Enforces the global
    authorization gate first, so an unauthorized run can never slip through.
    """
    assert_authorized_to_run()
    kept, dropped = [], []
    for a in addrs:
        (kept if is_in_scope(a) else dropped).append(str(a))
    if dropped:
        # Visible, auditable notice — never silently expand scope.
        from .audit import log_event
        log_event(
            actor="engine",
            action="scope.reject",
            target=",".join(dropped[:50]),
            detail={"rejected_count": len(dropped)},
        )
    return kept


def expand_scope() -> list[str]:
    """
    Enumerate every host address inside the allowlist (minus deny hosts).
    Used when the operator asks to scan "the whole authorized scope".
    """
    assert_authorized_to_run()
    s = effective_scope()
    hosts: list[str] = []
    for net in s["allowed_ranges"]:
        # .hosts() skips network/broadcast; cap to keep lab scans sane
        for ip in net.hosts():
            if is_in_scope(str(ip)):
                hosts.append(str(ip))
            if len(hosts) >= 4096:
                return hosts
    return hosts
