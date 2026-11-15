"""
Host discovery — find live hosts inside the authorized scope.

Two methods, both scope-gated:
  * ARP sweep (scapy) — fast & reliable on a local L2 lab segment, also yields
    the MAC address (used for rogue-device detection).
  * ICMP/TCP ping (nmap -sn) — fallback when ARP isn't available.

Nothing here ever touches an address that is not in the allowlist.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from common.allowlist import filter_targets, expand_scope
from common.audit import log_event
from common import syslog_logger as slog


@dataclass
class LiveHost:
    ip: str
    mac: str | None = None
    method: str = ""
    extra: dict = field(default_factory=dict)


def arp_sweep(targets: list[str]) -> list[LiveHost]:
    """ARP who-has sweep via scapy. Returns hosts that answered."""
    from common.netmode import is_nat, is_windows
    if is_nat():
        return []  # Docker Desktop (Windows): no layer-2 access to the lab
    if is_windows():
        # Windows native: scapy would send on the default (Wi-Fi) adapter.
        # nmap -sn (below) does the ARP ping on the right adapter via Npcap
        # and returns the MAC address too.
        return []
    targets = filter_targets(targets)
    if not targets:
        return []
    try:
        from scapy.all import ARP, Ether, srp  # imported lazily
    except Exception:
        return []  # scapy/libpcap unavailable -> caller falls back to nmap

    hosts: list[LiveHost] = []
    # batch the request; 2s timeout is plenty on a host-only lab net
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=targets)
    try:
        answered, _ = srp(pkt, timeout=2, verbose=0)
    except PermissionError:
        return []  # needs NET_RAW; compose grants it, bare runs may not
    for _, rcv in answered:
        hosts.append(LiveHost(ip=rcv.psrc, mac=rcv.hwsrc.lower(), method="arp"))
    return hosts


def nmap_ping(targets: list[str]) -> list[LiveHost]:
    """nmap -sn host discovery fallback."""
    targets = filter_targets(targets)
    if not targets:
        return []
    try:
        from common.netmode import nmap_scanner
        nm = nmap_scanner()
    except Exception as e:
        log_event("engine", "discovery.nmap_missing", "", {"error": str(e)[:200]})
        return []
    try:
        from common.netmode import is_nat, NAT_PING_PORTS
        if is_nat():
            # Docker Desktop: only normal TCP connections get through, so
            # "ping" by trying a few common ports with connect()
            args = f"-sn -n --unprivileged -PS{NAT_PING_PORTS} --max-retries 1"
        else:
            args = "-sn -n --max-retries 1"
        nm.scan(hosts=" ".join(targets), arguments=args)
    except Exception:
        return []
    hosts: list[LiveHost] = []
    for ip in nm.all_hosts():
        if nm[ip].state() == "up":
            mac = nm[ip]["addresses"].get("mac")
            hosts.append(LiveHost(ip=ip, mac=(mac.lower() if mac else None),
                                  method="nmap-sn"))
    return hosts


def discover(targets: list[str] | None = None) -> list[LiveHost]:
    """
    Discover live hosts. If `targets` is None, enumerate the whole authorized
    scope from ALLOWED_RANGES. ARP first, nmap fallback, results merged by IP.
    """
    if targets is None:
        targets = expand_scope()
    else:
        targets = filter_targets(targets)

    log_event("engine", "discovery.start", ",".join(targets[:20]),
              {"target_count": len(targets)})
    slog.send(f"host discovery started for {len(targets)} targets", slog.INFO)

    merged: dict[str, LiveHost] = {}
    for h in arp_sweep(targets):
        merged[h.ip] = h
    for h in nmap_ping(targets):
        if h.ip in merged:
            if h.mac and not merged[h.ip].mac:
                merged[h.ip].mac = h.mac
        else:
            merged[h.ip] = h

    hosts = list(merged.values())
    log_event("engine", "discovery.finish", "",
              {"live_hosts": len(hosts), "ips": [h.ip for h in hosts]})
    slog.send(f"host discovery finished: {len(hosts)} live", slog.NOTICE)
    return hosts
