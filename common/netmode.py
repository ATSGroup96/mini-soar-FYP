"""
Where the engine runs, and what that means for scanning.

NETWORK_MODE (in .env):
  * "host" (default) - Linux engine (e.g. Kali) in Docker with
    `network_mode: host`. The scanner sees the lab directly: ARP discovery,
    SYN scan, OS detection.
  * "nat"  - Docker Desktop on Windows. Containers reach the VirtualBox lab
    through Windows' own network (NAT), which only passes normal TCP
    connections. So the scanner uses TCP connect scans, no ARP, no raw
    packets, and guesses the OS from the service banners instead of -O.
  * "native" - no Docker: the engine runs directly on the machine (Windows
    with Nmap + Npcap, or Linux). Same full scan as "host": ARP/MAC, SYN
    scan, OS detection. The machine's own adapters are read directly.

ENGINE_HOST_IPS (optional): the engine machine's lab address(es) with prefix,
e.g. "192.168.103.1/24". Needed in nat mode (inside a Docker Desktop
container `ip addr` only shows Docker's own network). In other modes it is
added on top of the detected addresses. Used to (a) never scan/fix the engine
machine itself and (b) show the lab network on Settings -> Network scope.

NMAP_PATH (optional): full path to nmap / nmap.exe if it is not on PATH.
"""
from __future__ import annotations

import ipaddress
import os

# ports used to find live hosts when ICMP/ARP are not available (TCP connect)
NAT_PING_PORTS = "21,22,23,25,53,80,111,135,139,443,445,3306,3389,5432,8080"

_NMAP_WINDOWS_PATHS = (r"C:\Program Files (x86)\Nmap\nmap.exe",
                       r"C:\Program Files\Nmap\nmap.exe")


def network_mode() -> str:
    mode = (os.environ.get("NETWORK_MODE", "host") or "host").strip().lower()
    if mode in ("nat", "docker-desktop", "windows"):
        return "nat"
    if mode in ("native", "windows-native", "direct"):
        return "native"
    return "host"


def is_nat() -> bool:
    return network_mode() == "nat"


def is_native() -> bool:
    return network_mode() == "native"


def is_windows() -> bool:
    return os.name == "nt"


def nmap_scanner():
    """python-nmap PortScanner that also finds nmap.exe on Windows."""
    import nmap
    paths = []
    env_path = (os.environ.get("NMAP_PATH", "") or "").strip().strip('"')
    if env_path:
        paths.append(env_path)
    paths += ["nmap", "/usr/bin/nmap", "/usr/local/bin/nmap"]
    if is_windows():
        paths += list(_NMAP_WINDOWS_PATHS)
    return nmap.PortScanner(nmap_search_path=tuple(paths))


def engine_host_interfaces() -> list[dict]:
    """ENGINE_HOST_IPS parsed as interfaces: [{iface, ip, network, private}]."""
    out = []
    for part in (os.environ.get("ENGINE_HOST_IPS", "") or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            itf = ipaddress.ip_interface(part if "/" in part else part + "/24")
        except ValueError:
            continue
        if itf.version != 4:
            continue
        out.append({"iface": "windows-host", "ip": str(itf.ip),
                    "network": str(itf.network), "private": itf.ip.is_private})
    return out
