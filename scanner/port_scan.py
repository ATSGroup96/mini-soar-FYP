"""
Port + service + OS detection via nmap (python-nmap wrapper).

For each in-scope live host we run an nmap service/version scan and, when
possible, OS detection. Results are normalized into dataclasses the rest of the
pipeline consumes. CPE strings from nmap feed the offline CVE matcher.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from common.allowlist import assert_in_scope
from common.audit import log_event
from common import syslog_logger as slog

# A focused default port set keeps lab scans quick; override with full_ports=True
DEFAULT_PORTS = (
    "21,22,23,25,53,80,110,111,135,139,143,443,445,512,513,514,"
    "993,995,1099,1433,1524,2049,2121,3306,3389,3632,5432,5900,6000,6667,8009,8080,8180,8787"
)


@dataclass
class ServiceInfo:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service_name: str = ""
    product: str = ""
    version: str = ""
    cpe: str = ""
    banner: str = ""


@dataclass
class HostScan:
    ip: str
    mac: str | None = None
    hostname: str = ""
    os_guess: str = ""
    os_accuracy: int = 0
    services: list[ServiceInfo] = field(default_factory=list)


def _os_from_services(services) -> tuple[str, int]:
    """OS guess from service banners/CPEs when nmap -O is not possible
    (NAT mode). Rough on purpose: 'Linux' / 'Windows' plus a distro hint."""
    text = " ".join(f"{s.product} {s.version} {s.banner} {s.cpe}" for s in services).lower()
    if not text.strip():
        return "", 0
    if "windows" in text or "microsoft" in text:
        return "Microsoft Windows (from service banners)", 60
    for distro in ("ubuntu", "debian", "centos", "red hat", "fedora"):
        if distro in text:
            return f"Linux - {distro.title()} (from service banners)", 60
    if any(k in text for k in ("linux", "unix", "openssh", "apache", "samba", "vsftpd", "postfix")):
        return "Linux / Unix (from service banners)", 50
    return "", 0


def scan_host(ip: str, mac: str | None = None, full_ports: bool = False,
              os_detect: bool = True) -> HostScan:
    """Service/version (+OS) scan of a single in-scope host."""
    assert_in_scope(ip)  # hard gate, fails closed
    result = HostScan(ip=ip, mac=mac)

    try:
        from common.netmode import nmap_scanner
        nm = nmap_scanner()
    except Exception as e:
        log_event("engine", "portscan.skip", ip, {"reason": "nmap missing", "error": str(e)[:200]})
        return result

    ports = "-p-" if full_ports else f"-p {DEFAULT_PORTS}"
    from common.netmode import is_nat
    nat = is_nat()
    # -sV service/version; -sS SYN; -O OS; -T4 lab-speed; -n no DNS
    # NAT mode (Docker Desktop on Windows): -sT connect scan, no raw -O
    scan_type = "-sT -Pn --unprivileged" if nat else "-sS"
    args = f"{scan_type} -sV {ports} -T4 -n --max-retries 2 --host-timeout 180s"
    if os_detect and not nat:
        args += " -O --osscan-guess"

    slog.send(f"port scan started: {ip}", slog.INFO)
    try:
        nm.scan(hosts=ip, arguments=args)
    except Exception as e:
        log_event("engine", "portscan.error", ip, {"error": str(e)[:200]})
        return result

    if ip not in nm.all_hosts():
        return result

    node = nm[ip]
    hostnames = node.hostnames() or []
    if hostnames:
        result.hostname = hostnames[0].get("name", "")

    # OS detection
    osmatches = node.get("osmatch", []) if hasattr(node, "get") else []
    if osmatches:
        result.os_guess = osmatches[0].get("name", "")
        try:
            result.os_accuracy = int(osmatches[0].get("accuracy", 0))
        except (TypeError, ValueError):
            result.os_accuracy = 0

    # services
    for proto in ("tcp", "udp"):
        if proto not in node:
            continue
        for port, pdata in node[proto].items():
            if pdata.get("state") != "open":
                continue
            cpe = pdata.get("cpe", "")
            if isinstance(cpe, list):
                cpe = cpe[0] if cpe else ""
            result.services.append(ServiceInfo(
                port=int(port), protocol=proto, state=pdata.get("state", ""),
                service_name=pdata.get("name", ""),
                product=pdata.get("product", ""),
                version=pdata.get("version", ""),
                cpe=cpe,
                banner=(pdata.get("extrainfo", "") or "").strip(),
            ))

    if not result.os_guess:
        result.os_guess, result.os_accuracy = _os_from_services(result.services)

    log_event("engine", "portscan.finish", ip,
              {"open_ports": [s.port for s in result.services],
               "os": result.os_guess})
    slog.send(f"port scan finished: {ip} ({len(result.services)} open)", slog.NOTICE)
    return result
