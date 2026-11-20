"""
Nuclei template checks (misconfigurations, exposed panels, default logins).

Runs ProjectDiscovery Nuclei against the open services nmap found on ONE
in-scope host and turns its JSONL output into findings. Like Beligiannis et al.
(2026), Nuclei sits next to Nmap; unlike them, its findings go on to risk
scoring, prioritization and approved remediation instead of only a report.

Non-intrusive by construction (proposal: "assessment tools are used in their
non-intrusive check modes only"):
  * only templates with the tags below run; dos / fuzz / intrusive / OSINT /
    brute-force templates are excluded even if a tag matches
  * no interactsh (-ni): no out-of-band callbacks to servers outside the lab
  * no redirects (-dr): a web page can never send Nuclei to another host
  * no update check (-duc), rate-limited, short timeouts, one host at a time
  * targets are built in code from the host's own IP and its open ports, after
    assert_in_scope(); every result whose host is not that IP is dropped

Needs the nuclei binary (Docker image / run.bat update install it) and its
templates (downloaded once, like the NVD data). Missing binary = skipped.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from common.allowlist import assert_in_scope
from common.audit import log_event
from common import syslog_logger as slog

RUN_TAGS = "misconfig,exposure,panel,default-login,unauth,cve,network"
EXCLUDE_TAGS = "dos,fuzz,fuzzing,intrusive,osint,brute-force,bruteforce,headless"
SEVERITIES = "low,medium,high,critical"
# exposed admin panels are reported by Nuclei as "info"; keep only those
INFO_TAGS_KEPT = {"panel", "default-login", "exposure", "misconfig"}
WEB_NAMES = ("http", "https", "http-proxy", "http-alt", "ssl/http", "https-alt")
TLS_PORTS = (443, 8443, 9443)

_WIN_PATHS = (r"tools\nuclei\nuclei.exe",
              os.path.expandvars(r"%USERPROFILE%\go\bin\nuclei.exe"))


def binary() -> str | None:
    """Path to the nuclei binary, or None when it is not installed."""
    env = (os.environ.get("NUCLEI_PATH", "") or "").strip().strip('"')
    if env and Path(env).exists():
        return env
    found = shutil.which("nuclei")
    if found:
        return found
    for p in _WIN_PATHS:
        if Path(p).exists():
            return str(Path(p).resolve())
    return None


def available() -> bool:
    return binary() is not None


def _timeout() -> int:
    try:
        return max(60, int(os.environ.get("NUCLEI_TIMEOUT", "600") or 600))
    except ValueError:
        return 600


def build_targets(ip: str, services) -> list[str]:
    """http(s)://ip:port for web services, ip:port for every other open TCP port."""
    out: list[str] = []
    for s in services:
        port = getattr(s, "port", None) if not isinstance(s, dict) else s.get("port")
        name = (getattr(s, "service_name", "") if not isinstance(s, dict)
                else s.get("service_name", "")) or ""
        proto = (getattr(s, "protocol", "tcp") if not isinstance(s, dict)
                 else s.get("protocol", "tcp")) or "tcp"
        if port is None or proto != "tcp":
            continue
        name = name.lower()
        if name in WEB_NAMES or "http" in name:
            scheme = "https" if ("https" in name or "ssl" in name or port in TLS_PORTS) else "http"
            out.append(f"{scheme}://{ip}:{port}")
        out.append(f"{ip}:{port}")
    return sorted(set(out))


def build_command(nuclei: str, target_file: str) -> list[str]:
    return [nuclei, "-l", target_file, "-jsonl", "-silent", "-nc", "-duc", "-ni", "-dr", "-or",
            "-tags", RUN_TAGS, "-etags", EXCLUDE_TAGS,
            "-severity", "info," + SEVERITIES,
            "-rl", "50", "-c", "10", "-bs", "5", "-timeout", "5", "-retries", "1",
            "-mhe", "15"]


def _port_of(item: dict, ip: str) -> int | None:
    if item.get("port"):
        try:
            return int(item["port"])
        except (TypeError, ValueError):
            pass
    for field in ("matched-at", "host", "url"):
        val = str(item.get(field) or "")
        if "://" in val:
            u = urlparse(val)
            if u.port:
                return u.port
            return 443 if u.scheme == "https" else 80 if u.scheme == "http" else None
        m = re.match(rf"^{re.escape(ip)}:(\d+)", val)
        if m:
            return int(m.group(1))
    return None


def _host_of(item: dict) -> str:
    if item.get("ip"):
        return str(item["ip"])
    val = str(item.get("host") or item.get("matched-at") or "")
    if "://" in val:
        return urlparse(val).hostname or ""
    return val.split(":")[0]


def parse_jsonl(text: str, ip: str) -> list[dict]:
    """Nuclei JSONL -> finding dicts (only for this ip, de-duplicated)."""
    out: list[dict] = []
    seen: set = set()
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if _host_of(item) != ip:
            continue                     # never report another host
        info = item.get("info") or {}
        tags = info.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]
        sev = str(info.get("severity") or "unknown").lower()
        if sev == "info" and not (INFO_TAGS_KEPT & set(tags)):
            continue                     # plain technology detection: not a finding
        tid = item.get("template-id") or item.get("templateID") or "unknown"
        port = _port_of(item, ip)
        key = (f"nuclei:{tid}", port)
        if key in seen:
            continue
        seen.add(key)
        cls = info.get("classification") or {}
        cves = cls.get("cve-id") or []
        if isinstance(cves, str):
            cves = [cves]
        cvss = cls.get("cvss-score")
        try:
            cvss = float(cvss) if cvss not in (None, "") else None
        except (TypeError, ValueError):
            cvss = None
        extracted = item.get("extracted-results") or []
        evidence = item.get("matched-at") or ""
        if item.get("matcher-name"):
            evidence += f" [{item['matcher-name']}]"
        if extracted:
            evidence += " " + ", ".join(str(x) for x in extracted[:3])
        out.append({
            "source": "nuclei", "finding_key": f"nuclei:{tid}",
            "title": info.get("name") or tid, "severity": sev, "port": port,
            "cve_id": (str(cves[0]).upper() if cves else None),
            "cvss_score": cvss, "cvss_vector": cls.get("cvss-metrics") or "",
            "description": (info.get("description") or "").strip()[:1500],
            "evidence": evidence.strip()[:500], "tags": tags,
            "default_login": "default-login" in tags,
        })
    return out


def check_host(ip: str, services) -> list[dict]:
    """Run Nuclei against one in-scope host. Never raises (a failed run = [])."""
    assert_in_scope(ip)
    nuclei = binary()
    if not nuclei:
        return []
    targets = build_targets(ip, services)
    if not targets:
        return []
    with tempfile.TemporaryDirectory(prefix="minisoar-nuclei-") as tmp:
        tfile = Path(tmp) / "targets.txt"
        tfile.write_text("\n".join(targets) + "\n", encoding="utf-8")
        cmd = build_command(nuclei, str(tfile))
        log_event("engine", "nuclei.start", ip, {"targets": targets})
        slog.send(f"nuclei started: {ip} ({len(targets)} targets)", slog.INFO)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=_timeout(),
                                  encoding="utf-8", errors="replace")
        except subprocess.TimeoutExpired as e:
            out = e.stdout if isinstance(e.stdout, str) else (e.stdout or b"").decode("utf-8", "replace")
            findings = parse_jsonl(out, ip)
            log_event("engine", "nuclei.timeout", ip, {"after_sec": _timeout(),
                                                       "findings": len(findings)})
            return findings
        except Exception as e:
            log_event("engine", "nuclei.error", ip, {"error": str(e)[:200]})
            return []
    findings = parse_jsonl(proc.stdout, ip)
    log_event("engine", "nuclei.finish", ip,
              {"rc": proc.returncode, "findings": [f["finding_key"] for f in findings][:50]})
    for f in findings:
        if f["severity"] in ("high", "critical") or f["default_login"]:
            slog.send(f"NUCLEI {f['severity'].upper()} on {ip}:{f['port']} {f['title']}", slog.ALERT)
    return findings
