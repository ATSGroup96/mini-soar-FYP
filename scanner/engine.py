"""
Scan orchestration.

Pipeline per run:
  discover live hosts (scope-gated)
    -> for each host: port/service/OS scan
         -> default-credential check
         -> TLS certificate check
         -> (optional) offline CVE match        [intel, Part 3]
         -> (optional) ML explainable risk score [ml,    Part 4]
    -> encrypted + signed uplink to cloud / offline store

The intel and ML stages are imported lazily; if those modules are not present
yet the scan still completes with everything up to that point.
"""
from __future__ import annotations

import time

from common.config import assert_authorized_to_run, get_settings
from common.audit import log_event
from common import syslog_logger as slog

from . import discovery, port_scan, default_creds, tls_check, uplink


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _try_cve_match(host_result: dict) -> None:
    """Enrich services with CVE matches if the intel module is available."""
    try:
        from intel.match import match_host  # Part 3
    except Exception:
        return
    try:
        host_result["vulnerabilities"] = match_host(host_result)
    except Exception as e:
        log_event("engine", "cve.match.error", host_result["ip"],
                  {"error": str(e)[:200]})


def _try_ml_score(host_result: dict) -> None:
    """Attach explainable ML risk scores if the ML module is available."""
    try:
        from ml.risk_score import score_host  # Part 4
    except Exception:
        return
    try:
        score_host(host_result)
    except Exception as e:
        log_event("engine", "ml.score.error", host_result["ip"],
                  {"error": str(e)[:200]})


def _enabled(name: str) -> bool:
    """SCAN_NUCLEI / SCAN_NETEXEC in .env (default on); 'false' switches a tool off."""
    import os
    return (os.environ.get(name, "true") or "true").strip().lower() not in ("false", "0", "no", "off")


def _try_tools(ip: str, services) -> list[dict]:
    """Nuclei template checks + NetExec read-only posture checks for one host.
    A missing tool or a tool error never stops the scan."""
    found: list[dict] = []
    for env, mod in (("SCAN_NUCLEI", "nuclei_scan"), ("SCAN_NETEXEC", "netexec_check")):
        if not _enabled(env):
            continue
        try:
            module = __import__(f"scanner.{mod}", fromlist=["check_host"])
            found += module.check_host(ip, services)
        except Exception as e:
            log_event("engine", f"{mod}.error", ip, {"error": str(e)[:200]})
    return found


def _mark_rogue(host_result: dict) -> None:
    """Rogue = not on the authorized asset list. Set BEFORE scoring, because
    "rogue_asset" is one of the risk model's inputs (uplink sets it again)."""
    try:
        from common.db import get_service_client
        client = get_service_client()
        if not client:
            return
        rows = (client.table("assets").select("is_authorized")
                .eq("ip", host_result["ip"]).execute().data)
        host_result["is_rogue"] = not (rows and rows[0].get("is_authorized"))
    except Exception:
        pass


class ScanBusy(RuntimeError):
    """Another scan is already running (only one at a time)."""


def run_scan(targets: list[str] | None = None, full_ports: bool = False) -> dict:
    """Run one full scan; refuses to start while another scan is running."""
    assert_authorized_to_run()  # fail closed before anything happens
    from common.filelock import file_lock, LockBusy
    try:
        with file_lock("./data/.scan.lock", blocking=False):
            return _run_scan(targets, full_ports)
    except LockBusy:
        raise ScanBusy("A scan is already running. Wait for it to finish.")


def _run_scan(targets: list[str] | None, full_ports: bool) -> dict:
    s = get_settings()
    started = time.time()
    from common.scope_store import effective_scope
    scope = (",".join(str(n) for n in effective_scope()["allowed_ranges"])
             if targets is None else ",".join(targets))

    log_event("engine", "scan.start", scope, {"full_ports": full_ports})
    slog.send(f"=== SCAN START scope={scope} ===", slog.NOTICE)

    live = discovery.discover(targets)
    host_results: list[dict] = []

    for host in live:
        hs = port_scan.scan_host(host.ip, mac=host.mac, full_ports=full_ports)
        services = [vars(svc) for svc in hs.services]

        # default-credential hygiene check
        creds = default_creds.check_host(host.ip, hs.services)
        cred_ports = {c.port for c in creds}
        for svc in services:
            if svc["port"] in cred_ports:
                svc["has_default_cred"] = True

        # TLS certificate inspection
        certs = [vars(c) for c in tls_check.check_host(host.ip, hs.services)]

        # Nuclei (misconfig / panels / default logins) + NetExec (SMB / RDP / WinRM)
        extra = _try_tools(host.ip, hs.services) if hs.scan_ok else []

        host_result = {
            "ip": hs.ip, "mac": hs.mac, "hostname": hs.hostname,
            "os_guess": hs.os_guess, "os_accuracy": hs.os_accuracy,
            "services": services, "tls": certs,
            "default_creds": [vars(c) for c in creds],
            # False when nmap failed or timed out: "no open ports" then proves
            # nothing, and the upload / ticket steps leave this host untouched
            "scan_ok": hs.scan_ok,
        }

        _try_cve_match(host_result)   # Part 3 (optional)
        if extra:
            # one finding format: tool findings join the CVE matches
            from ml.finding_map import merge_into_host
            host_result["tool_findings"] = merge_into_host(host_result, extra)
        _mark_rogue(host_result)
        _try_ml_score(host_result)    # Part 4 (optional)

        host_results.append(host_result)

    finished = time.time()
    scan_meta = {
        "scope": scope, "started_at": _iso(started),
        "finished_at": _iso(finished), "host_count": len(host_results),
        "status": "completed",
        "summary": {
            "live_hosts": len(host_results),
            "open_services": sum(len(h["services"]) for h in host_results),
            "default_cred_hits": sum(len(h["default_creds"]) for h in host_results),
            "tool_findings": sum(h.get("tool_findings", 0) for h in host_results),
            # hosts whose port scan failed or timed out (nothing is closed for them)
            "failed_hosts": sum(1 for h in host_results if not h.get("scan_ok", True)),
            "duration_sec": round(finished - started, 1),
        },
    }

    result = uplink.push_scan(scan_meta, host_results)

    # open SLA-tracked tickets for high-priority findings + escalate overdue
    try:
        from soar.ticketing import (open_tickets_for_scan, escalate_overdue,
                                    resolve_fixed, resolve_by_rescan)
        resolved = resolve_fixed() + resolve_by_rescan(host_results)
        opened = open_tickets_for_scan(host_results)
        escalated = escalate_overdue()
        scan_meta["summary"]["tickets_opened"] = opened
        scan_meta["summary"]["tickets_resolved"] = resolved
        scan_meta["summary"]["tickets_escalated"] = escalated
    except Exception as e:
        log_event("engine", "ticketing.error", "", {"error": str(e)[:200]})

    # patch prioritization: compare each verified fix's Fix Impact Preview
    # with what this scan really found
    try:
        from soar.prioritization_store import evaluate_pending
        scan_meta["summary"]["fix_checks"] = evaluate_pending(host_results)
    except Exception as e:
        log_event("engine", "fix_preview.check.error", "", {"error": str(e)[:200]})

    # the scan row was written before the ticket step: store the final summary
    if result.get("scan_id"):
        try:
            from common.db import get_service_client
            get_service_client().table("scans").update(
                {"summary": scan_meta["summary"]}).eq("id", result["scan_id"]).execute()
        except Exception:
            pass

    log_event("engine", "scan.finish", scope, scan_meta["summary"])
    slog.send(f"=== SCAN DONE {scan_meta['summary']} ===", slog.NOTICE)
    return {"meta": scan_meta, "uplink": result, "hosts": host_results}
