"""
Digital-twin "what-if" simulation.

Clone the current state of a host (or the whole network), apply a PROPOSED fix
in memory ONLY, re-score, and report the before/after risk and grade — so an
analyst can see a fix's impact before approving it. Nothing is executed.

Supported hypothetical fixes:
  * block_port   {port}          -> drop vulns/services on that port
  * stop_service {service|port}  -> drop that service + its vulns
  * patch_cve    {cve_id}        -> drop that CVE across the host
"""
from __future__ import annotations

import copy

from ml.risk_score import score_host, grade_from_score
from .attack_path import build_graph, rank_paths


def _apply_one(h: dict, fix: dict) -> int:
    """Apply ONE hypothetical fix to the in-memory copy h (mutates h).
    Returns how many services/findings it removed (0 = the fix matched nothing)."""
    ftype = fix.get("type") or fix.get("action_type")
    params = fix.get("params") or fix
    if ftype in ("block_port", "stop_service"):
        port = params.get("port")
        svc = str(params.get("service") or "").strip().lower()
        if port in (None, "") and svc.isdigit():      # "stop_service 23" means port 23
            port, svc = svc, ""
        port = int(port) if port not in (None, "") else None
        gone = {s.get("port") for s in h.get("services", [])
                if (port is not None and s.get("port") == port)
                or (svc and (s.get("service_name") or "").lower() == svc)}
        before = len(h.get("services", [])) + len(h.get("vulnerabilities", []))
        h["services"] = [s for s in h.get("services", []) if s.get("port") not in gone]
        h["vulnerabilities"] = [v for v in h.get("vulnerabilities", [])
                                if v.get("port") not in gone]
        return before - len(h["services"]) - len(h["vulnerabilities"])
    if ftype == "patch_cve":
        cve = str(params.get("cve_id") or "").strip().upper()
        before = len(h.get("vulnerabilities", []))
        h["vulnerabilities"] = [v for v in h.get("vulnerabilities", [])
                                if (v.get("cve_id") or "").upper() != cve]
        return before - len(h["vulnerabilities"])
    if ftype == "disable_account":
        # locking the account removes the default-credential exposure
        # (only on the given port when one is passed)
        port = params.get("port")
        n = 0
        for s in h.get("services", []):
            if s.get("has_default_cred") and (port in (None, "") or s.get("port") == int(port)):
                s["has_default_cred"] = False
                n += 1
        return n
    return 0


def _as_list(fix) -> list[dict]:
    return fix if isinstance(fix, list) else [fix]


def _label(fix: dict) -> str:
    p = fix.get("params") or fix
    t = fix.get("type") or fix.get("action_type")
    val = p.get("port") or p.get("service") or p.get("cve_id") or p.get("username") or ""
    return f"{t} {val}".strip()


def _apply_hypothetical(host: dict, fix, unmatched: list | None = None) -> dict:
    h = copy.deepcopy(host)
    for f in _as_list(fix):
        if _apply_one(h, f) == 0 and unmatched is not None:
            unmatched.append(_label(f))
    return h


def _summary(h: dict) -> dict:
    vulns = h.get("vulnerabilities", [])
    scores = sorted(((v.get("ml_risk_score") or 0, v) for v in vulns),
                    key=lambda x: x[0], reverse=True)
    return {
        "risk_score": h.get("risk_score"),
        "grade": h.get("risk_grade"),
        "vuln_count": len(vulns),
        "open_ports": len(h.get("services", [])),
        "critical": sum(1 for sc, _ in scores if sc >= 80),
        "kev": sum(1 for v in vulns if v.get("in_kev")),
        "default_creds": sum(1 for s in h.get("services", []) if s.get("has_default_cred")),
        # total exposure: sum of all finding scores / 100 (shows progress even
        # when the worst single finding, and so the grade, stays the same)
        "exposure": round(sum(sc for sc, _ in scores) / 100, 1),
        "top_remaining": [{"cve_id": v.get("cve_id"), "port": v.get("port"),
                           "score": sc} for sc, v in scores[:3]],
    }


def simulate_host(host: dict, fix: dict) -> dict:
    before = copy.deepcopy(host)
    score_host(before)
    unmatched: list[str] = []
    after = _apply_hypothetical(host, fix, unmatched)
    score_host(after)
    b, a = _summary(before), _summary(after)
    note = ""
    if unmatched:
        note = ("No open service or finding matched: " + ", ".join(unmatched)
                + " (already closed, or not on this host).")
    elif (a["risk_score"] or 0) >= (b["risk_score"] or 0) and a["vuln_count"] < b["vuln_count"]:
        top = a["top_remaining"][0] if a["top_remaining"] else None
        where = f"{top['cve_id']} on port {top['port']}" if top else "another finding"
        note = (f"Host risk is set by its single worst finding, which is still open "
                f"({where}). Fix that too to lower the grade; the exposure and counts "
                f"below show the progress.")
    return {
        "fix": fix, "fixes_applied": len(_as_list(fix)), "unmatched": unmatched,
        "before": b, "after": a, "note": note,
        "risk_reduction": round((b["risk_score"] or 0) - (a["risk_score"] or 0), 1),
        "exposure_reduction": round(b["exposure"] - a["exposure"], 1),
    }


def simulate_network(hosts: list[dict], target_ip: str, fix: dict) -> dict:
    """Apply a fix to one host and show the effect on the whole attack graph."""
    before_hosts = copy.deepcopy(hosts)
    for h in before_hosts:
        score_host(h)
    before_paths = rank_paths(build_graph(before_hosts))

    after_hosts = copy.deepcopy(hosts)
    for h in after_hosts:
        if h["ip"] == target_ip:
            h.update(_apply_hypothetical(h, fix))
        score_host(h)
    after_paths = rank_paths(build_graph(after_hosts))

    def _net_risk(hs):
        return round(sum(h.get("risk_score", 0) for h in hs) / max(len(hs), 1), 1)

    return {
        "target": target_ip, "fix": fix,
        "network_risk_before": _net_risk(before_hosts),
        "network_risk_after": _net_risk(after_hosts),
        "attack_paths_before": len(before_paths),
        "attack_paths_after": len(after_paths),
        "top_path_before": before_paths[0] if before_paths else None,
        "top_path_after": after_paths[0] if after_paths else None,
    }
