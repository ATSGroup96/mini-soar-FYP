"""
Data side of the digital twin: load the network from Supabase, keep the
twin's predictions with each remediation, and check them after the next scan.

Every function here is fail-safe: if migration 005 has not been run yet (no
`criticality` column, no `twin_dependencies` table, no `twin_prediction`
column) the twin still works with defaults and the rest of Mini-SOAR is not
affected.
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone

from common.audit import log_event
from . import twin_model as T

PAPER = ("Jiang, Wang, Ding, Lu & Jing (2024), Leveraging Digital Twin Technology "
         "for Enhanced Cybersecurity in Cyber-Physical Production Systems, "
         "Future Internet 16(4):134")
MAX_PATCH_CANDIDATES = 40


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---- loading ---------------------------------------------------------------------
def load_hosts(client) -> list[dict]:
    """Reassemble host dicts (assets + open services + open vulns) from Supabase."""
    if not client:
        return []
    assets = client.table("assets").select("*").execute().data
    hosts = []
    for a in assets:
        svc = client.table("services").select("*").eq("asset_id", a["id"]).execute().data
        svc = [s for s in svc if (s.get("state") or "open") == "open"]
        port_of = {s["id"]: s["port"] for s in svc}
        vulns = (client.table("vulnerabilities").select("*").eq("asset_id", a["id"])
                 .eq("status", "open").execute().data)
        seen, vlist = set(), []
        for v in vulns:
            port = port_of.get(v.get("service_id"))
            if v.get("service_id") and port is None:
                continue  # its service is closed now
            key = (v["cve_id"], port)
            if key in seen:
                continue  # one entry per CVE per port
            seen.add(key)
            vlist.append({"cve_id": v["cve_id"], "cvss_score": v.get("cvss_score"),
                          "epss_score": v.get("epss_score"),
                          "epss_percentile": v.get("epss_percentile"),
                          "in_kev": v.get("in_kev"), "port": port,
                          "confidence": v.get("confidence") or "version-confirmed"})
        hosts.append({
            "ip": a["ip"], "asset_id": a.get("id"), "hostname": a.get("hostname"),
            "os_guess": a.get("os_guess"), "is_rogue": a.get("is_rogue"),
            "criticality": a.get("criticality") or T.DEFAULT_CRITICALITY,
            "risk_score": a.get("risk_score") or 0,
            "risk_grade": a.get("risk_grade") or "A",
            "services": [{"port": s["port"], "service_name": s.get("service_name"),
                          "has_default_cred": s.get("has_default_cred")} for s in svc],
            "vulnerabilities": vlist,
        })
    return hosts


def load_context(client, hosts: list[dict] | None = None) -> dict:
    """Asset weights (critical/normal/low) + the admin's manual dependencies."""
    ctx = {"criticality": {}, "manual": [], "ready": False}
    if hosts is not None:
        ctx["criticality"] = {T.norm_ip(h["ip"]): h.get("criticality") or T.DEFAULT_CRITICALITY
                              for h in hosts}
    if not client:
        return ctx
    if hosts is None:
        try:
            rows = client.table("assets").select("ip,criticality").execute().data
            ctx["criticality"] = {T.norm_ip(r["ip"]): r.get("criticality") or T.DEFAULT_CRITICALITY
                                  for r in rows}
        except Exception:
            pass
    try:
        ctx["manual"] = client.table("twin_dependencies").select("*").execute().data or []
        ctx["ready"] = True
    except Exception:
        ctx["manual"] = []         # migration 005 not run yet
    return ctx


def scored(hosts: list[dict]) -> list[dict]:
    from ml.risk_score import score_host
    return [score_host(copy.deepcopy(h)) for h in hosts]


def bounded_candidates(hosts: list[dict]) -> list[dict]:
    """All port / account fixes + the worst CVEs as vendor-patch candidates, so a
    host with hundreds of CVEs still ranks in a second or two."""
    cands = T.candidate_fixes(hosts)
    patches = [c for c in cands if c["fix"]["type"] == "patch_cve"]
    if len(patches) <= MAX_PATCH_CANDIDATES:
        return cands
    score: dict = {}
    for h in hosts:
        for v in h.get("vulnerabilities", []):
            key = (T.norm_ip(h["ip"]), (v.get("cve_id") or "").upper())
            score[key] = max(score.get(key, 0), v.get("ml_risk_score") or 0)
    patches.sort(key=lambda c: score.get((c["ip"], c["fix"]["params"]["cve_id"]), 0),
                 reverse=True)
    keep = {id(c) for c in patches[:MAX_PATCH_CANDIDATES]}
    return [c for c in cands if c["fix"]["type"] != "patch_cve" or id(c) in keep]


# ---- the overview the dashboard shows ----------------------------------------------
def overview(client) -> dict:
    hosts = scored(load_hosts(client))
    ctx = load_context(client, hosts)
    crit, manual = ctx["criticality"], ctx["manual"]
    ours_state = T.twin_state(hosts, crit, manual, "improved")
    base_state = T.twin_state(hosts, crit, manual, "baseline")

    cands = bounded_candidates(hosts)
    ours = T.rank_fixes(hosts, crit, manual, "improved", candidates=cands)
    base = T.rank_fixes(hosts, crit, manual, "baseline", candidates=cands)

    checks = recent_checks(client)
    return {
        "ready": ctx["ready"], "paper": PAPER,
        "parameters": {"criticality_weight": T.CRITICALITY_WEIGHT, "ccs_floor": T.CCS_FLOOR,
                       "band_weights": T.BAND_WEIGHTS, "cvss_bands": T.CVSS_BANDS,
                       "default_cred_score": T.DEFAULT_CRED_SCORE, "tolerance": T.TOLERANCE},
        "improved": _trim(ours_state), "baseline": _trim(base_state),
        "ranking": ours, "baseline_ranking": base,
        "comparison": T.compare(ours, base),
        "accuracy": T.accuracy([c["result"] for c in checks]),
        "recent_checks": checks[:10],
    }


def _trim(state: dict, n: int = 60) -> dict:
    return {"hosts": state["hosts"], "network_total": state["network_total"],
            "network_avg": state["network_avg"], "components": state["components"][:n],
            "dependencies": state["dependencies"]}


def whatif(client, target_ip: str, fixes) -> dict:
    """Twin numbers for the what-if panel (host + network, before / after)."""
    hosts = scored(load_hosts(client))
    ctx = load_context(client, hosts)
    pred = T.predict(hosts, target_ip, fixes, ctx["criticality"], ctx["manual"])
    before = T.twin_state(hosts, ctx["criticality"], ctx["manual"])
    after = T.twin_state(T.apply_fix(hosts, target_ip, fixes, rescore=True),
                         ctx["criticality"], ctx["manual"])
    pred.pop("snapshot", None)              # only needed when stored with a fix
    return dict(pred, network_total_before=before["network_total"],
                network_total_after=after["network_total"])


# ---- predictions kept with each remediation ------------------------------------------
TWIN_ACTIONS = ("block_port", "stop_service", "disable_account")


def prediction_for(client, asset_ip: str, action_type: str, params: dict) -> dict | None:
    """What the twin expects this remediation to change (None if it cannot say)."""
    if action_type not in TWIN_ACTIONS or not client:
        return None
    try:
        hosts = scored(load_hosts(client))
        ctx = load_context(client, hosts)
        fix = {"type": action_type, "params": {k: v for k, v in (params or {}).items()
                                               if k not in ("target_ip", "os", "proto")}}
        pred = T.predict(hosts, asset_ip, fix, ctx["criticality"], ctx["manual"])
        pred["made_at"] = _now()
        return pred
    except Exception as e:
        log_event("engine", "twin.predict.error", asset_ip, {"error": str(e)[:200]})
        return None


def evaluate_pending(host_results: list[dict], client=None) -> int:
    """After a scan: compare every verified fix's prediction with what the scan
    really found. Returns how many predictions were checked."""
    from common.db import get_service_client
    client = client or get_service_client()
    if not client:
        return 0
    try:
        rows = client.table("remediations").select("*").eq("status", "succeeded").execute().data
    except Exception:
        return 0
    todo = [r for r in rows if r.get("verified_fixed") and r.get("twin_prediction")
            and not r.get("twin_result")]
    if not todo:
        return 0
    fresh = scored(host_results)
    ctx = load_context(client)
    groups: dict[str, list[dict]] = {}
    for r in todo:
        groups.setdefault(T.norm_ip(r["twin_prediction"].get("ip")), []).append(r)
    n = 0
    for ip, rows_ in groups.items():
        results = T.check_predictions([r["twin_prediction"] for r in rows_], fresh,
                                      ctx["criticality"], ctx["manual"])
        for r, res in zip(rows_, results):
            if res is None:
                continue        # host not in this scan (or its scan failed): try next time
            res["checked_at"] = _now()
            try:
                client.table("remediations").update({"twin_result": res}) \
                    .eq("id", r["id"]).execute()
                n += 1
                log_event("engine", "twin.check", ip,
                          {"remediation": r["id"], "match": res["match"], "error": res["error"]})
            except Exception:
                pass
    return n


def recent_checks(client) -> list[dict]:
    if not client:
        return []
    try:
        rows = client.table("remediations").select("*").execute().data
    except Exception:
        return []
    out = []
    for r in rows:
        if r.get("twin_result"):
            p = r.get("twin_prediction") or {}
            out.append({"remediation_id": r["id"], "action": r.get("action_type"),
                        "params": {k: v for k, v in (r.get("action_params") or {}).items()
                                   if k in ("port", "service", "username")},
                        "ip": p.get("ip"), "result": r["twin_result"]})
    out.sort(key=lambda c: c["result"].get("checked_at") or "", reverse=True)
    return out


# ---- admin changes (called by the API) ----------------------------------------------
def set_criticality(client, asset_ip: str, level: str, actor: str) -> dict:
    if level not in T.CRITICALITY_WEIGHT:
        raise ValueError(f"criticality must be one of {', '.join(T.CRITICALITY_WEIGHT)}")
    ip = T.norm_ip(asset_ip)
    rows = client.table("assets").select("id,ip").execute().data
    asset = next((a for a in rows if T.norm_ip(a["ip"]) == ip), None)
    if not asset:
        raise LookupError(f"asset {ip} not found")
    client.table("assets").update({"criticality": level}).eq("id", asset["id"]).execute()
    log_event(actor, "twin.criticality", ip, {"criticality": level})
    return {"ip": ip, "criticality": level}


def _check_component(cid: str) -> str:
    import ipaddress
    ip, _, part = (cid or "").partition("|")
    ipaddress.ip_address(ip)                       # raises ValueError
    if part != "os" and not (part.isdigit() and 0 < int(part) < 65536):
        raise ValueError(f"bad component id {cid!r} (use IP|os or IP|port)")
    return f"{ip}|{part}"


def set_dependency(client, frm: str, to: str, rule: str, enabled: bool, note: str,
                   actor: str) -> dict:
    frm, to = _check_component(frm), _check_component(to)
    if frm == to:
        raise ValueError("a component cannot depend on itself")
    if rule not in T.RULES:
        raise ValueError(f"rule must be one of {', '.join(T.RULES)}")
    row = {"from_component": frm, "to_component": to, "rule": rule, "enabled": bool(enabled),
           "note": (note or "")[:300]}
    res = client.table("twin_dependencies").upsert(
        row, on_conflict="from_component,to_component").execute()
    log_event(actor, "twin.dependency", frm, {"to": to, "rule": rule, "enabled": bool(enabled)})
    return res.data[0] if res.data else row


def remove_dependency(client, dep_id: str, actor: str) -> int:
    gone = client.table("twin_dependencies").delete().eq("id", dep_id).execute().data
    log_event(actor, "twin.dependency.remove", dep_id, {"removed": len(gone or [])})
    return len(gone or [])
