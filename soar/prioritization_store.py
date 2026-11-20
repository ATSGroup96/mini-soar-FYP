"""
Data side of patch prioritization: load the network from Supabase, keep the
Fix Impact Preview with each remediation, and check it after the next scan.

Tables / columns (migration 006):
  * assets.importance            admin's weight per asset (critical / normal / low)
  * component_dependencies       dependencies the admin adds (or hides) by hand
  * remediations.fix_prediction  the Fix Impact Preview stored when the fix is approved
  * remediations.fix_check       the next scan's comparison with that prediction

Every function here is fail-safe: if migration 006 has not been run yet the
ranking still works with defaults and the rest of Mini-SOAR is not affected.
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone

from common.audit import log_event
from common.db import fetch_all
from . import prioritization as P

PAPER = ("Jiang, Wang, Ding, Lu & Jing (2024), Leveraging Digital Twin Technology "
         "for Enhanced Cybersecurity in Cyber-Physical Production Systems, "
         "Future Internet 16(4):134")
MIGRATION = "supabase/migrations/006_proposal_alignment.sql"
MAX_PATCH_CANDIDATES = 40


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---- loading ---------------------------------------------------------------------
def load_hosts(client) -> list[dict]:
    """Reassemble host dicts (assets + open services + open findings) from Supabase.
    Three paged queries in total, whatever the number of hosts."""
    if not client:
        return []
    assets = fetch_all(client, "assets")
    services = [s for s in fetch_all(client, "services")
                if (s.get("state") or "open") == "open"]
    vulns = fetch_all(client, "vulnerabilities", eq={"status": "open"})

    svc_by_asset: dict = {}
    port_of: dict = {}
    for s in services:
        svc_by_asset.setdefault(s["asset_id"], []).append(s)
        port_of[s["id"]] = s["port"]
    vuln_by_asset: dict = {}
    for v in vulns:
        vuln_by_asset.setdefault(v["asset_id"], []).append(v)

    hosts = []
    for a in assets:
        svc = svc_by_asset.get(a["id"], [])
        seen, vlist = set(), []
        for v in vuln_by_asset.get(a["id"], []):
            port = port_of.get(v.get("service_id"))
            if v.get("service_id") and port is None:
                continue  # its service is closed now
            item = {"cve_id": v.get("cve_id"), "finding_key": v.get("finding_key"),
                    "title": v.get("title"), "source": v.get("source") or "cve",
                    "cvss_score": v.get("cvss_score"), "epss_score": v.get("epss_score"),
                    "epss_percentile": v.get("epss_percentile"),
                    "in_kev": v.get("in_kev"), "port": port,
                    "confidence": v.get("confidence") or "version-confirmed"}
            key = (P._key(item), port)
            if key in seen:
                continue  # one entry per finding per port
            seen.add(key)
            vlist.append(item)
        hosts.append({
            "ip": a["ip"], "asset_id": a.get("id"), "hostname": a.get("hostname"),
            "os_guess": a.get("os_guess"), "is_rogue": a.get("is_rogue"),
            "importance": a.get("importance") or P.DEFAULT_IMPORTANCE,
            "risk_score": a.get("risk_score") or 0,
            "risk_grade": a.get("risk_grade") or "A",
            "services": [{"port": s["port"], "service_name": s.get("service_name"),
                          "has_default_cred": s.get("has_default_cred")} for s in svc],
            "vulnerabilities": vlist,
        })
    return hosts


def load_context(client, hosts: list[dict] | None = None) -> dict:
    """Asset importance (critical/normal/low) + the admin's manual dependencies."""
    ctx = {"importance": {}, "manual": [], "ready": False}
    if hosts is not None:
        ctx["importance"] = {P.norm_ip(h["ip"]): h.get("importance") or P.DEFAULT_IMPORTANCE
                             for h in hosts}
    if not client:
        return ctx
    if hosts is None:
        try:
            rows = fetch_all(client, "assets", columns="ip,importance")
            ctx["importance"] = {P.norm_ip(r["ip"]): r.get("importance") or P.DEFAULT_IMPORTANCE
                                 for r in rows}
        except Exception:
            pass
    try:
        ctx["manual"] = fetch_all(client, "component_dependencies")
        ctx["ready"] = True
    except Exception:
        ctx["manual"] = []         # migration 006 not run yet
    return ctx


def scored(hosts: list[dict]) -> list[dict]:
    from ml.risk_score import score_host
    return [score_host(copy.deepcopy(h)) for h in hosts]


def bounded_candidates(hosts: list[dict]) -> list[dict]:
    """All port / account fixes + the worst CVEs as vendor-patch candidates, so a
    host with hundreds of CVEs still ranks in a second or two."""
    cands = P.candidate_fixes(hosts)
    patches = [c for c in cands if c["fix"]["type"] == "patch_cve"]
    if len(patches) <= MAX_PATCH_CANDIDATES:
        return cands
    score: dict = {}
    for h in hosts:
        for v in h.get("vulnerabilities", []):
            key = (P.norm_ip(h["ip"]), (v.get("cve_id") or "").upper())
            score[key] = max(score.get(key, 0), v.get("ml_risk_score") or 0)
    patches.sort(key=lambda c: score.get((c["ip"], c["fix"]["params"]["cve_id"]), 0),
                 reverse=True)
    keep = {id(c) for c in patches[:MAX_PATCH_CANDIDATES]}
    return [c for c in cands if c["fix"]["type"] != "patch_cve" or id(c) in keep]


def _model(client) -> tuple[list[dict], dict]:
    hosts = scored(load_hosts(client))
    return hosts, load_context(client, hosts)


# ---- what the dashboard shows ---------------------------------------------------------
def overview(client) -> dict:
    hosts, ctx = _model(client)
    imp, manual = ctx["importance"], ctx["manual"]
    ours_state = P.risk_state(hosts, imp, manual, "improved")
    base_state = P.risk_state(hosts, imp, manual, "baseline")

    cands = bounded_candidates(hosts)
    ours = P.rank_fixes(hosts, imp, manual, "improved", candidates=cands)
    base = P.rank_fixes(hosts, imp, manual, "baseline", candidates=cands)

    checks = recent_checks(client)
    return {
        "ready": ctx["ready"], "migration": MIGRATION, "paper": PAPER,
        "parameters": {"importance_weight": P.IMPORTANCE_WEIGHT, "ccs_floor": P.CCS_FLOOR,
                       "band_weights": P.BAND_WEIGHTS, "cvss_bands": P.CVSS_BANDS,
                       "default_cred_score": P.DEFAULT_CRED_SCORE, "tolerance": P.TOLERANCE},
        "improved": _trim(ours_state), "baseline": _trim(base_state),
        "ranking": ours, "baseline_ranking": base,
        "comparison": P.compare(ours, base),
        "accuracy": P.accuracy([c["result"] for c in checks]),
        "recent_checks": checks[:10],
    }


def _trim(state: dict, n: int = 60) -> dict:
    return {"hosts": state["hosts"], "network_total": state["network_total"],
            "network_avg": state["network_avg"], "components": state["components"][:n],
            "dependencies": state["dependencies"]}


def topology(client) -> dict:
    """Hosts, components and dependencies for the Topology page."""
    hosts, ctx = _model(client)
    state = P.risk_state(hosts, ctx["importance"], ctx["manual"])
    return P.topology(state, hosts)


def fix_preview(client, target_ip: str, fixes) -> dict:
    """Fix Impact Preview for the dashboard (nothing is stored or executed)."""
    hosts, ctx = _model(client)
    pred = P.predict(hosts, target_ip, fixes, ctx["importance"], ctx["manual"])
    pred.pop("snapshot", None)              # only needed when stored with a fix
    return pred


# ---- predictions kept with each remediation ------------------------------------------
PLAYBOOK_ACTIONS = ("block_port", "stop_service", "disable_account")


def prediction_for(client, asset_ip: str, action_type: str, params: dict) -> dict | None:
    """Fix Impact Preview of one remediation (None if it cannot say)."""
    if action_type not in PLAYBOOK_ACTIONS or not client:
        return None
    try:
        hosts, ctx = _model(client)
        fix = {"type": action_type, "params": {k: v for k, v in (params or {}).items()
                                               if k not in ("target_ip", "os", "proto")
                                               and not k.startswith("_")}}
        pred = P.predict(hosts, asset_ip, fix, ctx["importance"], ctx["manual"])
        pred["made_at"] = _now()
        return pred
    except Exception as e:
        log_event("engine", "fix_preview.error", asset_ip, {"error": str(e)[:200]})
        return None


def evaluate_pending(host_results: list[dict], client=None) -> int:
    """After a scan: compare every verified fix's prediction with what the scan
    really found. Returns how many predictions were checked."""
    from common.db import get_service_client
    client = client or get_service_client()
    if not client:
        return 0
    try:
        rows = fetch_all(client, "remediations", eq={"status": "succeeded"})
    except Exception:
        return 0
    todo = [r for r in rows if r.get("verified_fixed") and r.get("fix_prediction")
            and not r.get("fix_check")]
    if not todo:
        return 0
    fresh = scored(host_results)
    ctx = load_context(client)
    groups: dict[str, list[dict]] = {}
    for r in todo:
        groups.setdefault(P.norm_ip(r["fix_prediction"].get("ip")), []).append(r)
    n = 0
    for ip, rows_ in groups.items():
        results = P.check_predictions([r["fix_prediction"] for r in rows_], fresh,
                                      ctx["importance"], ctx["manual"])
        for r, res in zip(rows_, results):
            if res is None:
                continue        # host not in this scan (or its scan failed): try next time
            res["checked_at"] = _now()
            try:
                client.table("remediations").update({"fix_check": res}) \
                    .eq("id", r["id"]).execute()
                n += 1
                log_event("engine", "fix_preview.check", ip,
                          {"remediation": r["id"], "match": res["match"], "error": res["error"]})
            except Exception:
                pass
    return n


def recent_checks(client) -> list[dict]:
    if not client:
        return []
    try:
        rows = fetch_all(client, "remediations")
    except Exception:
        return []
    out = []
    for r in rows:
        if r.get("fix_check"):
            p = r.get("fix_prediction") or {}
            out.append({"remediation_id": r["id"], "action": r.get("action_type"),
                        "params": {k: v for k, v in (r.get("action_params") or {}).items()
                                   if k in ("port", "service", "username")},
                        "ip": p.get("ip"), "result": r["fix_check"]})
    out.sort(key=lambda c: c["result"].get("checked_at") or "", reverse=True)
    return out


# ---- admin changes (called by the API) ----------------------------------------------
def set_importance(client, asset_ip: str, level: str, actor: str) -> dict:
    if level not in P.IMPORTANCE_WEIGHT:
        raise ValueError(f"importance must be one of {', '.join(P.IMPORTANCE_WEIGHT)}")
    ip = P.norm_ip(asset_ip)
    rows = fetch_all(client, "assets", columns="id,ip")
    asset = next((a for a in rows if P.norm_ip(a["ip"]) == ip), None)
    if not asset:
        raise LookupError(f"asset {ip} not found")
    client.table("assets").update({"importance": level}).eq("id", asset["id"]).execute()
    log_event(actor, "prioritization.importance", ip, {"importance": level})
    return {"ip": ip, "importance": level}


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
    if rule not in P.RULES:
        raise ValueError(f"rule must be one of {', '.join(P.RULES)}")
    row = {"from_component": frm, "to_component": to, "rule": rule, "enabled": bool(enabled),
           "note": (note or "")[:300]}
    res = client.table("component_dependencies").upsert(
        row, on_conflict="from_component,to_component").execute()
    log_event(actor, "prioritization.dependency", frm,
              {"to": to, "rule": rule, "enabled": bool(enabled)})
    return res.data[0] if res.data else row


def remove_dependency(client, dep_id: str, actor: str) -> int:
    gone = client.table("component_dependencies").delete().eq("id", dep_id).execute().data
    log_event(actor, "prioritization.dependency.remove", dep_id, {"removed": len(gone or [])})
    return len(gone or [])
