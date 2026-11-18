"""
Dependency-based security digital twin (component level).

Adapted from Jiang, Wang, Ding, Lu & Jing (2024), "Leveraging Digital Twin
Technology for Enhanced Cybersecurity in Cyber-Physical Production Systems",
Future Internet 16(4):134 - from factory systems (CPPS) to an IT network.

What is kept from the paper
  * the twin is a model of components and their functional dependencies
    (rule types: embedding, interaction, data, network)
  * criticality (CCS) comes from how many components depend on a component
  * component risk  CRS = CCS x CVS
  * fixes are tried on the twin first ("virtual patch") and ranked

What is changed (and why) - see docs/DIGITAL_TWIN.md
  * CVS uses our per-finding risk (CVSS + EPSS + KEV + default credentials ...)
    instead of CVSS only (Jacobs et al. 2023: CVSS alone predicts exploitation
    poorly)
  * CCS is normalised to the network and has a floor, so a component nobody
    depends on (e.g. a backdoored FTP server) is never ignored, and the admin's
    asset weight (critical / normal / low) is the paper's stakeholder step
  * a "baseline" mode computes the paper's own formulas (CVSS-only CVS, raw
    dependency count) so both rankings can be compared on the same lab

Everything here is pure Python on in-memory dicts: nothing is executed and
nothing is written. Hosts must already be scored (ml_risk_score on each vuln).
"""
from __future__ import annotations

import copy

from ml.risk_score import grade_from_score

# ---- tunable parameters (our choices; the paper does not publish its values) --
CRITICALITY_WEIGHT = {"critical": 1.0, "normal": 0.8, "low": 0.5}
DEFAULT_CRITICALITY = "normal"
CCS_FLOOR = 0.5                   # a component with no dependents keeps half weight
DEFAULT_CRED_SCORE = 65.0         # same value the host scorer uses for a bare default cred
BAND_WEIGHTS = ((80, 4), (60, 3), (40, 2), (0, 1))          # finding risk 0..100
CVSS_BANDS = ((9.0, 4), (7.0, 3), (4.0, 2), (0.1, 1))       # baseline: CVSS 0..10
PATCH_CANDIDATE_MIN = 80.0        # suggest a vendor patch for findings this bad
RULES = ("embedding", "interaction", "data", "network")

# ---- automatic dependency knowledge (same host) -------------------------------
# data rule: web / application servers usually keep their data in a local DB
WEB = ("http", "https", "http-proxy", "http-alt", "ssl/http", "ajp13")
DATABASES = ("mysql", "postgresql", "ms-sql-s", "oracle", "mongodb", "redis")
# interaction rule: RPC services are registered through the port mapper
RPC_CLIENTS = ("nfs", "mountd", "nlockmgr", "status", "rquotad")
RPC_SERVER = ("rpcbind", "portmapper")


def norm_ip(ip) -> str:
    return str(ip or "").split("/")[0].strip()


def os_id(ip) -> str:
    return f"{norm_ip(ip)}|os"


def svc_id(ip, port) -> str:
    return f"{norm_ip(ip)}|{int(port)}"


def _name(s: dict) -> str:
    return (s.get("service_name") or "").strip().lower()


def _is(name: str, kinds: tuple) -> bool:
    return any(name == k or name.startswith(k + "-") or name.endswith("/" + k) for k in kinds)


def cred_ports(host: dict) -> set:
    """Open ports where a default password works. A service explicitly marked
    has_default_cred = False (e.g. after a virtual 'lock account') does not count."""
    open_svc = {s.get("port"): s for s in host.get("services", []) or []}
    ports = {p for p, s in open_svc.items() if s.get("has_default_cred")}
    for c in host.get("default_creds", []) or []:
        s = open_svc.get(c.get("port"))
        if s is not None and s.get("has_default_cred") is not False:
            ports.add(c.get("port"))
    return {p for p in ports if p is not None}


def _finding(v: dict) -> dict:
    return {"cve_id": v.get("cve_id"), "score": float(v.get("ml_risk_score") or 0.0),
            "cvss": float(v.get("cvss_score") or 0.0), "kev": bool(v.get("in_kev"))}


# ---- 1. components ------------------------------------------------------------
def build_components(host: dict, criticality: str | None = None) -> list[dict]:
    """One component for the operating system + one per open service."""
    ip = norm_ip(host.get("ip"))
    crit = criticality if criticality in CRITICALITY_WEIGHT else DEFAULT_CRITICALITY
    creds = cred_ports(host)
    services = host.get("services", []) or []
    vulns = host.get("vulnerabilities", []) or []

    comps = [{
        "id": os_id(ip), "ip": ip, "kind": "os", "port": None, "service": "",
        "name": host.get("os_guess") or "Operating system", "criticality": crit,
        "default_cred": False,
        # CVEs not tied to a port belong to the OS itself
        "findings": [_finding(v) for v in vulns if v.get("port") is None],
    }]
    for s in services:
        port = s.get("port")
        if port is None:
            continue
        comps.append({
            "id": svc_id(ip, port), "ip": ip, "kind": "service", "port": int(port),
            "service": _name(s), "name": f"{_name(s) or 'unknown'}:{port}",
            "criticality": crit,
            "default_cred": port in creds,
            "findings": [_finding(v) for v in vulns if v.get("port") == port],
        })
    return comps


# ---- 2. dependencies ("A depends on B" = edge A -> B) --------------------------
def auto_dependencies(comps: list[dict]) -> list[dict]:
    by_host: dict[str, list[dict]] = {}
    for c in comps:
        by_host.setdefault(c["ip"], []).append(c)
    deps = []
    for ip, cs in by_host.items():
        svcs = [c for c in cs if c["kind"] == "service"]
        for c in svcs:                                   # embedding: runs on the OS
            deps.append({"from": c["id"], "to": os_id(ip), "rule": "embedding", "source": "auto"})
        for a in svcs:
            for b in svcs:
                if a is b:
                    continue
                if _is(a["service"], WEB) and _is(b["service"], DATABASES):
                    deps.append({"from": a["id"], "to": b["id"], "rule": "data", "source": "auto"})
                elif _is(a["service"], RPC_CLIENTS) and _is(b["service"], RPC_SERVER):
                    deps.append({"from": a["id"], "to": b["id"], "rule": "interaction",
                                 "source": "auto"})
    return deps


def merge_dependencies(auto: list[dict], manual: list[dict] | None) -> list[dict]:
    """Manual rows (from the dashboard) add edges, or remove an automatic one
    with enabled = false."""
    edges = {(d["from"], d["to"]): dict(d) for d in auto}
    for m in manual or []:
        key = (m.get("from_component"), m.get("to_component"))
        if not key[0] or not key[1] or key[0] == key[1]:
            continue
        if m.get("enabled", True) is False:
            edges.pop(key, None)
        else:
            rule = m.get("rule") if m.get("rule") in RULES else "network"
            edges[key] = {"from": key[0], "to": key[1], "rule": rule, "source": "manual",
                          "id": m.get("id")}
    return list(edges.values())


# ---- 3. scores ------------------------------------------------------------------
def _band_weight(score: float, bands) -> int:
    for low, w in bands:
        if score >= low:
            return w
    return 0


def cvs_improved(comp: dict) -> float:
    """Severity-weighted average of our finding risks (0..100)."""
    scores = [f["score"] for f in comp["findings"]]
    if comp.get("default_cred"):
        scores.append(DEFAULT_CRED_SCORE)
    if not scores:
        return 0.0
    weights = [_band_weight(s, BAND_WEIGHTS) for s in scores]
    return sum(w * s for w, s in zip(weights, scores)) / sum(weights)


def cvs_baseline(comp: dict) -> float:
    """The paper's Equation (3), literally: sum_i w_i * Sum(S_i) / sum_i N_i over
    the CVSS bands critical/high/medium/low. CVSS 0 ('none') is not counted."""
    scores = [f["cvss"] for f in comp["findings"] if f["cvss"] > 0]
    if not scores:
        return 0.0
    total = sum(_band_weight(s, CVSS_BANDS) * s for s in scores)
    return total / len(scores)


def evaluate(comps: list[dict], deps: list[dict], mode: str = "improved") -> dict:
    """Score every component. mode = 'improved' (ours) or 'baseline' (paper)."""
    ids = {c["id"] for c in comps}
    live = [d for d in deps if d["from"] in ids and d["to"] in ids]
    indeg = {i: 0 for i in ids}
    degree = {i: 0 for i in ids}
    for d in live:
        indeg[d["to"]] += 1
        degree[d["to"]] += 1
        degree[d["from"]] += 1
    max_in = max(indeg.values(), default=0)

    out = []
    for c in comps:
        if mode == "baseline":
            # paper: CCS = number of functional-dependency relations of the
            # component (its FD score); no normalisation, no stakeholder weight
            ccs = float(degree[c["id"]])
            cvs = cvs_baseline(c)
        else:
            d = indeg[c["id"]] / max_in if max_in else 0.0
            ccs = CRITICALITY_WEIGHT[c["criticality"]] * (CCS_FLOOR + (1 - CCS_FLOOR) * d)
            cvs = cvs_improved(c)
        out.append({
            "id": c["id"], "ip": c["ip"], "kind": c["kind"], "name": c["name"],
            "port": c["port"], "criticality": c["criticality"],
            "dependents": indeg[c["id"]], "relations": degree[c["id"]],
            "findings": len(c["findings"]), "kev": sum(1 for f in c["findings"] if f["kev"]),
            "default_cred": c["default_cred"],
            "ccs": round(ccs, 3), "cvs": round(cvs, 2), "crs": round(ccs * cvs, 2),
        })
    out.sort(key=lambda r: r["crs"], reverse=True)

    hosts: dict[str, float] = {}
    for r in out:
        hosts[r["ip"]] = max(hosts.get(r["ip"], 0.0), r["crs"])
    host_rows = [{"ip": ip, "crs": round(v, 2),
                  "grade": grade_from_score(v) if mode == "improved" else None}
                 for ip, v in sorted(hosts.items(), key=lambda kv: kv[1], reverse=True)]
    total = round(sum(r["crs"] for r in out), 2)
    return {
        "mode": mode, "components": out, "dependencies": live, "hosts": host_rows,
        "network_total": total,
        "network_avg": round(sum(hosts.values()) / len(hosts), 2) if hosts else 0.0,
    }


# ---- 4. the whole twin -------------------------------------------------------------
def build(hosts: list[dict], criticality: dict | None = None,
          manual: list[dict] | None = None) -> tuple[list[dict], list[dict]]:
    criticality = criticality or {}
    comps: list[dict] = []
    for h in hosts:
        comps += build_components(h, criticality.get(norm_ip(h.get("ip"))))
    return comps, merge_dependencies(auto_dependencies(comps), manual)


def twin_state(hosts: list[dict], criticality: dict | None = None,
               manual: list[dict] | None = None, mode: str = "improved") -> dict:
    comps, deps = build(hosts, criticality, manual)
    return evaluate(comps, deps, mode)


def host_crs(state: dict, ip) -> float:
    ip = norm_ip(ip)
    return next((h["crs"] for h in state["hosts"] if h["ip"] == ip), 0.0)


# ---- 5. virtual patching and fix ranking -------------------------------------------
def candidate_fixes(hosts: list[dict]) -> list[dict]:
    """Every fix the twin can try: block each risky port, lock each default
    account, and vendor-patch each very bad CVE (manual, not a playbook)."""
    from .remediation import PROTECTED_PORTS   # same rule the playbooks enforce
    out, seen = [], set()
    for h in hosts:
        ip = norm_ip(h.get("ip"))
        for c in build_components(h):
            if c["kind"] != "service":
                continue
            # never suggest a fix the system itself refuses (e.g. closing the
            # engine's own SSH port); locking the account is still offered
            if (c["findings"] or c["default_cred"]) and c["port"] not in PROTECTED_PORTS:
                out.append({"ip": ip, "executable": True,
                            "fix": {"type": "block_port", "params": {"port": c["port"]}},
                            "label": f"Block port {c['port']} ({c['service'] or 'service'})"})
            if c["default_cred"]:
                out.append({"ip": ip, "executable": True,
                            "fix": {"type": "disable_account", "params": {"port": c["port"]}},
                            "label": f"Lock default account on :{c['port']}"})
        for v in h.get("vulnerabilities", []) or []:
            bad = (v.get("ml_risk_score") or 0) >= PATCH_CANDIDATE_MIN or (v.get("cvss_score") or 0) >= 9.0
            key = (ip, (v.get("cve_id") or "").upper())
            if bad and key not in seen:
                seen.add(key)
                out.append({"ip": ip, "executable": False,
                            "fix": {"type": "patch_cve", "params": {"cve_id": key[1]}},
                            "label": f"Patch {key[1]} (vendor update)"})
    return out


def apply_fix(hosts: list[dict], ip, fix, rescore: bool = False) -> list[dict]:
    """Copy of the network with the fix applied to one host (same rules as the
    what-if simulator, so both always agree)."""
    from ml.risk_score import score_host
    from .digital_twin import _apply_hypothetical
    ip = norm_ip(ip)
    fixes = fix if isinstance(fix, list) else [fix]
    # locking an account changes a scoring input (default password works), so
    # the host's findings are re-scored; closing a port or patching a CVE only
    # removes findings, so the remaining scores stay valid (and fast)
    rescore = rescore or any((f.get("type") or f.get("action_type")) == "disable_account"
                             for f in fixes)
    out = []
    for h in hosts:
        if norm_ip(h.get("ip")) != ip:
            out.append(copy.deepcopy(h))
            continue
        after = _apply_hypothetical(h, fix)
        out.append(score_host(after) if rescore else after)
    return out


def _dangerous_removed(host_before: dict, host_after: dict) -> dict:
    def kev(h):
        return {(v.get("cve_id"), v.get("port")) for v in h.get("vulnerabilities", [])
                if v.get("in_kev")}
    return {"kev": len(kev(host_before) - kev(host_after)),
            "default_creds": len(cred_ports(host_before) - cred_ports(host_after)),
            "findings": len(host_before.get("vulnerabilities", []))
                        - len(host_after.get("vulnerabilities", []))}


def rank_fixes(hosts: list[dict], criticality: dict | None = None,
               manual: list[dict] | None = None, mode: str = "improved",
               top_n: int = 15, candidates: list[dict] | None = None) -> list[dict]:
    """Try every candidate on the twin; biggest drop in network risk first."""
    before = twin_state(hosts, criticality, manual, mode)
    ranked = []
    by_ip = {norm_ip(h.get("ip")): h for h in hosts}
    for cand in (candidates if candidates is not None else candidate_fixes(hosts)):
        after_hosts = apply_fix(hosts, cand["ip"], cand["fix"])
        after = twin_state(after_hosts, criticality, manual, mode)
        drop = round(before["network_total"] - after["network_total"], 2)
        if drop <= 0:
            continue
        after_host = next(h for h in after_hosts if norm_ip(h.get("ip")) == cand["ip"])
        ranked.append(dict(cand, drop=drop,
                           host_crs_before=host_crs(before, cand["ip"]),
                           host_crs_after=host_crs(after, cand["ip"]),
                           removes=_dangerous_removed(by_ip[cand["ip"]], after_host)))
    ranked.sort(key=lambda r: (-r["drop"], not r["executable"], r["label"]))
    for i, r in enumerate(ranked, 1):
        r["rank"] = i
    return ranked[:top_n]


def compare(ours: list[dict], base: list[dict], k: int = 5) -> dict:
    """How well each ranking puts known-dangerous fixes first. 'Dangerous' =
    the fix removes a CISA-KEV CVE or a working default password (a proxy for
    'really exploited', independent of both scoring formulas)."""
    def summary(rank):
        top = rank[:k]
        hits = [r for r in top if r["removes"]["kev"] or r["removes"]["default_creds"]]
        first = next((r["rank"] for r in rank
                      if r["removes"]["kev"] or r["removes"]["default_creds"]), None)
        return {"dangerous_in_top_k": len(hits), "first_dangerous_rank": first,
                "top": [r["label"] + f" @ {r['ip']}" for r in top]}

    def key(r):
        return (r["ip"], r["fix"]["type"], str(sorted(r["fix"]["params"].items())))
    overlap = len({key(r) for r in ours[:k]} & {key(r) for r in base[:k]})
    return {"k": k, "ours": summary(ours), "baseline": summary(base), "overlap": overlap,
            "note": "Dangerous = removes a CISA KEV CVE or a working default password."}


# ---- 6. prediction and its later check (twin accuracy) ---------------------------
TOLERANCE = 10.0       # predicted vs actual host CRS may differ this much and still match


def snapshot(host: dict) -> dict:
    """Compact copy of one host (enough to re-run the twin on it later)."""
    keep_v = ("cve_id", "port", "cvss_score", "epss_score", "epss_percentile", "in_kev",
              "confidence", "ml_risk_score")
    return {
        "ip": norm_ip(host.get("ip")), "os_guess": host.get("os_guess"),
        "is_rogue": host.get("is_rogue"),
        "services": [{"port": s.get("port"), "service_name": s.get("service_name"),
                      "has_default_cred": s.get("has_default_cred")}
                     for s in host.get("services", []) or []],
        "default_creds": [{"port": c.get("port")} for c in host.get("default_creds", []) or []],
        "vulnerabilities": [{k: v.get(k) for k in keep_v}
                            for v in host.get("vulnerabilities", []) or []],
    }


def predict(hosts: list[dict], ip, fix, criticality: dict | None = None,
            manual: list[dict] | None = None) -> dict:
    """What the twin expects a real fix to change on one host."""
    ip = norm_ip(ip)
    host = next((h for h in hosts if norm_ip(h.get("ip")) == ip), None)
    if host is None:
        raise KeyError(f"{ip} is not in the twin")
    before = twin_state(hosts, criticality, manual)
    after_hosts = apply_fix(hosts, ip, fix, rescore=True)
    after = twin_state(after_hosts, criticality, manual)
    h_after = next(h for h in after_hosts if norm_ip(h.get("ip")) == ip)
    ports_b = {s.get("port") for s in host.get("services", [])}
    ports_a = {s.get("port") for s in h_after.get("services", [])}
    cves_b = {(v.get("cve_id") or "").upper() for v in host.get("vulnerabilities", [])}
    cves_a = {(v.get("cve_id") or "").upper() for v in h_after.get("vulnerabilities", [])}
    cred_b, cred_a = cred_ports(host), cred_ports(h_after)
    return {
        "version": 1, "ip": ip, "fix": fix,
        "closed_ports": sorted(p for p in ports_b - ports_a if p is not None),
        "removed_cves": sorted(cves_b - cves_a),
        "cleared_default_creds": sorted(cred_b - cred_a),
        "host_crs_before": host_crs(before, ip), "host_crs_after": host_crs(after, ip),
        "snapshot": snapshot(host),
    }


def _expected_crs(preds: list[dict], fresh_hosts: list[dict], criticality, manual) -> float | None:
    """Host risk the twin expects after ALL these fixes together, worked out
    from the oldest snapshot and the same weights used for the actual value."""
    from ml.risk_score import score_host
    snaps = [p for p in preds if p.get("snapshot")]
    if not snaps:
        return None
    oldest = min(snaps, key=lambda p: p.get("made_at") or "")
    ip = norm_ip(oldest["ip"])
    expected = copy.deepcopy(oldest["snapshot"])
    expected = apply_fix([expected], ip, [p["fix"] for p in preds], rescore=False)[0]
    if any((f.get("type") or "") == "disable_account" for f in (p["fix"] for p in preds)):
        expected = score_host(expected)
    world = [expected if norm_ip(h.get("ip")) == ip else h for h in fresh_hosts]
    return host_crs(twin_state(world, criticality, manual), ip)


def check_predictions(preds: list[dict], fresh_hosts: list[dict],
                      criticality: dict | None = None,
                      manual: list[dict] | None = None) -> list[dict | None]:
    """Compare stored predictions for ONE host with a fresh scan. Fixes applied
    between the same two scans are checked together (the scan sees them all).
    Returns one result per prediction; None = host not in this scan."""
    if not preds:
        return []
    ip = norm_ip(preds[0].get("ip"))
    host = next((h for h in fresh_hosts if norm_ip(h.get("ip")) == ip), None)
    if host is None or not host.get("scan_ok", True):
        return [None] * len(preds)
    ports = {s.get("port") for s in host.get("services", [])}
    cves = {(v.get("cve_id") or "").upper() for v in host.get("vulnerabilities", [])}
    creds = cred_ports(host)
    actual = host_crs(twin_state(fresh_hosts, criticality, manual), ip)
    expected = _expected_crs(preds, fresh_hosts, criticality, manual)
    if expected is None and len(preds) == 1:           # old prediction without snapshot
        expected = preds[0].get("host_crs_after") or 0.0
    error = round(abs(actual - expected), 2) if expected is not None else None
    out = []
    for p in preds:
        misses = ([f"port {x} still open" for x in p.get("closed_ports", []) if x in ports]
                  + [f"{c} still present" for c in p.get("removed_cves", []) if c in cves]
                  + [f"default password still works on :{x}"
                     for x in p.get("cleared_default_creds", []) if x in creds])
        out.append({"removal_correct": not misses, "misses": misses,
                    "predicted_crs": expected, "actual_crs": actual, "error": error,
                    "checked_together": len(preds),
                    "match": not misses and error is not None and error <= TOLERANCE})
    return out


def check_prediction(pred: dict, fresh_hosts: list[dict], criticality: dict | None = None,
                     manual: list[dict] | None = None) -> dict | None:
    """One prediction on its own (see check_predictions)."""
    return check_predictions([pred], fresh_hosts, criticality, manual)[0]


def accuracy(results: list[dict]) -> dict:
    checked = [r for r in results if r]
    n = len(checked)
    hits = sum(1 for r in checked if r.get("match"))
    return {"checked": n, "matched": hits,
            "accuracy_pct": round(100.0 * hits / n, 1) if n else None,
            "mean_error": round(sum(r.get("error") or 0 for r in checked) / n, 2) if n else None,
            "tolerance": TOLERANCE}
