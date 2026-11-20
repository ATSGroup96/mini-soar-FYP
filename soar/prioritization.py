"""
Dependency-based patch prioritization and Fix Impact Preview.

Adapted from Jiang, Wang, Ding, Lu & Jing (2024), "Leveraging Digital Twin
Technology for Enhanced Cybersecurity in Cyber-Physical Production Systems",
Future Internet 16(4):134 - their dependency analysis, criticality calculation
and virtual-patch risk analysis, applied to an IT network WITHOUT building a
digital twin. After every scan each host is modelled as components (the
operating system and each open service) linked by dependency rules.

What is kept from the paper
  * components and functional dependencies, with the embedding, interaction,
    data and network rules (4 of the paper's 7 rules; no failure propagation)
  * a component's criticality score (CCS) comes from how many components
    depend on it
  * component risk  CRS = CCS x CVS
  * every candidate fix is tried on a copy of the model in memory ("virtual
    patch") and the fixes are ranked by how much they lower the network risk

What is changed (and why) - see docs/PATCH_PRIORITIZATION.md
  * CVS is the severity-weighted average of our exploit-aware finding risks
    (CVSS + EPSS + KEV + default passwords) instead of CVSS only
    (Jacobs et al. 2023: CVSS alone predicts exploitation poorly)
  * CCS is normalised to the network, has a floor (a component nobody depends
    on, e.g. a backdoored FTP server, is never ignored) and is weighted by the
    asset importance the admin sets (Della Penna et al. 2026; CISA SSVC
    "mission prevalence")
  * the paper's own CVSS-only formula is kept as a "baseline" mode so both
    rankings can be compared on the same lab
  * a fix's predicted effect is stored and checked against the next scan

The Fix Impact Preview of one fix uses exactly the same functions as the
ranking, so the preview and the ranked list always show the same numbers.
Everything here is pure Python on in-memory dicts: nothing is executed and
nothing is written. Hosts must already be scored (ml_risk_score on findings).
"""
from __future__ import annotations

import copy

from ml.risk_score import grade_from_score

# ---- tunable parameters (our design choices; the paper does not publish values) ----
IMPORTANCE_WEIGHT = {"critical": 1.0, "normal": 0.8, "low": 0.5}
DEFAULT_IMPORTANCE = "normal"
CCS_FLOOR = 0.5                   # a component with no dependents keeps half weight
DEFAULT_CRED_SCORE = 65.0         # same value the host scorer uses for a bare default password
BAND_WEIGHTS = ((80, 4), (60, 3), (40, 2), (0, 1))          # finding risk 0..100
CVSS_BANDS = ((9.0, 4), (7.0, 3), (4.0, 2), (0.1, 1))       # baseline: CVSS 0..10
PATCH_CANDIDATE_MIN = 80.0        # suggest a vendor patch for findings this bad
RULES = ("embedding", "interaction", "data", "network")
TOLERANCE = 10.0                  # predicted vs actual host CRS may differ this much

# ---- automatic dependency knowledge ------------------------------------------------
# data rule (same host): web / application servers keep their data in a local DB
WEB = ("http", "https", "http-proxy", "http-alt", "ssl/http", "ajp13")
DATABASES = ("mysql", "postgresql", "ms-sql-s", "oracle", "mongodb", "redis")
# interaction rule (same host): RPC services are registered through the port mapper
RPC_CLIENTS = ("nfs", "mountd", "nlockmgr", "status", "rquotad")
RPC_SERVER = ("rpcbind", "portmapper")
# network rule (between hosts): a directory server (Kerberos / LDAP, e.g. an Active
# Directory domain controller) is needed by every other machine on its subnet to log in
DIRECTORY_PORTS = (389, 636, 88, 3268, 3269)        # preferred order for the edge target


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


def _subnet(ip: str) -> str:
    return ".".join(norm_ip(ip).split(".")[:3])


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


def _key(v: dict) -> str:
    """Identity of a finding (CVE id, or the check id for findings without a CVE)."""
    return str(v.get("cve_id") or v.get("finding_key") or v.get("title") or "").upper()


def _finding(v: dict) -> dict:
    return {"id": _key(v), "score": float(v.get("ml_risk_score") or 0.0),
            "cvss": float(v.get("cvss_score") or 0.0), "kev": bool(v.get("in_kev"))}


# ---- 1. applying a fix to a copy of a host ------------------------------------------
def _as_list(fix) -> list[dict]:
    return fix if isinstance(fix, list) else [fix]


def fix_type(fix: dict) -> str:
    return fix.get("type") or fix.get("action_type") or ""


def fix_params(fix: dict) -> dict:
    return fix.get("params") or fix


def fix_label(fix: dict) -> str:
    p, t = fix_params(fix), fix_type(fix)
    val = p.get("port") or p.get("service") or p.get("cve_id") or p.get("username") or ""
    return f"{t} {val}".strip()


def _apply_one(h: dict, fix: dict) -> int:
    """Apply ONE fix to the in-memory host h (mutates h). Returns how many
    services/findings it removed or changed (0 = the fix matched nothing)."""
    ftype, params = fix_type(fix), fix_params(fix)
    if ftype in ("block_port", "stop_service"):
        port = params.get("port")
        svc = str(params.get("service") or "").strip().lower()
        if port in (None, "") and svc.isdigit():      # "stop_service 23" means port 23
            port, svc = svc, ""
        port = int(port) if port not in (None, "") else None
        gone = {s.get("port") for s in h.get("services", [])
                if (port is not None and s.get("port") == port)
                or (svc and _name(s) == svc)}
        before = len(h.get("services", [])) + len(h.get("vulnerabilities", []))
        h["services"] = [s for s in h.get("services", []) if s.get("port") not in gone]
        h["vulnerabilities"] = [v for v in h.get("vulnerabilities", [])
                                if v.get("port") not in gone]
        return before - len(h["services"]) - len(h["vulnerabilities"])
    if ftype == "patch_cve":
        cve = str(params.get("cve_id") or "").strip().upper()
        before = len(h.get("vulnerabilities", []))
        h["vulnerabilities"] = [v for v in h.get("vulnerabilities", []) if _key(v) != cve]
        return before - len(h["vulnerabilities"])
    if ftype == "disable_account":
        # locking the account removes the default-password exposure
        # (only on the given port when one is passed)
        port = params.get("port")
        n = 0
        for s in h.get("services", []):
            if s.get("has_default_cred") and (port in (None, "") or s.get("port") == int(port)):
                s["has_default_cred"] = False
                n += 1
        return n
    return 0


def apply_fix(hosts: list[dict], ip, fix, unmatched: list | None = None) -> list[dict]:
    """Copy of the network with the fix(es) applied to one host. The real data is
    never changed. Locking an account changes a scoring input (a default password
    works), so that host's findings are re-scored; closing a port or patching a
    CVE only removes findings, so the remaining scores stay as they are."""
    from ml.risk_score import score_host
    ip = norm_ip(ip)
    fixes = _as_list(fix)
    rescore = any(fix_type(f) == "disable_account" for f in fixes)
    out = []
    for h in hosts:
        h2 = copy.deepcopy(h)
        if norm_ip(h.get("ip")) == ip:
            for f in fixes:
                if _apply_one(h2, f) == 0 and unmatched is not None:
                    unmatched.append(fix_label(f))
            if rescore:
                score_host(h2)
        out.append(h2)
    return out


# ---- 2. components -----------------------------------------------------------------
def build_components(host: dict, importance: str | None = None) -> list[dict]:
    """One component for the operating system + one per open service."""
    ip = norm_ip(host.get("ip"))
    imp = importance if importance in IMPORTANCE_WEIGHT else DEFAULT_IMPORTANCE
    creds = cred_ports(host)
    services = host.get("services", []) or []
    vulns = host.get("vulnerabilities", []) or []

    comps = [{
        "id": os_id(ip), "ip": ip, "kind": "os", "port": None, "service": "",
        "name": host.get("os_guess") or "Operating system", "importance": imp,
        "default_cred": False,
        # findings not tied to a port belong to the OS itself
        "findings": [_finding(v) for v in vulns if v.get("port") is None],
    }]
    for s in services:
        port = s.get("port")
        if port is None:
            continue
        comps.append({
            "id": svc_id(ip, port), "ip": ip, "kind": "service", "port": int(port),
            "service": _name(s), "name": f"{_name(s) or 'unknown'}:{port}",
            "importance": imp,
            "default_cred": port in creds,
            "findings": [_finding(v) for v in vulns if v.get("port") == port],
        })
    return comps


# ---- 3. dependencies ("A depends on B" = edge A -> B) --------------------------------
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
    # network rule: every other host on the subnet needs the directory server to log in
    for ip, cs in by_host.items():
        ports = {c["port"]: c for c in cs if c["kind"] == "service"}
        target = next((ports[p] for p in DIRECTORY_PORTS if p in ports), None)
        if target is None:
            continue
        for other in by_host:
            if other != ip and _subnet(other) == _subnet(ip):
                deps.append({"from": os_id(other), "to": target["id"], "rule": "network",
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


# ---- 4. scores -----------------------------------------------------------------------
def _band_weight(score: float, bands) -> int:
    for low, w in bands:
        if score >= low:
            return w
    return 0


def cvs_improved(comp: dict) -> float:
    """Severity-weighted average of our exploit-aware finding risks (0..100)."""
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
            # component (its FD score); no normalisation, no importance weight
            ccs = float(degree[c["id"]])
            cvs = cvs_baseline(c)
        else:
            d = indeg[c["id"]] / max_in if max_in else 0.0
            ccs = IMPORTANCE_WEIGHT[c["importance"]] * (CCS_FLOOR + (1 - CCS_FLOOR) * d)
            cvs = cvs_improved(c)
        out.append({
            "id": c["id"], "ip": c["ip"], "kind": c["kind"], "name": c["name"],
            "port": c["port"], "importance": c["importance"],
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


def build(hosts: list[dict], importance: dict | None = None,
          manual: list[dict] | None = None) -> tuple[list[dict], list[dict]]:
    importance = importance or {}
    comps: list[dict] = []
    for h in hosts:
        comps += build_components(h, importance.get(norm_ip(h.get("ip"))))
    return comps, merge_dependencies(auto_dependencies(comps), manual)


def risk_state(hosts: list[dict], importance: dict | None = None,
               manual: list[dict] | None = None, mode: str = "improved") -> dict:
    """Components, dependencies and component / host / network risk."""
    comps, deps = build(hosts, importance, manual)
    return evaluate(comps, deps, mode)


def host_crs(state: dict, ip) -> float:
    ip = norm_ip(ip)
    return next((h["crs"] for h in state["hosts"] if h["ip"] == ip), 0.0)


# ---- 5. candidate fixes and their ranking ---------------------------------------------
def candidate_fixes(hosts: list[dict]) -> list[dict]:
    """Every fix that can be tried: block each risky port, lock each default
    account (playbooks), and vendor-patch each very bad CVE (manual)."""
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
            if not v.get("cve_id"):
                continue           # a vendor patch exists only for a CVE
            bad = (v.get("ml_risk_score") or 0) >= PATCH_CANDIDATE_MIN or (v.get("cvss_score") or 0) >= 9.0
            key = (ip, str(v.get("cve_id")).upper())
            if bad and key not in seen:
                seen.add(key)
                out.append({"ip": ip, "executable": False,
                            "fix": {"type": "patch_cve", "params": {"cve_id": key[1]}},
                            "label": f"Patch {key[1]} (vendor update)"})
    return out


def _dangerous_removed(host_before: dict, host_after: dict) -> dict:
    def kev(h):
        return {(_key(v), v.get("port")) for v in h.get("vulnerabilities", [])
                if v.get("in_kev")}
    return {"kev": len(kev(host_before) - kev(host_after)),
            "default_creds": len(cred_ports(host_before) - cred_ports(host_after)),
            "findings": len(host_before.get("vulnerabilities", []))
                        - len(host_after.get("vulnerabilities", []))}


def rank_fixes(hosts: list[dict], importance: dict | None = None,
               manual: list[dict] | None = None, mode: str = "improved",
               top_n: int = 15, candidates: list[dict] | None = None) -> list[dict]:
    """Try every candidate on a copy of the model; biggest drop in network risk first."""
    before = risk_state(hosts, importance, manual, mode)
    ranked = []
    by_ip = {norm_ip(h.get("ip")): h for h in hosts}
    for cand in (candidates if candidates is not None else candidate_fixes(hosts)):
        after_hosts = apply_fix(hosts, cand["ip"], cand["fix"])
        after = risk_state(after_hosts, importance, manual, mode)
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


# ---- 6. Fix Impact Preview (one fix, or several together) ------------------------------
def _host_summary(h: dict) -> dict:
    vulns = h.get("vulnerabilities", []) or []
    return {"open_ports": len(h.get("services", []) or []), "findings": len(vulns),
            "kev": sum(1 for v in vulns if v.get("in_kev")),
            "critical": sum(1 for v in vulns if (v.get("ml_risk_score") or 0) >= 80),
            "default_creds": len(cred_ports(h))}


def snapshot(host: dict) -> dict:
    """Compact copy of one host (enough to re-run the model on it later)."""
    keep_v = ("cve_id", "finding_key", "title", "source", "port", "cvss_score", "epss_score",
              "epss_percentile", "in_kev", "confidence", "ml_risk_score")
    return {
        "ip": norm_ip(host.get("ip")), "os_guess": host.get("os_guess"),
        "is_rogue": host.get("is_rogue"),
        "services": [{"port": s.get("port"), "service_name": s.get("service_name"),
                      "has_default_cred": s.get("has_default_cred")}
                     for s in host.get("services", []) or []],
        "default_creds": [{"port": c.get("port")} for c in host.get("default_creds", []) or []],
        "vulnerabilities": [{k: v.get(k) for k in keep_v if v.get(k) is not None}
                            for v in host.get("vulnerabilities", []) or []],
    }


def predict(hosts: list[dict], ip, fix, importance: dict | None = None,
            manual: list[dict] | None = None) -> dict:
    """The Fix Impact Preview: what one fix (or several together) changes on one
    host and on the whole network, before anything is executed. The same
    functions as rank_fixes() are used, so a fix shows the same numbers here as
    in the ranked list. Stored with an approved fix and checked after the next scan."""
    ip = norm_ip(ip)
    host = next((h for h in hosts if norm_ip(h.get("ip")) == ip), None)
    if host is None:
        raise KeyError(f"{ip} is not in the model (scanned hosts: "
                       f"{', '.join(sorted(norm_ip(h.get('ip')) for h in hosts)) or 'none'})")
    unmatched: list[str] = []
    before = risk_state(hosts, importance, manual)
    after_hosts = apply_fix(hosts, ip, fix, unmatched)
    after = risk_state(after_hosts, importance, manual)
    h_after = next(h for h in after_hosts if norm_ip(h.get("ip")) == ip)
    ports_b = {s.get("port") for s in host.get("services", [])}
    ports_a = {s.get("port") for s in h_after.get("services", [])}
    keys_b = {_key(v) for v in host.get("vulnerabilities", [])}
    keys_a = {_key(v) for v in h_after.get("vulnerabilities", [])}
    b_crs, a_crs = host_crs(before, ip), host_crs(after, ip)

    note = ""
    drop = round(before["network_total"] - after["network_total"], 2)
    if unmatched:
        note = ("Nothing matched: " + ", ".join(unmatched)
                + " (port already closed, or not on this host).")
    elif drop < 0:
        note = ("Risk goes UP: a component's vulnerability score is the weighted AVERAGE of "
                "its findings (as in Jiang et al.), so removing only its milder finding leaves "
                "the worse ones with a higher average. Fix the worst finding on that port "
                "(or close the port) instead. This fix is never suggested by the ranking.")
    elif a_crs >= b_crs and keys_a != keys_b:
        worst = next((c for c in after["components"] if c["ip"] == ip), None)
        where = worst["name"] if worst else "another component"
        note = (f"Host risk is set by its riskiest component, which is unchanged "
                f"({where}). The network total below still shows the progress.")
    remaining = [{"component": c["name"], "id": c["id"], "crs": c["crs"]}
                 for c in after["components"] if c["ip"] == ip and c["crs"] > 0][:3]
    return {
        "version": 2, "ip": ip, "fix": fix, "unmatched": unmatched, "note": note,
        "closed_ports": sorted(p for p in ports_b - ports_a if p is not None),
        "removed_findings": sorted(k for k in keys_b - keys_a if k),
        "cleared_default_creds": sorted(cred_ports(host) - cred_ports(h_after)),
        "host_crs_before": b_crs, "host_crs_after": a_crs,
        "host_grade_before": grade_from_score(b_crs), "host_grade_after": grade_from_score(a_crs),
        "network_total_before": before["network_total"],
        "network_total_after": after["network_total"],
        "drop": drop,
        "network_avg_before": before["network_avg"], "network_avg_after": after["network_avg"],
        "counts_before": _host_summary(host), "counts_after": _host_summary(h_after),
        "top_remaining": remaining,
        "snapshot": snapshot(host),
    }


# ---- 7. checking a stored prediction against the next scan ----------------------------
def _expected_crs(preds: list[dict], fresh_hosts: list[dict], importance, manual) -> float | None:
    """Host risk expected after ALL these fixes together, worked out from the
    oldest snapshot and the same weights used for the actual value."""
    snaps = [p for p in preds if p.get("snapshot")]
    if not snaps:
        return None
    oldest = min(snaps, key=lambda p: p.get("made_at") or "")
    ip = norm_ip(oldest["ip"])
    fixes = [f for p in preds for f in _as_list(p["fix"])]
    expected = apply_fix([copy.deepcopy(oldest["snapshot"])], ip, fixes)[0]
    world = [expected if norm_ip(h.get("ip")) == ip else h for h in fresh_hosts]
    return host_crs(risk_state(world, importance, manual), ip)


def _removed_keys(p: dict) -> list:
    # version 1 predictions (made before v14) called them removed_cves
    return p.get("removed_findings", p.get("removed_cves", [])) or []


def check_predictions(preds: list[dict], fresh_hosts: list[dict],
                      importance: dict | None = None,
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
    keys = {_key(v) for v in host.get("vulnerabilities", [])}
    creds = cred_ports(host)
    actual = host_crs(risk_state(fresh_hosts, importance, manual), ip)
    expected = _expected_crs(preds, fresh_hosts, importance, manual)
    if expected is None and len(preds) == 1:           # old prediction without snapshot
        expected = preds[0].get("host_crs_after") or 0.0
    error = round(abs(actual - expected), 2) if expected is not None else None
    out = []
    for p in preds:
        misses = ([f"port {x} still open" for x in p.get("closed_ports", []) if x in ports]
                  + [f"{c} still present" for c in _removed_keys(p) if c in keys]
                  + [f"default password still works on :{x}"
                     for x in p.get("cleared_default_creds", []) if x in creds])
        out.append({"removal_correct": not misses, "misses": misses,
                    "predicted_crs": expected, "actual_crs": actual, "error": error,
                    "checked_together": len(preds),
                    "match": not misses and error is not None and error <= TOLERANCE})
    return out


def check_prediction(pred: dict, fresh_hosts: list[dict], importance: dict | None = None,
                     manual: list[dict] | None = None) -> dict | None:
    """One prediction on its own (see check_predictions)."""
    return check_predictions([pred], fresh_hosts, importance, manual)[0]


def accuracy(results: list[dict]) -> dict:
    checked = [r for r in results if r]
    n = len(checked)
    hits = sum(1 for r in checked if r.get("match"))
    return {"checked": n, "matched": hits,
            "accuracy_pct": round(100.0 * hits / n, 1) if n else None,
            "mean_error": round(sum(r.get("error") or 0 for r in checked) / n, 2) if n else None,
            "tolerance": TOLERANCE}


# ---- 8. topology graph for the dashboard ------------------------------------------------
def topology(state: dict, hosts: list[dict]) -> dict:
    """Cytoscape nodes/edges: hosts, their components, and the dependencies."""
    info = {norm_ip(h.get("ip")): h for h in hosts}
    host_risk = {r["ip"]: r["crs"] for r in state["hosts"]}
    nodes, edges = [], []
    for ip, h in info.items():
        risk = host_risk.get(ip, 0.0)
        nodes.append({"id": f"host:{ip}", "label": h.get("hostname") or ip, "type": "host",
                      "ip": ip, "risk": risk, "grade": grade_from_score(risk),
                      "os": h.get("os_guess") or "", "rogue": bool(h.get("is_rogue"))})
    for c in state["components"]:
        nodes.append({"id": c["id"], "label": c["name"] if c["kind"] == "service" else "OS",
                      "type": c["kind"], "ip": c["ip"], "risk": c["crs"],
                      "findings": c["findings"], "kev": c["kev"]})
        edges.append({"source": f"host:{c['ip']}", "target": c["id"], "kind": "has"})
    for d in state["dependencies"]:
        if d["rule"] == "embedding":
            continue            # already shown by the host -> component edges
        edges.append({"source": d["from"], "target": d["to"], "kind": d["rule"]})
    return {"nodes": nodes, "edges": edges}
