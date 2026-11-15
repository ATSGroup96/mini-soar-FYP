"""
Attack-path / lateral-movement graph.

Builds a directed graph from the current asset + vulnerability inventory:
  * a synthetic "attacker" node
  * attacker -> host edge when the host has an "entry" weakness
    (a KEV CVE, a default credential, or a high ML risk service)
  * host -> host edges for lateral movement within the same /24, weighted by
    the destination's risk (a foothold lets you pivot to neighbours)

Then it ranks the most dangerous paths to the highest-value (highest-risk)
assets. Output is Cytoscape-friendly (nodes/edges) for the dashboard, plus a
ranked path list.
"""
from __future__ import annotations

import ipaddress
import heapq


def _entry_weakness(host: dict) -> list[str]:
    reasons = []
    seen = set()
    for v in host.get("vulnerabilities", []):
        if v.get("in_kev") and v.get("confidence") != "version-unconfirmed":
            where = f" on :{v['port']}" if v.get("port") is not None else ""
            label = f"KEV {v['cve_id']}{where}"
            if label not in seen:
                seen.add(label)
                reasons.append(label)
    for s in host.get("services", []):
        if s.get("has_default_cred"):
            reasons.append(f"default cred on :{s.get('port')}")
    if host.get("risk_score", 0) >= 70 and not reasons:
        reasons.append("high-risk exposed service")
    return reasons


def _same_subnet(ip_a: str, ip_b: str, bits: int = 24) -> bool:
    try:
        na = ipaddress.ip_network(f"{ip_a}/{bits}", strict=False)
        return ipaddress.ip_address(ip_b) in na
    except ValueError:
        return False


def build_graph(hosts: list[dict]) -> dict:
    nodes = [{"id": "attacker", "label": "Attacker", "type": "attacker",
              "risk": 100}]
    edges = []
    for h in hosts:
        nodes.append({
            "id": h["ip"], "label": h.get("hostname") or h["ip"],
            "type": "host", "risk": h.get("risk_score", 0),
            "grade": h.get("risk_grade", "A"),
            "os": h.get("os_guess", ""),
        })
        entry = _entry_weakness(h)
        if entry:
            edges.append({"source": "attacker", "target": h["ip"],
                          "kind": "initial-access", "why": entry,
                          "weight": round(100 - h.get("risk_score", 0) + 1, 1)})

    # lateral edges: from any host with a foothold to neighbours in same subnet
    footholds = [h for h in hosts if _entry_weakness(h)]
    for src in footholds:
        for dst in hosts:
            if dst["ip"] == src["ip"]:
                continue
            if _same_subnet(src["ip"], dst["ip"]):
                edges.append({
                    "source": src["ip"], "target": dst["ip"],
                    "kind": "lateral-movement",
                    "why": ["same L2 segment; pivot from foothold"],
                    "weight": round(100 - dst.get("risk_score", 0) + 1, 1),
                })
    return {"nodes": nodes, "edges": edges}


def rank_paths(graph: dict, top_n: int = 5) -> list[dict]:
    """
    Dijkstra from 'attacker' over edge weights (lower weight = easier hop).
    Returns the easiest paths to the highest-risk reachable hosts.
    """
    adj: dict[str, list[tuple[str, float, dict]]] = {}
    for e in graph["edges"]:
        adj.setdefault(e["source"], []).append((e["target"], e["weight"], e))

    dist = {"attacker": 0.0}
    prev: dict[str, tuple[str, dict]] = {}
    pq = [(0.0, "attacker")]
    while pq:
        d, node = heapq.heappop(pq)
        if d > dist.get(node, float("inf")):
            continue
        for nxt, w, e in adj.get(node, []):
            nd = d + w
            if nd < dist.get(nxt, float("inf")):
                dist[nxt] = nd
                prev[nxt] = (node, e)
                heapq.heappush(pq, (nd, nxt))

    risk_of = {n["id"]: n.get("risk", 0) for n in graph["nodes"]}
    targets = [n["id"] for n in graph["nodes"]
               if n["type"] == "host" and n["id"] in dist]
    targets.sort(key=lambda t: (risk_of[t], -dist[t]), reverse=True)

    paths = []
    for t in targets[:top_n]:
        chain, cur = [], t
        while cur in prev:
            p, e = prev[cur]
            chain.append({"from": p, "to": cur, "kind": e["kind"], "why": e["why"]})
            cur = p
        chain.reverse()
        paths.append({
            "target": t, "target_risk": risk_of[t],
            "ease": round(100 - dist[t], 1), "hops": len(chain), "steps": chain,
        })
    return paths
