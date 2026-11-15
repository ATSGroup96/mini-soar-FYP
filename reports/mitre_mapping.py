"""
Map findings to MITRE ATT&CK techniques.

A lightweight, offline heuristic mapping from service/finding characteristics to
the most relevant ATT&CK techniques — enough for an FYP report to show which
attacker behaviours each exposure enables. Not a replacement for full ATT&CK
navigator coverage.
"""
from __future__ import annotations

# (match predicate key) -> list of (technique_id, name, tactic)
_RULES = {
    "default_cred": [("T1078", "Valid Accounts", "Initial Access / Persistence"),
                     ("T1110", "Brute Force", "Credential Access")],
    "telnet":       [("T1040", "Network Sniffing", "Credential Access"),
                     ("T1021.004", "Remote Services: SSH/Telnet", "Lateral Movement")],
    "ftp":          [("T1071", "Application Layer Protocol", "Command and Control")],
    "smb":          [("T1021.002", "SMB/Windows Admin Shares", "Lateral Movement"),
                     ("T1570", "Lateral Tool Transfer", "Lateral Movement")],
    "rdp":          [("T1021.001", "Remote Desktop Protocol", "Lateral Movement")],
    "ssh":          [("T1021.004", "Remote Services: SSH", "Lateral Movement")],
    "http":         [("T1190", "Exploit Public-Facing Application", "Initial Access")],
    "kev":          [("T1203", "Exploitation for Client Execution", "Execution"),
                     ("T1190", "Exploit Public-Facing Application", "Initial Access")],
    "database":     [("T1213", "Data from Information Repositories", "Collection")],
    "rogue":        [("T1200", "Hardware Additions", "Initial Access")],
}

_DB_SVC = {"mysql", "postgresql", "ms-sql-s", "oracle", "mongodb", "redis"}


def map_host(host: dict) -> list[dict]:
    techniques: dict[str, dict] = {}

    def add(key):
        for tid, name, tactic in _RULES.get(key, []):
            techniques[tid] = {"technique_id": tid, "name": name, "tactic": tactic}

    if host.get("is_rogue"):
        add("rogue")
    for s in host.get("services", []):
        name = (s.get("service_name") or "").lower()
        if s.get("has_default_cred"):
            add("default_cred")
        if name in _DB_SVC:
            add("database")
        for key in ("telnet", "ftp", "smb", "rdp", "ssh", "http"):
            if key in name:
                add(key)
    for v in host.get("vulnerabilities", []):
        if v.get("in_kev"):
            add("kev")

    return list(techniques.values())


def map_all(hosts: list[dict]) -> dict:
    """Return per-host mapping + a deduped technique coverage summary."""
    per_host = {}
    coverage: dict[str, dict] = {}
    for h in hosts:
        techs = map_host(h)
        per_host[h["ip"]] = techs
        for t in techs:
            coverage[t["technique_id"]] = t
    return {"per_host": per_host, "coverage": list(coverage.values())}
