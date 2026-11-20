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
    # NetExec / Nuclei findings without a CVE
    "smb_relay":    [("T1557.001", "LLMNR/NBT-NS Poisoning and SMB Relay", "Credential Access")],
    "smbv1":        [("T1210", "Exploitation of Remote Services", "Lateral Movement")],
    "anon_share":   [("T1135", "Network Share Discovery", "Discovery"),
                     ("T1039", "Data from Network Shared Drive", "Collection")],
    "rdp_no_nla":   [("T1021.001", "Remote Desktop Protocol", "Lateral Movement"),
                     ("T1210", "Exploitation of Remote Services", "Lateral Movement")],
    "panel":        [("T1133", "External Remote Services", "Initial Access")],
}

# finding_key (prefix) -> rule
_FINDING_RULES = {
    "netexec:smb-signing-not-required": "smb_relay",
    "netexec:smbv1-enabled": "smbv1",
    "netexec:smb-null-session": "anon_share",
    "netexec:smb-anonymous-share": "anon_share",
    "netexec:rdp-nla-disabled": "rdp_no_nla",
    "netexec:winrm-http": "panel",
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
        key = v.get("finding_key") or ""
        for prefix, rule in _FINDING_RULES.items():
            if key.startswith(prefix):
                add(rule)
        if v.get("source") == "nuclei":
            add("panel" if "panel" in key else "http")

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
