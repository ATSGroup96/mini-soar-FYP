"""
Feature definitions shared by training and scoring.

A vulnerability (a CVE on a service on an asset) is turned into a fixed feature
vector. Keeping this in one place guarantees train-time and score-time parity.
"""
from __future__ import annotations

# ordered feature names — order matters, it is the model's input layout
FEATURE_NAMES = [
    "cvss",              # 0..10
    "epss",              # 0..1  probability of exploitation
    "epss_percentile",   # 0..1
    "in_kev",            # 0/1   on CISA KEV
    "has_default_cred",  # 0/1   service accepts a default credential
    "internet_facing",   # 0/1   reachable beyond the lab segment (future use)
    "service_criticality",  # 0..1  (ssh/rdp/db high, misc low)
    "version_confirmed", # 0/1   version range confirmed (vs unconfirmed)
    "asset_exposure",    # 0..1  open-port count normalized
    "rogue_asset",       # 0/1   unauthorized device
]

# human-readable explanations keyed by feature, used in the explainable output
FEATURE_EXPLANATION = {
    "cvss": "CVSS base severity",
    "epss": "EPSS exploitation probability",
    "epss_percentile": "EPSS percentile vs all CVEs",
    "in_kev": "Listed on CISA Known-Exploited (KEV)",
    "has_default_cred": "Service still uses a default credential",
    "internet_facing": "Reachable from outside the lab segment",
    "service_criticality": "Sensitivity of the exposed service",
    "version_confirmed": "Vulnerable version confirmed",
    "asset_exposure": "Overall open-port exposure of the host",
    "rogue_asset": "Unauthorized / rogue device",
}

# service name -> criticality weight
_CRIT = {
    "ssh": 0.9, "rdp": 1.0, "ms-wbt-server": 1.0, "telnet": 0.95,
    "mysql": 0.9, "postgresql": 0.9, "ms-sql-s": 0.95, "oracle": 0.95,
    "smb": 0.9, "microsoft-ds": 0.9, "netbios-ssn": 0.8, "ftp": 0.7,
    "vnc": 0.9, "rpcbind": 0.6, "http": 0.5, "https": 0.5, "smtp": 0.5,
}


def service_criticality(service_name: str) -> float:
    return _CRIT.get((service_name or "").lower(), 0.3)


def vuln_to_features(v: dict, host: dict | None = None) -> list[float]:
    """Map a vuln dict (+ optional host context) to the feature vector."""
    host = host or {}
    services = host.get("services", [])
    svc_name = ""
    default_cred = False
    for s in services:
        if s.get("port") == v.get("port"):
            svc_name = s.get("service_name", "")
            default_cred = bool(s.get("has_default_cred"))
            break
    exposure = min(len(services) / 20.0, 1.0)
    return [
        float(v.get("cvss_score") or 0.0),
        float(v.get("epss_score") or 0.0),
        float(v.get("epss_percentile") or 0.0),
        1.0 if v.get("in_kev") else 0.0,
        1.0 if default_cred else 0.0,
        1.0 if host.get("internet_facing") else 0.0,
        service_criticality(svc_name),
        1.0 if v.get("confidence") == "version-confirmed" else 0.0,
        exposure,
        1.0 if host.get("is_rogue") else 0.0,
    ]
