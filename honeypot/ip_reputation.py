"""
Attacker IP reputation lookups for honeypot hits.

Queries AbuseIPDB and AlienVault OTX (both free tiers). Returns a normalized
verdict. Fails soft: if keys are missing or a service is down, returns 'unknown'
rather than breaking the honeypot.
"""
from __future__ import annotations

from functools import lru_cache

import requests

from common.config import get_settings

ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"
OTX_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"


@lru_cache(maxsize=1024)
def lookup(ip: str) -> dict:
    s = get_settings()
    out = {"abuse_score": None, "otx_pulses": None, "reputation": "unknown"}

    if s.abuseipdb_api_key:
        try:
            r = requests.get(ABUSE_URL,
                             headers={"Key": s.abuseipdb_api_key, "Accept": "application/json"},
                             params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=8)
            if r.ok:
                out["abuse_score"] = r.json()["data"]["abuseConfidenceScore"]
        except Exception:
            pass

    if s.otx_api_key:
        try:
            r = requests.get(OTX_URL.format(ip=ip),
                             headers={"X-OTX-API-KEY": s.otx_api_key}, timeout=8)
            if r.ok:
                out["otx_pulses"] = r.json().get("pulse_info", {}).get("count", 0)
        except Exception:
            pass

    score = out["abuse_score"] or 0
    pulses = out["otx_pulses"] or 0
    if score >= 50 or pulses >= 3:
        out["reputation"] = "malicious"
    elif score >= 15 or pulses >= 1:
        out["reputation"] = "suspicious"
    elif out["abuse_score"] is not None or out["otx_pulses"] is not None:
        out["reputation"] = "clean"
    return out
