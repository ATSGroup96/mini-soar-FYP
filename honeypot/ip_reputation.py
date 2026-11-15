"""
Attacker IP reputation lookups for honeypot hits.

Queries AbuseIPDB and AlienVault OTX (both free tiers). Returns a normalized
verdict: malicious | suspicious | clean | unknown | internal.

  * internal - a private / loopback address (a lab machine). Such addresses
    mean nothing to a public reputation service and are never sent to one.
  * unknown  - keys missing or the services could not be reached.

Fails soft: a lookup problem never breaks the honeypot.
"""
from __future__ import annotations

import ipaddress
from functools import lru_cache

import requests

from common.config import get_settings

ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"
OTX_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"


def is_internal(ip: str) -> bool:
    """Private, loopback or link-local address (or not an IP address at all)."""
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return True  # garbage is never sent to an outside service
    return addr.is_private or addr.is_loopback or addr.is_link_local


@lru_cache(maxsize=1024)
def lookup(ip: str) -> dict:
    s = get_settings()
    out = {"abuse_score": None, "otx_pulses": None, "reputation": "unknown"}

    if is_internal(ip):
        out["reputation"] = "internal"
        return out

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
