"""
Central configuration loader.

Reads the .env file once and exposes typed settings. Also performs the
hard authorization checks that the rest of the platform relies on:
nothing may scan or remediate unless AUTHORIZED_LAB_ONLY=true and an
allowlist is configured.
"""
from __future__ import annotations

import os
import base64
import ipaddress
from dataclasses import dataclass, field
from functools import lru_cache

from dotenv import load_dotenv

load_dotenv()  # loads .env from the repo root if present


def _get(key: str, default: str = "") -> str:
    return os.environ.get(key, default).strip()


def _parse_cidrs(raw: str) -> list[ipaddress._BaseNetwork]:
    nets: list[ipaddress._BaseNetwork] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        nets.append(ipaddress.ip_network(part, strict=False))
    return nets


@dataclass(frozen=True)
class Settings:
    # safety / scope
    allowed_ranges: list = field(default_factory=list)
    deny_hosts: list = field(default_factory=list)
    authorized_lab_only: bool = False

    # supabase
    supabase_url: str = ""
    supabase_anon_key: str = ""
    supabase_service_role_key: str = ""
    supabase_db_url: str = ""

    # crypto
    aes_key: bytes = b""
    hmac_key: str = ""

    # intel
    intel_db_path: str = "./data/intel.sqlite"
    nvd_api_key: str = ""
    nvd_sync_days: int = 30

    # threat intel
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""

    # soar
    ssh_private_key_path: str = ""
    ssh_username: str = ""
    force_dry_run: bool = False

    # 2fa
    totp_issuer: str = "Mini-SOAR-Lab"

    # syslog
    syslog_host: str = "127.0.0.1"
    syslog_port: int = 514
    syslog_proto: str = "udp"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    aes_b64 = _get("AES_KEY_B64")
    aes_key = b""
    if aes_b64 and aes_b64 != "GENERATE-A-32-BYTE-BASE64-KEY":
        try:
            aes_key = base64.b64decode(aes_b64)
        except Exception:
            aes_key = b""

    return Settings(
        allowed_ranges=_parse_cidrs(_get("ALLOWED_RANGES")),
        deny_hosts=[h.strip() for h in _get("DENY_HOSTS").split(",") if h.strip()],
        authorized_lab_only=_get("AUTHORIZED_LAB_ONLY").lower() == "true",
        supabase_url=_get("SUPABASE_URL"),
        supabase_anon_key=_get("SUPABASE_ANON_KEY"),
        supabase_service_role_key=_get("SUPABASE_SERVICE_ROLE_KEY"),
        supabase_db_url=_get("SUPABASE_DB_URL"),
        aes_key=aes_key,
        hmac_key=_get("HMAC_KEY"),
        intel_db_path=_get("INTEL_DB_PATH", "./data/intel.sqlite"),
        nvd_api_key=_get("NVD_API_KEY"),
        nvd_sync_days=int(_get("NVD_SYNC_DAYS", "30") or 30),
        abuseipdb_api_key=_get("ABUSEIPDB_API_KEY"),
        otx_api_key=_get("OTX_API_KEY"),
        ssh_private_key_path=_get("SSH_PRIVATE_KEY_PATH"),
        ssh_username=_get("SSH_USERNAME"),
        force_dry_run=_get("FORCE_DRY_RUN").lower() == "true",
        totp_issuer=_get("TOTP_ISSUER", "Mini-SOAR-Lab"),
        syslog_host=_get("SYSLOG_HOST", "127.0.0.1"),
        syslog_port=int(_get("SYSLOG_PORT", "514") or 514),
        syslog_proto=_get("SYSLOG_PROTO", "udp"),
    )


class AuthorizationError(RuntimeError):
    """Raised when the engine is asked to act without proper authorization."""


def assert_authorized_to_run() -> None:
    """
    Gate that every active-network entry point calls before doing anything.
    Fails closed: if the operator has not explicitly declared lab authorization
    and an allowlist, the engine refuses to run.
    """
    from .scope_store import effective_scope   # lazy: avoids a circular import
    sc = effective_scope()
    if not get_settings().authorized_lab_only:
        raise AuthorizationError(
            "Refusing to run: AUTHORIZED_LAB_ONLY is not 'true' in .env. "
            "Set it only for a lab you are authorized to test."
        )
    if not sc["authorized"]:
        raise AuthorizationError(
            "Refusing to run: this network is not marked as authorized. "
            "An admin must confirm written authorization in Settings -> Network scope."
        )
    if not sc["allowed_ranges"]:
        raise AuthorizationError(
            "Refusing to run: no allowed range. Set the network scope in "
            "Settings -> Network scope (or ALLOWED_RANGES in .env)."
        )
