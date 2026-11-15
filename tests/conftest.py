"""
Shared test setup.

Safety first - the test suite must NEVER:
  * read the real .env (keys, real Supabase project),
  * talk to the real Supabase project,
  * send a packet to anything except this machine (127.0.0.1).

So, before any project module is imported, python-dotenv is switched off and
every setting is given a fixed test value. Each test then runs in its own empty
temporary folder (so ./data, ./audit, ./reports are throw-away) with a network
guard that only lets loopback connections through.
"""
from __future__ import annotations

import base64
import os
import socket
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# --- 1. never load the real .env ---------------------------------------------
import dotenv  # noqa: E402

dotenv.load_dotenv = lambda *a, **k: False  # type: ignore[assignment]

TEST_ENV = {
    "ALLOWED_RANGES": "192.168.56.0/24,127.0.0.1/32",
    "DENY_HOSTS": "192.168.56.1",
    "AUTHORIZED_LAB_ONLY": "true",
    "SCOPE_SOURCE": "env",
    "SCOPE_CEILING": "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
    "SUPABASE_URL": "",
    "SUPABASE_ANON_KEY": "",
    "SUPABASE_SERVICE_ROLE_KEY": "",
    "SUPABASE_DB_URL": "",
    "AES_KEY_B64": base64.b64encode(bytes(range(32))).decode(),
    "HMAC_KEY": "unit-test-hmac-key",
    "INTEL_DB_PATH": "./data/intel.sqlite",
    "NVD_API_KEY": "",
    "NVD_SYNC_DAYS": "30",
    "ABUSEIPDB_API_KEY": "",
    "OTX_API_KEY": "",
    "SSH_PRIVATE_KEY_PATH": "",
    "SSH_USERNAME": "soar",
    "FORCE_DRY_RUN": "false",
    "TOTP_ISSUER": "Mini-SOAR-Test",
    "SYSLOG_HOST": "127.0.0.1",
    "SYSLOG_PORT": "514",
    "SYSLOG_PROTO": "udp",
    "NETWORK_MODE": "host",
    "ENGINE_HOST_IPS": "",
    "NMAP_PATH": "",
    "VAPID_PRIVATE_KEY": "",
    "VAPID_SUBJECT": "",
    "NEXT_PUBLIC_VAPID_PUBLIC_KEY": "",
}
os.environ.update(TEST_ENV)

from tests.fakes import FakeSupabase  # noqa: E402

LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def _clear_caches() -> None:
    from common import config, db, scope_store
    config.get_settings.cache_clear()
    db.get_service_client.cache_clear()
    scope_store._cache.update(t=0.0, v=None)
    try:
        from ml import risk_score
        risk_score._load.cache_clear()
    except Exception:
        pass
    try:
        from honeypot import events, ip_reputation
        ip_reputation.lookup.cache_clear()
        events.reset_alert_throttle()
    except Exception:
        pass


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    """Every test: fixed settings, empty working folder, no cloud, no network."""
    for k, v in TEST_ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.chdir(tmp_path)

    # --- 2. the real Supabase client can never be created ---------------------
    from common import db, scope_store

    def _refuse(*_a, **_k):
        raise AssertionError("tests must not create a real Supabase client")

    monkeypatch.setattr(db, "create_client", _refuse, raising=False)
    # reading the machine's adapters is slow (PowerShell) and machine-specific
    monkeypatch.setattr(scope_store, "engine_interfaces", lambda: [])

    # --- 3. only loopback connections are allowed ----------------------------
    real_connect = socket.socket.connect

    def guarded_connect(self, address):
        host = address[0] if isinstance(address, tuple) else address
        if isinstance(host, str) and host not in LOOPBACK:
            raise OSError(f"network guard: test tried to connect to {host!r}")
        return real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)

    _clear_caches()
    yield
    _clear_caches()


@pytest.fixture
def supa(monkeypatch) -> FakeSupabase:
    """An in-memory Supabase; every module that asks for the client gets it."""
    from common import db
    fake = FakeSupabase()
    monkeypatch.setenv("SUPABASE_URL", "https://unit-test.invalid")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "unit-test-key")
    monkeypatch.setattr(db, "create_client", lambda _url, _key: fake, raising=False)
    _clear_caches()
    return fake


@pytest.fixture
def set_env(monkeypatch):
    """set_env(KEY='value', ...) and refresh the cached settings."""
    def _set(**kw):
        for k, v in kw.items():
            monkeypatch.setenv(k, v)
        _clear_caches()
    return _set


@pytest.fixture
def audit_actions():
    """Returns a function giving the list of actions written to the audit chain."""
    import json

    def _read() -> list[str]:
        f = Path("audit/audit_chain.jsonl")
        if not f.exists():
            return []
        return [json.loads(line)["action"] for line in f.read_text().splitlines() if line.strip()]
    return _read


# ---- sample data -------------------------------------------------------------
META_IP = "192.168.56.101"


def make_host(ip: str = META_IP, **over) -> dict:
    """A scanned host the way scanner.engine builds it (Metasploitable-like)."""
    host = {
        "ip": ip, "mac": "08:00:27:aa:bb:cc", "hostname": "meta",
        "os_guess": "Linux 2.6.X", "os_accuracy": 95,
        "services": [
            {"port": 21, "protocol": "tcp", "state": "open", "service_name": "ftp",
             "product": "vsftpd", "version": "2.3.4", "cpe": "cpe:/a:vsftpd:vsftpd:2.3.4",
             "banner": ""},
            {"port": 22, "protocol": "tcp", "state": "open", "service_name": "ssh",
             "product": "OpenSSH", "version": "4.7p1", "cpe": "cpe:/a:openbsd:openssh:4.7p1",
             "banner": "", "has_default_cred": True},
            {"port": 23, "protocol": "tcp", "state": "open", "service_name": "telnet",
             "product": "Linux telnetd", "version": "", "cpe": "", "banner": ""},
            {"port": 3306, "protocol": "tcp", "state": "open", "service_name": "mysql",
             "product": "MySQL", "version": "5.0.51a", "cpe": "cpe:/a:mysql:mysql:5.0.51a",
             "banner": ""},
        ],
        "tls": [],
        "default_creds": [{"ip": ip, "port": 22, "service": "ssh", "username": "msfadmin",
                           "password": "msfadmin", "note": "Default/weak credential accepted"}],
        "vulnerabilities": [
            {"cve_id": "CVE-2011-2523", "cvss_score": 9.8, "cvss_vector": "", "severity": "critical",
             "epss_score": 0.94, "epss_percentile": 0.99, "in_kev": True, "kev_due_date": None,
             "description": "vsftpd 2.3.4 backdoor", "port": 21, "product": "vsftpd",
             "version": "2.3.4", "confidence": "version-confirmed"},
            {"cve_id": "CVE-2008-0166", "cvss_score": 7.5, "cvss_vector": "", "severity": "high",
             "epss_score": 0.10, "epss_percentile": 0.90, "in_kev": False, "kev_due_date": None,
             "description": "weak keys", "port": 22, "product": "OpenSSH",
             "version": "4.7p1", "confidence": "version-confirmed"},
        ],
    }
    host.update(over)
    return host


@pytest.fixture
def host():
    return make_host()
