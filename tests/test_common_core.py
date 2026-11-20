"""Encryption, signing, audit hash chain, file lock, network mode, syslog."""
import json
import multiprocessing as mp
import socket
import time
from pathlib import Path

import pytest

from common import audit, crypto, netmode, syslog_logger
from common.filelock import LockBusy, file_lock
from tests._children import audit_writer, hold_lock


# ---- AES-256-GCM -------------------------------------------------------------
def test_encrypt_decrypt_roundtrip():
    blob = crypto.encrypt(b"secret scan data")
    assert b"secret" not in blob.encode()
    assert crypto.decrypt(blob) == b"secret scan data"


def test_encrypt_uses_fresh_nonce():
    assert crypto.encrypt(b"same") != crypto.encrypt(b"same")


def test_tampered_ciphertext_is_rejected():
    import base64
    raw = bytearray(base64.b64decode(crypto.encrypt(b"scan result")))
    raw[-1] ^= 0x01
    with pytest.raises(Exception):
        crypto.decrypt(base64.b64encode(bytes(raw)).decode())


def test_json_roundtrip():
    obj = {"hosts": [{"ip": "192.168.56.101", "ports": [21, 22]}]}
    assert crypto.decrypt_json(crypto.encrypt_json(obj)) == obj


def test_wrong_key_length_is_refused(set_env):
    set_env(AES_KEY_B64="c2hvcnQ=")
    with pytest.raises(ValueError, match="32 bytes"):
        crypto.encrypt(b"x")


# ---- HMAC signing ------------------------------------------------------------
def test_signature_verifies():
    sig = crypto.sign_payload(b'{"a":1}')
    assert crypto.verify_signature(b'{"a":1}', sig["X-Soar-Timestamp"], sig["X-Soar-Signature"])


def test_signature_fails_when_body_changes():
    sig = crypto.sign_payload(b'{"a":1}')
    assert not crypto.verify_signature(b'{"a":2}', sig["X-Soar-Timestamp"], sig["X-Soar-Signature"])


def test_signature_fails_with_other_key(set_env):
    sig = crypto.sign_payload(b"body")
    set_env(HMAC_KEY="another-key")
    assert not crypto.verify_signature(b"body", sig["X-Soar-Timestamp"], sig["X-Soar-Signature"])


def test_old_signature_is_a_replay():
    old = int(time.time()) - 3600
    sig = crypto.sign_payload(b"body", timestamp=old)
    assert not crypto.verify_signature(b"body", str(old), sig["X-Soar-Signature"])
    # stored bundles are checked without the freshness window
    assert crypto.verify_signature(b"body", str(old), sig["X-Soar-Signature"], max_skew_seconds=None)


def test_signing_needs_a_key(set_env):
    set_env(HMAC_KEY="")
    with pytest.raises(ValueError, match="HMAC_KEY"):
        crypto.sign_payload(b"x")
    assert not crypto.verify_signature(b"x", str(int(time.time())), "00")


# ---- audit hash chain --------------------------------------------------------
def test_chain_links_and_verifies():
    a = audit.log_event("engine", "scan.start", "192.168.56.0/24")
    b = audit.log_event("admin", "remediation.execute", "192.168.56.101", {"port": 23})
    assert a["prev_hash"] == "0" * 64
    assert b["prev_hash"] == a["curr_hash"]
    ok, n, msg = audit.verify_chain()
    assert (ok, n) == (True, 2) and "intact" in msg


def test_empty_chain_is_ok():
    assert audit.verify_chain()[:2] == (True, 0)


def _rewrite(line_no: int, change):
    f = Path("audit/audit_chain.jsonl")
    lines = f.read_text().splitlines()
    row = json.loads(lines[line_no])
    change(row)
    lines[line_no] = json.dumps(row)
    f.write_text("\n".join(lines) + "\n")


def test_edited_entry_is_detected():
    for i in range(3):
        audit.log_event("engine", f"event.{i}")
    _rewrite(1, lambda r: r.update(actor="attacker"))
    ok, _n, msg = audit.verify_chain()
    assert not ok and "entry 2" in msg


def test_deleted_entry_is_detected():
    for i in range(3):
        audit.log_event("engine", f"event.{i}")
    f = Path("audit/audit_chain.jsonl")
    lines = f.read_text().splitlines()
    f.write_text("\n".join([lines[0], lines[2]]) + "\n")
    ok, _n, msg = audit.verify_chain()
    assert not ok and "prev_hash" in msg


def test_audit_is_mirrored_to_cloud(supa):
    row = audit.log_event("engine", "scan.finish", "lab", {"hosts": 2})
    mirrored = supa.rows("audit_log")
    assert len(mirrored) == 1 and mirrored[0]["curr_hash"] == row["curr_hash"]


def test_audit_survives_cloud_failure(supa):
    supa.fail_tables.add("audit_log")
    audit.log_event("engine", "scan.finish")
    assert audit.verify_chain()[0]


def test_chain_stays_intact_with_parallel_writers(tmp_path):
    ctx = mp.get_context("spawn")
    procs = [ctx.Process(target=audit_writer, args=(str(tmp_path), w, 15)) for w in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(60)
    assert all(p.exitcode == 0 for p in procs)
    ok, n, _ = audit.verify_chain()
    assert ok and n == 60


# ---- file lock ---------------------------------------------------------------
def test_non_blocking_lock_reports_busy(tmp_path):
    ctx = mp.get_context("spawn")
    ready = ctx.Event()
    lock = str(tmp_path / "data" / ".scan.lock")
    p = ctx.Process(target=hold_lock, args=(lock, 1.5, ready))
    p.start()
    try:
        assert ready.wait(20)
        with pytest.raises(LockBusy):
            with file_lock(lock, blocking=False):
                pass
    finally:
        p.join(20)
    with file_lock(lock, blocking=False):        # free again afterwards
        pass


# ---- network mode ------------------------------------------------------------
@pytest.mark.parametrize("value,mode", [
    ("", "host"), ("host", "host"), ("nat", "nat"), ("docker-desktop", "nat"),
    ("windows", "nat"), ("native", "native"), ("windows-native", "native"),
    ("NATIVE", "native"), ("something-else", "host"),
])
def test_network_mode_names(set_env, value, mode):
    set_env(NETWORK_MODE=value)
    assert netmode.network_mode() == mode
    assert netmode.is_nat() is (mode == "nat")
    assert netmode.is_native() is (mode == "native")


def test_engine_host_interfaces_parsing(set_env):
    set_env(ENGINE_HOST_IPS="192.168.103.1/24, 10.0.0.5, junk, fe80::1/64")
    got = netmode.engine_host_interfaces()
    assert [(i["ip"], i["network"]) for i in got] == [
        ("192.168.103.1", "192.168.103.0/24"), ("10.0.0.5", "10.0.0.0/24")]


def test_nmap_scanner_uses_nmap_path(set_env, monkeypatch):
    nmap = pytest.importorskip("nmap")
    seen = {}

    class FakeScanner:
        def __init__(self, nmap_search_path=()):
            seen["paths"] = nmap_search_path

    monkeypatch.setattr(nmap, "PortScanner", FakeScanner)
    set_env(NMAP_PATH=r'"F:\Tools\Nmap\nmap.exe"')
    netmode.nmap_scanner()
    assert seen["paths"][0] == r"F:\Tools\Nmap\nmap.exe"
    assert "nmap" in seen["paths"]


# ---- syslog ------------------------------------------------------------------
def test_syslog_sends_udp_packet(set_env):
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(5)
    set_env(SYSLOG_PORT=str(srv.getsockname()[1]))
    try:
        syslog_logger.send("scan finished", syslog_logger.NOTICE)
        data = srv.recvfrom(2048)[0].decode()
    finally:
        srv.close()
    assert data.startswith("<133>mini-soar[")      # local0 (16*8) + notice (5)
    assert data.endswith("scan finished")


def test_syslog_never_raises_when_siem_is_down(set_env):
    set_env(SYSLOG_PROTO="tcp", SYSLOG_PORT="1")
    syslog_logger.send("nobody listens")           # must not raise


# ---- Supabase helpers (v14) ----------------------------------------------------
def test_fetch_all_reads_every_page(supa):
    from common.db import fetch_all
    for i in range(7):
        supa.add("services", asset_id="a", port=i, state="open")
    supa.add("services", asset_id="b", port=99, state="open")
    assert len(fetch_all(supa, "services", page=3)) == 8
    assert [r["port"] for r in fetch_all(supa, "services", eq={"asset_id": "b"}, page=3)] == [99]


def test_each_thread_gets_its_own_client(monkeypatch):
    """One HTTP/2 connection shared by API threads made Supabase drop it."""
    import threading
    from common import db
    made = []
    monkeypatch.setenv("SUPABASE_URL", "https://unit-test.invalid")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "k")
    monkeypatch.setattr(db, "create_client", lambda u, k: made.append(object()) or made[-1])
    from common import config
    config.get_settings.cache_clear()
    db.get_service_client.cache_clear()
    main = db.get_service_client()
    assert db.get_service_client() is main                       # cached per thread
    other = []
    t = threading.Thread(target=lambda: other.append(db.get_service_client()))
    t.start(); t.join()
    assert other[0] is not main and len(made) == 2
    db.get_service_client.cache_clear()
    assert db.get_service_client() is not main                   # cache_clear works


# ---- API login check (common/auth.py) ------------------------------------------
def test_local_jwt_check():
    jwt = pytest.importorskip("jwt")
    import time as _t
    from common import auth
    secret = "unit-test-jwt-secret-that-is-long-enough"
    good = jwt.encode({"sub": "u1", "aud": "authenticated", "exp": int(_t.time()) + 60},
                      secret, algorithm="HS256")
    assert auth._verify_local(good, secret) == "u1"
    for bad in (jwt.encode({"sub": "u1", "aud": "authenticated", "exp": int(_t.time()) - 5},
                           secret, algorithm="HS256"),                         # expired
                jwt.encode({"sub": "u1", "aud": "authenticated"}, "other-secret-long-enough-x",
                           algorithm="HS256"),                                 # forged
                jwt.encode({"sub": "u1", "aud": "anon"}, secret, algorithm="HS256"),
                "not-a-token"):
        with pytest.raises(auth.AuthError) as e:
            auth._verify_local(bad, secret)
        assert e.value.status == 401


def test_remote_check_asks_supabase(monkeypatch, set_env):
    import requests
    from common import auth
    set_env(SUPABASE_URL="https://unit-test.invalid", SUPABASE_ANON_KEY="anon")
    seen = {}

    class R:
        def __init__(self, code, body):
            self.status_code, self._b = code, body

        def json(self):
            return self._b

    def fake_get(url, headers, timeout):
        seen.update(url=url, headers=headers)
        return R(200, {"id": "u9"}) if headers["Authorization"] == "Bearer good" else R(401, {})
    monkeypatch.setattr(requests, "get", fake_get)
    assert auth._verify_remote("good") == "u9"
    assert seen["url"] == "https://unit-test.invalid/auth/v1/user" and seen["headers"]["apikey"] == "anon"
    with pytest.raises(auth.AuthError) as e:
        auth._verify_remote("bad")
    assert e.value.status == 401


def test_require_roles_and_header(supa):
    from common import auth
    v = supa.add("profiles", email="v@x", role="viewer")
    a = supa.add("profiles", email="a@x", role="admin")
    assert auth.require(supa, f"Bearer t-{v['id']}", "viewer")["id"] == v["id"]
    assert auth.require(supa, f"Bearer t-{a['id']}", "analyst")["id"] == a["id"]
    for header, role, status in ((None, "viewer", 401), ("Basic abc", "viewer", 401),
                                 ("Bearer ", "viewer", 401), (f"Bearer t-{v['id']}", "analyst", 403),
                                 ("Bearer t-ghost", "viewer", 403), ("Bearer forged", "viewer", 401)):
        with pytest.raises(auth.AuthError) as e:
            auth.require(supa, header, role)
        assert e.value.status == status, (header, role)
    with pytest.raises(auth.AuthError) as e:
        auth.require(None, f"Bearer t-{v['id']}")
    assert e.value.status == 503
