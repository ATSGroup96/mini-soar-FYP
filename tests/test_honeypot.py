"""Honeypot: fake SSH + fake HTTP, event recording, IP reputation."""
import base64
import http.client
import socket
import threading
import time

import pytest

from honeypot import events, http_honeypot, ip_reputation, ssh_honeypot


@pytest.fixture
def recorded(monkeypatch):
    """Capture honeypot hits instead of writing them anywhere."""
    hits = []

    def fake_record(service, src_ip, src_port=None, username=None, password=None,
                    path_or_cmd=None):
        hits.append({"service": service, "src_ip": src_ip, "username": username,
                     "password": password, "path_or_cmd": path_or_cmd})
        return hits[-1]

    monkeypatch.setattr(ssh_honeypot, "record", fake_record)
    monkeypatch.setattr(http_honeypot, "record", fake_record)
    return hits


def wait_for(cond, seconds=10):
    end = time.time() + seconds
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


# ---- fake SSH ----------------------------------------------------------------
@pytest.fixture
def ssh_port():
    pytest.importorskip("paramiko")
    srv = ssh_honeypot.listen(0, host="127.0.0.1")
    threading.Thread(target=ssh_honeypot.accept_loop,
                     args=(srv, ssh_honeypot._make_server_key()), daemon=True).start()
    yield srv.getsockname()[1]
    srv.close()


def test_ssh_honeypot_records_password_and_never_lets_in(ssh_port, recorded):
    import paramiko
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    with pytest.raises(paramiko.AuthenticationException):
        c.connect("127.0.0.1", port=ssh_port, username="root", password="toor",
                  allow_agent=False, look_for_keys=False, timeout=10, banner_timeout=10,
                  auth_timeout=10)
    c.close()
    assert wait_for(lambda: recorded)
    assert recorded[0] == {"service": "ssh", "src_ip": "127.0.0.1", "username": "root",
                           "password": "toor", "path_or_cmd": None}


def test_ssh_honeypot_refuses_every_password(ssh_port, recorded):
    import paramiko
    for user, pw in [("admin", "admin"), ("msfadmin", "msfadmin"), ("soar", "x")]:
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        with pytest.raises(paramiko.AuthenticationException):
            c.connect("127.0.0.1", port=ssh_port, username=user, password=pw,
                      allow_agent=False, look_for_keys=False, timeout=10,
                      banner_timeout=10, auth_timeout=10)
        c.close()
    assert wait_for(lambda: len(recorded) == 3)
    assert [h["username"] for h in recorded] == ["admin", "msfadmin", "soar"]


def test_ssh_honeypot_records_key_login_attempt(ssh_port, recorded):
    import paramiko
    key = paramiko.RSAKey.generate(2048)
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    with pytest.raises(paramiko.SSHException):
        c.connect("127.0.0.1", port=ssh_port, username="deploy", pkey=key,
                  allow_agent=False, look_for_keys=False, timeout=10, banner_timeout=10,
                  auth_timeout=10)
    c.close()
    assert wait_for(lambda: recorded)
    assert recorded[0]["username"] == "deploy" and recorded[0]["password"] == "<pubkey>"


def test_ssh_honeypot_shows_a_real_looking_banner(ssh_port):
    s = socket.create_connection(("127.0.0.1", ssh_port), timeout=10)
    banner = s.recv(64).decode()
    s.close()
    assert banner.startswith("SSH-2.0-OpenSSH_")


def test_ssh_honeypot_survives_garbage(ssh_port, recorded):
    for junk in (b"GET / HTTP/1.0\r\n\r\n", b"\x00" * 64, b""):
        s = socket.create_connection(("127.0.0.1", ssh_port), timeout=10)
        s.sendall(junk)
        s.close()
    # still alive and still answering
    s = socket.create_connection(("127.0.0.1", ssh_port), timeout=10)
    assert s.recv(16).startswith(b"SSH-2.0")
    s.close()


# ---- fake HTTP ---------------------------------------------------------------
@pytest.fixture
def http_port():
    srv = http_honeypot.make_server(0, host="127.0.0.1")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def req(port, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request(method, path, body=body, headers=headers or {})
    r = conn.getresponse()
    data = r.read()
    conn.close()
    return r, data


def test_http_get_serves_fake_login_and_records(http_port, recorded):
    r, body = req(http_port, "GET", "/admin")
    assert r.status == 200 and b"Administration Login" in body
    assert r.getheader("Server").startswith("Apache/")       # looks ordinary
    assert recorded[-1]["path_or_cmd"] == "GET /admin" and recorded[-1]["username"] is None


def test_http_post_login_records_credentials_and_denies(http_port, recorded):
    r, body = req(http_port, "POST", "/login", body="username=admin&password=hunter2",
                  headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status == 401 and b"Invalid credentials" in body
    assert (recorded[-1]["username"], recorded[-1]["password"]) == ("admin", "hunter2")


def test_http_basic_auth_is_recorded(http_port, recorded):
    token = base64.b64encode(b"root:toor").decode()
    req(http_port, "GET", "/", headers={"Authorization": f"Basic {token}"})
    assert (recorded[-1]["username"], recorded[-1]["password"]) == ("root", "toor")


def test_http_never_grants_access_even_with_right_looking_login(http_port):
    for body in ("username=admin&password=admin", "username=root&password=root"):
        r, _ = req(http_port, "POST", "/login", body=body)
        assert r.status == 401


@pytest.mark.parametrize("method", ["HEAD", "PUT", "DELETE", "OPTIONS"])
def test_http_other_methods_are_recorded_too(http_port, recorded, method):
    r, _ = req(http_port, method, "/cgi-bin/test.cgi")
    assert r.status in (200, 401, 405)
    assert recorded[-1]["path_or_cmd"] == f"{method} /cgi-bin/test.cgi"


def test_http_bad_content_length_does_not_crash(http_port, recorded):
    s = socket.create_connection(("127.0.0.1", http_port), timeout=10)
    s.sendall(b"POST /login HTTP/1.1\r\nHost: x\r\nContent-Length: banana\r\n\r\n")
    assert s.recv(64).startswith(b"HTTP/1.")
    s.close()
    r, _ = req(http_port, "GET", "/still-alive")
    assert r.status == 200


def test_http_huge_body_is_capped(http_port, recorded):
    body = "username=a&password=" + "x" * 200_000
    r, _ = req(http_port, "POST", "/login", body=body)
    assert r.status == 401
    assert len(recorded[-1]["password"]) <= http_honeypot.MAX_BODY


def test_http_long_path_is_trimmed(http_port, recorded):
    req(http_port, "GET", "/" + "A" * 5000)
    assert len(recorded[-1]["path_or_cmd"]) <= 520


# ---- event recording ---------------------------------------------------------
def test_event_is_audited_and_stored(supa, audit_actions, monkeypatch):
    monkeypatch.setattr(events, "lookup", lambda ip: {"abuse_score": 80, "otx_pulses": 4,
                                                      "reputation": "malicious"})
    ev = events.record("ssh", "8.8.4.4", 51234, username="root", password="toor")
    assert ev["reputation"] == "malicious"
    assert "honeypot.ssh" in audit_actions()
    row = supa.rows("honeypot_events")[0]
    assert (row["service"], row["src_ip"], row["username_tried"], row["password_tried"]) == \
        ("ssh", "8.8.4.4", "root", "toor")
    n = supa.rows("notifications")[0]
    assert n["level"] == "high" and "8.8.4.4" in n["body"] and n["link"] == "/honeypot"


def test_lab_device_touching_honeypot_raises_alert(supa):
    """Inside the lab nobody has a reason to touch the decoy: always alert."""
    ev = events.record("http", "192.168.56.105", 40000, path_or_cmd="GET /admin")
    assert ev["reputation"] == "internal"
    n = supa.rows("notifications")
    assert len(n) == 1 and n[0]["level"] == "medium" and "192.168.56.105" in n[0]["body"]


def test_alerts_are_throttled_but_every_event_is_stored(supa):
    for i in range(25):
        events.record("ssh", "192.168.56.105", 40000 + i, username="root", password=f"p{i}")
    assert len(supa.rows("honeypot_events")) == 25
    assert len(supa.rows("notifications")) == 1


def test_clean_public_ip_is_stored_without_alert(supa, monkeypatch):
    monkeypatch.setattr(events, "lookup", lambda ip: {"abuse_score": 0, "otx_pulses": 0,
                                                      "reputation": "clean"})
    events.record("http", "1.1.1.1", 1234, path_or_cmd="GET /")
    assert len(supa.rows("honeypot_events")) == 1 and supa.rows("notifications") == []


def test_event_works_without_cloud(audit_actions):
    ev = events.record("ssh", "192.168.56.105", 1, username="a", password="b")
    assert ev["service"] == "ssh" and "honeypot.ssh" in audit_actions()


def test_event_survives_cloud_failure(supa):
    supa.fail_tables.add("honeypot_events")
    events.record("ssh", "192.168.56.105", 1, username="a", password="b")   # must not raise


def test_long_inputs_are_trimmed_before_storage(supa):
    events.record("http", "192.168.56.105", 1, username="u" * 5000, password="p" * 5000,
                  path_or_cmd="GET /" + "A" * 5000)
    row = supa.rows("honeypot_events")[0]
    assert len(row["username_tried"]) <= 256 and len(row["password_tried"]) <= 256
    assert len(row["path_or_cmd"]) <= 512


# ---- IP reputation -----------------------------------------------------------
class _R:
    def __init__(self, data, ok=True):
        self._d, self.ok = data, ok

    def json(self):
        return self._d


def fake_feeds(monkeypatch, abuse=None, pulses=None):
    calls = []

    def get(url, **k):
        calls.append(url)
        if "abuseipdb" in url:
            return _R({"data": {"abuseConfidenceScore": abuse}})
        return _R({"pulse_info": {"count": pulses}})
    monkeypatch.setattr(ip_reputation.requests, "get", get)
    return calls


@pytest.mark.parametrize("abuse,pulses,verdict", [
    (80, 0, "malicious"), (10, 3, "malicious"), (20, 0, "suspicious"),
    (0, 1, "suspicious"), (0, 0, "clean"),
])
def test_reputation_verdicts(monkeypatch, set_env, abuse, pulses, verdict):
    set_env(ABUSEIPDB_API_KEY="k1", OTX_API_KEY="k2")
    fake_feeds(monkeypatch, abuse, pulses)
    out = ip_reputation.lookup("8.8.4.4")
    assert (out["abuse_score"], out["otx_pulses"], out["reputation"]) == (abuse, pulses, verdict)


def test_reputation_unknown_without_keys(monkeypatch):
    calls = fake_feeds(monkeypatch, 99, 99)
    assert ip_reputation.lookup("8.8.4.4")["reputation"] == "unknown"
    assert calls == []


def test_private_addresses_are_never_sent_to_reputation_services(monkeypatch, set_env):
    set_env(ABUSEIPDB_API_KEY="k1", OTX_API_KEY="k2")
    calls = fake_feeds(monkeypatch, 99, 99)
    for ip in ("192.168.56.105", "10.0.0.8", "127.0.0.1", "172.16.5.5"):
        assert ip_reputation.lookup(ip)["reputation"] == "internal"
    assert calls == []


def test_reputation_fails_soft_when_feeds_are_down(monkeypatch, set_env):
    set_env(ABUSEIPDB_API_KEY="k1", OTX_API_KEY="k2")

    def down(*a, **k):
        raise RuntimeError("no internet")
    monkeypatch.setattr(ip_reputation.requests, "get", down)
    assert ip_reputation.lookup("8.8.4.4")["reputation"] == "unknown"


def test_reputation_is_cached(monkeypatch, set_env):
    set_env(ABUSEIPDB_API_KEY="k1")
    calls = fake_feeds(monkeypatch, 60, 0)
    ip_reputation.lookup("8.8.4.4")
    ip_reputation.lookup("8.8.4.4")
    assert len(calls) == 1
