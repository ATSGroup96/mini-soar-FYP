"""Scanner: discovery, port scan, default-credential check, TLS check."""
import datetime
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from common import netmode
from common.allowlist import ScopeError
from scanner import default_creds, discovery, port_scan, tls_check
from scanner.port_scan import ServiceInfo
from tests.fakes import FakeNmap

META = "192.168.56.101"


def use_nmap(monkeypatch, fake):
    monkeypatch.setattr(netmode, "nmap_scanner", lambda: fake)
    return fake


# ---- discovery ---------------------------------------------------------------
def test_discovery_only_touches_in_scope_targets(monkeypatch):
    fake = use_nmap(monkeypatch, FakeNmap({META: {"addresses": {"mac": "08:00:27:AA:BB:CC"}}}))
    monkeypatch.setattr(discovery, "arp_sweep", lambda t: [])
    hosts = discovery.discover([META, "8.8.8.8", "192.168.56.1"])
    assert [(h.ip, h.mac, h.method) for h in hosts] == [(META, "08:00:27:aa:bb:cc", "nmap-sn")]
    assert fake.calls[0]["hosts"].split() == [META]


def test_discovery_whole_scope_when_no_target(monkeypatch):
    fake = use_nmap(monkeypatch, FakeNmap({}))
    monkeypatch.setattr(discovery, "arp_sweep", lambda t: [])
    assert discovery.discover() == []
    scanned = fake.calls[0]["hosts"].split()
    assert META in scanned and "192.168.56.1" not in scanned


def test_discovery_merges_arp_and_nmap(monkeypatch):
    use_nmap(monkeypatch, FakeNmap({META: {"addresses": {"mac": "08:00:27:AA:BB:CC"}},
                                    "192.168.56.102": {"addresses": {}}}))
    monkeypatch.setattr(discovery, "arp_sweep",
                        lambda t: [discovery.LiveHost(ip=META, mac=None, method="arp")])
    hosts = {h.ip: h for h in discovery.discover([META, "192.168.56.102"])}
    assert hosts[META].method == "arp" and hosts[META].mac == "08:00:27:aa:bb:cc"
    assert hosts["192.168.56.102"].method == "nmap-sn"


def test_nat_mode_discovers_with_tcp_ping_and_no_arp(monkeypatch, set_env):
    set_env(NETWORK_MODE="nat")
    fake = use_nmap(monkeypatch, FakeNmap({META: {"addresses": {}}}))
    assert discovery.arp_sweep([META]) == []
    discovery.nmap_ping([META])
    args = fake.calls[0]["arguments"]
    assert "--unprivileged" in args and "-PS21,22,23" in args


def test_host_and_native_mode_use_plain_ping_scan(monkeypatch, set_env):
    for mode in ("host", "native"):
        set_env(NETWORK_MODE=mode)
        fake = use_nmap(monkeypatch, FakeNmap({}))
        discovery.nmap_ping([META])
        assert fake.calls[0]["arguments"] == "-sn -n --max-retries 1"


def test_discovery_survives_missing_nmap(monkeypatch):
    def boom():
        raise RuntimeError("nmap program was not found in path")
    monkeypatch.setattr(netmode, "nmap_scanner", boom)
    assert discovery.nmap_ping([META]) == []


# ---- port scan ---------------------------------------------------------------
META_SCAN = {
    "hostnames": [{"name": "metasploitable", "type": "PTR"}],
    "osmatch": [{"name": "Linux 2.6.9 - 2.6.33", "accuracy": "100"}],
    "tcp": {
        21: {"state": "open", "name": "ftp", "product": "vsftpd", "version": "2.3.4",
             "cpe": "cpe:/a:vsftpd:vsftpd:2.3.4", "extrainfo": ""},
        22: {"state": "open", "name": "ssh", "product": "OpenSSH", "version": "4.7p1",
             "cpe": "cpe:/a:openbsd:openssh:4.7p1", "extrainfo": "protocol 2.0"},
        25: {"state": "closed", "name": "smtp", "product": "", "version": "", "cpe": ""},
        80: {"state": "filtered", "name": "http", "product": "", "version": "", "cpe": ""},
    },
}


def test_port_scan_parses_open_services(monkeypatch):
    use_nmap(monkeypatch, FakeNmap({META: META_SCAN}))
    r = port_scan.scan_host(META, mac="08:00:27:aa:bb:cc")
    assert r.scan_ok is True
    assert [s.port for s in r.services] == [21, 22]            # closed/filtered left out
    assert r.services[0].cpe == "cpe:/a:vsftpd:vsftpd:2.3.4"
    assert r.services[1].banner == "protocol 2.0"
    assert (r.hostname, r.os_guess, r.os_accuracy) == ("metasploitable", "Linux 2.6.9 - 2.6.33", 100)


def test_port_scan_refuses_out_of_scope():
    with pytest.raises(ScopeError):
        port_scan.scan_host("10.10.10.10")


@pytest.mark.parametrize("mode,wanted,unwanted", [
    ("host", ["-sS", "-O"], ["-sT"]),
    ("native", ["-sS", "-O"], ["-sT"]),
    ("nat", ["-sT", "-Pn", "--unprivileged"], ["-sS", "-O"]),
])
def test_port_scan_flags_per_mode(monkeypatch, set_env, mode, wanted, unwanted):
    set_env(NETWORK_MODE=mode)
    fake = use_nmap(monkeypatch, FakeNmap({META: META_SCAN}))
    port_scan.scan_host(META)
    args = fake.calls[0]["arguments"].split()
    assert all(w in args for w in wanted) and not any(u in args for u in unwanted)
    assert "-sV" in args


def test_full_ports_flag(monkeypatch):
    fake = use_nmap(monkeypatch, FakeNmap({META: META_SCAN}))
    port_scan.scan_host(META, full_ports=True)
    assert "-p-" in fake.calls[0]["arguments"]
    port_scan.scan_host(META)
    assert port_scan.DEFAULT_PORTS in fake.calls[1]["arguments"]


def test_failed_scan_is_not_reported_as_no_open_ports(monkeypatch):
    """nmap error / timeout / host missing from the result = scan FAILED,
    which must be told apart from a host that really has no open ports."""
    use_nmap(monkeypatch, FakeNmap({META: META_SCAN}, raise_on_scan=RuntimeError("timeout")))
    assert port_scan.scan_host(META).scan_ok is False

    use_nmap(monkeypatch, FakeNmap({}))                         # host not in nmap's answer
    assert port_scan.scan_host(META).scan_ok is False

    def no_nmap():
        raise RuntimeError("nmap not found")
    monkeypatch.setattr(netmode, "nmap_scanner", no_nmap)
    assert port_scan.scan_host(META).scan_ok is False


def test_host_timeout_is_a_failed_scan(monkeypatch, audit_actions):
    """What happened on 13 Nov: nmap hit --host-timeout, listed the host as up
    with no ports, and 66 tickets were closed as 'fixed'."""
    xml = ('<nmaprun><host starttime="1" endtime="2" timedout="true"><status state="up"/>'
           f'<address addr="{META}" addrtype="ipv4"/></host></nmaprun>')
    use_nmap(monkeypatch, FakeNmap({META: {}}, raw_xml=xml))
    r = port_scan.scan_host(META)
    assert r.scan_ok is False and r.services == []
    assert "portscan.timeout" in audit_actions()


def test_timeout_of_another_host_does_not_matter(monkeypatch):
    xml = ('<nmaprun><host timedout="true"><address addr="192.168.56.200" addrtype="ipv4"/></host>'
           f'<host><address addr="{META}" addrtype="ipv4"/></host></nmaprun>')
    use_nmap(monkeypatch, FakeNmap({META: META_SCAN}, raw_xml=xml))
    assert port_scan.scan_host(META).scan_ok is True


def test_host_timeout_setting(monkeypatch, set_env):
    fake = use_nmap(monkeypatch, FakeNmap({META: META_SCAN}))
    port_scan.scan_host(META)
    assert "--host-timeout 300s" in fake.calls[0]["arguments"]
    set_env(SCAN_HOST_TIMEOUT="600")
    port_scan.scan_host(META)
    assert "--host-timeout 600s" in fake.calls[1]["arguments"]
    set_env(SCAN_HOST_TIMEOUT="abc")
    port_scan.scan_host(META)
    assert "--host-timeout 300s" in fake.calls[2]["arguments"]


def test_host_with_really_no_open_ports_is_ok(monkeypatch):
    use_nmap(monkeypatch, FakeNmap({META: {"tcp": {21: {"state": "closed", "name": "ftp"}}}}))
    r = port_scan.scan_host(META)
    assert r.scan_ok is True and r.services == []


def test_cpe_given_as_list(monkeypatch):
    scan = {"tcp": {80: {"state": "open", "name": "http", "product": "Apache httpd",
                         "version": "2.2.8", "cpe": ["cpe:/a:apache:http_server:2.2.8", "x"]}}}
    use_nmap(monkeypatch, FakeNmap({META: scan}))
    assert port_scan.scan_host(META).services[0].cpe == "cpe:/a:apache:http_server:2.2.8"


@pytest.mark.parametrize("svc,expected", [
    (ServiceInfo(port=445, product="Microsoft Windows netbios-ssn"), "Microsoft Windows (from service banners)"),
    (ServiceInfo(port=22, product="OpenSSH", version="8.9p1 Ubuntu 3"), "Linux - Ubuntu (from service banners)"),
    (ServiceInfo(port=21, product="vsftpd"), "Linux / Unix (from service banners)"),
    (ServiceInfo(port=9999, product=""), ""),
])
def test_os_guess_from_banners(svc, expected):
    assert port_scan._os_from_services([svc])[0] == expected


def test_banner_os_guess_used_when_nmap_has_none(monkeypatch, set_env):
    set_env(NETWORK_MODE="nat")
    scan = {"tcp": {22: {"state": "open", "name": "ssh", "product": "OpenSSH",
                         "version": "6.6.1p1 Ubuntu", "cpe": ""}}}
    use_nmap(monkeypatch, FakeNmap({META: scan}))
    assert port_scan.scan_host(META).os_guess.startswith("Linux - Ubuntu")


# ---- default credentials -----------------------------------------------------
class _AuthHandler(BaseHTTPRequestHandler):
    """Small web server with HTTP Basic auth, to test the HTTP check for real."""
    accept = ("admin", "admin")
    protected = True

    def do_GET(self):
        import base64
        if not self.protected:
            self.send_response(200); self.end_headers(); self.wfile.write(b"public page")
            return
        auth = self.headers.get("Authorization", "")
        want = "Basic " + base64.b64encode(":".join(self.accept).encode()).decode()
        if auth == want:
            self.send_response(200); self.end_headers(); self.wfile.write(b"welcome")
        else:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="router"')
            self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture
def web():
    servers = []

    def start(accept=("admin", "admin"), protected=True):
        handler = type("H", (_AuthHandler,), {"accept": accept, "protected": protected})
        srv = HTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return srv.server_address[1]

    yield start
    for s in servers:
        s.shutdown(); s.server_close()


def test_http_default_password_is_found(web):
    port = web(accept=("admin", "admin"))
    f = default_creds._check_http_basic("127.0.0.1", port)
    assert f and (f.service, f.username, f.password) == ("http", "admin", "admin")


def test_http_strong_password_is_not_flagged(web):
    port = web(accept=("admin", "S3cure!long-passphrase"))
    assert default_creds._check_http_basic("127.0.0.1", port) is None


def test_http_public_page_is_not_flagged(web):
    """A site that never asks for a password must not be reported."""
    port = web(protected=False)
    assert default_creds._check_http_basic("127.0.0.1", port) is None


def test_http_check_closed_port_is_quiet():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    assert default_creds._check_http_basic("127.0.0.1", port) is None


def test_check_host_runs_only_known_services(monkeypatch, audit_actions):
    calls = []
    monkeypatch.setitem(default_creds._CHECKERS, "ssh",
                        lambda ip, port: calls.append(("ssh", port)) or
                        default_creds.CredFinding(ip, port, "ssh", "msfadmin", "msfadmin"))
    monkeypatch.setitem(default_creds._CHECKERS, "ftp", lambda ip, port: calls.append(("ftp", port)))
    svcs = [ServiceInfo(port=22, service_name="ssh"), ServiceInfo(port=21, service_name="ftp"),
            ServiceInfo(port=3306, service_name="mysql")]
    found = default_creds.check_host(META, svcs)
    assert calls == [("ssh", 22), ("ftp", 21)]
    assert [(f.port, f.username) for f in found] == [(22, "msfadmin")]
    assert "defaultcred.found" in audit_actions()


def test_check_host_refuses_out_of_scope():
    with pytest.raises(ScopeError):
        default_creds.check_host("8.8.8.8", [])


def test_credential_list_is_small_and_documented():
    assert ("msfadmin", "msfadmin") in default_creds.DEFAULT_CREDS
    assert len(default_creds.DEFAULT_CREDS) <= 10          # hygiene check, not a brute-forcer


# ---- TLS certificate check ---------------------------------------------------
def _self_signed(tmp_path, days_valid=30, start_days_ago=1):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "lab.local")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=start_days_ago))
            .not_valid_after(now + datetime.timedelta(days=days_valid))
            .sign(key, hashes.SHA256()))
    c, k = tmp_path / "c.pem", tmp_path / "k.pem"
    c.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    k.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.TraditionalOpenSSL,
                                    serialization.NoEncryption()))
    return str(c), str(k)


@pytest.fixture
def tls_server(tmp_path):
    made = []

    def start(**kw):
        cert, key = _self_signed(tmp_path, **kw)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        sock = socket.socket(); sock.bind(("127.0.0.1", 0)); sock.listen(5)
        stop = threading.Event()

        def loop():
            sock.settimeout(0.2)
            while not stop.is_set():
                try:
                    conn, _ = sock.accept()
                except OSError:
                    continue
                try:
                    with ctx.wrap_socket(conn, server_side=True) as s:
                        s.recv(1)
                except Exception:
                    pass
        threading.Thread(target=loop, daemon=True).start()
        made.append((sock, stop))
        return sock.getsockname()[1]

    yield start
    for sock, stop in made:
        stop.set(); sock.close()


def test_tls_reads_self_signed_certificate(tls_server):
    port = tls_server(days_valid=30)
    info = tls_check.check_cert("127.0.0.1", port)
    assert info is not None
    assert info.is_self_signed is True and info.is_expired is False
    assert 28 <= info.days_to_expiry <= 30
    assert "lab.local" in info.subject and info.tls_version.startswith("TLS")
    assert info.weak_sig_alg == ""


def test_tls_flags_expired_certificate(tls_server):
    port = tls_server(days_valid=-2, start_days_ago=30)
    info = tls_check.check_cert("127.0.0.1", port)
    assert info.is_expired is True and info.days_to_expiry < 0


def test_tls_returns_none_for_plain_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    assert tls_check.check_cert("127.0.0.1", port) is None


def test_tls_check_host_picks_tls_like_services(monkeypatch):
    seen = []
    monkeypatch.setattr(tls_check, "check_cert", lambda ip, port: seen.append(port))
    svcs = [ServiceInfo(port=443, service_name="https"), ServiceInfo(port=22, service_name="ssh"),
            ServiceInfo(port=25, service_name="smtp"), ServiceInfo(port=5432, service_name="postgresql"),
            ServiceInfo(port=8443, service_name="ssl/http"), ServiceInfo(port=80, service_name="http")]
    tls_check.check_host(META, svcs)
    assert seen == [443, 25, 5432, 8443]


def test_tls_refuses_out_of_scope():
    with pytest.raises(ScopeError):
        tls_check.check_cert("8.8.8.8", 443)
