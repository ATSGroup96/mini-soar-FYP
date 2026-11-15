"""Whole flows, from 'scan' to 'ticket closed', with every real module in the
chain (only nmap, the target's SSH and Supabase are stand-ins)."""
import multiprocessing as mp

import pytest

from common import netmode
from common.config import AuthorizationError
from intel import db_init, sync_nvd
from scanner import cli, default_creds, engine, tls_check
from tests._children import hold_lock
from tests.conftest import META_IP
from tests.fakes import FakeNmap
from tests.test_intel import nvd_item

META_NMAP = {
    "addresses": {"mac": "08:00:27:AA:BB:CC"},
    "hostnames": [{"name": "metasploitable"}],
    "osmatch": [{"name": "Linux 2.6.9 - 2.6.33", "accuracy": "100"}],
    "tcp": {
        21: {"state": "open", "name": "ftp", "product": "vsftpd", "version": "2.3.4",
             "cpe": "cpe:/a:vsftpd:vsftpd:2.3.4"},
        22: {"state": "open", "name": "ssh", "product": "OpenSSH", "version": "4.7p1",
             "cpe": "cpe:/a:openbsd:openssh:4.7p1"},
        23: {"state": "open", "name": "telnet", "product": "Linux telnetd", "version": "", "cpe": ""},
    },
}
TIMEOUT_XML = (f'<nmaprun><host timedout="true"><address addr="{META_IP}" addrtype="ipv4"/>'
               '</host></nmaprun>')


@pytest.fixture
def lab(monkeypatch):
    """A fake lab: nmap answers for Metasploitable, msfadmin/msfadmin works on SSH."""
    state = {"nmap": FakeNmap({META_IP: dict(META_NMAP)})}
    monkeypatch.setattr(netmode, "nmap_scanner", lambda: state["nmap"])
    monkeypatch.setitem(default_creds._CHECKERS, "ssh",
                        lambda ip, port: default_creds.CredFinding(ip, port, "ssh", "msfadmin", "msfadmin"))
    monkeypatch.setitem(default_creds._CHECKERS, "ftp", lambda ip, port: None)
    monkeypatch.setattr(tls_check, "check_cert", lambda ip, port: None)
    db_init.init_db()
    from common.db import get_intel_db
    conn = get_intel_db()
    sync_nvd._store(conn, [
        nvd_item("CVE-2011-2523", 9.8, "cpe:2.3:a:vsftpd_project:vsftpd:2.3.4:*:*:*:*:*:*:*"),
        nvd_item("CVE-2008-0166", 7.5, "cpe:2.3:a:openbsd:openssh:4.7:p1:*:*:*:*:*:*")])
    conn.execute("insert into epss values('CVE-2011-2523', 0.94, 0.99)")
    conn.execute("insert into kev(cve_id,due_date) values('CVE-2011-2523','2022-05-03')")
    conn.commit(); conn.close()
    return state


def test_scan_offline_runs_the_whole_pipeline(lab, audit_actions):
    r = engine.run_scan([META_IP])
    h = r["hosts"][0]
    assert r["uplink"]["mode"] == "offline" and r["meta"]["summary"]["live_hosts"] == 1
    assert (h["mac"], h["hostname"], h["scan_ok"]) == ("08:00:27:aa:bb:cc", "metasploitable", True)
    assert [s["port"] for s in h["services"]] == [21, 22, 23]
    assert next(s for s in h["services"] if s["port"] == 22)["has_default_cred"] is True
    cves = {v["cve_id"]: v for v in h["vulnerabilities"]}
    assert set(cves) == {"CVE-2011-2523", "CVE-2008-0166"}
    assert cves["CVE-2011-2523"]["in_kev"] and cves["CVE-2011-2523"]["epss_score"] == 0.94
    assert cves["CVE-2011-2523"]["ml_risk_score"] > cves["CVE-2008-0166"]["ml_risk_score"]
    assert h["risk_grade"] in ("D", "F") and h["risk_score"] >= 60
    assert r["meta"]["summary"]["default_cred_hits"] == 1
    for action in ("scan.start", "discovery.finish", "portscan.finish", "defaultcred.found",
                   "uplink.offline", "scan.finish"):
        assert action in audit_actions()


def test_scan_refuses_without_authorization(lab, set_env):
    set_env(AUTHORIZED_LAB_ONLY="false")
    with pytest.raises(AuthorizationError):
        engine.run_scan([META_IP])
    assert lab["nmap"].calls == []                       # not one packet


def test_out_of_scope_target_is_never_scanned(lab):
    r = engine.run_scan(["8.8.8.8", "192.168.56.1"])
    assert r["hosts"] == []
    assert all("8.8.8.8" not in c["hosts"] for c in lab["nmap"].calls)


def test_second_scan_is_refused_while_one_runs(lab, tmp_path):
    ctx = mp.get_context("spawn")
    ready = ctx.Event()
    p = ctx.Process(target=hold_lock, args=(str(tmp_path / "data" / ".scan.lock"), 1.5, ready))
    p.start()
    try:
        assert ready.wait(20)
        with pytest.raises(engine.ScanBusy):
            engine.run_scan([META_IP])
    finally:
        p.join(20)
    assert engine.run_scan([META_IP])["hosts"]           # works again afterwards


def test_scan_to_fix_to_closed_ticket(lab, supa, monkeypatch):
    """The demo, start to end: scan -> tickets -> dry-run -> approve with 2FA ->
    worker fixes over SSH -> verified -> re-scan confirms -> tickets closed."""
    pyotp = pytest.importorskip("pyotp")
    from soar import approval, remediation, totp_2fa, worker

    r = engine.run_scan([META_IP])
    assert r["uplink"]["mode"] == "cloud" and r["meta"]["summary"]["tickets_opened"] == 3
    tickets = {t["title"].split(" (")[0]: t for t in supa.rows("tickets")}
    assert set(tickets) == {"CVE-2011-2523 on ftp:21 [KEV]", "Clear-text service telnet:23",
                            "Default credential 'msfadmin' on ssh:22"}
    assert supa.rows("assets")[0]["risk_grade"] in ("D", "F")

    secret = totp_2fa.new_secret()
    admin = supa.add("profiles", email="admin@lab.local", role="admin",
                     totp_secret=totp_2fa.seal_secret(secret), totp_enrolled=True)
    ran = []
    monkeypatch.setattr(remediation, "run_remote",
                        lambda ip, cmds, check=True: ran.extend(cmds) or [(c, 0, "ok") for c in cmds])
    monkeypatch.setattr(worker, "verify_fix", lambda ip, params, action: True)

    for title in ("Clear-text service telnet:23", "CVE-2011-2523 on ftp:21 [KEV]"):
        t = tickets[title]
        act = t["suggested_action"]
        rid = approval.create_request(t["id"], META_IP, act["action_type"], act["params"],
                                      admin["id"])["remediation"]["id"]
        approval.approve_and_arm(rid, admin, pyotp.TOTP(secret).now())
    assert worker.run_once(supa) == 2 and len(ran) == 2
    assert all(x["status"] == "succeeded" and x["verified_fixed"] for x in supa.rows("remediations"))

    # the lab now really has ports 21 and 23 closed -> the re-scan proves it
    after = dict(META_NMAP, tcp={22: META_NMAP["tcp"][22]})
    lab["nmap"] = FakeNmap({META_IP: after})
    r2 = engine.run_scan([META_IP])
    status = {t["title"].split(" (")[0]: t["status"] for t in supa.rows("tickets")}
    assert status["CVE-2011-2523 on ftp:21 [KEV]"] == "resolved"
    assert status["Clear-text service telnet:23"] == "resolved"
    assert status["Default credential 'msfadmin' on ssh:22"] == "open"      # not fixed yet
    vul = {v["cve_id"]: v["status"] for v in supa.rows("vulnerabilities")}
    assert vul == {"CVE-2011-2523": "remediated", "CVE-2008-0166": "open"}
    assert r2["uplink"]["changes"]["ports_closed"] == 2
    net = [x["risk_score"] for x in supa.rows("risk_history") if x["asset_id"] is None]
    assert len(net) == 2 and net[1] < net[0]                               # trend went down


def test_timed_out_scan_closes_nothing_end_to_end(lab, supa):
    """Replay of 13 Nov: second scan times out -> nothing is 'fixed'."""
    engine.run_scan([META_IP])
    opened = len(supa.rows("tickets"))
    lab["nmap"] = FakeNmap({META_IP: {"addresses": {"mac": "08:00:27:AA:BB:CC"}}}, raw_xml=TIMEOUT_XML)
    r = engine.run_scan([META_IP])
    s = r["meta"]["summary"]
    assert r["hosts"][0]["scan_ok"] is False
    assert (s["tickets_resolved"], s["tickets_opened"]) == (0, 0)
    assert len(supa.rows("tickets")) == opened
    assert all(t["status"] == "open" for t in supa.rows("tickets"))
    assert all(v["status"] == "open" for v in supa.rows("vulnerabilities"))
    assert all(x["state"] == "open" for x in supa.rows("services"))
    assert supa.rows("assets")[0]["risk_grade"] in ("D", "F")              # grade not reset to A
    assert s["failed_hosts"] == 1


def test_new_port_between_scans_is_reported(lab, supa):
    engine.run_scan([META_IP])
    more = dict(META_NMAP, tcp={**META_NMAP["tcp"], 1524: {
        "state": "open", "name": "bindshell", "product": "Metasploitable root shell",
        "version": "", "cpe": ""}})
    lab["nmap"] = FakeNmap({META_IP: more})
    r = engine.run_scan([META_IP])
    assert r["uplink"]["changes"]["ports_opened"] == 1
    assert any(t["title"].startswith("Exposed bind shell") for t in supa.rows("tickets"))
    assert "New open port" in [n["title"] for n in supa.rows("notifications")]


# ---- command line ------------------------------------------------------------
def test_cli_show_scope(capsys):
    assert cli.main(["show-scope"]) == 0
    out = capsys.readouterr().out
    assert "192.168.56.0/24" in out and "Authorization gate: PASS" in out


def test_cli_show_scope_fails_closed(capsys, set_env):
    set_env(AUTHORIZED_LAB_ONLY="false")
    assert cli.main(["show-scope"]) == 1
    assert "FAIL" in capsys.readouterr().out


def test_cli_scan_and_verify_commands(lab, capsys):
    assert cli.main(["scan", "--targets", META_IP]) == 0
    out = capsys.readouterr().out
    assert META_IP in out and "3 services" in out and "2 CVE" in out
    assert cli.main(["verify-audit"]) == 0
    assert cli.main(["verify-bundles"]) == 0
    assert "1 of 1 verified" in capsys.readouterr().out


def test_cli_discover(lab, capsys):
    assert cli.main(["discover"]) == 0
    assert META_IP in capsys.readouterr().out


def test_cli_scan_refused_without_authorization(lab, capsys, set_env):
    set_env(ALLOWED_RANGES="")
    assert cli.main(["scan"]) == 1
    assert "Refused" in capsys.readouterr().out
