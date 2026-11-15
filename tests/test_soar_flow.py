"""Tickets + SLA, approval gates (admin + 2FA), the worker, verify and rollback."""
from datetime import datetime, timedelta, timezone

import pytest

pyotp = pytest.importorskip("pyotp")

from scanner import uplink                                   # noqa: E402
from soar import approval, remediation, ticketing, totp_2fa, worker   # noqa: E402
from soar.remediation import CommandFailed                   # noqa: E402
from tests.conftest import META_IP, make_host                # noqa: E402

META = {"scope": "192.168.56.0/24", "started_at": "t", "finished_at": "t", "summary": {}}


def scan(supa, host=None):
    from ml.risk_score import score_host
    h = score_host(host or make_host())
    uplink.push_scan(META, [h])
    return h


def by_title(supa, start):
    return [t for t in supa.rows("tickets") if t["title"].startswith(start)]


@pytest.fixture
def admin(supa):
    secret = totp_2fa.new_secret()
    prof = supa.add("profiles", email="admin@lab.local", role="admin",
                    totp_secret=totp_2fa.seal_secret(secret), totp_enrolled=True)
    prof["_secret"] = secret
    return prof


def code(profile):
    return pyotp.TOTP(profile["_secret"]).now()


@pytest.fixture
def ticket(supa):
    h = scan(supa)
    ticketing.open_tickets_for_scan([h])
    return by_title(supa, "Clear-text service telnet")[0]


# ---- TOTP --------------------------------------------------------------------
def test_totp_verify_and_sealed_secret():
    secret = totp_2fa.new_secret()
    assert totp_2fa.verify(secret, pyotp.TOTP(secret).now())
    assert not totp_2fa.verify(secret, "000000") or pyotp.TOTP(secret).now() == "000000"
    assert not totp_2fa.verify(secret, "") and not totp_2fa.verify("", "123456")
    sealed = totp_2fa.seal_secret(secret)
    assert secret not in sealed and totp_2fa.open_secret(sealed) == secret


def test_totp_old_code_is_rejected():
    secret = totp_2fa.new_secret()
    old = pyotp.TOTP(secret).at(datetime.now() - timedelta(minutes=5))
    assert not totp_2fa.verify(secret, old)


def test_totp_enrolment_uri_and_qr():
    uri = totp_2fa.provisioning_uri("JBSWY3DPEHPK3PXP", "admin@lab.local")
    assert uri.startswith("otpauth://totp/") and "issuer=Mini-SOAR-Test" in uri
    pytest.importorskip("qrcode")
    assert totp_2fa.qr_png_base64(uri).startswith("data:image/png;base64,")


# ---- tickets -----------------------------------------------------------------
def test_tickets_opened_for_priority_findings(supa):
    h = scan(supa)
    n = ticketing.open_tickets_for_scan([h])
    titles = sorted(t["title"] for t in supa.rows("tickets"))
    assert titles == [
        "CVE-2011-2523 on ftp:21 [KEV]",
        "Clear-text service telnet:23 (192.168.56.101)",
        "Default credential 'msfadmin' on ssh:22 (192.168.56.101)",
        "Exposed MySQL :3306 (192.168.56.101)",
    ]
    assert n == 4


def test_ticket_severity_sla_and_suggested_fix(supa):
    h = scan(supa)
    ticketing.open_tickets_for_scan([h])
    now = datetime.now(timezone.utc)

    def due_hours(t):
        return (datetime.fromisoformat(t["sla_due_at"]) - now).total_seconds() / 3600

    cve = by_title(supa, "CVE-2011-2523")[0]
    assert cve["severity"] == "critical" and 23.9 < due_hours(cve) <= 24
    assert cve["suggested_action"]["action_type"] == "block_port"
    assert cve["suggested_action"]["params"]["port"] == 21

    cred = by_title(supa, "Default credential")[0]
    assert cred["severity"] == "critical"
    assert cred["suggested_action"] == {"action_type": "disable_account",
                                        "params": {"username": "msfadmin", "os": "linux"},
                                        "reason": "account 'msfadmin' still uses a default password"}
    telnet = by_title(supa, "Clear-text")[0]
    assert telnet["severity"] == "high" and 71.9 < due_hours(telnet) <= 72
    assert telnet["suggested_action"]["action_type"] == "stop_service"


def test_no_duplicate_tickets_on_rescan(supa):
    for _ in range(3):
        ticketing.open_tickets_for_scan([scan(supa)])
    assert len(supa.rows("tickets")) == 4


def test_unconfirmed_version_does_not_open_a_ticket(supa):
    h = make_host()
    for v in h["vulnerabilities"]:
        v["confidence"] = "version-unconfirmed"
    ticketing.open_tickets_for_scan([scan(supa, h)])
    assert by_title(supa, "CVE-") == []


def test_low_risk_cve_gets_no_ticket_but_watchlisted_one_does(supa):
    h = make_host()
    h["vulnerabilities"] = [{"cve_id": "CVE-2020-1111", "cvss_score": 3.1, "severity": "low",
                             "epss_score": 0.001, "epss_percentile": 0.1, "in_kev": False,
                             "port": 3306, "confidence": "version-confirmed", "description": ""}]
    ticketing.open_tickets_for_scan([scan(supa, h)])
    assert by_title(supa, "CVE-2020-1111") == []
    h2 = make_host()
    h2["vulnerabilities"] = [dict(h["vulnerabilities"][0], cve_id="CVE-2020-2222", on_watchlist=True)]
    ticketing.open_tickets_for_scan([scan(supa, h2)])
    assert len(by_title(supa, "CVE-2020-2222")) == 1


def test_overdue_tickets_are_escalated_once(supa):
    ticketing.open_tickets_for_scan([scan(supa)])
    t = by_title(supa, "Clear-text")[0]
    t["sla_due_at"] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    assert ticketing.escalate_overdue() == 1
    t = by_title(supa, "Clear-text")[0]
    assert t["escalated"] is True and t["status"] == "escalated"
    assert [n["title"] for n in supa.rows("notifications")].count("SLA breached") == 1
    assert ticketing.escalate_overdue() == 0


def test_resolved_tickets_are_not_escalated(supa):
    ticketing.open_tickets_for_scan([scan(supa)])
    t = by_title(supa, "Clear-text")[0]
    t.update(status="resolved", sla_due_at=(datetime.now(timezone.utc) - timedelta(days=2)).isoformat())
    assert ticketing.escalate_overdue() == 0


def test_tickets_close_when_rescan_shows_the_fix(supa):
    ticketing.open_tickets_for_scan([scan(supa)])
    fixed = make_host()
    fixed["services"] = [s for s in fixed["services"] if s["port"] not in (21, 23)]
    fixed["vulnerabilities"] = [v for v in fixed["vulnerabilities"] if v["port"] != 21]
    fixed["default_creds"] = []
    h = scan(supa, fixed)
    closed = ticketing.resolve_fixed() + ticketing.resolve_by_rescan([h])
    status = {t["title"].split(" (")[0]: t["status"] for t in supa.rows("tickets")}
    assert closed == 3
    assert status == {"CVE-2011-2523 on ftp:21 [KEV]": "resolved",
                      "Clear-text service telnet:23": "resolved",
                      "Default credential 'msfadmin' on ssh:22": "resolved",
                      "Exposed MySQL :3306": "open"}


def test_failed_scan_closes_no_tickets(supa):
    """The 13-Nov bug, end to end: 0 open ports from a failed scan closes nothing."""
    ticketing.open_tickets_for_scan([scan(supa)])
    failed = {"ip": META_IP, "services": [], "tls": [], "default_creds": [],
              "vulnerabilities": [], "scan_ok": False}
    uplink.push_scan(META, [failed])
    closed = ticketing.resolve_fixed() + ticketing.resolve_by_rescan([failed])
    assert closed == 0
    assert all(t["status"] == "open" for t in supa.rows("tickets"))
    assert ticketing.open_tickets_for_scan([failed]) == 0


def test_partial_scan_only_judges_scanned_hosts(supa):
    ticketing.open_tickets_for_scan([scan(supa)])
    other = make_host(ip="192.168.56.102")
    other["services"] = []
    assert ticketing.resolve_by_rescan([other]) == 0


def test_ticketing_is_a_no_op_offline():
    assert ticketing.open_tickets_for_scan([make_host()]) == 0
    assert ticketing.resolve_fixed() == 0 and ticketing.escalate_overdue() == 0


# ---- request (dry-run) -------------------------------------------------------
def request_fix(ticket, action="stop_service", params=None):
    return approval.create_request(ticket["id"], META_IP, action,
                                   params or {"service": "telnet", "port": 23}, "analyst-1")


def test_request_creates_dry_run_without_touching_the_host(supa, ticket, monkeypatch):
    monkeypatch.setattr(remediation, "run_remote",
                        lambda *a, **k: pytest.fail("a request must not connect to the host"))
    out = request_fix(ticket)
    rem = supa.rows("remediations")[0]
    assert rem["status"] == "dry_run" and rem["totp_verified"] is False
    assert "DRY-RUN" in rem["dry_run_output"] and "telnet" in rem["command_preview"]
    assert rem["rollback_plan"]["cmds"] == out["rollback"]
    assert rem["action_params"]["target_ip"] == META_IP and rem["action_params"]["os"] == "linux"
    assert by_title(supa, "Clear-text")[0]["status"] == "awaiting_approval"


def test_request_for_unsafe_or_out_of_scope_target_is_refused(supa, ticket):
    with pytest.raises(remediation.RemediationError):
        request_fix(ticket, "block_port", {"port": 22})
    with pytest.raises(Exception):
        approval.create_request(ticket["id"], "8.8.8.8", "block_port", {"port": 23}, "a")
    assert supa.rows("remediations") == []


def test_windows_os_is_picked_from_the_asset(supa, ticket):
    supa.rows("assets")[0]["os_guess"] = "Microsoft Windows Server 2019"
    request_fix(ticket, "block_port", {"port": 3389})
    assert supa.rows("remediations")[0]["action_params"]["os"] == "windows"
    assert "New-NetFirewallRule" in supa.rows("remediations")[0]["command_preview"]


# ---- approval gates ----------------------------------------------------------
def test_admin_with_valid_code_approves(supa, ticket, admin, audit_actions):
    rid = request_fix(ticket)["remediation"]["id"]
    out = approval.approve_and_arm(rid, admin, code(admin))
    rem = supa.rows("remediations")[0]
    assert out["status"] == "approved"
    assert (rem["status"], rem["totp_verified"], rem["approved_by"]) == ("approved", True, admin["id"])
    assert by_title(supa, "Clear-text")[0]["status"] == "approved"
    assert "remediation.approve" in audit_actions()


@pytest.mark.parametrize("role", ["analyst", "viewer"])
def test_non_admin_cannot_approve(supa, ticket, admin, role):
    rid = request_fix(ticket)["remediation"]["id"]
    with pytest.raises(PermissionError, match="Only an admin"):
        approval.approve_and_arm(rid, dict(admin, role=role), code(admin))
    assert supa.rows("remediations")[0]["status"] == "dry_run"


def test_wrong_code_is_refused_and_audited(supa, ticket, admin, audit_actions):
    rid = request_fix(ticket)["remediation"]["id"]
    wrong = "000000" if code(admin) != "000000" else "111111"
    with pytest.raises(PermissionError, match="Invalid TOTP"):
        approval.approve_and_arm(rid, admin, wrong)
    assert supa.rows("remediations")[0]["status"] == "dry_run"
    assert "remediation.approve.totp_fail" in audit_actions()


def test_admin_without_2fa_cannot_approve(supa, ticket, admin):
    rid = request_fix(ticket)["remediation"]["id"]
    with pytest.raises(PermissionError, match="no TOTP enrolled"):
        approval.approve_and_arm(rid, dict(admin, totp_secret=None), "123456")


def test_only_a_dry_run_can_be_approved(supa, ticket, admin):
    rid = request_fix(ticket)["remediation"]["id"]
    for status in ("approved", "executing", "succeeded", "failed", "rolled_back"):
        supa.rows("remediations")[0]["status"] = status
        with pytest.raises(PermissionError, match="Only a dry-run"):
            approval.approve_and_arm(rid, admin, code(admin))
    with pytest.raises(PermissionError, match="not found"):
        approval.approve_and_arm("no-such-id", admin, code(admin))


def test_reject_sends_ticket_back_to_open(supa, ticket, admin):
    rid = request_fix(ticket)["remediation"]["id"]
    with pytest.raises(PermissionError):
        approval.reject(rid, dict(admin, role="analyst"), "no")
    approval.reject(rid, admin, "wrong host")
    rem = supa.rows("remediations")[0]
    assert rem["status"] == "failed" and rem["result_output"] == "Rejected: wrong host"
    assert by_title(supa, "Clear-text")[0]["status"] == "open"
    with pytest.raises(PermissionError, match="cannot reject"):
        approval.reject(rid, admin, "again")


# ---- worker ------------------------------------------------------------------
@pytest.fixture
def host_ssh(monkeypatch):
    """Fake the target: record commands, let tests choose failures."""
    state = {"ran": [], "fail_on": None, "verify": True}

    def run_remote(ip, cmds, check=True):
        out = []
        for c in cmds:
            state["ran"].append(c)
            if state["fail_on"] and state["fail_on"] in c:
                if check:
                    raise CommandFailed("command failed (rc=3): service not found")
                out.append((c, 3, "service not found"))
            else:
                out.append((c, 0, "ok"))
        return out

    monkeypatch.setattr(remediation, "run_remote", run_remote)
    monkeypatch.setattr(worker, "verify_fix", lambda ip, params, action: state["verify"])
    return state


def approved_fix(supa, ticket, admin, **kw):
    rid = request_fix(ticket, **kw)["remediation"]["id"]
    approval.approve_and_arm(rid, admin, code(admin))
    return rid


def test_worker_applies_verifies_and_resolves(supa, ticket, admin, host_ssh):
    approved_fix(supa, ticket, admin)
    assert worker.run_once(supa) == 1
    rem = supa.rows("remediations")[0]
    assert rem["status"] == "succeeded" and rem["verified_fixed"] is True and rem["executed_at"]
    assert "[rc=0] ok" in rem["result_output"]
    assert by_title(supa, "Clear-text")[0]["status"] == "resolved"
    assert "Remediation applied and verified" in [n["title"] for n in supa.rows("notifications")]
    assert len(host_ssh["ran"]) == 1 and "telnet" in host_ssh["ran"][0]
    assert worker.run_once(supa) == 0                              # never runs twice


def test_worker_ignores_everything_that_is_not_approved(supa, ticket, admin, host_ssh):
    request_fix(ticket)
    for status in ("dry_run", "planned", "failed", "succeeded", "rolled_back", "executing"):
        supa.rows("remediations")[0]["status"] = status
        assert worker.run_once(supa) == 0
    assert host_ssh["ran"] == []


def test_fix_that_does_not_verify_is_rolled_back(supa, ticket, admin, host_ssh):
    approved_fix(supa, ticket, admin)
    host_ssh["verify"] = False
    worker.run_once(supa)
    rem = supa.rows("remediations")[0]
    assert rem["status"] == "rolled_back" and rem["verified_fixed"] is False and rem["rolled_back_at"]
    assert "AUTO-ROLLBACK (verification failed)" in rem["result_output"]
    assert by_title(supa, "Clear-text")[0]["status"] == "in_progress"
    assert len(host_ssh["ran"]) == 2 and "#SOAR# telnet" in host_ssh["ran"][1]
    assert any("rolled back" in n["title"] for n in supa.rows("notifications"))


def test_failed_command_is_rolled_back(supa, ticket, admin, host_ssh):
    approved_fix(supa, ticket, admin)
    host_ssh["fail_on"] = "systemctl stop telnet"
    worker.run_once(supa)
    rem = supa.rows("remediations")[0]
    assert rem["status"] == "rolled_back" and "AUTO-ROLLBACK (apply failed" in rem["result_output"]
    assert "Remediation failed" in [n["title"] for n in supa.rows("notifications")]


def test_ssh_login_failure_changes_nothing_and_does_not_roll_back(supa, ticket, admin, monkeypatch):
    approved_fix(supa, ticket, admin)
    calls = []

    def no_ssh(ip, cmds, check=True):
        calls.append(cmds)
        raise remediation.RemediationError("SSH to host failed: timed out")
    monkeypatch.setattr(remediation, "run_remote", no_ssh)
    worker.run_once(supa)
    rem = supa.rows("remediations")[0]
    assert rem["status"] == "failed" and "SSH to host failed" in rem["result_output"]
    assert len(calls) == 1                                         # no rollback attempt


def test_refused_plan_fails_once(supa, ticket, admin, host_ssh):
    rid = approved_fix(supa, ticket, admin)
    supa.rows("remediations")[0]["action_params"]["service"] = "sshd"     # tampered after approval
    worker.run_once(supa)
    rem = supa.rows("remediations")[0]
    assert rem["id"] == rid and rem["status"] == "failed" and "plan refused" in rem["result_output"]
    assert worker.run_once(supa) == 0 and host_ssh["ran"] == []


def test_row_approved_without_totp_is_not_executed(supa, ticket, admin, host_ssh):
    """Someone flips the status in the database by hand: the 2FA flag still gates it."""
    request_fix(ticket)
    supa.rows("remediations")[0]["status"] = "approved"            # totp_verified stays False
    worker.run_once(supa)
    rem = supa.rows("remediations")[0]
    assert rem["status"] == "failed" and "TOTP" in rem["result_output"]
    assert host_ssh["ran"] == []


def test_kill_switch_stops_the_worker_from_changing_hosts(supa, ticket, admin, host_ssh, set_env):
    approved_fix(supa, ticket, admin)
    set_env(FORCE_DRY_RUN="true")
    worker.run_once(supa)
    rem = supa.rows("remediations")[0]
    assert "FORCE_DRY_RUN is on" in rem["result_output"] and host_ssh["ran"] == []
    assert rem["verified_fixed"] is None
    assert by_title(supa, "Clear-text")[0]["status"] != "resolved"


def test_row_without_target_fails_cleanly(supa, host_ssh):
    supa.add("remediations", status="approved", totp_verified=True, action_type="block_port",
             action_params={"port": 23}, ticket_id=None)
    assert worker.run_once(supa) == 0
    assert supa.rows("remediations")[0]["status"] == "failed"


# ---- manual rollback ---------------------------------------------------------
def test_admin_rollback_with_2fa(supa, ticket, admin, host_ssh, audit_actions):
    rid = approved_fix(supa, ticket, admin)
    worker.run_once(supa)
    with pytest.raises(PermissionError):
        approval.rollback_with_totp(rid, dict(admin, role="analyst"), code(admin))
    out = approval.rollback_with_totp(rid, admin, code(admin))
    assert out["status"] == "rolled_back"
    assert supa.rows("remediations")[0]["status"] == "rolled_back"
    assert by_title(supa, "Clear-text")[0]["status"] == "in_progress"
    assert "#SOAR# telnet" in host_ssh["ran"][-1]
    assert "remediation.rollback.manual" in audit_actions()


def test_only_an_executed_fix_can_be_rolled_back(supa, ticket, admin, host_ssh):
    rid = request_fix(ticket)["remediation"]["id"]
    with pytest.raises(RuntimeError, match="only an executed remediation"):
        approval.rollback_with_totp(rid, admin, code(admin))
    with pytest.raises(RuntimeError, match="not found"):
        approval.rollback_with_totp("nope", admin, code(admin))
