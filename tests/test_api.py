"""API gateway: every endpoint, through real HTTP requests (FastAPI TestClient)."""
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pyotp = pytest.importorskip("pyotp")

from fastapi.testclient import TestClient             # noqa: E402

from api import main                                   # noqa: E402
from scanner import engine, uplink                     # noqa: E402
from soar import remediation, ticketing, totp_2fa      # noqa: E402
from tests.conftest import META_IP, make_host          # noqa: E402


@pytest.fixture
def api():
    return TestClient(main.app)


@pytest.fixture
def admin(supa):
    secret = totp_2fa.new_secret()
    prof = supa.add("profiles", email="admin@lab.local", role="admin",
                    totp_secret=totp_2fa.seal_secret(secret), totp_enrolled=True)
    prof["code"] = lambda: pyotp.TOTP(secret).now()
    return prof


@pytest.fixture
def scanned(supa):
    from ml.risk_score import score_host
    h = score_host(make_host())
    uplink.push_scan({"scope": "lab", "summary": {}}, [h])
    ticketing.open_tickets_for_scan([h])
    return h


def ticket(supa, start="Clear-text"):
    return next(t for t in supa.rows("tickets") if t["title"].startswith(start))


# ---- health / scope ----------------------------------------------------------
def test_health_offline(api):
    r = api.get("/health").json()
    assert r["ok"] is True and r["cloud"] is False and r["authorized"] is True
    assert r["scope"] == ["192.168.56.0/24", "127.0.0.1/32"]
    assert r["model"]["engine"] == "formula" and r["model"]["trained"] is False
    assert r["intel"]["cves"] == 0 and r["push"]["configured"] is False


def test_health_reports_cloud(api, supa):
    assert api.get("/health").json()["cloud"] is True


def test_get_scope(api):
    r = api.get("/scope").json()
    assert r["allowed_ranges"] == ["192.168.56.0/24", "127.0.0.1/32"]
    assert r["editable"] is False and r["env_master_switch"] is True and r["max_prefix"] == 22


def test_set_scope_needs_dashboard_mode(api, admin):
    r = api.post("/scope", json={"admin_user_id": admin["id"], "totp_code": admin["code"](),
                                 "allowed_ranges": ["192.168.110.0/24"]})
    assert r.status_code == 400 and "SCOPE_SOURCE=env" in r.text


def test_set_scope_admin_2fa_and_validation(api, supa, admin, set_env, audit_actions):
    set_env(SCOPE_SOURCE="dashboard")
    body = {"admin_user_id": admin["id"], "totp_code": "000000",
            "allowed_ranges": ["192.168.110.0/24"], "deny_hosts": ["192.168.110.1"],
            "authorized": True, "authorization_note": "Own VirtualBox lab"}
    if admin["code"]() != "000000":
        assert api.post("/scope", json=body).status_code == 403            # wrong code
    body["totp_code"] = admin["code"]()
    assert api.post("/scope", json=dict(body, allowed_ranges=["8.8.8.0/24"])).status_code == 400
    r = api.post("/scope", json=body)
    assert r.status_code == 200 and r.json()["allowed_ranges"] == ["192.168.110.0/24"]
    assert {"scope.update", "scope.totp_fail"} & set(audit_actions())
    viewer = supa.add("profiles", email="v@lab", role="viewer")
    assert api.post("/scope", json=dict(body, admin_user_id=viewer["id"])).status_code == 403
    assert api.post("/scope", json=dict(body, admin_user_id="nobody")).status_code == 404


# ---- scan --------------------------------------------------------------------
def test_scan_endpoint_runs_engine(api, monkeypatch):
    seen = {}

    def fake(targets=None, full_ports=False):
        seen.update(targets=targets, full_ports=full_ports)
        return {"meta": {"host_count": 1}, "uplink": {"mode": "offline"}, "hosts": []}
    monkeypatch.setattr(engine, "run_scan", fake)
    r = api.post("/scan", json={"targets": [META_IP], "full_ports": True})
    assert r.status_code == 200 and r.json()["meta"]["host_count"] == 1
    assert seen == {"targets": [META_IP], "full_ports": True}


def test_scan_busy_gives_409_and_errors_give_400(api, monkeypatch):
    def busy(**k):
        raise engine.ScanBusy("A scan is already running.")
    monkeypatch.setattr(engine, "run_scan", busy)
    assert api.post("/scan", json={}).status_code == 409

    def refused(**k):
        raise RuntimeError("Refusing to run: AUTHORIZED_LAB_ONLY is not 'true'")
    monkeypatch.setattr(engine, "run_scan", refused)
    r = api.post("/scan", json={})
    assert r.status_code == 400 and "Refusing to run" in r.text


# ---- attack graph / what-if --------------------------------------------------
def test_attack_graph(api, scanned):
    r = api.get("/attack-graph").json()
    ids = [n["id"] for n in r["graph"]["nodes"]]
    assert ids == ["attacker", META_IP]
    assert r["paths"][0]["target"] == META_IP and r["paths"][0]["hops"] == 1


def test_attack_graph_empty_without_cloud(api):
    r = api.get("/attack-graph").json()
    assert len(r["graph"]["nodes"]) == 1 and r["paths"] == []


def test_whatif_single_and_many(api, scanned):
    r = api.post("/whatif", json={"target_ip": f" {META_IP} ",
                                  "fix": {"type": "block_port", "params": {"port": 21}}})
    assert r.status_code == 200
    host = r.json()["host"]
    assert host["before"]["vuln_count"] == 2 and host["after"]["vuln_count"] == 1
    assert host["risk_reduction"] > 0 and "network" in r.json()
    r = api.post("/whatif", json={"target_ip": META_IP, "fixes": [
        {"type": "block_port", "params": {"port": 21}},
        {"type": "patch_cve", "params": {"cve_id": "CVE-2008-0166"}}]})
    assert r.json()["host"]["after"]["vuln_count"] == 0


def test_whatif_errors(api, scanned):
    assert api.post("/whatif", json={"target_ip": META_IP}).status_code == 400
    r = api.post("/whatif", json={"target_ip": "192.168.56.200",
                                  "fix": {"type": "block_port", "params": {"port": 21}}})
    assert r.status_code == 404 and META_IP in r.text


def test_whatif_ignores_closed_ports_and_fixed_findings(api, supa, scanned):
    next(s for s in supa.rows("services") if s["port"] == 21)["state"] = "closed"
    r = api.post("/whatif", json={"target_ip": META_IP,
                                  "fix": {"type": "block_port", "params": {"port": 21}}})
    assert r.json()["host"]["unmatched"] == ["block_port 21"]
    assert r.json()["host"]["before"]["vuln_count"] == 1


# ---- remediation pipeline over HTTP ------------------------------------------
def test_full_remediation_flow(api, supa, scanned, admin, monkeypatch):
    ran = []
    monkeypatch.setattr(remediation, "run_remote",
                        lambda ip, cmds, check=True: ran.extend(cmds) or [(c, 0, "ok") for c in cmds])
    from soar import worker
    monkeypatch.setattr(worker, "verify_fix", lambda *a: True)
    t = ticket(supa)

    r = api.post("/remediation/request", json={
        "ticket_id": t["id"], "asset_ip": META_IP, "action_type": "stop_service",
        "params": {"service": "telnet", "port": 23}, "requested_by": admin["id"]})
    assert r.status_code == 200 and "DRY-RUN" in r.json()["preview"] and ran == []
    rid = r.json()["remediation"]["id"]

    bad = api.post("/remediation/approve", json={"remediation_id": rid,
                                                 "admin_user_id": admin["id"], "totp_code": "12"})
    assert bad.status_code == 403 and ran == []

    ok = api.post("/remediation/approve", json={"remediation_id": rid,
                                                "admin_user_id": admin["id"],
                                                "totp_code": admin["code"]()})
    assert ok.status_code == 200 and ok.json()["status"] == "approved"

    assert worker.run_once(supa) == 1 and len(ran) == 1
    assert ticket(supa)["status"] == "resolved"

    back = api.post("/remediation/rollback", json={"remediation_id": rid,
                                                   "admin_user_id": admin["id"],
                                                   "totp_code": admin["code"]()})
    assert back.status_code == 200 and back.json()["status"] == "rolled_back" and len(ran) == 2


def test_request_errors_are_400(api, supa, scanned):
    t = ticket(supa)
    for body in ({"asset_ip": "8.8.8.8", "action_type": "block_port", "params": {"port": 23}},
                 {"asset_ip": META_IP, "action_type": "block_port", "params": {"port": 22}},
                 {"asset_ip": META_IP, "action_type": "nope", "params": {}}):
        r = api.post("/remediation/request", json={"ticket_id": t["id"], "requested_by": "x", **body})
        assert r.status_code == 400
    assert api.post("/remediation/request", json={"asset_ip": META_IP}).status_code == 422


def test_reject_and_rollback_guards(api, supa, scanned, admin):
    t = ticket(supa)
    rid = api.post("/remediation/request", json={
        "ticket_id": t["id"], "asset_ip": META_IP, "action_type": "block_port",
        "params": {"port": 23}, "requested_by": "x"}).json()["remediation"]["id"]
    viewer = supa.add("profiles", email="v@lab", role="viewer")
    assert api.post("/remediation/reject", json={"remediation_id": rid,
                                                 "admin_user_id": viewer["id"]}).status_code == 403
    r = api.post("/remediation/rollback", json={"remediation_id": rid, "admin_user_id": admin["id"],
                                                "totp_code": admin["code"]()})
    assert r.status_code == 400                       # never executed -> nothing to undo
    assert api.post("/remediation/reject", json={"remediation_id": rid, "admin_user_id": admin["id"],
                                                 "reason": "no"}).status_code == 200
    assert ticket(supa)["status"] == "open"


# ---- 2FA enrolment -----------------------------------------------------------
def test_totp_enroll_first_time(api, supa):
    pytest.importorskip("qrcode")
    user = supa.add("profiles", email="new@lab.local", role="admin")
    r = api.post("/totp/enroll", json={"user_id": user["id"]})
    assert r.status_code == 200 and r.json()["qr"].startswith("data:image/png;base64,")
    assert "otpauth://totp/" in r.json()["otpauth_uri"]
    stored = supa.rows("profiles")[0]
    assert stored["totp_enrolled"] is True and "secret=" + stored["totp_secret"] not in r.json()["otpauth_uri"]
    secret = totp_2fa.open_secret(stored["totp_secret"])
    assert f"secret={secret}" in r.json()["otpauth_uri"]


def test_totp_cannot_be_replaced_without_current_code(api, supa, admin, audit_actions):
    pytest.importorskip("qrcode")
    before = supa.rows("profiles")[0]["totp_secret"]
    assert api.post("/totp/enroll", json={"user_id": admin["id"]}).status_code == 403
    assert api.post("/totp/enroll", json={"user_id": admin["id"],
                                          "current_code": "123"}).status_code == 403
    assert supa.rows("profiles")[0]["totp_secret"] == before
    assert "totp.reenroll_refused" in audit_actions()
    ok = api.post("/totp/enroll", json={"user_id": admin["id"], "current_code": admin["code"]()})
    assert ok.status_code == 200 and supa.rows("profiles")[0]["totp_secret"] != before


def test_totp_reset_cli(supa, admin, capsys):
    assert totp_2fa.main(["reset", "admin@lab.local"]) == 0
    p = supa.rows("profiles")[0]
    assert p["totp_secret"] is None and p["totp_enrolled"] is False
    assert totp_2fa.main(["reset", "nobody@lab.local"]) == 1
    assert totp_2fa.main([]) == 1


def test_unknown_profile_is_404_and_no_cloud_is_503(api, supa):
    assert api.post("/totp/enroll", json={"user_id": "nope"}).status_code == 404


def test_actions_need_cloud(api):
    r = api.post("/remediation/approve", json={"remediation_id": "x", "admin_user_id": "y",
                                               "totp_code": "123456"})
    assert r.status_code == 503


# ---- audit / report / target check -------------------------------------------
def test_audit_verify_includes_bundles(api, host):
    uplink.push_scan({"scope": "lab", "summary": {}}, [host])
    r = api.get("/audit/verify").json()
    assert r["ok"] is True and r["entries"] >= 1 and "intact" in r["message"]
    assert r["bundles"] == {"checked": 1, "ok": 1, "bad": []}


def test_audit_verify_detects_tampering(api, host):
    from pathlib import Path
    uplink.push_scan({"scope": "lab", "summary": {}}, [host])
    f = Path("audit/audit_chain.jsonl")
    f.write_text(f.read_text().replace("uplink.offline", "uplink.edited"))
    r = api.get("/audit/verify").json()
    assert r["ok"] is False and "Tampered" in r["message"]


def test_report_pdf_download(api, scanned):
    pytest.importorskip("reportlab")
    r = api.get("/report/latest.pdf")
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf"
    assert r.content[:5] == b"%PDF-"


def test_target_check(api, monkeypatch):
    from soar import enroll
    monkeypatch.setattr(enroll, "check_target",
                        lambda ip, os_guess=None: {"ip": ip, "ready": True, "checks": [], "hint": ""})
    assert api.get(f"/targets/{META_IP}/check").json()["ready"] is True

    def boom(ip, os_guess=None):
        raise RuntimeError("Target '8.8.8.8' is OUTSIDE the authorized allowlist.")
    monkeypatch.setattr(enroll, "check_target", boom)
    assert api.get("/targets/8.8.8.8/check").status_code == 400
