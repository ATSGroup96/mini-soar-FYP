"""API gateway: every endpoint, through real HTTP requests (FastAPI TestClient)."""
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pyotp = pytest.importorskip("pyotp")

from fastapi.testclient import TestClient             # noqa: E402

from api import main                                   # noqa: E402
from scanner import engine, uplink                     # noqa: E402
from soar import remediation, ticketing, totp_2fa      # noqa: E402
from tests.conftest import META_IP, make_host, make_user  # noqa: E402


@pytest.fixture
def api():
    return TestClient(main.app)


@pytest.fixture
def admin(supa):
    return make_user(supa, "admin")


@pytest.fixture
def analyst(supa):
    return make_user(supa, "analyst", totp=False)


@pytest.fixture
def viewer(supa):
    return make_user(supa, "viewer", totp=False)


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


def test_get_scope(api, viewer):
    r = api.get("/scope", headers=viewer["h"]).json()
    assert r["allowed_ranges"] == ["192.168.56.0/24", "127.0.0.1/32"]
    assert r["editable"] is False and r["env_master_switch"] is True and r["max_prefix"] == 22


def test_set_scope_needs_dashboard_mode(api, admin):
    r = api.post("/scope", headers=admin["h"], json={"totp_code": admin["code"](),
                                                     "allowed_ranges": ["192.168.110.0/24"]})
    assert r.status_code == 400 and "SCOPE_SOURCE=env" in r.text


def test_set_scope_admin_2fa_and_validation(api, supa, admin, set_env, audit_actions):
    set_env(SCOPE_SOURCE="dashboard")
    h = admin["h"]
    body = {"totp_code": "000000",
            "allowed_ranges": ["192.168.110.0/24"], "deny_hosts": ["192.168.110.1"],
            "authorized": True, "authorization_note": "Own VirtualBox lab"}
    if admin["code"]() != "000000":
        assert api.post("/scope", headers=h, json=body).status_code == 403   # wrong code
    body["totp_code"] = admin["code"]()
    assert api.post("/scope", headers=h, json=dict(body, allowed_ranges=["8.8.8.0/24"])).status_code == 400
    body["totp_code"] = admin["code"]()
    r = api.post("/scope", headers=h, json=body)
    assert r.status_code == 200 and r.json()["allowed_ranges"] == ["192.168.110.0/24"]
    assert {"scope.update", "scope.totp_fail"} & set(audit_actions())
    viewer = make_user(supa, "viewer", email="v@lab")
    assert api.post("/scope", headers=viewer["h"], json=body).status_code == 403
    assert api.post("/scope", headers={"Authorization": "Bearer t-nobody"},
                    json=body).status_code == 403                       # no profile
    assert api.post("/scope", json=body).status_code == 401              # not signed in


# ---- scan --------------------------------------------------------------------
def test_scan_endpoint_runs_engine(api, analyst, monkeypatch):
    seen = {}

    def fake(targets=None, full_ports=False):
        seen.update(targets=targets, full_ports=full_ports)
        return {"meta": {"host_count": 1}, "uplink": {"mode": "offline"}, "hosts": []}
    monkeypatch.setattr(engine, "run_scan", fake)
    r = api.post("/scan", headers=analyst["h"], json={"targets": [META_IP], "full_ports": True})
    assert r.status_code == 200 and r.json()["meta"]["host_count"] == 1
    assert seen == {"targets": [META_IP], "full_ports": True}


def test_scan_busy_gives_409_and_errors_give_400(api, analyst, monkeypatch):
    def busy(**k):
        raise engine.ScanBusy("A scan is already running.")
    monkeypatch.setattr(engine, "run_scan", busy)
    assert api.post("/scan", headers=analyst["h"], json={}).status_code == 409

    def refused(**k):
        raise RuntimeError("Refusing to run: AUTHORIZED_LAB_ONLY is not 'true'")
    monkeypatch.setattr(engine, "run_scan", refused)
    r = api.post("/scan", headers=analyst["h"], json={})
    assert r.status_code == 400 and "Refusing to run" in r.text


def test_scan_needs_analyst_role(api, viewer, monkeypatch):
    monkeypatch.setattr(engine, "run_scan", lambda **k: pytest.fail("must not scan"))
    assert api.post("/scan", json={}).status_code == 401
    assert api.post("/scan", headers=viewer["h"], json={}).status_code == 403


# ---- remediation pipeline over HTTP ------------------------------------------
def test_full_remediation_flow(api, supa, scanned, admin, analyst, monkeypatch):
    ran = []
    monkeypatch.setattr(remediation, "run_remote",
                        lambda ip, cmds, check=True: ran.extend(cmds) or [(c, 0, "ok") for c in cmds])
    from soar import worker
    monkeypatch.setattr(worker, "verify_fix", lambda *a: True)
    t = ticket(supa)

    r = api.post("/remediation/request", headers=analyst["h"], json={
        "ticket_id": t["id"], "asset_ip": META_IP, "action_type": "stop_service",
        "params": {"service": "telnet", "port": 23}})
    assert r.status_code == 200 and "DRY-RUN" in r.json()["preview"] and ran == []
    rid = r.json()["remediation"]["id"]
    assert r.json()["remediation"]["requested_by"] == analyst["id"]     # from the login

    # an analyst can ask for a fix but never approve it
    assert api.post("/remediation/approve", headers=analyst["h"],
                    json={"remediation_id": rid, "totp_code": admin["code"]()}).status_code == 403
    bad = api.post("/remediation/approve", headers=admin["h"],
                   json={"remediation_id": rid, "totp_code": "12"})
    assert bad.status_code == 403 and ran == []

    ok = api.post("/remediation/approve", headers=admin["h"],
                  json={"remediation_id": rid, "totp_code": admin["code"]()})
    assert ok.status_code == 200 and ok.json()["status"] == "approved"

    assert worker.run_once(supa) == 1 and len(ran) == 1
    assert ticket(supa)["status"] == "resolved"

    back = api.post("/remediation/rollback", headers=admin["h"],
                    json={"remediation_id": rid, "totp_code": admin["code"]()})
    assert back.status_code == 200 and back.json()["status"] == "rolled_back" and len(ran) == 2


def test_a_totp_code_works_only_once(api, supa, scanned, admin, audit_actions):
    t = ticket(supa)
    rids = [api.post("/remediation/request", headers=admin["h"], json={
        "ticket_id": t["id"], "asset_ip": META_IP, "action_type": "block_port",
        "params": {"port": p}}).json()["remediation"]["id"] for p in (23, 3306)]
    code = admin["code"]()
    assert api.post("/remediation/approve", headers=admin["h"],
                    json={"remediation_id": rids[0], "totp_code": code}).status_code == 200
    again = api.post("/remediation/approve", headers=admin["h"],
                     json={"remediation_id": rids[1], "totp_code": code})
    assert again.status_code == 403 and "already used" in again.text
    assert "totp.replay_refused" in audit_actions()


def test_viewer_cannot_request_a_fix(api, supa, scanned, viewer):
    t = ticket(supa)
    r = api.post("/remediation/request", headers=viewer["h"], json={
        "ticket_id": t["id"], "asset_ip": META_IP, "action_type": "block_port",
        "params": {"port": 23}})
    assert r.status_code == 403 and supa.rows("remediations") == []


def test_request_errors_are_400(api, supa, scanned, analyst):
    t = ticket(supa)
    for body in ({"asset_ip": "8.8.8.8", "action_type": "block_port", "params": {"port": 23}},
                 {"asset_ip": META_IP, "action_type": "block_port", "params": {"port": 22}},
                 {"asset_ip": META_IP, "action_type": "nope", "params": {}}):
        r = api.post("/remediation/request", headers=analyst["h"],
                     json={"ticket_id": t["id"], **body})
        assert r.status_code == 400
    assert api.post("/remediation/request", headers=analyst["h"],
                    json={"asset_ip": META_IP}).status_code == 422


def test_reject_and_rollback_guards(api, supa, scanned, admin, analyst):
    t = ticket(supa)
    rid = api.post("/remediation/request", headers=analyst["h"], json={
        "ticket_id": t["id"], "asset_ip": META_IP, "action_type": "block_port",
        "params": {"port": 23}}).json()["remediation"]["id"]
    assert api.post("/remediation/reject", headers=analyst["h"],
                    json={"remediation_id": rid}).status_code == 403
    assert api.post("/remediation/reject", json={"remediation_id": rid,
                                                 "admin_user_id": admin["id"]}).status_code == 401
    r = api.post("/remediation/rollback", headers=admin["h"],
                 json={"remediation_id": rid, "totp_code": admin["code"]()})
    assert r.status_code == 400                       # never executed -> nothing to undo
    assert api.post("/remediation/reject", headers=admin["h"],
                    json={"remediation_id": rid, "reason": "no"}).status_code == 200
    assert ticket(supa)["status"] == "open"


# ---- 2FA enrolment -----------------------------------------------------------
def test_totp_enroll_first_time(api, supa):
    pytest.importorskip("qrcode")
    user = make_user(supa, "admin", email="new@lab.local", totp=False)
    r = api.post("/totp/enroll", headers=user["h"], json={})
    assert r.status_code == 200 and r.json()["qr"].startswith("data:image/png;base64,")
    assert "otpauth://totp/" in r.json()["otpauth_uri"]
    stored = supa.rows("profiles")[0]
    assert stored["totp_enrolled"] is True and "secret=" + stored["totp_secret"] not in r.json()["otpauth_uri"]
    secret = totp_2fa.open_secret(stored["totp_secret"])
    assert f"secret={secret}" in r.json()["otpauth_uri"]


def test_totp_enroll_is_only_for_yourself(api, supa):
    """Before v14 anyone who knew a user id could enrol 2FA for that user."""
    victim = make_user(supa, "admin", email="victim@lab.local", totp=False)
    other = make_user(supa, "viewer", email="other@lab.local", totp=False)
    assert api.post("/totp/enroll", json={"user_id": victim["id"]}).status_code == 401
    api.post("/totp/enroll", headers=other["h"], json={"user_id": victim["id"]})
    rows = {r["email"]: r for r in supa.rows("profiles")}
    assert rows["victim@lab.local"]["totp_enrolled"] is False        # untouched
    assert rows["other@lab.local"]["totp_enrolled"] is True          # the caller's own


def test_totp_cannot_be_replaced_without_current_code(api, supa, admin, audit_actions):
    pytest.importorskip("qrcode")
    before = supa.rows("profiles")[0]["totp_secret"]
    assert api.post("/totp/enroll", headers=admin["h"], json={}).status_code == 403
    assert api.post("/totp/enroll", headers=admin["h"],
                    json={"current_code": "123"}).status_code == 403
    assert supa.rows("profiles")[0]["totp_secret"] == before
    assert "totp.reenroll_refused" in audit_actions()
    ok = api.post("/totp/enroll", headers=admin["h"], json={"current_code": admin["code"]()})
    assert ok.status_code == 200 and supa.rows("profiles")[0]["totp_secret"] != before


def test_totp_reset_cli(supa, admin, capsys):
    assert totp_2fa.main(["reset", "admin@lab.local"]) == 0
    p = supa.rows("profiles")[0]
    assert p["totp_secret"] is None and p["totp_enrolled"] is False
    assert totp_2fa.main(["reset", "nobody@lab.local"]) == 1
    assert totp_2fa.main([]) == 1


def test_matched_step_accepts_neighbours_only():
    secret = totp_2fa.new_secret()
    t = 1_800_000_000
    totp = pyotp.TOTP(secret)
    assert totp_2fa.matched_step(secret, totp.at(t), now=t) == t // 30
    assert totp_2fa.matched_step(secret, totp.at(t - 30), now=t) == t // 30 - 1
    assert totp_2fa.matched_step(secret, totp.at(t - 90), now=t) is None
    assert totp_2fa.matched_step(secret, "", now=t) is None


def test_actions_need_cloud(api):
    r = api.post("/remediation/approve", headers={"Authorization": "Bearer t-y"},
                 json={"remediation_id": "x", "totp_code": "123456"})
    assert r.status_code == 503


# ---- audit / report / target check -------------------------------------------
def test_audit_verify_includes_bundles(api, supa, viewer, host, monkeypatch):
    from common import db
    monkeypatch.setattr(uplink, "get_service_client", lambda: None)   # offline upload
    uplink.push_scan({"scope": "lab", "summary": {}}, [host])
    r = api.get("/audit/verify", headers=viewer["h"]).json()
    assert r["ok"] is True and r["entries"] >= 1 and "intact" in r["message"]
    assert r["bundles"] == {"checked": 1, "ok": 1, "bad": []}
    assert api.get("/audit/verify").status_code == 401


def test_audit_verify_detects_tampering(api, supa, viewer, host, monkeypatch):
    from pathlib import Path
    monkeypatch.setattr(uplink, "get_service_client", lambda: None)
    uplink.push_scan({"scope": "lab", "summary": {}}, [host])
    f = Path("audit/audit_chain.jsonl")
    f.write_text(f.read_text().replace("uplink.offline", "uplink.edited"))
    r = api.get("/audit/verify", headers=viewer["h"]).json()
    assert r["ok"] is False and "Tampered" in r["message"]


def test_report_pdf_download(api, scanned, viewer):
    pytest.importorskip("reportlab")
    assert api.get("/report/latest.pdf").status_code == 401
    r = api.get("/report/latest.pdf", headers=viewer["h"])
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf"
    assert r.content[:5] == b"%PDF-"


def test_target_check(api, supa, analyst, viewer, monkeypatch):
    from soar import enroll
    monkeypatch.setattr(enroll, "check_target",
                        lambda ip, os_guess=None: {"ip": ip, "ready": True, "checks": [], "hint": ""})
    assert api.get(f"/targets/{META_IP}/check", headers=analyst["h"]).json()["ready"] is True
    assert api.get(f"/targets/{META_IP}/check", headers=viewer["h"]).status_code == 403

    def boom(ip, os_guess=None):
        raise RuntimeError("Target '8.8.8.8' is OUTSIDE the authorized allowlist.")
    monkeypatch.setattr(enroll, "check_target", boom)
    assert api.get("/targets/8.8.8.8/check", headers=analyst["h"]).status_code == 400


def test_health_stays_public(api):
    assert api.get("/health").status_code == 200
