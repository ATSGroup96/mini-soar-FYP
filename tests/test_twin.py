"""Dependency-based digital twin (soar/twin_model.py, soar/twin_store.py, API).

Adapted from Jiang et al. (2024): components + dependency rules -> criticality
(CCS), component vulnerability score (CVS), CRS = CCS x CVS, virtual patching
and fix ranking; plus our additions (baseline comparison, prediction check).
"""
import time

import pytest

from ml.risk_score import score_host
from soar import twin_model as T
from soar import twin_store
from tests.conftest import META_IP, make_host

OTHER_IP = "192.168.56.102"


def vuln(cve, port, score, cvss=7.0, kev=False):
    """A finding that is already scored (ml_risk_score set by hand)."""
    return {"cve_id": cve, "port": port, "ml_risk_score": score, "cvss_score": cvss,
            "in_kev": kev, "epss_score": 0.0, "confidence": "version-confirmed"}


def plain_host(ip=META_IP, services=(), vulns=(), creds=(), os_guess="Linux"):
    return {"ip": ip, "os_guess": os_guess,
            "services": [{"port": p, "service_name": n} for p, n in services],
            "vulnerabilities": list(vulns),
            "default_creds": [{"port": p, "username": "u"} for p in creds]}


def comp(state, cid):
    return next(c for c in state["components"] if c["id"] == cid)


# ---- 1. components and dependency rules -----------------------------------------
def test_components_are_os_plus_each_open_service(host):
    score_host(host)
    comps = T.build_components(host)
    assert [c["id"] for c in comps] == [f"{META_IP}|os", f"{META_IP}|21", f"{META_IP}|22",
                                        f"{META_IP}|23", f"{META_IP}|3306"]
    by = {c["id"]: c for c in comps}
    assert by[f"{META_IP}|21"]["findings"][0]["kev"] is True
    assert by[f"{META_IP}|22"]["default_cred"] is True
    assert by[f"{META_IP}|os"]["findings"] == []          # every CVE here has a port
    assert all(c["criticality"] == "normal" for c in comps)


def test_cve_without_port_belongs_to_the_os():
    h = plain_host(services=[(80, "http")], vulns=[vuln("CVE-K", None, 70)])
    os_c = T.build_components(h)[0]
    assert os_c["kind"] == "os" and [f["cve_id"] for f in os_c["findings"]] == ["CVE-K"]


def test_automatic_rules_embedding_data_interaction():
    h = plain_host(services=[(80, "http"), (3306, "mysql"), (2049, "nfs"), (111, "rpcbind"),
                             (22, "ssh")])
    deps = {(d["from"], d["to"]): d["rule"] for d in T.auto_dependencies(T.build_components(h))}
    ip = META_IP
    for port in (80, 3306, 2049, 111, 22):                   # embedding: runs on the OS
        assert deps[(f"{ip}|{port}", f"{ip}|os")] == "embedding"
    assert deps[(f"{ip}|80", f"{ip}|3306")] == "data"         # web app keeps data in the DB
    assert deps[(f"{ip}|2049", f"{ip}|111")] == "interaction"  # NFS registers via rpcbind
    assert (f"{ip}|22", f"{ip}|3306") not in deps             # no invented links
    assert (f"{ip}|3306", f"{ip}|80") not in deps             # direction matters


def test_no_dependencies_across_hosts_unless_the_admin_adds_them():
    a = plain_host(META_IP, services=[(80, "http")])
    b = plain_host(OTHER_IP, services=[(3306, "mysql")])
    comps = T.build_components(a) + T.build_components(b)
    auto = T.auto_dependencies(comps)
    assert not any(d["from"].split("|")[0] != d["to"].split("|")[0] for d in auto)
    merged = T.merge_dependencies(auto, [{"from_component": f"{META_IP}|80",
                                          "to_component": f"{OTHER_IP}|3306",
                                          "rule": "network", "id": "m1"}])
    m = [d for d in merged if d["source"] == "manual"]
    assert m == [{"from": f"{META_IP}|80", "to": f"{OTHER_IP}|3306", "rule": "network",
                  "source": "manual", "id": "m1"}]


def test_manual_row_can_hide_an_automatic_dependency_and_bad_rows_are_ignored():
    h = plain_host(services=[(80, "http"), (3306, "mysql")])
    auto = T.auto_dependencies(T.build_components(h))
    merged = T.merge_dependencies(auto, [
        {"from_component": f"{META_IP}|80", "to_component": f"{META_IP}|3306", "enabled": False},
        {"from_component": f"{META_IP}|80", "to_component": f"{META_IP}|80"},          # self
        {"from_component": "", "to_component": f"{META_IP}|os"},                       # empty
        {"from_component": f"{META_IP}|3306", "to_component": f"{META_IP}|80", "rule": "odd"},
    ])
    keys = {(d["from"], d["to"]): d["rule"] for d in merged}
    assert (f"{META_IP}|80", f"{META_IP}|3306") not in keys
    assert keys[(f"{META_IP}|3306", f"{META_IP}|80")] == "network"     # unknown rule -> network
    assert len(merged) == len(auto) - 1 + 1


# ---- 2. the scores ------------------------------------------------------------------
def test_cvs_is_a_severity_weighted_average_of_finding_risks():
    c = {"findings": [{"score": 90.0}, {"score": 30.0}], "default_cred": False}
    assert T.cvs_improved(c) == pytest.approx((4 * 90 + 1 * 30) / 5)        # 78.0
    c["default_cred"] = True                                               # + 65 (weight 3)
    assert T.cvs_improved(c) == pytest.approx((4 * 90 + 30 + 3 * 65) / 8)
    assert T.cvs_improved({"findings": [], "default_cred": False}) == 0.0
    assert T.cvs_improved({"findings": [], "default_cred": True}) == 65.0


def test_baseline_cvs_is_the_papers_equation_3_with_cvss():
    c = {"findings": [{"cvss": 9.8}, {"cvss": 7.5}, {"cvss": 5.0}, {"cvss": 2.0}, {"cvss": 0.0}]}
    # sum_i w_i * Sum(S_i) / sum_i N_i, 'none' (0.0) not counted
    assert T.cvs_baseline(c) == pytest.approx((4 * 9.8 + 3 * 7.5 + 2 * 5.0 + 1 * 2.0) / 4)
    assert T.cvs_baseline({"findings": [{"cvss": 0.0}]}) == 0.0


def test_ccs_uses_dependents_floor_and_admin_weight():
    h = plain_host(services=[(80, "http"), (3306, "mysql"), (21, "ftp")],
                   vulns=[vuln("A", 21, 90), vuln("B", 3306, 90)])
    st = T.twin_state([h])
    os_c, db, ftp = comp(st, f"{META_IP}|os"), comp(st, f"{META_IP}|3306"), comp(st, f"{META_IP}|21")
    assert (os_c["dependents"], db["dependents"], ftp["dependents"]) == (3, 1, 0)
    assert os_c["ccs"] == pytest.approx(0.8 * 1.0)                      # most depended-on
    assert db["ccs"] == pytest.approx(0.8 * (0.5 + 0.5 * 1 / 3), abs=1e-3)
    assert ftp["ccs"] == pytest.approx(0.8 * 0.5)                       # floor: never zero
    crit = T.twin_state([h], {META_IP: "critical"})
    low = T.twin_state([h], {META_IP: "low"})
    assert comp(crit, f"{META_IP}|21")["ccs"] == 0.5 and comp(low, f"{META_IP}|21")["ccs"] == 0.25
    bogus = T.twin_state([h], {META_IP: "nonsense"})                     # unknown -> normal
    assert comp(bogus, f"{META_IP}|21")["ccs"] == pytest.approx(0.4)


def test_crs_is_ccs_times_cvs_and_host_risk_is_its_worst_component():
    h = plain_host(services=[(80, "http"), (3306, "mysql"), (21, "ftp")],
                   vulns=[vuln("A", 21, 90), vuln("B", 3306, 60)])
    st = T.twin_state([h])
    for c in st["components"]:
        assert c["crs"] == pytest.approx(c["ccs"] * c["cvs"], abs=0.02)
    worst = max(c["crs"] for c in st["components"])
    assert st["hosts"] == [{"ip": META_IP, "crs": round(worst, 2),
                            "grade": T.grade_from_score(worst)}]
    assert st["network_total"] == pytest.approx(sum(c["crs"] for c in st["components"]), abs=0.05)
    assert st["components"][0]["crs"] == worst                           # sorted, worst first


def test_baseline_ccs_is_the_raw_dependency_count():
    h = plain_host(services=[(80, "http"), (3306, "mysql")], vulns=[vuln("B", 3306, 60, cvss=9.8)])
    st = T.twin_state([h], mode="baseline")
    db = comp(st, f"{META_IP}|3306")
    assert db["relations"] == 2 and db["ccs"] == 2.0                    # on OS + used by web
    assert db["crs"] == pytest.approx(2.0 * 4 * 9.8, abs=0.02)
    assert st["hosts"][0]["grade"] is None                                # no A-F in the paper


def test_empty_network():
    st = T.twin_state([])
    assert st["components"] == [] and st["network_total"] == 0 and st["network_avg"] == 0.0
    assert T.rank_fixes([]) == []


# ---- 3. virtual patching and ranking -------------------------------------------------
def test_ranking_puts_the_backdoor_first_and_only_lists_real_gains(host):
    score_host(host)
    ranked = T.rank_fixes([host])
    assert ranked[0]["label"] == "Block port 21 (ftp)" and ranked[0]["executable"] is True
    assert ranked[0]["removes"]["kev"] == 1
    assert [r["rank"] for r in ranked] == list(range(1, len(ranked) + 1))
    assert all(r["drop"] > 0 for r in ranked)
    assert [r["drop"] for r in ranked] == sorted((r["drop"] for r in ranked), reverse=True)
    patch = next(r for r in ranked if r["fix"]["type"] == "patch_cve")
    assert patch["executable"] is False and "vendor" in patch["label"]
    # telnet has no finding and no default password -> nothing to gain, not listed
    assert not any(r["fix"]["params"].get("port") == 23 for r in ranked)


def test_protected_port_is_never_suggested_but_its_account_lock_is(host):
    score_host(host)
    ranked = T.rank_fixes([host])
    assert not any(r["fix"] == {"type": "block_port", "params": {"port": 22}} for r in ranked)
    assert any(r["fix"] == {"type": "disable_account", "params": {"port": 22}} for r in ranked)
    # and what the twin does suggest, the playbook accepts
    from soar import remediation
    for r in ranked:
        if r["executable"] and r["fix"]["type"] == "block_port":
            remediation.build_plan("block_port", META_IP, dict(r["fix"]["params"]))


def test_locking_a_default_account_is_rescored(host):
    score_host(host)
    lock = next(r for r in T.rank_fixes([host]) if r["fix"]["type"] == "disable_account")
    assert lock["removes"]["default_creds"] == 1
    # the CVE on :22 loses its 'default password works' boost after re-scoring
    assert lock["drop"] > 5


def test_criticality_changes_which_host_is_fixed_first():
    same = dict(services=[(21, "ftp")], vulns=[vuln("X", 21, 90)])
    a, b = plain_host(META_IP, **same), plain_host(OTHER_IP, **same)
    first = T.rank_fixes([a, b], {META_IP: "low", OTHER_IP: "critical"})[0]
    assert first["ip"] == OTHER_IP
    first = T.rank_fixes([a, b], {META_IP: "critical", OTHER_IP: "low"})[0]
    assert first["ip"] == META_IP


def test_dependencies_change_the_order():
    # the same finding on a database that a web app uses vs. on a lone FTP server
    h = plain_host(services=[(80, "http"), (3306, "mysql"), (21, "ftp")],
                   vulns=[vuln("DB", 3306, 70), vuln("FTP", 21, 70)])
    ranked = [r for r in T.rank_fixes([h]) if r["fix"]["type"] == "block_port"]
    assert ranked[0]["fix"]["params"]["port"] == 3306


def test_baseline_misses_a_default_password_without_cve_and_ours_does_not():
    h = plain_host(services=[(5900, "vnc"), (21, "ftp")], vulns=[vuln("LOW", 21, 20, cvss=3.0)],
                   creds=[5900])
    ours = T.rank_fixes([h])
    base = T.rank_fixes([h], mode="baseline")
    assert ours[0]["fix"]["params"]["port"] == 5900 and ours[0]["removes"]["default_creds"] == 1
    assert not any(r["fix"]["params"].get("port") == 5900 for r in base)  # CVSS-only: invisible
    cmp = T.compare(ours, base, k=3)
    assert cmp["ours"]["first_dangerous_rank"] == 1
    assert cmp["baseline"]["first_dangerous_rank"] is None
    assert cmp["ours"]["dangerous_in_top_k"] >= 1 and cmp["baseline"]["dangerous_in_top_k"] == 0


def test_given_candidate_list_is_used():
    h = plain_host(services=[(21, "ftp")], vulns=[vuln("X", 21, 90, cvss=9.8)])
    only = [c for c in T.candidate_fixes([h]) if c["fix"]["type"] == "patch_cve"]
    ranked = T.rank_fixes([h], candidates=only)
    assert [r["fix"]["type"] for r in ranked] == ["patch_cve"]


# ---- 4. prediction and its check -------------------------------------------------------
def test_prediction_lists_what_should_change(host):
    score_host(host)
    p = T.predict([host], META_IP, {"type": "block_port", "params": {"port": 21}})
    assert p["closed_ports"] == [21] and p["removed_cves"] == ["CVE-2011-2523"]
    assert p["cleared_default_creds"] == [] and p["host_crs_after"] < p["host_crs_before"]
    lock = T.predict([host], META_IP, {"type": "disable_account", "params": {"port": 22}})
    assert lock["closed_ports"] == [] and lock["cleared_default_creds"] == [22]
    with pytest.raises(KeyError):
        T.predict([host], "192.168.56.250", {"type": "block_port", "params": {"port": 21}})


def test_check_matches_when_the_scan_agrees(host):
    score_host(host)
    p = T.predict([host], META_IP, {"type": "block_port", "params": {"port": 21}})
    fresh = make_host()
    fresh["services"] = [s for s in fresh["services"] if s["port"] != 21]
    fresh["vulnerabilities"] = [v for v in fresh["vulnerabilities"] if v["port"] != 21]
    r = T.check_prediction(p, [score_host(fresh)])
    assert r["match"] is True and r["removal_correct"] is True and r["misses"] == []
    assert r["error"] <= T.TOLERANCE


def test_check_fails_when_the_port_is_still_open(host):
    score_host(host)
    p = T.predict([host], META_IP, {"type": "block_port", "params": {"port": 21}})
    r = T.check_prediction(p, [score_host(make_host())])
    assert r["match"] is False and "port 21 still open" in r["misses"]
    assert "CVE-2011-2523 still present" in r["misses"]


def test_check_fails_when_risk_is_far_from_the_prediction(host):
    score_host(host)
    p = dict(T.predict([host], META_IP, {"type": "block_port", "params": {"port": 23}}),
             host_crs_after=0.0)                         # an obviously wrong prediction
    p.pop("snapshot")                                    # (an old row: only the number)
    fresh = make_host()
    fresh["services"] = [s for s in fresh["services"] if s["port"] != 23]   # port really closed
    r = T.check_prediction(p, [score_host(fresh)])
    assert r["removal_correct"] is True and r["error"] > T.TOLERANCE and r["match"] is False


def test_two_fixes_between_scans_are_checked_together(host):
    score_host(host)
    p21 = dict(T.predict([host], META_IP, {"type": "block_port", "params": {"port": 21}}),
               made_at="2026-01-01T00:00:00")
    p22 = dict(T.predict([host], META_IP, {"type": "block_port", "params": {"port": 22}}),
               made_at="2026-01-01T00:05:00")
    fresh = make_host()
    fresh["services"] = [s for s in fresh["services"] if s["port"] not in (21, 22)]
    fresh["vulnerabilities"] = []
    fresh["default_creds"] = []
    r21, r22 = T.check_predictions([p21, p22], [score_host(fresh)])
    assert r21["match"] and r22["match"] and r21["checked_together"] == 2
    assert r21["error"] == r22["error"] <= 0.01
    # each alone would have expected more risk than the scan shows
    assert p21["host_crs_after"] > r21["actual_crs"] + T.TOLERANCE


def test_check_waits_when_host_missing_or_scan_failed(host):
    score_host(host)
    p = T.predict([host], META_IP, {"type": "block_port", "params": {"port": 21}})
    assert T.check_prediction(p, []) is None
    assert T.check_prediction(p, [dict(make_host(), scan_ok=False)]) is None


def test_accuracy_summary():
    assert T.accuracy([]) == {"checked": 0, "matched": 0, "accuracy_pct": None,
                              "mean_error": None, "tolerance": T.TOLERANCE}
    a = T.accuracy([{"match": True, "error": 1.0}, {"match": False, "error": 13.0}, None])
    assert (a["checked"], a["matched"], a["accuracy_pct"], a["mean_error"]) == (2, 1, 50.0, 7.0)


# ---- 5. data layer + API -----------------------------------------------------------------
fastapi = pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pyotp = pytest.importorskip("pyotp")
from fastapi.testclient import TestClient   # noqa: E402

from api import main                          # noqa: E402
from scanner import uplink                    # noqa: E402
from soar import ticketing, totp_2fa          # noqa: E402
from tests.test_engine_e2e import META_NMAP, lab  # noqa: E402,F401  (fixture)


@pytest.fixture
def api():
    return TestClient(main.app)


@pytest.fixture
def scanned(supa):
    h = score_host(make_host())
    uplink.push_scan({"scope": "lab", "summary": {}}, [h])
    ticketing.open_tickets_for_scan([h])
    return h


@pytest.fixture
def admin(supa):
    secret = totp_2fa.new_secret()
    prof = supa.add("profiles", email="admin@lab.local", role="admin",
                    totp_secret=totp_2fa.seal_secret(secret), totp_enrolled=True)
    prof["code"] = lambda: pyotp.TOTP(secret).now()
    return prof


def test_twin_endpoint(api, scanned):
    r = api.get("/twin")
    assert r.status_code == 200
    t = r.json()
    assert t["ready"] is True and "Jiang" in t["paper"]
    assert t["improved"]["hosts"][0]["ip"] == META_IP and t["improved"]["network_total"] > 0
    assert t["baseline"]["network_total"] > 0
    assert t["ranking"][0]["label"] == "Block port 21 (ftp)"
    assert t["baseline_ranking"] and t["comparison"]["k"] == 5
    assert t["accuracy"]["checked"] == 0 and t["recent_checks"] == []
    rules = {d["rule"] for d in t["improved"]["dependencies"]}
    assert "embedding" in rules
    assert t["parameters"]["ccs_floor"] == 0.5


def test_twin_endpoint_without_cloud(api):
    t = api.get("/twin").json()
    assert t["ready"] is False and t["ranking"] == [] and t["improved"]["components"] == []


def test_twin_works_before_migration_005(api, supa, scanned):
    supa.fail_tables.add("twin_dependencies")          # table does not exist yet
    t = api.get("/twin").json()
    assert t["ready"] is False and t["ranking"]        # still ranks with defaults


def test_whatif_returns_twin_numbers(api, scanned):
    r = api.post("/whatif", json={"target_ip": META_IP,
                                  "fix": {"type": "block_port", "port": 21}}).json()
    tw = r["twin"]
    assert tw["closed_ports"] == [21] and tw["host_crs_after"] < tw["host_crs_before"]
    assert tw["network_total_after"] < tw["network_total_before"]
    assert "host" in r and "network" in r                # old answer unchanged


def test_set_criticality(api, supa, scanned, admin, audit_actions):
    body = {"admin_user_id": admin["id"], "asset_ip": META_IP, "criticality": "Critical"}
    r = api.post("/twin/criticality", json=body)
    assert r.status_code == 200 and r.json() == {"ip": META_IP, "criticality": "critical"}
    assert supa.rows("assets")[0]["criticality"] == "critical"
    assert "twin.criticality" in audit_actions()
    t = api.get("/twin").json()
    assert all(c["criticality"] == "critical" for c in t["improved"]["components"])
    assert api.post("/twin/criticality", json=dict(body, criticality="vip")).status_code == 400
    assert api.post("/twin/criticality",
                    json=dict(body, asset_ip="192.168.56.250")).status_code == 404


def test_twin_changes_need_an_admin(api, supa, scanned):
    viewer = supa.add("profiles", email="v@lab", role="viewer")
    r = api.post("/twin/criticality", json={"admin_user_id": viewer["id"], "asset_ip": META_IP,
                                            "criticality": "low"})
    assert r.status_code == 403
    r = api.post("/twin/dependency", json={"admin_user_id": viewer["id"],
                                           "from_component": f"{META_IP}|21",
                                           "to_component": f"{META_IP}|3306"})
    assert r.status_code == 403
    assert api.post("/twin/criticality", json={"admin_user_id": "nobody", "asset_ip": META_IP,
                                               "criticality": "low"}).status_code == 404


def test_twin_changes_without_cloud_are_503(api):
    assert api.post("/twin/criticality", json={"admin_user_id": "a", "asset_ip": META_IP,
                                               "criticality": "low"}).status_code == 503


def test_add_hide_and_remove_dependencies(api, supa, scanned, admin, audit_actions):
    base = {"admin_user_id": admin["id"]}
    ok = api.post("/twin/dependency", json=dict(base, from_component=f"{META_IP}|21",
                                                to_component=f"{META_IP}|3306", rule="data",
                                                note="ftp uploads go to the DB"))
    assert ok.status_code == 200 and ok.json()["rule"] == "data"
    t = api.get("/twin").json()
    manual = [d for d in t["improved"]["dependencies"] if d["source"] == "manual"]
    assert manual and manual[0]["from"] == f"{META_IP}|21"
    # the same pair again updates it (no duplicates)
    api.post("/twin/dependency", json=dict(base, from_component=f"{META_IP}|21",
                                           to_component=f"{META_IP}|3306", rule="network"))
    assert len(supa.rows("twin_dependencies")) == 1
    assert supa.rows("twin_dependencies")[0]["rule"] == "network"
    # hide an automatic one
    api.post("/twin/dependency", json=dict(base, from_component=f"{META_IP}|21",
                                           to_component=f"{META_IP}|os", rule="embedding",
                                           enabled=False))
    t = api.get("/twin").json()
    assert not any(d["from"] == f"{META_IP}|21" and d["to"] == f"{META_IP}|os"
                   for d in t["improved"]["dependencies"])
    dep_id = supa.rows("twin_dependencies")[0]["id"]
    assert api.post("/twin/dependency/remove",
                    json=dict(base, id=dep_id)).json() == {"removed": 1}
    assert {"twin.dependency", "twin.dependency.remove"} <= set(audit_actions())


@pytest.mark.parametrize("frm,to,rule", [
    ("not-an-ip|21", f"{META_IP}|3306", "data"),
    (f"{META_IP}|99999", f"{META_IP}|3306", "data"),
    (f"{META_IP}|ftp", f"{META_IP}|3306", "data"),
    (f"{META_IP}|21", f"{META_IP}|21", "data"),
    (f"{META_IP}|21", f"{META_IP}|3306", "magic"),
])
def test_bad_dependency_is_400(api, supa, scanned, admin, frm, to, rule):
    r = api.post("/twin/dependency", json={"admin_user_id": admin["id"], "from_component": frm,
                                           "to_component": to, "rule": rule})
    assert r.status_code == 400


def test_dependency_before_migration_is_409(api, supa, scanned, admin):
    supa.fail_tables.add("twin_dependencies")
    r = api.post("/twin/dependency", json={"admin_user_id": admin["id"],
                                           "from_component": f"{META_IP}|21",
                                           "to_component": f"{META_IP}|3306"})
    assert r.status_code == 409 and "005_digital_twin.sql" in r.text


def _request_fix(api, supa, admin, action="block_port", params=None):
    t = next(t for t in supa.rows("tickets") if t["title"].startswith("Clear-text"))
    r = api.post("/remediation/request", json={
        "ticket_id": t["id"], "asset_ip": META_IP, "action_type": action,
        "params": params or {"port": 23}, "requested_by": admin["id"]})
    assert r.status_code == 200
    return r.json()["remediation"]["id"]


def test_fix_request_stores_the_twin_prediction(api, supa, scanned, admin):
    rid = _request_fix(api, supa, admin)
    row = next(r for r in supa.rows("remediations") if r["id"] == rid)
    pred = row["twin_prediction"]
    assert pred["ip"] == META_IP and pred["closed_ports"] == [23]
    assert pred["fix"] == {"type": "block_port", "params": {"port": 23}}
    assert "made_at" in pred


def test_fix_request_without_twin_columns_still_works(api, supa, scanned, admin, monkeypatch):
    from tests import fakes
    real = fakes._Query.execute

    def no_column(self):
        if self._table == "remediations" and self._op == "insert" and \
                "twin_prediction" in (self._payload or {}):
            raise RuntimeError("column twin_prediction does not exist")
        return real(self)
    monkeypatch.setattr(fakes._Query, "execute", no_column)
    rid = _request_fix(api, supa, admin)
    row = next(r for r in supa.rows("remediations") if r["id"] == rid)
    assert "twin_prediction" not in row and row["status"] == "dry_run"


def test_custom_action_gets_no_prediction(supa, scanned):
    assert twin_store.prediction_for(supa, META_IP, "custom", {}) is None
    assert twin_store.prediction_for(None, META_IP, "block_port", {"port": 21}) is None
    # an unknown host is logged, never raised
    assert twin_store.prediction_for(supa, "192.168.56.250", "block_port", {"port": 21}) is None


def test_next_scan_checks_verified_predictions(api, supa, scanned, admin):
    rid = _request_fix(api, supa, admin, params={"port": 23})
    supa.table("remediations").update({"status": "succeeded", "verified_fixed": True}) \
        .eq("id", rid).execute()
    fresh = make_host()
    fresh["services"] = [s for s in fresh["services"] if s["port"] != 23]
    assert twin_store.evaluate_pending([score_host(fresh)], supa) == 1
    res = next(r for r in supa.rows("remediations") if r["id"] == rid)["twin_result"]
    assert res["match"] is True and "checked_at" in res
    assert twin_store.evaluate_pending([score_host(fresh)], supa) == 0   # checked only once
    t = api.get("/twin").json()
    assert t["accuracy"]["checked"] == 1 and t["accuracy"]["accuracy_pct"] == 100.0
    assert t["recent_checks"][0]["remediation_id"] == rid


def test_wrong_prediction_counts_against_accuracy(api, supa, scanned, admin):
    rid = _request_fix(api, supa, admin, params={"port": 23})
    supa.table("remediations").update({"status": "succeeded", "verified_fixed": True}) \
        .eq("id", rid).execute()
    assert twin_store.evaluate_pending([score_host(make_host())], supa) == 1  # 23 still open
    res = next(r for r in supa.rows("remediations") if r["id"] == rid)["twin_result"]
    assert res["match"] is False and res["misses"] == ["port 23 still open"]
    assert api.get("/twin").json()["accuracy"]["accuracy_pct"] == 0.0


def test_unverified_or_unscanned_fixes_are_not_checked(supa, scanned, admin, api):
    rid = _request_fix(api, supa, admin, params={"port": 23})
    assert twin_store.evaluate_pending([score_host(make_host())], supa) == 0      # not run yet
    supa.table("remediations").update({"status": "succeeded", "verified_fixed": False}) \
        .eq("id", rid).execute()
    assert twin_store.evaluate_pending([score_host(make_host())], supa) == 0      # not verified
    supa.table("remediations").update({"verified_fixed": True}).eq("id", rid).execute()
    assert twin_store.evaluate_pending([], supa) == 0                              # host not scanned
    assert twin_store.evaluate_pending([], None) == 0


def test_scan_runs_the_twin_check_and_never_breaks_it(lab, supa, monkeypatch):
    from scanner import engine
    seen = {}

    def fake_eval(hosts, client=None):
        seen["hosts"] = [h["ip"] for h in hosts]
        return 3
    monkeypatch.setattr(twin_store, "evaluate_pending", fake_eval)
    r = engine.run_scan([META_IP])
    assert seen["hosts"] == [META_IP] and r["meta"]["summary"]["twin_checked"] == 3

    def boom(hosts, client=None):
        raise RuntimeError("twin down")
    monkeypatch.setattr(twin_store, "evaluate_pending", boom)
    r = engine.run_scan([META_IP])
    assert r["meta"]["summary"]["live_hosts"] == 1 and "twin_checked" not in r["meta"]["summary"]


def test_end_to_end_predict_fix_rescan_and_score_the_twin(lab, supa, monkeypatch):
    """The real chain: scan -> twin predicts each requested fix -> approve with
    2FA -> worker fixes + verifies -> re-scan -> twin checks itself."""
    from scanner import engine
    from soar import approval, remediation, worker

    engine.run_scan([META_IP])
    tickets = {t["title"].split(" (")[0]: t for t in supa.rows("tickets")}
    secret = totp_2fa.new_secret()
    adm = supa.add("profiles", email="admin@lab.local", role="admin",
                   totp_secret=totp_2fa.seal_secret(secret), totp_enrolled=True)
    monkeypatch.setattr(remediation, "run_remote",
                        lambda ip, cmds, check=True: [(c, 0, "ok") for c in cmds])
    monkeypatch.setattr(worker, "verify_fix", lambda ip, params, action: True)
    for title in ("Clear-text service telnet:23", "CVE-2011-2523 on ftp:21 [KEV]"):
        act = tickets[title]["suggested_action"]
        rid = approval.create_request(tickets[title]["id"], META_IP, act["action_type"],
                                      act["params"], adm["id"])["remediation"]["id"]
        approval.approve_and_arm(rid, adm, pyotp.TOTP(secret).now())
    preds = [r["twin_prediction"] for r in supa.rows("remediations")]
    assert sorted(p["closed_ports"][0] for p in preds) == [21, 23]
    assert worker.run_once(supa) == 2

    # ports 21 and 23 are really closed now -> the twin's predictions come true
    from tests.fakes import FakeNmap
    lab["nmap"] = FakeNmap({META_IP: dict(META_NMAP, tcp={22: META_NMAP["tcp"][22]})})
    r2 = engine.run_scan([META_IP])
    assert r2["meta"]["summary"]["twin_checked"] == 2
    results = [r["twin_result"] for r in supa.rows("remediations")]
    assert all(x["match"] for x in results), results
    acc = twin_store.overview(supa)["accuracy"]
    assert acc["checked"] == 2 and acc["accuracy_pct"] == 100.0


def test_large_host_ranks_quickly(supa):
    """Metasploitable-sized: 25 services and 500 CVEs must rank in a few seconds."""
    services = [(p, n) for p, n in zip(range(1000, 1025), ["svc"] * 25)]
    vulns = [vuln(f"CVE-2000-{i:04d}", 1000 + i % 25, 40 + i % 60, cvss=4 + (i % 60) / 10,
                  kev=i % 50 == 0) for i in range(500)]
    h = plain_host(services=services, vulns=vulns)
    t0 = time.time()
    cands = twin_store.bounded_candidates([h])
    ranked = T.rank_fixes([h], candidates=cands)
    base = T.rank_fixes([h], mode="baseline", candidates=cands)
    assert time.time() - t0 < 20
    assert sum(1 for c in cands if c["fix"]["type"] == "patch_cve") == twin_store.MAX_PATCH_CANDIDATES
    assert ranked and base and len(ranked) <= 15
