"""Patch prioritization + Fix Impact Preview (soar/prioritization*.py, API).

Adapted from Jiang et al. (2024): components + dependency rules -> criticality
(CCS), component vulnerability score (CVS), CRS = CCS x CVS, virtual patching
and fix ranking; plus our additions (baseline comparison, prediction check).
"""
import time

import pytest

from ml.risk_score import score_host
from soar import prioritization as T
from soar import prioritization_store
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
    assert all(c["importance"] == "normal" for c in comps)


def test_cve_without_port_belongs_to_the_os():
    h = plain_host(services=[(80, "http")], vulns=[vuln("CVE-K", None, 70)])
    os_c = T.build_components(h)[0]
    assert os_c["kind"] == "os" and [f["id"] for f in os_c["findings"]] == ["CVE-K"]


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
    st = T.risk_state([h])
    os_c, db, ftp = comp(st, f"{META_IP}|os"), comp(st, f"{META_IP}|3306"), comp(st, f"{META_IP}|21")
    assert (os_c["dependents"], db["dependents"], ftp["dependents"]) == (3, 1, 0)
    assert os_c["ccs"] == pytest.approx(0.8 * 1.0)                      # most depended-on
    assert db["ccs"] == pytest.approx(0.8 * (0.5 + 0.5 * 1 / 3), abs=1e-3)
    assert ftp["ccs"] == pytest.approx(0.8 * 0.5)                       # floor: never zero
    crit = T.risk_state([h], {META_IP: "critical"})
    low = T.risk_state([h], {META_IP: "low"})
    assert comp(crit, f"{META_IP}|21")["ccs"] == 0.5 and comp(low, f"{META_IP}|21")["ccs"] == 0.25
    bogus = T.risk_state([h], {META_IP: "nonsense"})                     # unknown -> normal
    assert comp(bogus, f"{META_IP}|21")["ccs"] == pytest.approx(0.4)


def test_crs_is_ccs_times_cvs_and_host_risk_is_its_worst_component():
    h = plain_host(services=[(80, "http"), (3306, "mysql"), (21, "ftp")],
                   vulns=[vuln("A", 21, 90), vuln("B", 3306, 60)])
    st = T.risk_state([h])
    for c in st["components"]:
        assert c["crs"] == pytest.approx(c["ccs"] * c["cvs"], abs=0.02)
    worst = max(c["crs"] for c in st["components"])
    assert st["hosts"] == [{"ip": META_IP, "crs": round(worst, 2),
                            "grade": T.grade_from_score(worst)}]
    assert st["network_total"] == pytest.approx(sum(c["crs"] for c in st["components"]), abs=0.05)
    assert st["components"][0]["crs"] == worst                           # sorted, worst first


def test_baseline_ccs_is_the_raw_dependency_count():
    h = plain_host(services=[(80, "http"), (3306, "mysql")], vulns=[vuln("B", 3306, 60, cvss=9.8)])
    st = T.risk_state([h], mode="baseline")
    db = comp(st, f"{META_IP}|3306")
    assert db["relations"] == 2 and db["ccs"] == 2.0                    # on OS + used by web
    assert db["crs"] == pytest.approx(2.0 * 4 * 9.8, abs=0.02)
    assert st["hosts"][0]["grade"] is None                                # no A-F in the paper


def test_empty_network():
    st = T.risk_state([])
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


def test_importance_changes_which_host_is_fixed_first():
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
    assert p["closed_ports"] == [21] and p["removed_findings"] == ["CVE-2011-2523"]
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


# ---- 4b. Fix Impact Preview (replaces the old what-if) ----------------------------------
def test_preview_never_changes_the_real_data(host):
    score_host(host)
    before = repr(host)
    T.predict([host], META_IP, {"type": "block_port", "params": {"port": 21}})
    assert repr(host) == before


def test_stop_service_by_name_or_port_number(host):
    score_host(host)
    by_name = T.predict([host], META_IP, {"type": "stop_service", "params": {"service": "telnet"}})
    by_port = T.predict([host], META_IP, {"type": "stop_service", "params": {"service": "23"}})
    assert by_name["closed_ports"] == by_port["closed_ports"] == [23]


def test_lock_account_clears_the_default_password(host):
    score_host(host)
    p = T.predict([host], META_IP, {"type": "disable_account", "params": {"username": "msfadmin"}})
    assert p["cleared_default_creds"] == [22] and p["closed_ports"] == []
    assert p["counts_after"]["default_creds"] == 0 and p["counts_before"]["default_creds"] == 1


def test_several_fixes_together(host):
    score_host(host)
    p = T.predict([host], META_IP, [{"type": "block_port", "params": {"port": 21}},
                                    {"type": "patch_cve", "params": {"cve_id": "cve-2008-0166"}}])
    assert p["removed_findings"] == ["CVE-2008-0166", "CVE-2011-2523"]
    assert p["counts_after"]["findings"] == 0 and p["unmatched"] == []


def test_fix_that_matches_nothing_is_reported(host):
    score_host(host)
    p = T.predict([host], META_IP, {"type": "block_port", "params": {"port": 9999}})
    assert p["unmatched"] == ["block_port 9999"] and p["drop"] == 0
    assert "Nothing matched" in p["note"]


def test_minor_fix_explains_why_the_host_grade_stays(host):
    score_host(host)
    p = T.predict([host], META_IP, {"type": "patch_cve", "params": {"cve_id": "CVE-2008-0166"}})
    # port 22 keeps its worse problem (a working default password, 65): the
    # component's average goes UP when only the milder CVE is removed
    assert p["drop"] < 0 and "Risk goes UP" in p["note"]
    assert not any(r["fix"]["type"] == "patch_cve" and r["fix"]["params"]["cve_id"] == "CVE-2008-0166"
                   for r in T.rank_fixes([host]))
    p = T.predict([host], META_IP, {"type": "patch_cve", "params": {"cve_id": "CVE-2011-2523"}})
    assert p["drop"] > 0 and p["note"] == ""


def test_preview_drop_equals_the_ranked_drop(host):
    score_host(host)
    for r in T.rank_fixes([host]):
        p = T.predict([host], r["ip"], r["fix"])
        assert p["drop"] == r["drop"]
        assert (p["host_crs_before"], p["host_crs_after"]) == (r["host_crs_before"], r["host_crs_after"])


# ---- 4c. automatic network rule + topology ------------------------------------------------
def test_directory_server_is_needed_by_the_other_hosts():
    dc = plain_host("192.168.56.10", services=[(53, "domain"), (88, "kerberos-sec"),
                                               (389, "ldap")], os_guess="Windows Server")
    pc = plain_host("192.168.56.20", services=[(3389, "ms-wbt-server")], os_guess="Windows 10")
    far = plain_host("10.0.0.5", services=[(22, "ssh")])
    deps = T.auto_dependencies(T.build_components(dc) + T.build_components(pc)
                               + T.build_components(far))
    net = [(d["from"], d["to"]) for d in deps if d["rule"] == "network"]
    assert net == [("192.168.56.20|os", "192.168.56.10|389")]     # other subnet: no edge
    st = T.risk_state([dc, pc, far])
    assert comp(st, "192.168.56.10|389")["dependents"] == 1


def test_no_directory_server_means_no_network_edges(host):
    assert not [d for d in T.auto_dependencies(T.build_components(host)) if d["rule"] == "network"]


def test_topology_graph(host):
    score_host(host)
    g = T.topology(T.risk_state([host]), [host])
    kinds = {n["type"] for n in g["nodes"]}
    assert kinds == {"host", "os", "service"}
    assert all(e["kind"] != "embedding" for e in g["edges"])
    host_node = next(n for n in g["nodes"] if n["type"] == "host")
    assert host_node["ip"] == META_IP and host_node["risk"] > 0


# ---- 5. data layer + API -----------------------------------------------------------------
fastapi = pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pyotp = pytest.importorskip("pyotp")
from fastapi.testclient import TestClient   # noqa: E402

from api import main                          # noqa: E402
from scanner import uplink                    # noqa: E402
from soar import ticketing                    # noqa: E402
from tests.conftest import make_user          # noqa: E402
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
    return make_user(supa, "admin")


@pytest.fixture
def viewer(supa):
    return make_user(supa, "viewer", totp=False)


def test_prioritization_endpoint(api, scanned, viewer):
    r = api.get("/prioritization", headers=viewer["h"])
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


def test_prioritization_needs_a_login(api, scanned):
    assert api.get("/prioritization").status_code == 401
    assert api.get("/prioritization", headers={"Authorization": "Bearer forged"}).status_code == 401


def test_prioritization_without_cloud_is_503(api):
    assert api.get("/prioritization", headers={"Authorization": "Bearer t-x"}).status_code == 503


def test_prioritization_works_before_migration_006(api, supa, scanned, viewer):
    supa.fail_tables.add("component_dependencies")          # table does not exist yet
    t = api.get("/prioritization", headers=viewer["h"]).json()
    assert t["ready"] is False and t["ranking"]              # still ranks with defaults


def test_fix_preview_matches_the_ranking(api, scanned, viewer):
    t = api.get("/prioritization", headers=viewer["h"]).json()
    top = t["ranking"][0]
    p = api.post("/fix-preview", headers=viewer["h"],
                 json={"target_ip": f" {META_IP} ", "fix": top["fix"]}).json()
    assert p["closed_ports"] == [21] and p["host_crs_after"] < p["host_crs_before"]
    # the preview of one fix shows the same numbers as the ranked list
    assert p["drop"] == top["drop"]
    assert (p["host_crs_before"], p["host_crs_after"]) == (top["host_crs_before"], top["host_crs_after"])
    assert "snapshot" not in p


def test_fix_preview_errors(api, scanned, viewer):
    assert api.post("/fix-preview", headers=viewer["h"],
                    json={"target_ip": META_IP}).status_code == 400
    r = api.post("/fix-preview", headers=viewer["h"],
                 json={"target_ip": "192.168.56.200", "fix": {"type": "block_port", "port": 21}})
    assert r.status_code == 404 and META_IP in r.text


def test_fix_preview_ignores_closed_ports(api, supa, scanned, viewer):
    next(s for s in supa.rows("services") if s["port"] == 21)["state"] = "closed"
    p = api.post("/fix-preview", headers=viewer["h"],
                 json={"target_ip": META_IP, "fix": {"type": "block_port", "params": {"port": 21}}}).json()
    assert p["unmatched"] == ["block_port 21"] and "Nothing matched" in p["note"]


def test_topology_endpoint(api, scanned, viewer):
    g = api.get("/topology", headers=viewer["h"]).json()
    ids = {n["id"] for n in g["nodes"]}
    assert f"host:{META_IP}" in ids and f"{META_IP}|21" in ids and f"{META_IP}|os" in ids
    assert {"source": f"host:{META_IP}", "target": f"{META_IP}|21", "kind": "has"} in g["edges"]


def test_set_importance(api, supa, scanned, admin, audit_actions):
    body = {"asset_ip": META_IP, "importance": "Critical"}
    r = api.post("/prioritization/importance", headers=admin["h"], json=body)
    assert r.status_code == 200 and r.json() == {"ip": META_IP, "importance": "critical"}
    assert supa.rows("assets")[0]["importance"] == "critical"
    assert "prioritization.importance" in audit_actions()
    t = api.get("/prioritization", headers=admin["h"]).json()
    assert all(c["importance"] == "critical" for c in t["improved"]["components"])
    assert api.post("/prioritization/importance", headers=admin["h"],
                    json=dict(body, importance="vip")).status_code == 400
    assert api.post("/prioritization/importance", headers=admin["h"],
                    json=dict(body, asset_ip="192.168.56.250")).status_code == 404


def test_prioritization_changes_need_an_admin(api, supa, scanned, viewer):
    r = api.post("/prioritization/importance", headers=viewer["h"],
                 json={"asset_ip": META_IP, "importance": "low"})
    assert r.status_code == 403
    r = api.post("/prioritization/dependency", headers=viewer["h"],
                 json={"from_component": f"{META_IP}|21", "to_component": f"{META_IP}|3306"})
    assert r.status_code == 403
    # a user id written in the body is ignored: only the login counts
    assert api.post("/prioritization/importance", json={
        "admin_user_id": "someone", "asset_ip": META_IP, "importance": "low"}).status_code == 401


def test_add_hide_and_remove_dependencies(api, supa, scanned, admin, audit_actions):
    h = admin["h"]
    ok = api.post("/prioritization/dependency", headers=h, json={
        "from_component": f"{META_IP}|21", "to_component": f"{META_IP}|3306", "rule": "data",
        "note": "ftp uploads go to the DB"})
    assert ok.status_code == 200 and ok.json()["rule"] == "data"
    t = api.get("/prioritization", headers=h).json()
    manual = [d for d in t["improved"]["dependencies"] if d["source"] == "manual"]
    assert manual and manual[0]["from"] == f"{META_IP}|21"
    # the same pair again updates it (no duplicates)
    api.post("/prioritization/dependency", headers=h, json={
        "from_component": f"{META_IP}|21", "to_component": f"{META_IP}|3306", "rule": "network"})
    assert len(supa.rows("component_dependencies")) == 1
    assert supa.rows("component_dependencies")[0]["rule"] == "network"
    # hide an automatic one
    api.post("/prioritization/dependency", headers=h, json={
        "from_component": f"{META_IP}|21", "to_component": f"{META_IP}|os", "rule": "embedding",
        "enabled": False})
    t = api.get("/prioritization", headers=h).json()
    assert not any(d["from"] == f"{META_IP}|21" and d["to"] == f"{META_IP}|os"
                   for d in t["improved"]["dependencies"])
    dep_id = supa.rows("component_dependencies")[0]["id"]
    assert api.post("/prioritization/dependency/remove", headers=h,
                    json={"id": dep_id}).json() == {"removed": 1}
    assert {"prioritization.dependency", "prioritization.dependency.remove"} <= set(audit_actions())


@pytest.mark.parametrize("frm,to,rule", [
    ("not-an-ip|21", f"{META_IP}|3306", "data"),
    (f"{META_IP}|99999", f"{META_IP}|3306", "data"),
    (f"{META_IP}|ftp", f"{META_IP}|3306", "data"),
    (f"{META_IP}|21", f"{META_IP}|21", "data"),
    (f"{META_IP}|21", f"{META_IP}|3306", "magic"),
])
def test_bad_dependency_is_400(api, supa, scanned, admin, frm, to, rule):
    r = api.post("/prioritization/dependency", headers=admin["h"],
                 json={"from_component": frm, "to_component": to, "rule": rule})
    assert r.status_code == 400


def test_dependency_before_migration_is_409(api, supa, scanned, admin):
    supa.fail_tables.add("component_dependencies")
    r = api.post("/prioritization/dependency", headers=admin["h"],
                 json={"from_component": f"{META_IP}|21", "to_component": f"{META_IP}|3306"})
    assert r.status_code == 409 and "006_proposal_alignment.sql" in r.text


def _request_fix(api, supa, user, action="block_port", params=None):
    t = next(t for t in supa.rows("tickets") if t["title"].startswith("Clear-text"))
    r = api.post("/remediation/request", headers=user["h"], json={
        "ticket_id": t["id"], "asset_ip": META_IP, "action_type": action,
        "params": params or {"port": 23}})
    assert r.status_code == 200, r.text
    return r.json()["remediation"]["id"]


def test_fix_request_stores_the_preview_for_the_approver(api, supa, scanned, admin):
    rid = _request_fix(api, supa, admin)
    row = next(r for r in supa.rows("remediations") if r["id"] == rid)
    pred = row["fix_prediction"]
    assert pred["ip"] == META_IP and pred["closed_ports"] == [23]
    assert pred["fix"] == {"type": "block_port", "params": {"port": 23}}
    assert "made_at" in pred and row["requested_by"] == admin["id"]


def test_approval_stores_a_fresh_preview(api, supa, scanned, admin):
    rid = _request_fix(api, supa, admin)
    first = next(r for r in supa.rows("remediations") if r["id"] == rid)["fix_prediction"]
    time.sleep(0.01)
    r = api.post("/remediation/approve", headers=admin["h"],
                 json={"remediation_id": rid, "totp_code": admin["code"]()})
    assert r.status_code == 200
    kept = next(x for x in supa.rows("remediations") if x["id"] == rid)["fix_prediction"]
    assert kept["made_at"] > first["made_at"] and kept["closed_ports"] == [23]


def test_fix_request_without_the_new_columns_still_works(api, supa, scanned, admin, monkeypatch):
    from tests import fakes
    real = fakes._Query.execute

    def no_column(self):
        if self._table == "remediations" and self._op in ("insert", "update") and \
                "fix_prediction" in (self._payload or {}):
            raise RuntimeError("column fix_prediction does not exist")
        return real(self)
    monkeypatch.setattr(fakes._Query, "execute", no_column)
    rid = _request_fix(api, supa, admin)
    row = next(r for r in supa.rows("remediations") if r["id"] == rid)
    assert "fix_prediction" not in row and row["status"] == "dry_run"
    r = api.post("/remediation/approve", headers=admin["h"],
                 json={"remediation_id": rid, "totp_code": admin["code"]()})
    assert r.status_code == 200 and r.json()["status"] == "approved"


def test_custom_action_gets_no_prediction(supa, scanned):
    assert prioritization_store.prediction_for(supa, META_IP, "custom", {}) is None
    assert prioritization_store.prediction_for(None, META_IP, "block_port", {"port": 21}) is None
    # an unknown host is logged, never raised
    assert prioritization_store.prediction_for(supa, "192.168.56.250", "block_port",
                                               {"port": 21}) is None


def test_next_scan_checks_verified_predictions(api, supa, scanned, admin):
    rid = _request_fix(api, supa, admin, params={"port": 23})
    supa.table("remediations").update({"status": "succeeded", "verified_fixed": True}) \
        .eq("id", rid).execute()
    fresh = make_host()
    fresh["services"] = [s for s in fresh["services"] if s["port"] != 23]
    assert prioritization_store.evaluate_pending([score_host(fresh)], supa) == 1
    res = next(r for r in supa.rows("remediations") if r["id"] == rid)["fix_check"]
    assert res["match"] is True and "checked_at" in res
    assert prioritization_store.evaluate_pending([score_host(fresh)], supa) == 0   # only once
    t = api.get("/prioritization", headers=admin["h"]).json()
    assert t["accuracy"]["checked"] == 1 and t["accuracy"]["accuracy_pct"] == 100.0
    assert t["recent_checks"][0]["remediation_id"] == rid


def test_wrong_prediction_counts_against_accuracy(api, supa, scanned, admin):
    rid = _request_fix(api, supa, admin, params={"port": 23})
    supa.table("remediations").update({"status": "succeeded", "verified_fixed": True}) \
        .eq("id", rid).execute()
    assert prioritization_store.evaluate_pending([score_host(make_host())], supa) == 1
    res = next(r for r in supa.rows("remediations") if r["id"] == rid)["fix_check"]
    assert res["match"] is False and res["misses"] == ["port 23 still open"]
    assert api.get("/prioritization", headers=admin["h"]).json()["accuracy"]["accuracy_pct"] == 0.0


def test_old_version_1_prediction_is_still_checked(supa, scanned):
    p = T.predict([score_host(make_host())], META_IP, {"type": "block_port", "params": {"port": 21}})
    p["removed_findings"] = p.pop("removed_findings")         # how v13 stored it
    r = T.check_prediction(p, [score_host(make_host())])
    assert "CVE-2011-2523 still present" in r["misses"]


def test_unverified_or_unscanned_fixes_are_not_checked(supa, scanned, admin, api):
    rid = _request_fix(api, supa, admin, params={"port": 23})
    assert prioritization_store.evaluate_pending([score_host(make_host())], supa) == 0
    supa.table("remediations").update({"status": "succeeded", "verified_fixed": False}) \
        .eq("id", rid).execute()
    assert prioritization_store.evaluate_pending([score_host(make_host())], supa) == 0
    supa.table("remediations").update({"verified_fixed": True}).eq("id", rid).execute()
    assert prioritization_store.evaluate_pending([], supa) == 0
    assert prioritization_store.evaluate_pending([], None) == 0


def test_scan_runs_the_prediction_check_and_never_breaks_it(lab, supa, monkeypatch):
    from scanner import engine
    seen = {}

    def fake_eval(hosts, client=None):
        seen["hosts"] = [h["ip"] for h in hosts]
        return 3
    monkeypatch.setattr(prioritization_store, "evaluate_pending", fake_eval)
    r = engine.run_scan([META_IP])
    assert seen["hosts"] == [META_IP] and r["meta"]["summary"]["fix_checks"] == 3

    def boom(hosts, client=None):
        raise RuntimeError("model down")
    monkeypatch.setattr(prioritization_store, "evaluate_pending", boom)
    r = engine.run_scan([META_IP])
    assert r["meta"]["summary"]["live_hosts"] == 1 and "fix_checks" not in r["meta"]["summary"]


def test_end_to_end_preview_fix_rescan_and_check(lab, supa, monkeypatch):
    """The real chain: scan -> preview of each requested fix -> approve with
    2FA -> worker fixes + verifies -> re-scan -> each preview is checked."""
    from scanner import engine
    from soar import approval, remediation, worker

    engine.run_scan([META_IP])
    tickets = {t["title"].split(" (")[0]: t for t in supa.rows("tickets")}
    adm = make_user(supa, "admin")
    monkeypatch.setattr(remediation, "run_remote",
                        lambda ip, cmds, check=True: [(c, 0, "ok") for c in cmds])
    monkeypatch.setattr(worker, "verify_fix", lambda ip, params, action: True)
    for title in ("Clear-text service telnet:23", "CVE-2011-2523 on ftp:21 [KEV]"):
        act = tickets[title]["suggested_action"]
        rid = approval.create_request(tickets[title]["id"], META_IP, act["action_type"],
                                      act["params"], adm["id"])["remediation"]["id"]
        approval.approve_and_arm(rid, dict(adm, totp_last_step=None), adm["code"]())
    preds = [r["fix_prediction"] for r in supa.rows("remediations")]
    assert sorted(p["closed_ports"][0] for p in preds) == [21, 23]
    assert worker.run_once(supa) == 2

    # ports 21 and 23 are really closed now -> the predictions come true
    from tests.fakes import FakeNmap
    lab["nmap"] = FakeNmap({META_IP: dict(META_NMAP, tcp={22: META_NMAP["tcp"][22]})})
    r2 = engine.run_scan([META_IP])
    assert r2["meta"]["summary"]["fix_checks"] == 2
    results = [r["fix_check"] for r in supa.rows("remediations")]
    assert all(x["match"] for x in results), results
    acc = prioritization_store.overview(supa)["accuracy"]
    assert acc["checked"] == 2 and acc["accuracy_pct"] == 100.0


def test_large_host_ranks_quickly(supa):
    """Metasploitable-sized: 25 services and 500 CVEs must rank in a few seconds."""
    services = [(p, n) for p, n in zip(range(1000, 1025), ["svc"] * 25)]
    vulns = [vuln(f"CVE-2000-{i:04d}", 1000 + i % 25, 40 + i % 60, cvss=4 + (i % 60) / 10,
                  kev=i % 50 == 0) for i in range(500)]
    h = plain_host(services=services, vulns=vulns)
    t0 = time.time()
    cands = prioritization_store.bounded_candidates([h])
    ranked = T.rank_fixes([h], candidates=cands)
    base = T.rank_fixes([h], mode="baseline", candidates=cands)
    assert time.time() - t0 < 20
    assert sum(1 for c in cands if c["fix"]["type"] == "patch_cve") == prioritization_store.MAX_PATCH_CANDIDATES
    assert ranked and base and len(ranked) <= 15
