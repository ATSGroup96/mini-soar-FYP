"""Attack-path graph, digital twin (what-if), MITRE mapping and the PDF report."""
import pytest

from ml.risk_score import score_host
from reports import mitre_mapping, pdf_report
from soar import attack_path, digital_twin
from tests.conftest import make_host


def clean_host(ip, risk=5.0):
    return {"ip": ip, "hostname": "", "os_guess": "Linux", "services":
            [{"port": 80, "service_name": "http"}], "vulnerabilities": [],
            "risk_score": risk, "risk_grade": "A"}


# ---- attack paths ------------------------------------------------------------
def test_entry_weakness_reasons(host):
    score_host(host)
    reasons = attack_path._entry_weakness(host)
    assert "KEV CVE-2011-2523 on :21" in reasons and "default cred on :22" in reasons


def test_unconfirmed_kev_is_not_an_entry_point():
    h = make_host()
    h["services"][1]["has_default_cred"] = False
    for v in h["vulnerabilities"]:
        v["confidence"] = "version-unconfirmed"
    h["risk_score"] = 10
    assert attack_path._entry_weakness(h) == []


def test_graph_has_attacker_initial_access_and_lateral_edges(host):
    score_host(host)
    g = attack_path.build_graph([host, clean_host("192.168.56.102"), clean_host("10.0.0.5")])
    kinds = {(e["source"], e["target"], e["kind"]) for e in g["edges"]}
    assert ("attacker", "192.168.56.101", "initial-access") in kinds
    assert ("192.168.56.101", "192.168.56.102", "lateral-movement") in kinds
    assert not any(e["target"] == "10.0.0.5" for e in g["edges"])        # other subnet
    assert not any(e["source"] == "192.168.56.102" for e in g["edges"])  # no foothold there
    assert [n["id"] for n in g["nodes"]][0] == "attacker"


def test_paths_are_ranked_by_target_risk(host):
    score_host(host)
    g = attack_path.build_graph([host, clean_host("192.168.56.102", risk=30)])
    paths = attack_path.rank_paths(g)
    assert [p["target"] for p in paths] == ["192.168.56.101", "192.168.56.102"]
    assert paths[0]["hops"] == 1 and paths[1]["hops"] == 2
    assert paths[1]["steps"][0]["to"] == "192.168.56.101"
    assert paths[1]["steps"][1]["kind"] == "lateral-movement"


def test_no_weak_host_means_no_paths():
    g = attack_path.build_graph([clean_host("192.168.56.102"), clean_host("192.168.56.103")])
    assert g["edges"] == [] and attack_path.rank_paths(g) == []


def test_empty_network():
    g = attack_path.build_graph([])
    assert len(g["nodes"]) == 1 and attack_path.rank_paths(g) == []


# ---- digital twin ------------------------------------------------------------
def test_what_if_never_changes_the_real_data(host):
    import copy
    before = copy.deepcopy(host)
    digital_twin.simulate_host(host, {"type": "block_port", "params": {"port": 21}})
    assert host == before


def test_blocking_the_worst_port_lowers_risk(host):
    r = digital_twin.simulate_host(host, {"type": "block_port", "params": {"port": 21}})
    assert r["before"]["vuln_count"] == 2 and r["after"]["vuln_count"] == 1
    assert r["after"]["open_ports"] == r["before"]["open_ports"] - 1
    assert r["after"]["kev"] == 0 and r["before"]["kev"] == 1
    assert r["risk_reduction"] > 0 and r["exposure_reduction"] > 0
    assert r["after"]["risk_score"] < r["before"]["risk_score"] and r["note"] == ""


def test_fixing_a_minor_finding_explains_why_grade_stays(host):
    r = digital_twin.simulate_host(host, {"type": "patch_cve", "params": {"cve_id": "cve-2008-0166"}})
    assert r["risk_reduction"] == 0 and r["exposure_reduction"] > 0
    assert "single worst finding" in r["note"] and "CVE-2011-2523" in r["note"]


def test_fix_that_matches_nothing_is_reported(host):
    r = digital_twin.simulate_host(host, {"type": "block_port", "params": {"port": 9999}})
    assert r["unmatched"] == ["block_port 9999"] and "No open service" in r["note"]
    assert r["risk_reduction"] == 0


def test_stop_service_by_name_or_port_number(host):
    by_name = digital_twin.simulate_host(host, {"type": "stop_service", "params": {"service": "telnet"}})
    by_port = digital_twin.simulate_host(host, {"type": "stop_service", "params": {"service": "23"}})
    assert by_name["after"]["open_ports"] == by_port["after"]["open_ports"] == 3


def test_disable_account_removes_default_credential(host):
    r = digital_twin.simulate_host(host, {"type": "disable_account", "params": {"username": "msfadmin"}})
    assert r["before"]["default_creds"] == 1 and r["after"]["default_creds"] == 0


def test_several_fixes_together(host):
    r = digital_twin.simulate_host(host, [
        {"type": "block_port", "params": {"port": 21}},
        {"type": "patch_cve", "params": {"cve_id": "CVE-2008-0166"}},
        {"type": "disable_account", "params": {"username": "msfadmin"}}])
    assert r["fixes_applied"] == 3 and r["after"]["vuln_count"] == 0
    assert r["after"]["risk_score"] == 0 and r["after"]["grade"] == "A"


def test_network_what_if(host):
    hosts = [host, clean_host("192.168.56.102")]
    fix = [{"type": "block_port", "params": {"port": 21}},
           {"type": "disable_account", "params": {"username": "msfadmin"}},
           {"type": "patch_cve", "params": {"cve_id": "CVE-2008-0166"}}]
    r = digital_twin.simulate_network(hosts, "192.168.56.101", fix)
    assert r["network_risk_after"] < r["network_risk_before"]
    assert r["attack_paths_before"] == 2 and r["attack_paths_after"] == 0
    assert r["top_path_before"]["target"] == "192.168.56.101" and r["top_path_after"] is None


# ---- MITRE ATT&CK ------------------------------------------------------------
def test_mitre_mapping_from_services_and_findings(host):
    host["is_rogue"] = True
    ids = {t["technique_id"] for t in mitre_mapping.map_host(host)}
    assert {"T1078", "T1110",        # default credential
            "T1040",                 # telnet
            "T1071",                 # ftp
            "T1021.004",             # ssh
            "T1213",                 # database
            "T1203", "T1190",        # KEV
            "T1200"} <= ids          # rogue device


def test_mitre_clean_host_maps_nothing():
    assert mitre_mapping.map_host({"ip": "x", "services": [], "vulnerabilities": []}) == []


def test_mitre_coverage_is_deduplicated(host):
    out = mitre_mapping.map_all([host, make_host(ip="192.168.56.102")])
    ids = [t["technique_id"] for t in out["coverage"]]
    assert len(ids) == len(set(ids)) and set(out["per_host"]) == {"192.168.56.101", "192.168.56.102"}


# ---- PDF report --------------------------------------------------------------
def pdf_text(path):
    pypdf = pytest.importorskip("pypdf")
    return "\n".join(p.extract_text() for p in pypdf.PdfReader(path).pages)


def test_report_is_built_without_cloud():
    path = pdf_report.build_latest_report()
    assert open(path, "rb").read(5) == b"%PDF-"


def test_report_contains_findings_grade_and_mitre(supa, host):
    pytest.importorskip("reportlab")
    from scanner import uplink
    uplink.push_scan({"scope": "lab", "summary": {}}, [score_host(host)])
    data = pdf_report._gather()
    hosts = pdf_report._hosts_for_mitre(data)
    assert hosts[0]["services"], "MITRE mapping needs the host's services"
    ids = {t["technique_id"] for t in mitre_mapping.map_all(hosts)["coverage"]}
    assert {"T1078", "T1040", "T1203"} <= ids          # default cred, telnet, KEV
    path = pdf_report.build_latest_report()
    assert open(path, "rb").read(5) == b"%PDF-"
    text = pdf_text(path)
    assert "CVE-2011-2523" in text and "Valid Accounts" in text and "Security grade" in text


def test_report_counts_only_open_findings(supa, host):
    from scanner import uplink
    uplink.push_scan({"scope": "lab", "summary": {}}, [score_host(host)])
    supa.rows("vulnerabilities")[0]["status"] = "remediated"
    data = pdf_report._gather()
    assert len(data["vulns"]) == 1
