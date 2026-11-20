"""MITRE ATT&CK mapping and the PDF report."""
import pytest

from ml.risk_score import score_host
from reports import mitre_mapping, pdf_report
from tests.conftest import make_host


def clean_host(ip, risk=5.0):
    return {"ip": ip, "hostname": "", "os_guess": "Linux", "services":
            [{"port": 80, "service_name": "http"}], "vulnerabilities": [],
            "risk_score": risk, "risk_grade": "A"}


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
