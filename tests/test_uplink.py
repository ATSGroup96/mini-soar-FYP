"""Scan upload: encrypted bundle, rogue devices, change detection, re-scan
verification, risk trend, watchlist alerts, and the 'failed scan' safety rule."""
import copy
import json
from pathlib import Path

import pytest

from common import crypto
from scanner import uplink
from tests.conftest import META_IP, make_host

META = {"scope": "192.168.56.0/24", "started_at": "2026-11-15T10:00:00Z",
        "finished_at": "2026-11-15T10:03:00Z", "host_count": 1, "summary": {}}


def scored(**over):
    from ml.risk_score import score_host
    return score_host(make_host(**over))


def push(supa, *hosts):
    return uplink.push_scan(dict(META, host_count=len(hosts)), list(hosts))


def titles(supa):
    return [n["title"] for n in supa.rows("notifications")]


def changes(supa, kind=None):
    return [c for c in supa.rows("asset_changes") if kind is None or c["kind"] == kind]


# ---- stored bundle -----------------------------------------------------------
def test_offline_mode_stores_encrypted_signed_bundle(host):
    out = uplink.push_scan(META, [host])
    assert out["mode"] == "offline"
    raw = Path(out["path"]).read_text()
    assert "192.168.56.101" not in raw and "msfadmin" not in raw      # really encrypted
    bundle = uplink.load_bundle(out["path"])
    assert bundle["hosts"][0]["ip"] == META_IP and bundle["scan"]["scope"] == META["scope"]


def test_tampered_bundle_is_rejected(host):
    path = Path(uplink.push_scan(META, [host])["path"])
    wrapper = json.loads(path.read_text())

    # 1) ciphertext changed
    bad = dict(wrapper, ciphertext=wrapper["ciphertext"][:-4] + "AAAA")
    path.write_text(json.dumps(bad))
    with pytest.raises(uplink.BundleTampered, match="decrypted"):
        uplink.load_bundle(path)

    # 2) a different (validly encrypted) bundle swapped in under the old signature
    forged = crypto.encrypt_json({"scan": META, "hosts": []})
    path.write_text(json.dumps(dict(wrapper, ciphertext=forged)))
    with pytest.raises(uplink.BundleTampered, match="signature"):
        uplink.load_bundle(path)


def test_bundle_signed_with_other_key_is_rejected(host, set_env):
    path = uplink.push_scan(META, [host])["path"]
    set_env(HMAC_KEY="attacker-key")
    with pytest.raises(uplink.BundleTampered):
        uplink.load_bundle(path)


def test_verify_stored_bundles_reports_bad_files(host, audit_actions):
    good = uplink.push_scan(META, [host])["path"]
    assert uplink.verify_stored_bundles() == {"checked": 1, "ok": 1, "bad": []}
    Path(good).with_name("scan_1.enc.json").write_text("{not json")
    result = uplink.verify_stored_bundles()
    assert (result["checked"], result["ok"], len(result["bad"])) == (2, 1, 1)
    assert "bundle.verify_failed" in audit_actions()


def test_verify_with_no_bundles():
    assert uplink.verify_stored_bundles() == {"checked": 0, "ok": 0, "bad": []}


# ---- first upload ------------------------------------------------------------
def test_first_scan_creates_rows(supa):
    out = push(supa, scored())
    assert out["mode"] == "cloud" and out["rogue"] == 1
    asset = supa.rows("assets")[0]
    assert asset["ip"] == META_IP and asset["is_rogue"] is True
    assert asset["risk_grade"] in "ABCDF" and asset["risk_score"] > 0
    assert sorted(s["port"] for s in supa.rows("services")) == [21, 22, 23, 3306]
    assert next(s for s in supa.rows("services") if s["port"] == 22)["has_default_cred"] is True
    vulns = {v["cve_id"]: v for v in supa.rows("vulnerabilities")}
    assert set(vulns) == {"CVE-2011-2523", "CVE-2008-0166"}
    ftp = next(s for s in supa.rows("services") if s["port"] == 21)
    assert vulns["CVE-2011-2523"]["service_id"] == ftp["id"]
    assert vulns["CVE-2011-2523"]["status"] == "open" and vulns["CVE-2011-2523"]["ml_risk_score"] > 0
    assert supa.rows("scans")[0]["status"] == "completed"


def test_rogue_alert_only_on_first_sight(supa):
    push(supa, scored())
    push(supa, scored())
    assert titles(supa).count("Rogue / unknown device") == 1


def test_authorized_device_is_not_rogue(supa):
    supa.add("assets", ip=META_IP, is_authorized=True)
    out = push(supa, scored())
    assert out["rogue"] == 0 and supa.rows("assets")[0]["is_rogue"] is False
    assert "Rogue / unknown device" not in titles(supa)


def test_rescan_does_not_duplicate_rows(supa):
    for _ in range(3):
        push(supa, scored())
    assert len(supa.rows("assets")) == 1
    assert len(supa.rows("services")) == 4
    assert len(supa.rows("vulnerabilities")) == 2
    assert len(supa.rows("scans")) == 3


def test_tls_certificates_are_replaced_not_piled_up(supa):
    cert = {"port": 443, "subject": "CN=lab", "issuer": "CN=lab", "days_to_expiry": 10,
            "is_self_signed": True, "is_expired": False, "weak_sig_alg": "", "tls_version": "TLSv1.2"}
    for _ in range(2):
        push(supa, scored(tls=[cert]))
    assert len(supa.rows("tls_certs")) == 1


# ---- change detection --------------------------------------------------------
def test_no_change_events_on_first_scan_of_a_host(supa):
    push(supa, scored())
    assert [c["kind"] for c in changes(supa)] == ["new_asset"]
    assert "New open port" not in titles(supa)


def test_closed_port_is_detected_and_vuln_marked_fixed(supa, audit_actions):
    push(supa, scored())
    after = scored()
    after["services"] = [s for s in after["services"] if s["port"] != 21]
    after["vulnerabilities"] = [v for v in after["vulnerabilities"] if v["port"] != 21]
    out = push(supa, after)
    assert out["changes"]["ports_closed"] == 1
    assert next(s for s in supa.rows("services") if s["port"] == 21)["state"] == "closed"
    v = {v["cve_id"]: v["status"] for v in supa.rows("vulnerabilities")}
    assert v == {"CVE-2011-2523": "remediated", "CVE-2008-0166": "open"}
    assert [c["port"] for c in changes(supa, "port_closed")] == [21]
    assert "change.port_closed" in audit_actions()


def test_new_port_raises_alert(supa, audit_actions):
    push(supa, scored())
    after = scored()
    after["services"].append({"port": 4444, "protocol": "tcp", "state": "open",
                              "service_name": "krb524", "product": "", "version": "", "cpe": ""})
    out = push(supa, after)
    assert out["changes"]["ports_opened"] == 1
    assert [c["port"] for c in changes(supa, "port_opened")] == [4444]
    n = next(n for n in supa.rows("notifications") if n["title"] == "New open port")
    assert "4444" in n["body"] and META_IP in n["body"] and n["level"] == "medium"
    assert "change.port_opened" in audit_actions()


def test_reopened_port_and_regression_are_detected(supa):
    push(supa, scored())
    closed = scored()
    closed["services"] = [s for s in closed["services"] if s["port"] != 21]
    closed["vulnerabilities"] = [v for v in closed["vulnerabilities"] if v["port"] != 21]
    push(supa, closed)
    out = push(supa, scored())                                   # port 21 is back
    assert out["changes"]["ports_opened"] == 1
    assert changes(supa, "port_opened")[0]["detail"]["reopened"] is True
    assert next(s for s in supa.rows("services") if s["port"] == 21)["state"] == "open"
    v = {v["cve_id"]: v["status"] for v in supa.rows("vulnerabilities")}
    assert v["CVE-2011-2523"] == "open"                          # reopened, not duplicated
    assert len(supa.rows("vulnerabilities")) == 2


def test_version_change_is_detected(supa):
    push(supa, scored())
    after = scored()
    next(s for s in after["services"] if s["port"] == 3306)["version"] = "5.7.44"
    out = push(supa, after)
    assert out["changes"]["versions_changed"] == 1
    c = changes(supa, "version_changed")[0]
    assert (c["port"], c["detail"]["from"], c["detail"]["to"]) == (3306, "MySQL 5.0.51a", "MySQL 5.7.44")


def test_missing_version_answer_is_not_a_change(supa):
    push(supa, scored())
    after = scored()
    next(s for s in after["services"] if s["port"] == 3306).update(product="", version="")
    assert push(supa, after)["changes"]["versions_changed"] == 0


def test_analyst_decision_survives_rescan(supa):
    push(supa, scored())
    v = next(v for v in supa.rows("vulnerabilities") if v["cve_id"] == "CVE-2008-0166")
    v["status"] = "accepted"
    push(supa, scored())
    assert next(x for x in supa.rows("vulnerabilities") if x["id"] == v["id"])["status"] == "accepted"


# ---- the 13-Nov bug: a failed scan must close nothing -------------------------
def test_failed_scan_of_a_host_changes_nothing(supa, audit_actions):
    push(supa, scored())
    before = copy.deepcopy((supa.rows("services"), supa.rows("vulnerabilities"),
                            supa.rows("assets")[0]["risk_score"]))
    failed = {"ip": META_IP, "mac": "08:00:27:aa:bb:cc", "hostname": "", "os_guess": "",
              "os_accuracy": 0, "services": [], "tls": [], "default_creds": [],
              "scan_ok": False, "risk_score": 0.0, "risk_grade": "A", "vulnerabilities": []}
    out = push(supa, failed)
    assert out["changes"]["inconclusive_hosts"] == 1 and out["changes"]["ports_closed"] == 0
    assert all(s["state"] == "open" for s in supa.rows("services"))
    assert all(v["status"] == "open" for v in supa.rows("vulnerabilities"))
    asset = supa.rows("assets")[0]
    assert asset["risk_score"] == before[2] and asset["os_guess"] == "Linux 2.6.X"
    assert "Scan of a host did not finish" in titles(supa)
    assert "scan.host_inconclusive" in audit_actions()
    assert changes(supa, "port_closed") == []


def test_other_hosts_in_the_same_scan_are_still_processed(supa):
    push(supa, scored(), scored(ip="192.168.56.102"))
    failed = {"ip": META_IP, "services": [], "tls": [], "default_creds": [],
              "scan_ok": False, "vulnerabilities": []}
    ok = scored(ip="192.168.56.102")
    ok["services"] = [s for s in ok["services"] if s["port"] != 23]
    out = push(supa, failed, ok)
    assert out["changes"] == dict(out["changes"], inconclusive_hosts=1, ports_closed=1)


# ---- risk trend --------------------------------------------------------------
def test_risk_history_per_host_and_network(supa):
    push(supa, scored())
    rows = supa.rows("risk_history")
    host_row = next(r for r in rows if r["asset_id"])
    net_row = next(r for r in rows if r["asset_id"] is None)
    asset = supa.rows("assets")[0]
    assert host_row["risk_score"] == asset["risk_score"] and host_row["risk_grade"] == asset["risk_grade"]
    assert (host_row["open_vulns"], host_row["kev_count"]) == (2, 1)
    assert net_row["risk_score"] == asset["risk_score"] and net_row["kev_count"] == 1


def test_risk_trend_goes_down_after_a_fix(supa):
    push(supa, scored())
    fixed = make_host()
    fixed["services"] = [s for s in fixed["services"] if s["port"] not in (21, 22)]
    fixed["vulnerabilities"] = []
    fixed["default_creds"] = []
    from ml.risk_score import score_host
    push(supa, score_host(fixed))
    net = [r["risk_score"] for r in supa.rows("risk_history") if r["asset_id"] is None]
    assert len(net) == 2 and net[1] < net[0]


def test_network_risk_is_average_of_all_assets(supa):
    supa.add("assets", ip="192.168.56.9", risk_score=0)
    push(supa, scored())
    asset = next(a for a in supa.rows("assets") if a["ip"] == META_IP)
    net = next(r for r in supa.rows("risk_history") if r["asset_id"] is None)
    assert net["risk_score"] == round(asset["risk_score"] / 2, 1)


# ---- watchlist ---------------------------------------------------------------
def test_watchlist_hit_alerts_once(supa):
    h = scored()
    h["vulnerabilities"][0]["on_watchlist"] = True
    out = push(supa, h)
    assert out["changes"]["watchlist_hits"] == 1
    n = next(n for n in supa.rows("notifications") if n["title"] == "Watchlisted CVE found")
    assert "CVE-2011-2523" in n["body"] and n["level"] == "high"
    h2 = scored()
    h2["vulnerabilities"][0]["on_watchlist"] = True
    push(supa, h2)
    assert titles(supa).count("Watchlisted CVE found") == 1


def test_cve_added_to_watchlist_later_alerts_on_next_scan(supa):
    push(supa, scored())                                  # finding already known and open
    assert "Watchlisted CVE found" not in titles(supa)
    h = make_host()
    h["vulnerabilities"][0]["on_watchlist"] = True         # the team adds it to the watchlist
    from ml.risk_score import score_host
    push(supa, score_host(h))
    assert titles(supa).count("Watchlisted CVE found") == 1
    h2 = make_host()
    h2["vulnerabilities"][0]["on_watchlist"] = True
    push(supa, score_host(h2))
    assert titles(supa).count("Watchlisted CVE found") == 1    # still only once


# ---- older database without the new tables -----------------------------------
def test_upload_works_when_new_tables_are_missing(supa):
    supa.fail_tables.update({"risk_history", "asset_changes"})
    out = push(supa, scored())
    assert out["mode"] == "cloud" and len(supa.rows("vulnerabilities")) == 2
