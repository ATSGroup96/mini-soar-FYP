"""Offline CVE intelligence: database, NVD/EPSS/KEV sync, CVE matching."""
import gzip

import pytest

from common.db import get_intel_db
from intel import cli, db_init, match, sync_cpe, sync_epss, sync_kev, sync_nvd


def nvd_item(cve_id, score, criteria, start_inc=None, end_inc=None, end_exc=None,
             start_exc=None, desc="test cve"):
    m = {"criteria": criteria, "vulnerable": True}
    for k, v in (("versionStartIncluding", start_inc), ("versionEndIncluding", end_inc),
                 ("versionEndExcluding", end_exc), ("versionStartExcluding", start_exc)):
        if v:
            m[k] = v
    return {"cve": {
        "id": cve_id, "published": "2011-07-07T00:00:00", "lastModified": "2024-01-01T00:00:00",
        "descriptions": [{"lang": "es", "value": "x"}, {"lang": "en", "value": desc}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score,
                                                    "vectorString": "CVSS:3.1/AV:N"}}]},
        "configurations": [{"nodes": [{"cpeMatch": [m]}]}],
    }}


@pytest.fixture
def intel_db():
    db_init.init_db()
    conn = get_intel_db()
    sync_nvd._store(conn, [
        nvd_item("CVE-2011-2523", 9.8, "cpe:2.3:a:vsftpd_project:vsftpd:2.3.4:*:*:*:*:*:*:*"),
        nvd_item("CVE-2021-0001", 7.5, "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                 start_inc="2.4.0", end_inc="2.4.48"),
        nvd_item("CVE-2021-0002", 5.3, "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                 end_inc="2.4.48"),                                   # no lower bound
        nvd_item("CVE-2010-0003", 6.8, "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                 start_inc="2.2.0", end_exc="2.2.9"),
        nvd_item("CVE-2010-0004", 4.3, "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                 start_inc="2.2.0", end_exc="2.2.8"),                 # fixed IN 2.2.8
        nvd_item("CVE-2008-0166", 7.5, "cpe:2.3:a:openbsd:openssh:4.7:p1:*:*:*:*:*:*"),
        nvd_item("CVE-2007-0005", 5.0, "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                 end_inc="4.7"),
        nvd_item("CVE-2016-0006", 5.9, "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                 start_inc="1.0.2", end_exc="1.0.2h"),
    ])
    conn.execute("insert into epss values('CVE-2011-2523', 0.94, 0.99)")
    conn.execute("insert into kev(cve_id,due_date) values('CVE-2011-2523','2022-05-03')")
    conn.commit()
    yield conn
    conn.close()


def ids(matches):
    return {m.cve_id: m.confidence for m in matches}


# ---- database ----------------------------------------------------------------
def test_init_db_is_repeatable():
    db_init.init_db()
    db_init.init_db()
    conn = get_intel_db()
    tables = {r["name"] for r in conn.execute("select name from sqlite_master where type='table'")}
    conn.close()
    assert {"cves", "cpe_match", "epss", "kev", "meta"} <= tables


def test_store_parses_nvd_record(intel_db):
    row = intel_db.execute("select * from cves where cve_id='CVE-2011-2523'").fetchone()
    assert (row["cvss_score"], row["severity"], row["description"]) == (9.8, "critical", "test cve")
    m = intel_db.execute("select * from cpe_match where cve_id='CVE-2011-2523'").fetchone()
    assert (m["vendor"], m["product"], m["version_exact"]) == ("vsftpd_project", "vsftpd", "2.3.4")


def test_store_twice_does_not_duplicate(intel_db):
    sync_nvd._store(intel_db, [nvd_item("CVE-2011-2523", 9.8,
                                        "cpe:2.3:a:vsftpd_project:vsftpd:2.3.4:*:*:*:*:*:*:*")])
    n = intel_db.execute("select count(*) c from cpe_match where cve_id='CVE-2011-2523'").fetchone()["c"]
    assert n == 1


@pytest.mark.parametrize("score,sev", [(9.8, "critical"), (9.0, "critical"), (8.9, "high"),
                                       (7.0, "high"), (4.0, "medium"), (0.1, "low"),
                                       (0, "info"), (None, None)])
def test_severity_bands(score, sev):
    assert sync_nvd._severity_from_cvss(score) == sev


# ---- matching ----------------------------------------------------------------
def test_exact_version_match_with_epss_and_kev(intel_db):
    got = match.match_service(intel_db, "vsftpd", "2.3.4", 21, set())
    assert len(got) == 1
    m = got[0]
    assert (m.cve_id, m.confidence, m.port) == ("CVE-2011-2523", "version-confirmed", 21)
    assert (m.epss_score, m.epss_percentile, m.in_kev, m.kev_due_date) == (0.94, 0.99, True, "2022-05-03")


def test_other_exact_version_does_not_match(intel_db):
    assert match.match_service(intel_db, "vsftpd", "3.0.3", 21, set()) == []


def test_version_inside_range(intel_db):
    got = ids(match.match_service(intel_db, "http_server", "2.4.10", 80, set()))
    assert got["CVE-2021-0001"] == "version-confirmed"
    assert got["CVE-2021-0002"] == "version-confirmed"
    assert "CVE-2010-0003" not in got


def test_version_after_fix_is_not_matched(intel_db):
    assert ids(match.match_service(intel_db, "http_server", "2.4.49", 80, set())) == {}


def test_older_branch_is_only_unconfirmed(intel_db):
    """Apache 2.2.8 sits 'below 2.4.48' only because NVD gave no lower bound."""
    got = ids(match.match_service(intel_db, "http_server", "2.2.8", 80, set()))
    assert got["CVE-2021-0002"] == "version-unconfirmed"
    assert "CVE-2021-0001" not in got                    # has a real lower bound 2.4.0
    assert got["CVE-2010-0003"] == "version-confirmed"   # 2.2.0 <= 2.2.8 < 2.2.9


def test_end_excluding_bound_is_respected(intel_db):
    """'fixed in 2.2.8' means 2.2.8 itself is NOT vulnerable."""
    got = ids(match.match_service(intel_db, "http_server", "2.2.8", 80, set()))
    assert "CVE-2010-0004" not in got
    got = ids(match.match_service(intel_db, "http_server", "2.2.7", 80, set()))
    assert got["CVE-2010-0004"] == "version-confirmed"


def test_portable_suffix_is_same_version(intel_db):
    """nmap says OpenSSH '4.7p1'; NVD lists '4.7' (+ update p1) and '<= 4.7'."""
    got = ids(match.match_service(intel_db, "openssh", "4.7p1", 22, set()))
    assert got == {"CVE-2008-0166": "version-confirmed", "CVE-2007-0005": "version-confirmed"}
    assert ids(match.match_service(intel_db, "openssh", "9.6p1", 22, set())) == {}


def test_letter_suffix_ordering(intel_db):
    """OpenSSL 1.0.2g is before the fix 1.0.2h; 1.0.2k is after it."""
    assert "CVE-2016-0006" in ids(match.match_service(intel_db, "openssl", "1.0.2g", 443, set()))
    assert "CVE-2016-0006" not in ids(match.match_service(intel_db, "openssl", "1.0.2k", 443, set()))
    assert "CVE-2016-0006" not in ids(match.match_service(intel_db, "openssl", "1.0.2h", 443, set()))


def test_unknown_version_gives_unconfirmed_candidates(intel_db):
    got = ids(match.match_service(intel_db, "vsftpd", "", 21, set()))
    assert got == {"CVE-2011-2523": "version-unconfirmed"}


def test_unknown_product_gives_nothing(intel_db):
    assert match.match_service(intel_db, "", "1.0", 80, set()) == []
    assert match.match_service(intel_db, "totally-unknown", "1.0", 80, set()) == []


def test_product_name_normalisation(intel_db):
    # nmap CPE says http_server; a display name with other separators also works
    assert match.match_service(intel_db, "HTTP-Server", "2.4.10", 80, set())


def test_watchlist_hit_is_marked(intel_db):
    got = match.match_service(intel_db, "vsftpd", "2.3.4", 21, {"CVE-2011-2523"})
    assert got[0].on_watchlist is True
    assert "on CVE watchlist" in got[0].ml_reasons


def test_match_host_prefers_cpe_and_sorts_kev_first(intel_db, host):
    host["services"].append({"port": 80, "service_name": "http", "product": "Apache httpd",
                             "version": "2.2.8", "cpe": "cpe:/a:apache:http_server:2.2.8"})
    out = match.match_host(host)
    assert out[0]["cve_id"] == "CVE-2011-2523" and out[0]["in_kev"]
    by_port = {(v["cve_id"], v["port"]) for v in out}
    assert ("CVE-2010-0003", 80) in by_port         # found through the CPE product name
    assert ("CVE-2008-0166", 22) in by_port


def test_match_host_reads_cloud_watchlist(intel_db, supa, host):
    supa.add("cve_watchlist", cve_id="CVE-2011-2523")
    out = match.match_host(host)
    assert next(v for v in out if v["cve_id"] == "CVE-2011-2523")["on_watchlist"] is True


def test_match_host_without_database_rows_is_empty(host):
    db_init.init_db()
    assert match.match_host(host) == []


# ---- feeds -------------------------------------------------------------------
class _Resp:
    def __init__(self, json_data=None, content=b"", status=200):
        self._json, self.content, self.status_code, self.ok = json_data, content, status, status < 400

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


def test_kev_sync(monkeypatch):
    feed = {"vulnerabilities": [
        {"cveID": "CVE-2011-2523", "vendorProject": "vsftpd", "product": "vsftpd",
         "vulnerabilityName": "backdoor", "dateAdded": "2022-04-12", "dueDate": "2022-05-03",
         "knownRansomwareCampaignUse": "Unknown"},
        {"cveID": "CVE-2017-0144", "dueDate": "2022-08-10"}]}
    monkeypatch.setattr(sync_kev.requests, "get", lambda *a, **k: _Resp(feed))
    assert sync_kev.sync() == 2
    assert sync_kev.sync() == 2                               # run again: replaced, not doubled
    conn = get_intel_db()
    assert conn.execute("select count(*) c from kev").fetchone()["c"] == 2
    assert conn.execute("select rows from meta where feed='kev'").fetchone()["rows"] == 2
    conn.close()


def test_epss_sync_skips_comment_and_header(monkeypatch):
    csv = ("#model_version:v2026.01.01,score_date:2026-11-15\n"
           "cve,epss,percentile\n"
           "CVE-2011-2523,0.94321,0.99876\n"
           "CVE-2017-0144,0.97000,0.99990\n"
           "CVE-BROKEN,not-a-number,0.5\n")
    monkeypatch.setattr(sync_epss.requests, "get",
                        lambda *a, **k: _Resp(content=gzip.compress(csv.encode())))
    assert sync_epss.sync() == 2
    conn = get_intel_db()
    row = conn.execute("select * from epss where cve_id='CVE-2011-2523'").fetchone()
    conn.close()
    assert (row["epss"], row["percentile"]) == (0.94321, 0.99876)


def test_epss_sync_tries_second_source(monkeypatch):
    calls = []

    def fake_get(url, **k):
        calls.append(url)
        if len(calls) == 1:
            raise RuntimeError("first mirror down")
        return _Resp(content=gzip.compress(b"cve,epss,percentile\nCVE-1,0.1,0.2\n"))
    monkeypatch.setattr(sync_epss.requests, "get", fake_get)
    assert sync_epss.sync() == 1 and len(calls) == 2


def test_epss_sync_fails_clearly_when_all_sources_down(monkeypatch):
    def down(*a, **k):
        raise RuntimeError("offline")
    monkeypatch.setattr(sync_epss.requests, "get", down)
    with pytest.raises(RuntimeError, match="EPSS"):
        sync_epss.sync()


@pytest.mark.parametrize("cpe,expected", [
    ("cpe:/a:apache:http_server:2.2.8", "cpe:2.3:a:apache:http_server"),
    ("cpe:2.3:a:vsftpd:vsftpd:2.3.4:*:*:*:*:*:*:*", "cpe:2.3:a:vsftpd:vsftpd"),
    ("cpe:/o:linux:linux_kernel:2.6", None),          # operating systems are skipped
    ("cpe:/h:cisco:router", None),
    ("", None), ("garbage", None),
])
def test_cpe_to_match_string(cpe, expected):
    assert sync_cpe._to_match_string(cpe) == expected


def test_vendor_alias_candidates():
    assert sync_cpe._candidates("cpe:2.3:a:vsftpd:vsftpd") == [
        "cpe:2.3:a:vsftpd:vsftpd", "cpe:2.3:a:vsftpd_project:vsftpd", "cpe:2.3:a:beasts:vsftpd"]


def test_sync_cpe_uses_alias_when_first_name_has_no_cves(monkeypatch):
    asked = []

    def fake_get(params, headers):
        asked.append(params.get("virtualMatchString") or params.get("keywordSearch"))
        if params.get("virtualMatchString") == "cpe:2.3:a:vsftpd_project:vsftpd":
            return {"totalResults": 1, "vulnerabilities": [
                nvd_item("CVE-2011-2523", 9.8, "cpe:2.3:a:vsftpd_project:vsftpd:2.3.4:*:*:*:*:*:*:*")]}
        return {"totalResults": 0, "vulnerabilities": []}
    monkeypatch.setattr(sync_cpe, "_get", fake_get)
    monkeypatch.setattr(sync_cpe.time, "sleep", lambda s: None)
    assert sync_cpe.sync(["cpe:/a:vsftpd:vsftpd:2.3.4", "cpe:/o:linux:linux_kernel"]) == 1
    assert asked == ["cpe:2.3:a:vsftpd:vsftpd", "cpe:2.3:a:vsftpd_project:vsftpd"]


def test_sync_cpe_reads_cpes_from_scans(supa, monkeypatch):
    supa.add("services", asset_id="a", port=21, cpe="cpe:/a:vsftpd:vsftpd:2.3.4")
    supa.add("services", asset_id="a", port=23, cpe=None)
    assert sync_cpe.cpes_from_scans() == ["cpe:/a:vsftpd:vsftpd:2.3.4"]


def test_sync_cpe_without_scans_does_nothing():
    assert sync_cpe.sync([]) == 0


def test_cli_stats_and_init(capsys):
    assert cli.main(["init"]) == 0
    assert cli.main(["stats"]) == 0
    out = capsys.readouterr().out
    assert "never synced" in out and "table cves" in out
