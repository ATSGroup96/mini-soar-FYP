"""Nuclei + NetExec (scanner/nuclei_scan.py, scanner/netexec_check.py), the
mapping of their findings for the risk model (ml/finding_map.py), and the whole
path scan -> one finding format -> score -> tickets -> prioritization.

The real tools are never run: subprocess.run is replaced by canned output
taken from the tools' documented formats."""
import json
import subprocess

import pytest

from common.allowlist import ScopeError
from ml import finding_map
from scanner import engine, netexec_check, nuclei_scan
from tests.conftest import META_IP
from tests.test_engine_e2e import META_NMAP, lab  # noqa: F401  (fixture)

SVC = [{"port": 80, "service_name": "http", "protocol": "tcp"},
       {"port": 443, "service_name": "https", "protocol": "tcp"},
       {"port": 445, "service_name": "microsoft-ds", "protocol": "tcp"},
       {"port": 53, "service_name": "domain", "protocol": "udp"}]


def nuclei_line(tid, sev, host=META_IP, port=80, tags=("misconfig",), cve=None, cvss=None,
                matched=None, name=None):
    info = {"name": name or tid, "severity": sev, "tags": list(tags)}
    if cve or cvss:
        info["classification"] = {"cve-id": [cve] if cve else None, "cvss-score": cvss}
    return json.dumps({"template-id": tid, "info": info, "host": f"http://{host}:{port}",
                       "ip": host, "port": str(port),
                       "matched-at": matched or f"http://{host}:{port}/x"})


class Done:
    def __init__(self, out, rc=0, err=""):
        self.stdout, self.returncode, self.stderr = out, rc, err


# ---- Nuclei ------------------------------------------------------------------------
def test_targets_only_from_this_hosts_open_tcp_ports():
    t = nuclei_scan.build_targets(META_IP, SVC)
    assert t == sorted({f"http://{META_IP}:80", f"https://{META_IP}:443", f"{META_IP}:80",
                        f"{META_IP}:443", f"{META_IP}:445"})               # no UDP 53


def test_command_is_non_intrusive():
    cmd = nuclei_scan.build_command("nuclei", "t.txt")
    for flag in ("-ni", "-dr", "-duc", "-jsonl", "-silent"):
        assert flag in cmd
    etags = cmd[cmd.index("-etags") + 1].split(",")
    assert {"dos", "fuzz", "intrusive", "osint", "brute-force"} <= set(etags)
    assert "default-login" in cmd[cmd.index("-tags") + 1]


def test_parse_keeps_real_findings_for_this_host_only():
    out = "\n".join([
        nuclei_line("apache-detect", "info", tags=("tech",)),                 # dropped: tech
        nuclei_line("tomcat-panel", "info", port=8180, tags=("panel", "tomcat")),
        nuclei_line("tomcat-default-login", "high", port=8180, tags=("default-login",)),
        nuclei_line("CVE-2011-2523", "critical", port=21, tags=("cve", "network"),
                    cve="CVE-2011-2523", cvss=9.8, matched=f"{META_IP}:21"),
        nuclei_line("x", "high", host="192.168.56.250"),                      # another host
        nuclei_line("tomcat-panel", "info", port=8180, tags=("panel",)),      # duplicate
        "not json", "",
    ])
    f = {x["finding_key"]: x for x in nuclei_scan.parse_jsonl(out, META_IP)}
    assert set(f) == {"nuclei:tomcat-panel", "nuclei:tomcat-default-login", "nuclei:CVE-2011-2523"}
    assert f["nuclei:tomcat-default-login"]["default_login"] is True
    assert f["nuclei:tomcat-default-login"]["port"] == 8180
    assert f["nuclei:CVE-2011-2523"]["cve_id"] == "CVE-2011-2523"
    assert f["nuclei:CVE-2011-2523"]["cvss_score"] == 9.8 and f["nuclei:CVE-2011-2523"]["port"] == 21


def test_check_host_runs_nuclei_once_and_never_outside_scope(monkeypatch, audit_actions):
    monkeypatch.setattr(nuclei_scan, "binary", lambda: "nuclei")
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        targets = open(cmd[cmd.index("-l") + 1]).read().split()
        assert all(META_IP in t for t in targets)
        return Done(nuclei_line("ftp-anonymous-login", "medium", port=21,
                                tags=("default-login", "ftp")))
    monkeypatch.setattr(subprocess, "run", fake_run)
    out = nuclei_scan.check_host(META_IP, [{"port": 21, "service_name": "ftp"}])
    assert len(calls) == 1 and out[0]["finding_key"] == "nuclei:ftp-anonymous-login"
    assert {"nuclei.start", "nuclei.finish"} <= set(audit_actions())
    with pytest.raises(ScopeError):
        nuclei_scan.check_host("8.8.8.8", [{"port": 80, "service_name": "http"}])
    assert len(calls) == 1


def test_nuclei_missing_or_failing_is_harmless(monkeypatch):
    assert nuclei_scan.check_host(META_IP, SVC) == []                     # not installed
    monkeypatch.setattr(nuclei_scan, "binary", lambda: "nuclei")

    def boom(*a, **k):
        raise OSError("cannot start")
    monkeypatch.setattr(subprocess, "run", boom)
    assert nuclei_scan.check_host(META_IP, SVC) == []

    def slow(cmd, **k):
        raise subprocess.TimeoutExpired(cmd, 1, output=nuclei_line("p", "high", port=80))
    monkeypatch.setattr(subprocess, "run", slow)
    assert [f["finding_key"] for f in nuclei_scan.check_host(META_IP, SVC)] == ["nuclei:p"]


# ---- NetExec -------------------------------------------------------------------------
SMB_INFO = (f"SMB         {META_IP}  445    METASPLOITABLE   [*] Unix (name:METASPLOITABLE) "
            "(domain:localdomain) (signing:False) (SMBv1:True)\n")
SMB_NULL = (f"SMB  {META_IP}  445  METASPLOITABLE  [*] Unix (name:METASPLOITABLE) (signing:False) (SMBv1:True)\n"
            f"SMB  {META_IP}  445  METASPLOITABLE  [+] localdomain\\:\n"
            f"SMB  {META_IP}  445  METASPLOITABLE  [*] Enumerated shares\n"
            f"SMB  {META_IP}  445  METASPLOITABLE  Share           Permissions     Remark\n"
            f"SMB  {META_IP}  445  METASPLOITABLE  -----           -----------     ------\n"
            f"SMB  {META_IP}  445  METASPLOITABLE  print$                          Printer Drivers\n"
            f"SMB  {META_IP}  445  METASPLOITABLE  tmp             READ,WRITE      oh noes!\n"
            f"SMB  {META_IP}  445  METASPLOITABLE  opt                             \n"
            f"SMB  {META_IP}  445  METASPLOITABLE  IPC$            READ            IPC Service\n")
RDP = (f"\x1b[1;34mRDP\x1b[0m  {META_IP}  3389  WIN10  [*] Windows 10 Build 19041 (name:WIN10) "
       "(domain:WIN10) (nla:False)\n")


def test_only_read_only_commands_are_built():
    cmds = dict(netexec_check.build_commands("nxc", META_IP, {139, 445, 3389, 5985, 5986}))
    assert set(cmds) == {"smb-info", "smb-null", "rdp-info", "winrm-http"}
    assert cmds["smb-info"][1:5] == ["smb", META_IP, "--port", "445"]
    for argv in cmds.values():
        netexec_check.assert_read_only(argv, META_IP)
    assert netexec_check.build_commands("nxc", META_IP, {22, 80}) == []


@pytest.mark.parametrize("extra", [["-M", "ms17-010"], ["-x", "whoami"], ["--sam"], ["--lsa"],
                                   ["--put-file", "a", "b"], ["--spider", "C$"],
                                   ["-u", "admin", "-p", "admin"], ["-u", "guest", "-p", ""]])
def test_exploit_and_credential_options_are_refused(extra):
    with pytest.raises(netexec_check.NotReadOnly):
        netexec_check.assert_read_only(["nxc", "smb", META_IP] + extra, META_IP)


def test_other_protocol_or_host_is_refused():
    for argv in (["nxc", "mssql", META_IP], ["nxc", "smb", "192.168.56.250"], ["nxc"]):
        with pytest.raises(netexec_check.NotReadOnly):
            netexec_check.assert_read_only(argv, META_IP)


def test_parsers():
    keys = {f["finding_key"] for f in netexec_check.parse_smb_info(SMB_INFO, 445)}
    assert keys == {"netexec:smbv1-enabled", "netexec:smb-signing-not-required"}
    null = {f["finding_key"]: f for f in netexec_check.parse_smb_null(SMB_NULL, 445)}
    assert set(null) == {"netexec:smb-null-session", "netexec:smb-anonymous-share-write"}
    assert "tmp" in null["netexec:smb-anonymous-share-write"]["evidence"]
    assert "IPC$" not in null["netexec:smb-anonymous-share-write"]["evidence"]
    denied = SMB_INFO + f"SMB  {META_IP}  445  X  [-] localdomain\\: STATUS_ACCESS_DENIED\n"
    assert netexec_check.parse_smb_null(denied, 445) == []
    rdp = netexec_check.parse_rdp(RDP)
    assert rdp[0]["finding_key"] == "netexec:rdp-nla-disabled" and "Windows 10" in rdp[0]["evidence"]
    assert netexec_check.parse_rdp(RDP.replace("nla:False", "nla:True")) == []
    safe = SMB_INFO.replace("signing:False", "signing:True").replace("SMBv1:True", "SMBv1:False")
    assert netexec_check.parse_smb_info(safe, 445) == []


def test_netexec_check_host(monkeypatch, audit_actions):
    monkeypatch.setattr(netexec_check, "binary", lambda: "nxc")
    seen = []

    def fake_run(argv, **kw):
        seen.append(argv)
        return Done(SMB_NULL if "--shares" in argv else SMB_INFO)
    monkeypatch.setattr(subprocess, "run", fake_run)
    out = netexec_check.check_host(META_IP, [{"port": 445}, {"port": 22}])
    assert len(seen) == 2
    assert {f["finding_key"] for f in out} == {
        "netexec:smbv1-enabled", "netexec:smb-signing-not-required", "netexec:smb-null-session",
        "netexec:smb-anonymous-share-write"}
    assert all(f["port"] == 445 and f["source"] == "netexec" for f in out)
    assert "netexec.finish" in audit_actions()
    with pytest.raises(ScopeError):
        netexec_check.check_host("8.8.8.8", [{"port": 445}])
    assert netexec_check.check_host(META_IP, [{"port": 22}]) == [] and len(seen) == 2


# ---- one finding format + scoring ------------------------------------------------------
def test_tool_finding_becomes_a_scorable_vulnerability():
    v = finding_map.to_vuln({"source": "netexec", "finding_key": "netexec:smbv1-enabled",
                             "title": "SMBv1 enabled", "port": 445, "cvss_score": 8.1,
                             "severity": "high"})
    assert v["cve_id"] is None and v["confidence"] == "version-confirmed"
    assert v["cvss_score"] == 8.1 and v["severity"] == "high" and v["in_kev"] is False
    n = finding_map.to_vuln({"source": "nuclei", "finding_key": "nuclei:x", "severity": "medium"})
    assert n["cvss_score"] == finding_map.SEVERITY_CVSS["medium"] and n["severity"] == "medium"
    from ml.risk_score import score_host
    h = score_host({"ip": META_IP, "services": [{"port": 445, "service_name": "microsoft-ds"}],
                    "vulnerabilities": [v]})
    assert h["vulnerabilities"][0]["ml_risk_score"] > 30 and h["risk_grade"] != "A"


def test_merge_confirms_a_cve_and_marks_default_logins(lab):
    host = {"ip": META_IP, "services": [{"port": 21, "service_name": "ftp"},
                                        {"port": 8180, "service_name": "http"}],
            "vulnerabilities": [{"cve_id": "CVE-2011-2523", "port": 21,
                                 "confidence": "version-unconfirmed"}]}
    added = finding_map.merge_into_host(host, [
        {"source": "nuclei", "finding_key": "nuclei:CVE-2011-2523", "cve_id": "CVE-2011-2523",
         "port": 21, "severity": "critical", "evidence": "backdoor answered"},
        {"source": "nuclei", "finding_key": "nuclei:tomcat-default-login", "port": 8180,
         "severity": "high", "default_login": True},
        {"source": "nuclei", "finding_key": "nuclei:tomcat-default-login", "port": 8180,
         "severity": "high", "default_login": True},                   # duplicate
    ])
    assert added == 1 and len(host["vulnerabilities"]) == 2
    cve = host["vulnerabilities"][0]
    assert cve["confidence"] == "version-confirmed" and "nuclei" in cve["evidence"]
    assert next(s for s in host["services"] if s["port"] == 8180)["has_default_cred"] is True


def test_cve_named_by_nuclei_gets_epss_and_kev(lab):
    host = {"ip": META_IP, "services": [], "vulnerabilities": []}
    finding_map.merge_into_host(host, [{"source": "nuclei", "finding_key": "nuclei:vsftpd-backdoor",
                                        "cve_id": "CVE-2011-2523", "port": 21, "severity": "critical"}])
    v = host["vulnerabilities"][0]
    assert v["in_kev"] is True and v["epss_score"] == 0.94


# ---- the whole path ----------------------------------------------------------------------
SAMBA = {**META_NMAP, "tcp": {**META_NMAP["tcp"],
                              445: {"state": "open", "name": "netbios-ssn", "product": "Samba smbd",
                                    "version": "3.0.20", "cpe": "cpe:/a:samba:samba:3.0.20"}}}


def test_scan_stores_tool_findings_and_opens_tickets(lab, supa, set_env, monkeypatch):
    from tests.fakes import FakeNmap
    from soar import prioritization_store
    lab["nmap"] = FakeNmap({META_IP: dict(SAMBA)})
    set_env(SCAN_NUCLEI="true", SCAN_NETEXEC="true")
    monkeypatch.setattr(nuclei_scan, "binary", lambda: "nuclei")
    monkeypatch.setattr(netexec_check, "binary", lambda: "nxc")

    def fake_run(argv, **kw):
        if argv[0] == "nuclei":
            return Done(nuclei_line("ftp-anon", "medium", port=21, tags=("default-login",)))
        return Done(SMB_NULL if "--shares" in argv else SMB_INFO)
    monkeypatch.setattr(subprocess, "run", fake_run)

    r = engine.run_scan([META_IP])
    assert r["meta"]["summary"]["tool_findings"] == 5
    rows = {v.get("finding_key"): v for v in supa.rows("vulnerabilities")}
    assert rows["netexec:smbv1-enabled"]["source"] == "netexec"
    assert rows["netexec:smbv1-enabled"]["cve_id"] is None
    assert rows["netexec:smbv1-enabled"]["ml_risk_score"] > 0
    assert rows["CVE-2011-2523"]["source"] == "cve"
    titles = [t["title"] for t in supa.rows("tickets")]
    assert any(t.startswith("SMBv1 enabled on netbios-ssn:445") for t in titles)
    assert any(t.startswith("SMB share writable without a password") for t in titles)
    smb_ticket = next(t for t in supa.rows("tickets") if t["title"].startswith("SMBv1"))
    assert smb_ticket["suggested_action"]["action_type"] == "block_port"
    assert "netexec" in smb_ticket["description"]

    # the patch-prioritization model sees them as findings of the 445 component
    ov = prioritization_store.overview(supa)
    c445 = next(c for c in ov["improved"]["components"] if c["id"] == f"{META_IP}|445")
    assert c445["findings"] == 4
    assert any(x["fix"] == {"type": "block_port", "params": {"port": 445}} for x in ov["ranking"])

    # SMB fixed on the host -> the next scan marks the findings remediated
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw: Done(""))
    lab["nmap"] = FakeNmap({META_IP: dict(META_NMAP)})
    engine.run_scan([META_IP])
    assert {v["status"] for v in supa.rows("vulnerabilities")
            if (v.get("finding_key") or "").startswith("netexec:")} == {"remediated"}


def test_tools_can_be_switched_off(lab, set_env, monkeypatch):
    set_env(SCAN_NUCLEI="false", SCAN_NETEXEC="false")
    monkeypatch.setattr(nuclei_scan, "check_host", lambda *a: pytest.fail("nuclei must not run"))
    monkeypatch.setattr(netexec_check, "check_host", lambda *a: pytest.fail("nxc must not run"))
    assert engine.run_scan([META_IP])["meta"]["summary"]["tool_findings"] == 0


def test_a_crashing_tool_never_breaks_the_scan(lab, set_env, monkeypatch, audit_actions):
    set_env(SCAN_NUCLEI="true", SCAN_NETEXEC="true")

    def boom(*a):
        raise RuntimeError("tool crashed")
    monkeypatch.setattr(nuclei_scan, "check_host", boom)
    monkeypatch.setattr(netexec_check, "check_host", boom)
    r = engine.run_scan([META_IP])
    assert r["hosts"][0]["vulnerabilities"] and "nuclei_scan.error" in audit_actions()


def test_old_database_still_stores_cve_findings(lab, supa, set_env, monkeypatch):
    """Before migration 006: tool findings are skipped, CVE findings still saved."""
    from tests import fakes
    set_env(SCAN_NETEXEC="true")
    monkeypatch.setattr(netexec_check, "binary", lambda: "nxc")
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw: Done(SMB_INFO))
    from tests.fakes import FakeNmap
    lab["nmap"] = FakeNmap({META_IP: dict(SAMBA)})
    real = fakes._Query.execute

    def old_db(self):
        if self._table == "vulnerabilities" and self._op in ("insert", "update") and \
                "finding_key" in (self._payload or {}):
            raise RuntimeError("column finding_key does not exist")
        return real(self)
    monkeypatch.setattr(fakes._Query, "execute", old_db)
    engine.run_scan([META_IP])
    rows = supa.rows("vulnerabilities")
    assert rows and all(r.get("cve_id") for r in rows)


def test_mitre_maps_tool_findings():
    from reports import mitre_mapping
    ids = {t["technique_id"] for t in mitre_mapping.map_host({"ip": META_IP, "services": [],
           "vulnerabilities": [{"finding_key": "netexec:smb-signing-not-required"},
                               {"finding_key": "netexec:smb-anonymous-share-read"},
                               {"finding_key": "netexec:rdp-nla-disabled"}]})}
    assert {"T1557.001", "T1135", "T1039", "T1021.001"} <= ids
