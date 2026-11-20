"""
Findings without a CVE -> inputs the risk model already understands.

Nuclei templates (misconfigurations, exposed panels, default logins) and NetExec
posture checks (SMBv1, SMB signing, anonymous shares, RDP without NLA, WinRM
over HTTP) often have no CVE id, so they have no CVSS, EPSS or KEV value of
their own. To score them with the SAME model as CVE findings (same 10 features,
no retraining) each one gets:

  * cvss_score  - the template's own CVSS when it has one, otherwise a
                  CVSS-equivalent taken from its severity (table below)
  * epss / KEV  - the real EPSS / CISA-KEV values when the template names a CVE,
                  otherwise 0 / not on KEV (no exploitation data exists for a
                  configuration problem)
  * confidence  - "version-confirmed": these checks observed the problem on the
                  live service; they did not guess it from a version banner
  * default password - a Nuclei "default-login" hit marks the service, exactly
                  like the scanner's own default-credential check

The numbers are a design choice of this project (documented in
docs/PATCH_PRIORITIZATION.md and the report), like the weights of the score.
"""
from __future__ import annotations

# Nuclei / generic severity -> CVSS-equivalent (middle of the CVSS v3 band)
SEVERITY_CVSS = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0,
                 "info": 0.0, "unknown": 0.0}


def severity_from_cvss(score: float | None) -> str:
    if score is None:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


# NetExec read-only checks: key -> (title, CVSS-equivalent, why)
NETEXEC_CHECKS = {
    "netexec:smbv1-enabled": (
        "SMBv1 enabled", 8.1,
        "SMBv1 is the protocol attacked by EternalBlue / WannaCry (MS17-010). "
        "Microsoft has deprecated it."),
    "netexec:smb-signing-not-required": (
        "SMB signing not required", 6.5,
        "Without required signing, SMB authentication can be relayed (NTLM relay)."),
    "netexec:smb-null-session": (
        "SMB anonymous (null session) login allowed", 5.3,
        "Anyone on the network can log in to SMB without a password."),
    "netexec:smb-anonymous-share-read": (
        "SMB share readable without a password", 7.5,
        "Files on this share can be read by anyone on the network."),
    "netexec:smb-anonymous-share-write": (
        "SMB share writable without a password", 9.1,
        "Anyone on the network can change or plant files on this share."),
    "netexec:rdp-nla-disabled": (
        "RDP without Network Level Authentication", 7.0,
        "Without NLA the RDP login screen is reachable before authentication "
        "(pre-auth attack surface such as BlueKeep, CVE-2019-0708)."),
    "netexec:winrm-http": (
        "WinRM listening on HTTP (5985)", 4.3,
        "Remote management on plain HTTP; prefer HTTPS (5986)."),
}


def _intel(conn, cve_id: str) -> dict:
    """CVSS / EPSS / KEV for a CVE from the offline database (empty if unknown)."""
    if not conn or not cve_id:
        return {}
    out: dict = {}
    try:
        row = conn.execute("select cvss_score,cvss_vector,severity,description from cves "
                           "where cve_id=?", (cve_id,)).fetchone()
        if row:
            out.update(cvss_score=row["cvss_score"], cvss_vector=row["cvss_vector"],
                       severity=row["severity"], description=row["description"])
        e = conn.execute("select epss,percentile from epss where cve_id=?", (cve_id,)).fetchone()
        if e:
            out.update(epss_score=e["epss"], epss_percentile=e["percentile"])
        k = conn.execute("select due_date from kev where cve_id=?", (cve_id,)).fetchone()
        out["in_kev"] = bool(k)
        if k:
            out["kev_due_date"] = k["due_date"]
    except Exception:
        pass
    return out


def to_vuln(f: dict, conn=None, watch: set | None = None) -> dict:
    """One Nuclei / NetExec finding -> a vulnerability dict the rest of the
    pipeline (ML score, tickets, prioritization, report) can use."""
    cve = (f.get("cve_id") or "").upper() or None
    sev = (f.get("severity") or "").lower()
    cvss = f.get("cvss_score")
    if cvss is None:
        cvss = SEVERITY_CVSS.get(sev, 0.0)
    v = {
        "cve_id": cve, "source": f["source"], "finding_key": f["finding_key"],
        "title": f.get("title") or f["finding_key"], "port": f.get("port"),
        "cvss_score": float(cvss), "cvss_vector": f.get("cvss_vector") or "",
        "severity": sev if sev in SEVERITY_CVSS and sev != "unknown" else severity_from_cvss(cvss),
        "epss_score": 0.0, "epss_percentile": 0.0, "in_kev": False, "kev_due_date": None,
        "description": f.get("description") or "", "evidence": (f.get("evidence") or "")[:1000],
        "product": "", "version": "", "confidence": "version-confirmed",
        "on_watchlist": False, "ml_reasons": [],
    }
    if cve:
        intel = _intel(conn, cve)
        for k in ("epss_score", "epss_percentile", "in_kev", "kev_due_date"):
            if intel.get(k) is not None:
                v[k] = intel[k]
        if f.get("cvss_score") is None and intel.get("cvss_score") is not None:
            v["cvss_score"] = float(intel["cvss_score"])
            v["severity"] = intel.get("severity") or severity_from_cvss(v["cvss_score"])
        if not v["description"]:
            v["description"] = intel.get("description") or ""
        if watch and cve in watch:
            from .features import WATCHLIST_REASON
            v["on_watchlist"] = True
            v["ml_reasons"].append(WATCHLIST_REASON)
    return v


def merge_into_host(host_result: dict, findings: list[dict]) -> int:
    """Add tool findings to host_result["vulnerabilities"].

    * a finding that names a CVE the version matcher already found on the same
      port does not create a second row: the existing CVE row becomes
      "version-confirmed" (seen live) and keeps the tool's evidence
    * a Nuclei default-login hit marks the service has_default_cred
    Returns how many new findings were added."""
    from common.db import get_intel_db
    try:
        from intel.match import _watchlist_cves
        watch = _watchlist_cves()
    except Exception:
        watch = set()
    try:
        conn = get_intel_db()
    except Exception:
        conn = None
    vulns = host_result.setdefault("vulnerabilities", [])
    by_cve_port = {(v.get("cve_id"), v.get("port")): v for v in vulns if v.get("cve_id")}
    seen = {(v.get("finding_key") or v.get("cve_id"), v.get("port")) for v in vulns}
    added = 0
    try:
        for f in findings:
            if f.get("default_login") and f.get("port") is not None:
                for s in host_result.get("services", []):
                    if s.get("port") == f["port"]:
                        s["has_default_cred"] = True
            v = to_vuln(f, conn, watch)
            twin = by_cve_port.get((v["cve_id"], v["port"])) if v["cve_id"] else None
            if twin is not None:
                twin["confidence"] = "version-confirmed"
                twin["evidence"] = (f"confirmed by {v['source']} ({v['finding_key']})"
                                    + (f": {v['evidence']}" if v["evidence"] else ""))[:1000]
                continue
            key = (v["finding_key"], v["port"])
            if key in seen:
                continue
            seen.add(key)
            vulns.append(v)
            added += 1
    finally:
        if conn is not None:
            conn.close()
    return added
