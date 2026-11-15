"""
FastAPI gateway — the API the dashboard calls for actions.

Read paths (lists of assets, vulns, etc.) go straight from the browser to
Supabase (with RLS). This gateway handles the ACTIONS that must run trusted
server-side Python: trigger scans, build the attack graph, run what-if
simulations, the remediation approval pipeline (dry-run / approve+TOTP /
rollback), TOTP enrollment, audit-chain verification, and PDF reports.

Run (compose does this):
  uvicorn api.main:app --host 0.0.0.0 --port 8000

Auth note (lab): endpoints that change state expect an admin's Supabase user id
+ a TOTP code where relevant; the gateway re-checks role + 2FA server-side via
soar.approval, so it never trusts the client alone.
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from common.config import get_settings
from common.audit import verify_chain
from common.db import get_service_client
from common import scope_store
from common.audit import log_event
from soar import approval, digital_twin, attack_path, totp_2fa

app = FastAPI(title="Mini-SOAR Gateway", version="1.0")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)


def _profile(user_id: str) -> dict:
    client = get_service_client()
    if not client:
        raise HTTPException(503, "Supabase not configured")
    rows = client.table("profiles").select("*").eq("id", user_id).execute().data
    if not rows:
        raise HTTPException(404, "profile not found")
    return rows[0]


def _engine_status() -> dict:
    """What the scoring and CVE data rest on right now (shown on Settings)."""
    status: dict = {}
    try:
        from ml.risk_score import model_status
        status["model"] = model_status()
    except Exception as e:
        status["model"] = {"engine": "unavailable", "trained": False, "error": str(e)[:120]}
    try:
        from intel.cli import intel_status
        status["intel"] = intel_status()
    except Exception as e:
        status["intel"] = {"cves": 0, "kev": 0, "epss": 0, "error": str(e)[:120]}
    try:
        from common import webpush
        status["push"] = {"configured": webpush.is_configured()}
    except Exception:
        status["push"] = {"configured": False}
    return status


@app.get("/health")
def health():
    sc = scope_store.effective_scope()
    return {"ok": True, "authorized": sc["authorized"], "scope_source": sc["source"],
            "scope": [str(n) for n in sc["allowed_ranges"]],
            "cloud": get_service_client() is not None,
            **_engine_status()}


# ----- target readiness (Assets page "Test" button) ---------------------------
@app.get("/targets/{ip}/check")
def target_check(ip: str):
    """Is this host enrolled for auto-fix? Key login + sudo checks, changes nothing."""
    from soar import enroll
    os_guess = None
    client = get_service_client()
    if client:
        rows = client.table("assets").select("os_guess").eq("ip", ip).execute().data
        os_guess = rows[0].get("os_guess") if rows else None
    try:
        r = enroll.check_target(ip, os_guess)
    except Exception as e:
        raise HTTPException(400, str(e))
    log_event("dashboard", "target.check", ip, {"ready": r["ready"]})
    return r


# ----- network scope (Settings page) -----------------------------------------
@app.get("/scope")
def get_scope():
    """Current scope + the networks the engine is connected to (suggestions)."""
    sc = scope_store.effective_scope(force=True)
    ifaces = scope_store.engine_interfaces()
    return {
        "source": sc["source"], "authorized": sc["authorized"], "note": sc["note"],
        "updated_at": sc["updated_at"],
        "allowed_ranges": [str(n) for n in sc["allowed_ranges"]],
        "deny_hosts": sc["deny_hosts"],
        "env_master_switch": get_settings().authorized_lab_only,
        "editable": scope_store.scope_source() == "dashboard",
        "ceiling": [str(n) for n in scope_store.ceiling()],
        "max_prefix": scope_store.MIN_PREFIX,
        "detected": ifaces,
        "engine_ips": [i["ip"] for i in ifaces],
    }


class ScopeReq(BaseModel):
    admin_user_id: str
    totp_code: str
    allowed_ranges: list[str]
    deny_hosts: list[str] = []
    authorized: bool = False
    authorization_note: str = ""


@app.post("/scope")
def set_scope(req: ScopeReq):
    if scope_store.scope_source() != "dashboard":
        raise HTTPException(400, "SCOPE_SOURCE=env in .env: change the scope in .env")
    prof = _profile(req.admin_user_id)
    try:
        approval._check_admin_totp(prof, req.totp_code, "change the network scope",
                                   "scope_config", event="scope.totp_fail")
    except PermissionError as e:
        raise HTTPException(403, str(e))
    old = scope_store.effective_scope(force=True)
    try:
        new = scope_store.save_scope(req.allowed_ranges, req.deny_hosts, req.authorized,
                                     req.authorization_note, prof["id"])
    except (ValueError, RuntimeError) as e:
        raise HTTPException(400, str(e))
    log_event(prof.get("email", "admin"), "scope.update", ",".join(req.allowed_ranges),
              {"old": [str(n) for n in old["allowed_ranges"]],
               "new": [str(n) for n in new["allowed_ranges"]],
               "deny": new["deny_hosts"], "authorized": new["authorized"],
               "note": new["note"]})
    return {"allowed_ranges": [str(n) for n in new["allowed_ranges"]],
            "deny_hosts": new["deny_hosts"], "authorized": new["authorized"]}


# ----- scanning --------------------------------------------------------------
class ScanReq(BaseModel):
    targets: list[str] | None = None
    full_ports: bool = False


@app.post("/scan")
def run_scan(req: ScanReq):
    from scanner import engine
    try:
        result = engine.run_scan(targets=req.targets, full_ports=req.full_ports)
    except engine.ScanBusy as e:
        raise HTTPException(409, str(e))
    except Exception as e:
        raise HTTPException(400, str(e))
    return {"meta": result["meta"], "uplink": result["uplink"]}


# ----- attack graph + what-if ------------------------------------------------
def _load_hosts() -> list[dict]:
    """Reassemble host dicts (assets + open services + open vulns) from Supabase."""
    client = get_service_client()
    if not client:
        return []
    assets = client.table("assets").select("*").execute().data
    hosts = []
    for a in assets:
        svc = client.table("services").select("*").eq("asset_id", a["id"]).execute().data
        svc = [s for s in svc if (s.get("state") or "open") == "open"]
        port_of = {s["id"]: s["port"] for s in svc}
        vulns = (client.table("vulnerabilities").select("*").eq("asset_id", a["id"])
                 .eq("status", "open").execute().data)
        seen, vlist = set(), []
        for v in vulns:
            port = port_of.get(v.get("service_id"))
            if v.get("service_id") and port is None:
                continue  # its service is closed now
            key = (v["cve_id"], port)
            if key in seen:
                continue  # one entry per CVE per port
            seen.add(key)
            vlist.append({"cve_id": v["cve_id"], "cvss_score": v.get("cvss_score"),
                          "epss_score": v.get("epss_score"),
                          "epss_percentile": v.get("epss_percentile"),
                          "in_kev": v.get("in_kev"), "port": port,
                          "confidence": v.get("confidence") or "version-confirmed"})
        hosts.append({
            "ip": a["ip"], "hostname": a.get("hostname"),
            "os_guess": a.get("os_guess"), "is_rogue": a.get("is_rogue"),
            "risk_score": a.get("risk_score") or 0,
            "risk_grade": a.get("risk_grade") or "A",
            "services": [{"port": s["port"], "service_name": s.get("service_name"),
                          "has_default_cred": s.get("has_default_cred")} for s in svc],
            "vulnerabilities": vlist,
        })
    return hosts


@app.get("/attack-graph")
def attack_graph():
    hosts = _load_hosts()
    g = attack_path.build_graph(hosts)
    return {"graph": g, "paths": attack_path.rank_paths(g)}


class WhatIfReq(BaseModel):
    target_ip: str
    fix: dict | None = None          # {type: block_port|stop_service|patch_cve, ...}
    fixes: list[dict] | None = None  # several fixes simulated together


@app.post("/whatif")
def whatif(req: WhatIfReq):
    fixes = list(req.fixes or []) + ([req.fix] if req.fix else [])
    if not fixes:
        raise HTTPException(400, "give 'fix' or 'fixes'")
    hosts = _load_hosts()
    target = req.target_ip.strip().split("/")[0]
    host = next((h for h in hosts if str(h["ip"]).split("/")[0] == target), None)
    if not host:
        known = ", ".join(sorted(str(h["ip"]).split("/")[0] for h in hosts)) or "none - run a scan first"
        raise HTTPException(404, f"asset {target} not found. Scanned hosts: {known}")
    return {
        "host": digital_twin.simulate_host(host, fixes),
        "network": digital_twin.simulate_network(hosts, str(host["ip"]), fixes),
    }


# ----- remediation -----------------------------------------------------------
class RemReq(BaseModel):
    ticket_id: str
    asset_ip: str
    action_type: str
    params: dict
    requested_by: str


@app.post("/remediation/request")
def remediation_request(req: RemReq):
    try:
        return approval.create_request(req.ticket_id, req.asset_ip,
                                        req.action_type, req.params, req.requested_by)
    except Exception as e:
        raise HTTPException(400, str(e))


class ApproveReq(BaseModel):
    remediation_id: str
    admin_user_id: str
    totp_code: str


@app.post("/remediation/approve")
def remediation_approve(req: ApproveReq):
    prof = _profile(req.admin_user_id)
    try:
        return approval.approve_and_arm(req.remediation_id, prof, req.totp_code)
    except PermissionError as e:
        raise HTTPException(403, str(e))


class RollbackReq(BaseModel):
    remediation_id: str
    admin_user_id: str
    totp_code: str


@app.post("/remediation/rollback")
def remediation_rollback(req: RollbackReq):
    prof = _profile(req.admin_user_id)
    try:
        return approval.rollback_with_totp(req.remediation_id, prof, req.totp_code)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except Exception as e:
        raise HTTPException(400, str(e))


class RejectReq(BaseModel):
    remediation_id: str
    admin_user_id: str
    reason: str = ""


@app.post("/remediation/reject")
def remediation_reject(req: RejectReq):
    prof = _profile(req.admin_user_id)
    try:
        return approval.reject(req.remediation_id, prof, req.reason)
    except PermissionError as e:
        raise HTTPException(403, str(e))


# ----- TOTP enrollment -------------------------------------------------------
class EnrollReq(BaseModel):
    user_id: str
    current_code: str = ""      # needed only to REPLACE an existing 2FA setup


@app.post("/totp/enroll")
def totp_enroll(req: EnrollReq):
    prof = _profile(req.user_id)
    if prof.get("totp_enrolled") and prof.get("totp_secret"):
        # replacing 2FA needs proof of the current one; otherwise anyone who
        # can reach the API could take over an admin's second factor
        try:
            valid = totp_2fa.verify(totp_2fa.open_secret(prof["totp_secret"]), req.current_code)
        except Exception:
            valid = False
        if not valid:
            log_event(prof.get("email", "user"), "totp.reenroll_refused", req.user_id)
            raise HTTPException(
                403, "2FA is already set up for this user. Enter a current 6-digit code to "
                     "replace it, or reset it on the engine PC: run.bat totp-reset <email>")
    secret = totp_2fa.new_secret()
    uri = totp_2fa.provisioning_uri(secret, prof.get("email", "user"))
    client = get_service_client()
    client.table("profiles").update({
        "totp_secret": totp_2fa.seal_secret(secret), "totp_enrolled": True,
    }).eq("id", req.user_id).execute()
    log_event(prof.get("email", "user"), "totp.enroll", req.user_id)
    return {"qr": totp_2fa.qr_png_base64(uri), "otpauth_uri": uri}


# ----- audit + reports -------------------------------------------------------
@app.get("/audit/verify")
def audit_verify():
    """Re-check the audit hash chain and the signatures of the stored scan bundles."""
    from scanner.uplink import verify_stored_bundles
    ok, n, msg = verify_chain()
    return {"ok": ok, "entries": n, "message": msg, "bundles": verify_stored_bundles()}


@app.get("/report/latest.pdf")
def report_pdf():
    from fastapi.responses import FileResponse
    from reports.pdf_report import build_latest_report
    path = build_latest_report()
    return FileResponse(path, media_type="application/pdf",
                        filename="mini-soar-report.pdf")
