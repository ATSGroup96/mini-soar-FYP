"""
FastAPI gateway — the API the dashboard calls for actions.

Read paths (lists of assets, findings, etc.) go straight from the browser to
Supabase (with RLS). This gateway handles the ACTIONS that must run trusted
server-side Python: scans, patch prioritization and the Fix Impact Preview,
the remediation pipeline (dry-run / approve + TOTP / reject / rollback), TOTP
enrolment, audit-chain verification and PDF reports.

Run (compose does this):
  uvicorn api.main:app --host 0.0.0.0 --port 8000

Authentication: every endpoint except /health needs the dashboard login, sent
as "Authorization: Bearer <Supabase access token>". The caller's identity and
role come from that token (common/auth.py), never from the request body.
  viewer  : read the model, previews, audit check, report
  analyst : + run scans, request fixes (dry-run), test a target
  admin   : + approve / reject / roll back (approve, rollback and scope also need TOTP),
            change asset importance, dependencies and the network scope
"""
from __future__ import annotations

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from common import auth, scope_store
from common.audit import log_event, verify_chain
from common.config import get_settings
from common.db import get_service_client
from soar import approval, prioritization_store, totp_2fa

app = FastAPI(title="Mini-SOAR Gateway", version="1.4")
# bearer tokens (not cookies) carry the login, so a foreign page cannot act for a user
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
    allow_headers=["Authorization", "Content-Type"], allow_credentials=False,
)


def _who(role: str):
    """Dependency: the signed-in caller's profile, with at least `role`."""
    def dep(authorization: str | None = Header(default=None)) -> dict:
        try:
            return auth.require(get_service_client(), authorization, role)
        except auth.AuthError as e:
            raise HTTPException(e.status, str(e))
    return dep


viewer, analyst, admin = _who("viewer"), _who("analyst"), _who("admin")


def _client():
    client = get_service_client()
    if not client:
        raise HTTPException(503, "Supabase not configured")
    return client


def _actor(prof: dict) -> str:
    return prof.get("email") or prof.get("id") or "user"


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
    try:
        from scanner import nuclei_scan, netexec_check
        status["tools"] = {"nuclei": nuclei_scan.available(), "netexec": netexec_check.available()}
    except Exception:
        status["tools"] = {"nuclei": False, "netexec": False}
    return status


@app.get("/health")
def health():
    """Public: the launchers use it to see that the API is up."""
    sc = scope_store.effective_scope()
    return {"ok": True, "authorized": sc["authorized"], "scope_source": sc["source"],
            "scope": [str(n) for n in sc["allowed_ranges"]],
            "cloud": get_service_client() is not None,
            **_engine_status()}


# ----- target readiness (Assets page "Test" button) ---------------------------
@app.get("/targets/{ip}/check")
def target_check(ip: str, prof: dict = Depends(analyst)):
    """Is this host enrolled for auto-fix? Key login + sudo checks, changes nothing."""
    from soar import enroll
    rows = _client().table("assets").select("os_guess").eq("ip", ip).execute().data
    os_guess = rows[0].get("os_guess") if rows else None
    try:
        r = enroll.check_target(ip, os_guess)
    except Exception as e:
        raise HTTPException(400, str(e))
    log_event(_actor(prof), "target.check", ip, {"ready": r["ready"]})
    return r


# ----- network scope (Settings page) -----------------------------------------
@app.get("/scope")
def get_scope(prof: dict = Depends(viewer)):
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
    totp_code: str
    allowed_ranges: list[str]
    deny_hosts: list[str] = []
    authorized: bool = False
    authorization_note: str = ""


@app.post("/scope")
def set_scope(req: ScopeReq, prof: dict = Depends(admin)):
    if scope_store.scope_source() != "dashboard":
        raise HTTPException(400, "SCOPE_SOURCE=env in .env: change the scope in .env")
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
    log_event(_actor(prof), "scope.update", ",".join(req.allowed_ranges),
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
def run_scan(req: ScanReq, prof: dict = Depends(analyst)):
    from scanner import engine
    log_event(_actor(prof), "scan.request", ",".join(req.targets or []) or "scope",
              {"full_ports": req.full_ports})
    try:
        result = engine.run_scan(targets=req.targets, full_ports=req.full_ports)
    except engine.ScanBusy as e:
        raise HTTPException(409, str(e))
    except Exception as e:
        raise HTTPException(400, str(e))
    return {"meta": result["meta"], "uplink": result["uplink"]}


# ----- topology + patch prioritization + Fix Impact Preview ------------------
@app.get("/topology")
def topology(prof: dict = Depends(viewer)):
    """Hosts, their components (OS + services) and the dependencies between them."""
    return prioritization_store.topology(_client())


@app.get("/prioritization")
def prioritization(prof: dict = Depends(viewer)):
    """Components, dependencies, component risk (ours + the paper's baseline),
    ranked fixes, and how accurate past Fix Impact Previews were."""
    return prioritization_store.overview(_client())


class PreviewReq(BaseModel):
    target_ip: str
    fix: dict | None = None          # {type: block_port|stop_service|disable_account|patch_cve, ...}
    fixes: list[dict] | None = None  # several fixes previewed together


@app.post("/fix-preview")
def fix_preview(req: PreviewReq, prof: dict = Depends(viewer)):
    fixes = list(req.fixes or []) + ([req.fix] if req.fix else [])
    if not fixes:
        raise HTTPException(400, "give 'fix' or 'fixes'")
    try:
        return prioritization_store.fix_preview(_client(), req.target_ip.strip(),
                                                fixes if len(fixes) > 1 else fixes[0])
    except KeyError as e:
        raise HTTPException(404, str(e).strip("'\""))


def _need_migration(e: Exception):
    return HTTPException(409, f"Could not save. Run {prioritization_store.MIGRATION} "
                              f"in Supabase first. ({str(e)[:120]})")


class ImportanceReq(BaseModel):
    asset_ip: str
    importance: str             # critical | normal | low


@app.post("/prioritization/importance")
def set_importance(req: ImportanceReq, prof: dict = Depends(admin)):
    try:
        return prioritization_store.set_importance(_client(), req.asset_ip,
                                                   req.importance.strip().lower(), _actor(prof))
    except ValueError as e:
        raise HTTPException(400, str(e))
    except LookupError as e:
        raise HTTPException(404, str(e))
    except Exception as e:
        raise _need_migration(e)


class DependencyReq(BaseModel):
    from_component: str         # "IP|os" or "IP|port"  (this one depends on ...)
    to_component: str           # ... this one
    rule: str = "network"       # embedding | interaction | data | network
    enabled: bool = True        # false = hide an automatic dependency
    note: str = ""


@app.post("/prioritization/dependency")
def set_dependency(req: DependencyReq, prof: dict = Depends(admin)):
    try:
        return prioritization_store.set_dependency(_client(), req.from_component,
                                                   req.to_component, req.rule.strip().lower(),
                                                   req.enabled, req.note, _actor(prof))
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise _need_migration(e)


class DependencyRemoveReq(BaseModel):
    id: str


@app.post("/prioritization/dependency/remove")
def remove_dependency(req: DependencyRemoveReq, prof: dict = Depends(admin)):
    try:
        return {"removed": prioritization_store.remove_dependency(_client(), req.id,
                                                                  _actor(prof))}
    except Exception as e:
        raise HTTPException(409, str(e)[:200])


# ----- remediation -----------------------------------------------------------
class RemReq(BaseModel):
    ticket_id: str
    asset_ip: str
    action_type: str
    params: dict


@app.post("/remediation/request")
def remediation_request(req: RemReq, prof: dict = Depends(analyst)):
    try:
        return approval.create_request(req.ticket_id, req.asset_ip,
                                       req.action_type, req.params, prof["id"])
    except Exception as e:
        raise HTTPException(400, str(e))


class ApproveReq(BaseModel):
    remediation_id: str
    totp_code: str


@app.post("/remediation/approve")
def remediation_approve(req: ApproveReq, prof: dict = Depends(admin)):
    try:
        return approval.approve_and_arm(req.remediation_id, prof, req.totp_code)
    except PermissionError as e:
        raise HTTPException(403, str(e))


@app.post("/remediation/rollback")
def remediation_rollback(req: ApproveReq, prof: dict = Depends(admin)):
    try:
        return approval.rollback_with_totp(req.remediation_id, prof, req.totp_code)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except Exception as e:
        raise HTTPException(400, str(e))


class RejectReq(BaseModel):
    remediation_id: str
    reason: str = ""


@app.post("/remediation/reject")
def remediation_reject(req: RejectReq, prof: dict = Depends(admin)):
    try:
        return approval.reject(req.remediation_id, prof, req.reason)
    except PermissionError as e:
        raise HTTPException(403, str(e))


# ----- TOTP enrolment (always for the signed-in user only) -------------------
class EnrollReq(BaseModel):
    current_code: str = ""      # needed only to REPLACE an existing 2FA setup


@app.post("/totp/enroll")
def totp_enroll(req: EnrollReq, prof: dict = Depends(viewer)):
    if prof.get("totp_enrolled") and prof.get("totp_secret"):
        # replacing 2FA needs proof of the current one
        try:
            valid = totp_2fa.verify(totp_2fa.open_secret(prof["totp_secret"]), req.current_code)
        except Exception:
            valid = False
        if not valid:
            log_event(_actor(prof), "totp.reenroll_refused", prof["id"])
            raise HTTPException(
                403, "2FA is already set up for this user. Enter a current 6-digit code to "
                     "replace it, or reset it on the engine PC: run.bat totp-reset <email>")
    secret = totp_2fa.new_secret()
    uri = totp_2fa.provisioning_uri(secret, prof.get("email", "user"))
    _client().table("profiles").update({
        "totp_secret": totp_2fa.seal_secret(secret), "totp_enrolled": True,
    }).eq("id", prof["id"]).execute()
    log_event(_actor(prof), "totp.enroll", prof["id"])
    return {"qr": totp_2fa.qr_png_base64(uri), "otpauth_uri": uri}


# ----- audit + reports -------------------------------------------------------
@app.get("/audit/verify")
def audit_verify(prof: dict = Depends(viewer)):
    """Re-check the audit hash chain and the signatures of the stored scan bundles."""
    from scanner.uplink import verify_stored_bundles
    ok, n, msg = verify_chain()
    return {"ok": ok, "entries": n, "message": msg, "bundles": verify_stored_bundles()}


@app.get("/report/latest.pdf")
def report_pdf(prof: dict = Depends(viewer)):
    from fastapi.responses import FileResponse
    from reports.pdf_report import build_latest_report
    path = build_latest_report()
    log_event(_actor(prof), "report.download", "", {})
    return FileResponse(path, media_type="application/pdf",
                        filename="mini-soar-report.pdf")
