"""
Remediation approval lifecycle (the safe-remediation core).

State machine for a remediation row:
  planned -> dry_run -> approved -> executing -> succeeded | failed -> rolled_back

Gates (all required before execution):
  1. the remediation targets an in-scope asset
  2. a dry-run preview has been generated and shown
  3. an ADMIN approved it (RBAC — enforced in DB RLS + checked here)
  4. a valid TOTP 2FA code was supplied at approval time
These functions are called by the dashboard API routes and the worker.
"""
from __future__ import annotations

from datetime import datetime, timezone


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

from common.allowlist import assert_in_scope
from common.audit import log_event
from common.db import get_service_client
from . import remediation, totp_2fa


def create_request(ticket_id: str, asset_ip: str, action_type: str,
                   params: dict, requested_by: str) -> dict:
    """Create a 'planned' remediation + its dry-run preview. No changes made."""
    assert_in_scope(asset_ip)
    client = get_service_client()
    params = dict(params or {})
    params["target_ip"] = asset_ip          # so the worker always knows the host
    asset_id = None
    if client:
        a = client.table("assets").select("id,os_guess").eq("ip", asset_ip).execute().data
        asset_id = a[0]["id"] if a else None
        if a and "os" not in params:
            # pick Linux or Windows playbooks from the scanner's OS fingerprint
            params["os"] = remediation.os_family(a[0].get("os_guess"))
    plan = remediation.build_plan(action_type, asset_ip, params)
    preview = remediation.dry_run(plan)
    row = {
        "ticket_id": ticket_id, "asset_id": asset_id, "action_type": action_type,
        "action_params": params,
        "command_preview": plan.params.get("_preview_apply") or "\n".join(plan.apply_cmds),
        "dry_run_output": preview,
        "rollback_plan": {"cmds": plan.rollback_cmds},
        "status": "dry_run", "requested_by": requested_by or None,
    }
    if client:
        res = client.table("remediations").insert(row).execute()
        row["id"] = res.data[0]["id"]
        if ticket_id:
            client.table("tickets").update({"status": "awaiting_approval"}).eq(
                "id", ticket_id).execute()
    log_event("analyst", "remediation.request", asset_ip,
              {"action": action_type, "ticket": ticket_id})
    return {"preview": preview, "remediation": row, "rollback": plan.rollback_cmds}


def _check_admin_totp(admin_profile: dict, totp_code: str, what: str, ref: str,
                      event: str | None = None) -> None:
    if admin_profile.get("role") != "admin":
        raise PermissionError(f"Only an admin may {what}.")
    sealed = admin_profile.get("totp_secret")
    if not sealed:
        raise PermissionError(f"Admin has no TOTP enrolled; cannot {what}.")
    if not totp_2fa.verify(totp_2fa.open_secret(sealed), totp_code):
        log_event(admin_profile.get("email", "admin"), event or f"remediation.{what}.totp_fail", ref)
        raise PermissionError("Invalid TOTP code.")


def rollback_with_totp(remediation_id: str, admin_profile: dict, totp_code: str) -> dict:
    """Admin-triggered undo of an executed remediation (needs TOTP too)."""
    _check_admin_totp(admin_profile, totp_code, "rollback", remediation_id)
    client = get_service_client()
    if not client:
        raise RuntimeError("Supabase not configured")
    rows = client.table("remediations").select("*").eq("id", remediation_id).execute().data
    if not rows:
        raise RuntimeError("remediation not found")
    row = rows[0]
    if row.get("status") != "succeeded":
        # failed/rejected ones never changed the host (or were already auto-rolled back)
        raise RuntimeError(f"only an executed remediation can be rolled back (status '{row.get('status')}')")
    params = row.get("action_params") or {}
    ip = params.get("target_ip")
    if not ip:
        raise RuntimeError("remediation has no target_ip")
    plan = remediation.build_plan(row["action_type"], ip, params)
    out = remediation.rollback(plan)
    client.table("remediations").update({
        "status": "rolled_back", "rolled_back_at": _now(), "result_output": out[:4000],
    }).eq("id", remediation_id).execute()
    if row.get("ticket_id"):
        client.table("tickets").update({"status": "in_progress"}).eq(
            "id", row["ticket_id"]).execute()
    log_event(admin_profile.get("email", "admin"), "remediation.rollback.manual", ip,
              {"remediation_id": remediation_id})
    return {"status": "rolled_back", "output": out}


def approve_and_arm(remediation_id: str, admin_profile: dict,
                    totp_code: str) -> dict:
    """
    Admin approves + supplies a TOTP code. On success the row becomes
    'approved' and is picked up by the worker. Enforces RBAC + 2FA here as a
    second layer on top of DB RLS.
    """
    if admin_profile.get("role") != "admin":
        raise PermissionError("Only an admin may approve a remediation.")

    sealed = admin_profile.get("totp_secret")
    if not sealed:
        raise PermissionError("Admin has no TOTP enrolled; cannot approve.")
    secret = totp_2fa.open_secret(sealed)
    if not totp_2fa.verify(secret, totp_code):
        log_event(admin_profile.get("email", "admin"),
                  "remediation.approve.totp_fail", remediation_id)
        raise PermissionError("Invalid TOTP code.")

    client = get_service_client()
    if client:
        cur = (client.table("remediations").select("status,ticket_id")
               .eq("id", remediation_id).execute().data)
        if not cur:
            raise PermissionError("remediation not found")
        if cur[0].get("status") != "dry_run":
            # never re-arm something that already ran, failed or was rejected
            raise PermissionError(
                f"Only a dry-run remediation can be approved (this one is '{cur[0].get('status')}').")
        client.table("remediations").update({
            "status": "approved", "approved_by": admin_profile["id"],
            "approved_at": _now(), "totp_verified": True,
        }).eq("id", remediation_id).execute()
        if cur[0].get("ticket_id"):
            client.table("tickets").update({"status": "approved"}).eq(
                "id", cur[0]["ticket_id"]).execute()
    log_event(admin_profile.get("email", "admin"),
              "remediation.approve", remediation_id, {"totp_verified": True})
    return {"status": "approved", "remediation_id": remediation_id}


def reject(remediation_id: str, admin_profile: dict, reason: str = "") -> dict:
    if admin_profile.get("role") != "admin":
        raise PermissionError("Only an admin may reject a remediation.")
    client = get_service_client()
    if client:
        cur = (client.table("remediations").select("status,ticket_id")
               .eq("id", remediation_id).execute().data)
        if cur and cur[0].get("status") not in ("dry_run", "planned"):
            raise PermissionError(f"cannot reject a remediation in status '{cur[0].get('status')}'")
        client.table("remediations").update(
            {"status": "failed", "result_output": f"Rejected: {reason}"}
        ).eq("id", remediation_id).execute()
        if cur and cur[0].get("ticket_id"):
            client.table("tickets").update({"status": "open"}).eq(
                "id", cur[0]["ticket_id"]).execute()
    log_event(admin_profile.get("email", "admin"), "remediation.reject",
              remediation_id, {"reason": reason})
    return {"status": "rejected"}
