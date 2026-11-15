"""
Remediation worker.

Polls Supabase for remediations in status 'approved' (admin-approved AND
TOTP-verified), executes each through the gated remediation.apply(), then runs
a confirming re-scan to verify the fix and updates the ticket/vuln. All changes
are undoable via the stored rollback plan.

Run (compose does this automatically):
  python -m soar.worker
"""
from __future__ import annotations

import time
from datetime import datetime, timezone

from common.config import assert_authorized_to_run, get_settings
from common.db import get_service_client
from common.audit import log_event
from common.notify import notify
from common import syslog_logger as slog
from . import remediation
from .verify import verify_fix

POLL_SECONDS = 5


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _execute_row(client, row: dict) -> None:
    rid = row["id"]
    asset_ip = row.get("_asset_ip")
    params = row.get("action_params", {}) or {}
    try:
        plan = remediation.build_plan(row["action_type"], asset_ip, params)
    except Exception as e:
        # refused / invalid plan: fail it once instead of retrying forever
        client.table("remediations").update({
            "status": "failed", "result_output": f"plan refused: {e}"[:1000],
        }).eq("id", rid).execute()
        log_event("engine", "remediation.plan_refused", asset_ip or "",
                  {"remediation_id": rid, "error": str(e)[:300]})
        notify(client, "high", "Remediation refused", str(e)[:200], "/remediation")
        return

    client.table("remediations").update({"status": "executing"}).eq("id", rid).execute()
    try:
        out = remediation.apply(plan, approved=True,
                                totp_verified=row.get("totp_verified", False))
    except Exception as e:
        msg = f"apply failed: {e}"
        log_event("engine", "remediation.worker.error", asset_ip or "",
                  {"remediation_id": rid, "error": str(e)[:300]})
        slog.send(f"remediation {rid} FAILED: {e}", slog.ERR)
        client.table("remediations").update(
            {"status": "failed", "result_output": msg[:1000]}).eq("id", rid).execute()
        # only undo when a command actually ran on the host (it may be half-changed);
        # a refused gate or an SSH login failure changed nothing
        if isinstance(e, remediation.CommandFailed) and not get_settings().force_dry_run:
            _auto_rollback(client, rid, plan, msg)
        notify(client, "high", "Remediation failed",
                f"{plan.description}: {str(e)[:200]}", "/remediation")
        return

    client.table("remediations").update({
        "status": "succeeded", "executed_at": _now(), "result_output": out[:4000],
    }).eq("id", rid).execute()
    if get_settings().force_dry_run:
        return  # kill-switch on: nothing changed, nothing to verify

    # patch verification on the live host
    try:
        fixed = verify_fix(asset_ip, params, row["action_type"])
    except Exception as e:
        log_event("engine", "remediation.verify.error", asset_ip, {"error": str(e)[:300]})
        fixed = False
    client.table("remediations").update({"verified_fixed": fixed}).eq("id", rid).execute()

    if fixed:
        if row.get("ticket_id"):
            client.table("tickets").update({"status": "resolved"}).eq(
                "id", row["ticket_id"]).execute()
        notify(client, "info", "Remediation applied and verified",
                f"{plan.description} — verified fixed", "/remediation")
        slog.send(f"remediation {rid} succeeded and verified", slog.NOTICE)
    else:
        # the change did not achieve its goal -> undo it automatically
        rb = _auto_rollback(client, rid, plan, "verification failed", out)
        if row.get("ticket_id"):
            client.table("tickets").update({"status": "in_progress"}).eq(
                "id", row["ticket_id"]).execute()
        notify(client, "medium", "Remediation not verified — rolled back",
                f"{plan.description}: fix did not verify; rollback "
                f"{'done' if rb else 'FAILED, check host'}", "/remediation")


def _auto_rollback(client, rid: str, plan, why: str, previous: str = "") -> bool:
    try:
        out = remediation.rollback(plan)
        client.table("remediations").update({
            "status": "rolled_back", "rolled_back_at": _now(),
            "result_output": (f"{previous}\n\n" if previous else "") +
                             f"AUTO-ROLLBACK ({why}):\n{out}"[:3000],
        }).eq("id", rid).execute()
        log_event("engine", "remediation.auto_rollback", plan.target_ip,
                  {"remediation_id": rid, "why": why[:200]})
        return True
    except Exception as e:
        log_event("engine", "remediation.auto_rollback.error", plan.target_ip,
                  {"remediation_id": rid, "error": str(e)[:300]})
        return False


def _resolve_asset_ip(client, row: dict) -> str | None:
    # find the asset ip via the ticket's asset, or action params
    if row.get("action_params", {}).get("target_ip"):
        return row["action_params"]["target_ip"]
    tid = row.get("ticket_id")
    if not tid:
        return None
    t = client.table("tickets").select("asset_id").eq("id", tid).execute().data
    if not t or not t[0].get("asset_id"):
        return None
    a = client.table("assets").select("ip").eq("id", t[0]["asset_id"]).execute().data
    return a[0]["ip"] if a else None


def run_once(client) -> int:
    rows = client.table("remediations").select("*").eq("status", "approved").execute().data
    n = 0
    for row in rows:
        ip = _resolve_asset_ip(client, row)
        if not ip:
            client.table("remediations").update({
                "status": "failed",
                "result_output": "Could not resolve target IP.",
            }).eq("id", row["id"]).execute()
            continue
        row["_asset_ip"] = ip
        _execute_row(client, row)
        n += 1
    return n


def main() -> int:
    assert_authorized_to_run()
    client = get_service_client()
    if not client:
        print("Supabase not configured — worker idle. Configure .env to enable.")
        # idle loop so the container stays up without busy-spinning
        while True:
            time.sleep(60)
    print("SOAR remediation worker started. Waiting for approved remediations...")
    slog.send("SOAR worker online", slog.NOTICE)
    while True:
        try:
            run_once(client)
        except Exception as e:
            slog.send(f"worker loop error: {e}", slog.ERR)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
