"use client";
import { useEffect, useState } from "react";
import { useSession } from "@/components/AuthGate";
import Topbar from "@/components/Topbar";
import ConfigNotice from "@/components/ConfigNotice";
import { useTable } from "@/lib/useData";
import { api } from "@/lib/api";
import { Empty } from "@/lib/ui";
import { ShieldCheck, ShieldX, RotateCcw, CheckCircle2 } from "lucide-react";

const STATUS_CLS: Record<string, string> = {
  planned: "text-muted",
  dry_run: "text-info",
  approved: "text-accent",
  executing: "text-medium",
  succeeded: "text-low",
  failed: "text-critical",
  rolled_back: "text-high",
};

export default function RemediationPage() {
  const { rows } = useTable<any>("remediations", { orderBy: "created_at" });
  const [active, setActive] = useState<any>(null);
  const [adminId, setAdminId] = useState("");
  const session = useSession();
  useEffect(() => {
    if (session) setAdminId(session.user.id);
  }, [session]);
  const [totp, setTotp] = useState("");
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);

  async function approve() {
    if (!active) return;
    setBusy(true);
    setMsg("");
    try {
      await api.approveRemediation(active.id, adminId, totp);
      setMsg(
        "Approved + armed. The worker will execute, then re-scan to verify.",
      );
      setActive(null);
      setTotp("");
    } catch (e: any) {
      setMsg(`Refused: ${e.message}`);
    } finally {
      setBusy(false);
    }
  }
  async function rollback() {
    if (!active) return;
    setBusy(true);
    setMsg("");
    try {
      await api.rollbackRemediation(active.id, adminId, totp);
      setMsg("Rolled back. The host is back to its previous state.");
      setActive(null);
      setTotp("");
    } catch (e: any) {
      setMsg(`Refused: ${e.message}`);
    } finally {
      setBusy(false);
    }
  }
  async function reject() {
    if (!active) return;
    setBusy(true);
    setMsg("");
    try {
      await api.rejectRemediation(
        active.id,
        adminId,
        "rejected from dashboard",
      );
      setMsg("Rejected.");
      setActive(null);
    } catch (e: any) {
      setMsg(`Error: ${e.message}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <Topbar title="Safe Remediation" />
      <div className="p-6 space-y-4">
        <ConfigNotice />
        <div className="card border-accent/30 bg-accent/5">
          <div className="text-sm font-semibold flex items-center gap-2">
            <ShieldCheck size={16} className="text-accent" /> Safety gate
          </div>
          <p className="text-xs text-muted mt-1">
            Every fix passes: <b>allowlist</b> → <b>dry-run preview</b> →{" "}
            <b>admin approval</b> →<b> TOTP 2FA</b> → execute → verify on the
            host → <b>auto-rollback if it fails</b>. Changes only touch
            allowlisted lab hosts.
          </p>
        </div>

        <div className="grid lg:grid-cols-2 gap-4">
          <div className="card p-0 overflow-hidden">
            <table className="w-full">
              <thead className="bg-panel2">
                <tr>
                  <th className="th">Action</th>
                  <th className="th">Status</th>
                  <th className="th">Verified</th>
                  <th className="th"></th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.id} className="hover:bg-panel2/50">
                    <td className="td">
                      <div className="font-mono text-xs">{r.action_type}</div>
                      <div className="text-xs text-muted">
                        {JSON.stringify(r.action_params)}
                      </div>
                    </td>
                    <td className="td">
                      <span
                        className={`text-sm font-semibold ${STATUS_CLS[r.status] || ""}`}
                      >
                        {r.status}
                      </span>
                    </td>
                    <td className="td">
                      {r.verified_fixed === true ? (
                        <CheckCircle2 size={16} className="text-low" />
                      ) : r.verified_fixed === false ? (
                        <span className="text-xs text-high">not verified</span>
                      ) : (
                        "–"
                      )}
                    </td>
                    <td className="td">
                      {r.status === "dry_run" && (
                        <button
                          className="btn"
                          onClick={() => {
                            setActive(r);
                            setMsg("");
                          }}
                        >
                          Review
                        </button>
                      )}
                      {["succeeded", "failed", "rolled_back"].includes(
                        r.status,
                      ) && (
                        <button
                          className="btn"
                          onClick={() => {
                            setActive(r);
                            setMsg("");
                          }}
                        >
                          Details
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!rows.length && (
              <Empty msg="No remediations yet. Open Tickets and press Fix to create one." />
            )}
          </div>

          <div className="card">
            {active && active.status !== "dry_run" ? (
              <>
                <div className="text-sm font-semibold mb-2">
                  Result —{" "}
                  <span className={STATUS_CLS[active.status] || ""}>
                    {active.status}
                  </span>
                </div>
                <pre className="bg-base border border-edge rounded-lg p-3 text-xs overflow-auto max-h-64 whitespace-pre-wrap">
                  {active.result_output || active.command_preview}
                </pre>
                {active.status === "succeeded" && (
                  <div className="mt-3 space-y-2">
                    <input
                      className="bg-panel2 border border-edge rounded-lg px-3 py-2 text-sm w-full font-mono tracking-widest"
                      placeholder="6-digit TOTP code"
                      value={totp}
                      maxLength={6}
                      onChange={(e) => setTotp(e.target.value)}
                    />
                    <button
                      className="btn btn-danger w-full"
                      onClick={rollback}
                      disabled={busy || totp.length < 6}
                    >
                      <RotateCcw size={15} /> Roll back this change
                    </button>
                  </div>
                )}
              </>
            ) : active ? (
              <>
                <div className="text-sm font-semibold mb-2">
                  Review &amp; approve
                </div>
                <pre className="bg-base border border-edge rounded-lg p-3 text-xs overflow-auto max-h-56 whitespace-pre-wrap">
                  {active.dry_run_output || active.command_preview}
                </pre>
                <div className="mt-3 space-y-2">
                  <input
                    className="bg-panel2 border border-edge rounded-lg px-3 py-2 text-sm w-full"
                    placeholder="admin user id (Supabase uuid)"
                    value={adminId}
                    onChange={(e) => setAdminId(e.target.value)}
                  />
                  <input
                    className="bg-panel2 border border-edge rounded-lg px-3 py-2 text-sm w-full font-mono tracking-widest"
                    placeholder="6-digit TOTP code"
                    value={totp}
                    maxLength={6}
                    onChange={(e) => setTotp(e.target.value)}
                  />
                  <div className="flex gap-2">
                    <button
                      className="btn btn-primary flex-1"
                      onClick={approve}
                      disabled={busy || totp.length < 6}
                    >
                      <ShieldCheck size={15} /> Approve &amp; arm
                    </button>
                    <button
                      className="btn btn-danger"
                      onClick={reject}
                      disabled={busy}
                    >
                      <ShieldX size={15} /> Reject
                    </button>
                  </div>
                  {active.rollback_plan?.cmds && (
                    <div className="text-xs text-muted flex items-center gap-1 mt-1">
                      <RotateCcw size={12} /> Rollback is stored and one click
                      away after execution.
                    </div>
                  )}
                </div>
              </>
            ) : (
              <Empty msg="Select a remediation to review, approve or roll back." />
            )}
            {msg && <div className="mt-3 text-sm text-muted">{msg}</div>}
          </div>
        </div>
      </div>
    </div>
  );
}
