"use client";
import { useState } from "react";
import Topbar from "@/components/Topbar";
import ConfigNotice from "@/components/ConfigNotice";
import FixImpact, { FixCheck } from "@/components/FixImpact";
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
  const [activeId, setActiveId] = useState<string | null>(null);
  const active = rows.find((r) => r.id === activeId) || null;   // stays live (realtime)
  const [totp, setTotp] = useState("");
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);

  async function run(fn: () => Promise<any>, ok: string) {
    if (!active) return;
    setBusy(true);
    setMsg("");
    try {
      await fn();
      setMsg(ok);
      setTotp("");
    } catch (e: any) {
      setMsg(`Refused: ${e.message}`);
    } finally {
      setBusy(false);
    }
  }
  const approve = () => run(() => api.approveRemediation(active.id, totp),
    "Approved + armed. The worker executes it, checks the host, and the next scan checks the preview.");
  const rollback = () => run(() => api.rollbackRemediation(active.id, totp),
    "Rolled back. The host is back to its previous state.");
  const reject = () => run(() => api.rejectRemediation(active.id, "rejected from dashboard"), "Rejected.");

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
            Every fix passes: <b>allowlist</b> → <b>dry-run preview</b> + <b>Fix Impact Preview</b> →{" "}
            <b>admin approval</b> → <b>TOTP 2FA</b> (each code works once) → execute → post-fix check
            on the host → <b>auto-rollback if it fails</b> → next scan compares the result with the
            prediction. Changes only touch allowlisted lab hosts.
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
                  <tr key={r.id} className={`hover:bg-panel2/50 ${r.id === activeId ? "bg-panel2/60" : ""}`}>
                    <td className="td">
                      <div className="font-mono text-xs">{r.action_type}</div>
                      <div className="text-xs text-muted">{JSON.stringify(r.action_params)}</div>
                    </td>
                    <td className="td">
                      <span className={`text-sm font-semibold ${STATUS_CLS[r.status] || ""}`}>{r.status}</span>
                    </td>
                    <td className="td">
                      {r.verified_fixed === true ? (
                        <CheckCircle2 size={16} className="text-low" />
                      ) : r.verified_fixed === false ? (
                        <span className="text-xs text-high">not verified</span>
                      ) : "–"}
                    </td>
                    <td className="td">
                      <button className="btn" onClick={() => { setActiveId(r.id); setMsg(""); }}>
                        {r.status === "dry_run" ? "Review" : "Details"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!rows.length && <Empty msg="No remediations yet. Open Tickets and press Fix to create one." />}
          </div>

          <div className="card space-y-3">
            {active && active.status !== "dry_run" ? (
              <>
                <div className="text-sm font-semibold">
                  Result — <span className={STATUS_CLS[active.status] || ""}>{active.status}</span>
                </div>
                <pre className="bg-base border border-edge rounded-lg p-3 text-xs overflow-auto max-h-64 whitespace-pre-wrap">
                  {active.result_output || active.command_preview}
                </pre>
                <FixImpact p={active.fix_prediction} title="Fix Impact Preview (as approved)" />
                <FixCheck c={active.fix_check} />
                {active.status === "succeeded" && (
                  <div className="space-y-2">
                    <input
                      className="bg-panel2 border border-edge rounded-lg px-3 py-2 text-sm w-full font-mono tracking-widest"
                      placeholder="6-digit TOTP code" value={totp} maxLength={6}
                      onChange={(e) => setTotp(e.target.value)}
                    />
                    <button className="btn btn-danger w-full" onClick={rollback} disabled={busy || totp.length < 6}>
                      <RotateCcw size={15} /> Roll back this change
                    </button>
                  </div>
                )}
              </>
            ) : active ? (
              <>
                <div className="text-sm font-semibold">Review &amp; approve</div>
                <pre className="bg-base border border-edge rounded-lg p-3 text-xs overflow-auto max-h-56 whitespace-pre-wrap">
                  {active.dry_run_output || active.command_preview}
                </pre>
                {active.fix_prediction ? (
                  <FixImpact p={active.fix_prediction} />
                ) : (
                  <div className="text-xs text-muted">
                    No Fix Impact Preview for this fix (run migration 006, or a manual action).
                  </div>
                )}
                <div className="space-y-2">
                  <input
                    className="bg-panel2 border border-edge rounded-lg px-3 py-2 text-sm w-full font-mono tracking-widest"
                    placeholder="6-digit TOTP code" value={totp} maxLength={6}
                    onChange={(e) => setTotp(e.target.value)}
                  />
                  <div className="flex gap-2">
                    <button className="btn btn-primary flex-1" onClick={approve} disabled={busy || totp.length < 6}>
                      <ShieldCheck size={15} /> Approve &amp; arm
                    </button>
                    <button className="btn btn-danger" onClick={reject} disabled={busy}>
                      <ShieldX size={15} /> Reject
                    </button>
                  </div>
                  {active.rollback_plan?.cmds && (
                    <div className="text-xs text-muted flex items-center gap-1">
                      <RotateCcw size={12} /> Rollback is stored and one click away after execution.
                    </div>
                  )}
                </div>
              </>
            ) : (
              <Empty msg="Select a remediation to review, approve or roll back." />
            )}
            {msg && <div className="text-sm text-muted">{msg}</div>}
          </div>
        </div>
      </div>
    </div>
  );
}
