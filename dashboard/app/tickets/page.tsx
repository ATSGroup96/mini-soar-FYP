"use client";
import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import Topbar from "@/components/Topbar";
import ConfigNotice from "@/components/ConfigNotice";
import { useSession } from "@/components/AuthGate";
import { useTable } from "@/lib/useData";
import { api } from "@/lib/api";
import { SeverityBadge, Empty } from "@/lib/ui";
import { Wand2 } from "lucide-react";

function slaLeft(due?: string) {
  if (!due) return { text: "–", cls: "text-muted" };
  const ms = new Date(due).getTime() - Date.now();
  const h = Math.round(ms / 3.6e6);
  if (ms < 0) return { text: `overdue ${Math.abs(h)}h`, cls: "text-critical" };
  if (h < 8) return { text: `${h}h left`, cls: "text-high" };
  return { text: `${h}h left`, cls: "text-low" };
}

const STATUS_CLS: Record<string, string> = {
  open: "bg-info/20 text-info border border-info/40",
  in_progress: "bg-medium/20 text-medium border border-medium/40",
  awaiting_approval: "bg-high/20 text-high border border-high/40",
  approved: "bg-accent/20 text-accent border border-accent/40",
  resolved: "bg-low/20 text-low border border-low/40",
  rejected: "bg-panel2 text-muted border border-edge",
  escalated: "bg-critical/20 text-critical border border-critical/40",
};

const ACTIONS = ["block_port", "stop_service", "disable_account"] as const;
const PARAM_OF: Record<string, string> = {
  block_port: "port", stop_service: "service", disable_account: "username",
};

function describe(a: any) {
  if (!a) return "–";
  const p = a.params || {};
  const key = PARAM_OF[a.action_type];
  const v = (key && p[key]) ?? p.port ?? "";
  return `${a.action_type} ${v}${p.os === "windows" ? " (win)" : ""}`;
}

export default function TicketsPage() {
  const { rows } = useTable<any>("tickets", { orderBy: "created_at" });
  const assets = useTable<any>("assets");
  const ipOf = useMemo(() => {
    const m: Record<string, string> = {};
    assets.rows.forEach((a: any) => (m[a.id] = String(a.ip)));
    return m;
  }, [assets.rows]);
  const session = useSession();

  const [active, setActive] = useState<any>(null);
  const [action, setAction] = useState<string>("block_port");
  const [value, setValue] = useState("");
  const [targetOs, setTargetOs] = useState("auto");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const [preview, setPreview] = useState("");

  useEffect(() => {
    if (!active) return;
    const s = active.suggested_action;
    const a = s?.action_type || "block_port";
    setAction(a);
    const p = s?.params || {};
    setValue(String(p[PARAM_OF[a]] ?? ""));
    setTargetOs(p.os || "auto");
    setMsg(""); setPreview("");
  }, [active]);

  async function planFix() {
    if (!active) return;
    const ip = ipOf[active.asset_id];
    if (!ip) { setMsg("This ticket has no asset IP."); return; }
    const params: Record<string, unknown> = { ...(active.suggested_action?.params || {}) };
    Object.keys(PARAM_OF).forEach((k) => delete params[PARAM_OF[k]]);
    params[PARAM_OF[action]] = action === "block_port" ? parseInt(value, 10) : value;
    if (action === "block_port") params.proto = params.proto || "tcp";
    if (targetOs === "auto") delete params.os; else params.os = targetOs;
    setBusy(true); setMsg("");
    try {
      const r = await api.requestRemediation({
        ticket_id: active.id, asset_ip: ip, action_type: action, params,
        requested_by: session?.user.id || "",
      });
      setPreview(r.preview || "");
      setMsg("Dry-run created. An admin can now approve it with 2FA on the Remediation page.");
    } catch (e: any) {
      setMsg(`Refused: ${e.message}`);
    } finally { setBusy(false); }
  }

  return (
    <div>
      <Topbar title="Tickets & SLA" />
      <div className="p-6 space-y-4">
        <ConfigNotice />
        <div className="grid xl:grid-cols-3 gap-4">
          <div className="card p-0 overflow-hidden xl:col-span-2">
            <table className="w-full">
              <thead className="bg-panel2">
                <tr>
                  <th className="th">Title</th><th className="th">Severity</th><th className="th">Status</th>
                  <th className="th">SLA</th><th className="th">Suggested fix</th><th className="th"></th>
                </tr>
              </thead>
              <tbody>
                {rows.map((t) => {
                  const sla = slaLeft(t.sla_due_at);
                  return (
                    <tr key={t.id} className={`hover:bg-panel2/50 ${active?.id === t.id ? "bg-panel2/60" : ""}`}>
                      <td className="td">{t.title}{t.escalated && <span className="ml-2 badge bg-critical/20 text-critical border border-critical/40">escalated</span>}</td>
                      <td className="td"><SeverityBadge level={t.severity} /></td>
                      <td className="td"><span className={`badge ${STATUS_CLS[t.status] || STATUS_CLS.open}`}>{t.status}</span></td>
                      <td className={`td text-sm ${sla.cls}`}>{sla.text}</td>
                      <td className="td font-mono text-xs">{describe(t.suggested_action)}</td>
                      <td className="td">
                        {!["resolved", "rejected"].includes(t.status) && (
                          <button className="btn" onClick={() => setActive(t)}><Wand2 size={14} /> Fix</button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {!rows.length && <Empty msg="No tickets yet. They are created automatically after each scan." />}
          </div>

          <div className="card">
            {active ? (
              <>
                <div className="text-sm font-semibold mb-1">Plan a fix</div>
                <div className="text-xs text-muted mb-3">{active.title} — {ipOf[active.asset_id] || "?"}</div>
                {active.suggested_action?.reason && (
                  <div className="text-xs mb-3 p-2 rounded-lg bg-accent/10 border border-accent/30">
                    <b>Auto-suggested:</b> {active.suggested_action.reason}
                  </div>
                )}
                <div className="flex gap-2 mb-2">
                  <select className="bg-panel2 border border-edge rounded-lg px-2 py-2 text-sm flex-1"
                    value={action} onChange={(e) => { setAction(e.target.value); setValue(""); }}>
                    {ACTIONS.map((a) => <option key={a} value={a}>{a}</option>)}
                  </select>
                  <input className="bg-panel2 border border-edge rounded-lg px-3 py-2 text-sm w-32"
                    placeholder={PARAM_OF[action]} value={value} onChange={(e) => setValue(e.target.value)} />
                </div>
                <div className="flex items-center gap-2 mb-2 text-xs text-muted">
                  Target OS
                  <select className="bg-panel2 border border-edge rounded-lg px-2 py-1 text-sm"
                    value={targetOs} onChange={(e) => setTargetOs(e.target.value)}>
                    <option value="auto">auto (from scan)</option>
                    <option value="linux">linux</option>
                    <option value="windows">windows</option>
                  </select>
                </div>
                <button className="btn btn-primary w-full" onClick={planFix} disabled={busy || !value}>
                  {busy ? "Planning…" : "Create dry-run"}
                </button>
                {preview && (
                  <pre className="mt-3 bg-base border border-edge rounded-lg p-3 text-xs overflow-auto max-h-56 whitespace-pre-wrap">{preview}</pre>
                )}
                {msg && (
                  <div className="mt-3 text-sm text-muted">
                    {msg} {preview && <Link className="text-accent underline" href="/remediation">Open Remediation →</Link>}
                  </div>
                )}
              </>
            ) : (
              <Empty msg="Pick a ticket and press Fix. The agent pre-fills the right playbook." />
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
