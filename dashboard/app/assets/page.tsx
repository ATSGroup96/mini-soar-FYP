"use client";
import { useState } from "react";
import { useSession } from "@/components/AuthGate";
import Topbar from "@/components/Topbar";
import { api } from "@/lib/api";
import ConfigNotice from "@/components/ConfigNotice";
import { useTable } from "@/lib/useData";
import { GradeBadge, RiskBar, Empty } from "@/lib/ui";

export default function AssetsPage() {
  const { rows, loading } = useTable<any>("assets", { orderBy: "risk_score" });
  const [ready, setReady] = useState<Record<string, any>>({});
  const session = useSession();
  const [critMsg, setCritMsg] = useState("");
  const [crit, setCrit] = useState<Record<string, string>>({});

  // digital twin: the admin's importance weight for this asset
  async function setCriticality(ip: string, level: string) {
    setCritMsg("");
    try {
      await api.setCriticality(session?.user?.id || "", ip, level);
      setCrit((c) => ({ ...c, [ip]: level }));
      setCritMsg(`${ip} is now "${level}". The digital twin uses it on the Topology page.`);
    } catch (e: any) {
      setCritMsg(e.message);
    }
  }

  async function test(ip: string) {
    setReady((r) => ({ ...r, [ip]: { busy: true } }));
    try {
      const res = await api.checkTarget(ip);
      setReady((r) => ({ ...r, [ip]: res }));
    } catch (e: any) {
      setReady((r) => ({ ...r, [ip]: { ready: false, error: e.message } }));
    }
  }
  return (
    <div>
      <Topbar title="Assets (CAASM Inventory)" />
      <div className="p-6 space-y-4">
        <ConfigNotice />
        {critMsg && <div className="card text-sm">{critMsg}</div>}
        <div className="card p-0 overflow-hidden">
          <table className="w-full">
            <thead className="bg-panel2">
              <tr>
                <th className="th">IP</th><th className="th">Hostname</th><th className="th">MAC</th>
                <th className="th">OS</th><th className="th">Grade</th><th className="th">Risk</th>
                <th className="th">Status</th><th className="th">Importance</th>
                <th className="th">Last seen</th><th className="th">Auto-fix</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((a) => (
                <tr key={a.id} className="hover:bg-panel2/50">
                  <td className="td font-mono">{a.ip}</td>
                  <td className="td">{a.hostname || "–"}</td>
                  <td className="td font-mono text-xs text-muted">{a.mac || "–"}</td>
                  <td className="td text-xs">{a.os_guess || "–"}</td>
                  <td className="td"><GradeBadge grade={a.risk_grade} /></td>
                  <td className="td"><RiskBar score={a.risk_score} /></td>
                  <td className="td">
                    {a.is_rogue ? (
                      <span className="badge bg-critical/20 text-critical border border-critical/40">rogue</span>
                    ) : a.is_authorized ? (
                      <span className="badge bg-low/20 text-low border border-low/40">authorized</span>
                    ) : (
                      <span className="badge bg-panel2 text-muted border border-edge">known</span>
                    )}
                  </td>
                  <td className="td text-xs">
                    {(() => {
                      const ip = String(a.ip).split("/")[0];
                      return (
                        <select
                          className="bg-panel2 border border-edge rounded-lg px-2 py-1 text-xs"
                          value={crit[ip] || a.criticality || "normal"}
                          onChange={(e) => setCriticality(ip, e.target.value)}
                          title="Digital-twin weight: critical 1.0, normal 0.8, low 0.5"
                        >
                          <option value="critical">critical</option>
                          <option value="normal">normal</option>
                          <option value="low">low</option>
                        </select>
                      );
                    })()}
                  </td>
                  <td className="td text-xs text-muted">{(a.last_seen || "").slice(0, 16).replace("T", " ")}</td>
                  <td className="td text-xs">
                    {(() => {
                      const ip = String(a.ip).split("/")[0];
                      const r = ready[ip];
                      if (!r) return <button className="btn text-xs" onClick={() => test(ip)}>Test</button>;
                      if (r.busy) return <span className="text-muted">testing…</span>;
                      if (r.ready) return (
                        <span className="badge bg-low/20 text-low border border-low/40"
                          title={(r.checks || []).map((c: any) => `✔ ${c.check}`).join("\n")}>ready ✔</span>);
                      const failed = (r.checks || []).find((c: any) => !c.ok);
                      return (
                        <div className="space-y-1">
                          <span className="badge bg-critical/20 text-critical border border-critical/40">not ready</span>
                          <div className="text-muted">{r.error || (failed ? `✘ ${failed.check}` : "")}</div>
                          {r.hint && <code className="font-mono text-[11px]">{r.hint.replace("Run on the engine: ", "")}</code>}
                          <button className="btn text-xs" onClick={() => test(ip)}>Re-test</button>
                        </div>
                      );
                    })()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!loading && !rows.length && <Empty msg="No assets discovered yet. Run a scan." />}
        </div>
      </div>
    </div>
  );
}
