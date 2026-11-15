"use client";
import Topbar from "@/components/Topbar";
import ConfigNotice from "@/components/ConfigNotice";
import { useTable } from "@/lib/useData";
import { Empty } from "@/lib/ui";

const REP_CLS: Record<string, string> = {
  malicious: "bg-critical/20 text-critical border border-critical/40",
  suspicious: "bg-high/20 text-high border border-high/40",
  clean: "bg-low/20 text-low border border-low/40",
  // a machine inside the lab touched the decoy: always worth a look
  internal: "bg-medium/20 text-medium border border-medium/40",
  unknown: "bg-panel2 text-muted border border-edge",
};

export default function HoneypotPage() {
  const { rows } = useTable<any>("honeypot_events", { orderBy: "ts" });
  return (
    <div>
      <Topbar title="Honeypot" />
      <div className="p-6 space-y-4">
        <ConfigNotice />
        <div className="card text-xs text-muted">
          Fake SSH (:2222) and HTTP (:8081) decoys. Every attempt is logged and the decoys never grant
          access. Public source addresses are checked against AbuseIPDB &amp; AlienVault OTX; an address
          from inside the lab is marked <span className="font-mono">internal</span> and always raises an alert.
        </div>
        <div className="card p-0 overflow-hidden">
          <table className="w-full">
            <thead className="bg-panel2">
              <tr>
                <th className="th">Time</th><th className="th">Service</th><th className="th">Source IP</th>
                <th className="th">User</th><th className="th">Password</th><th className="th">Abuse</th>
                <th className="th">OTX</th><th className="th">Reputation</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((e) => (
                <tr key={e.id} className="hover:bg-panel2/50">
                  <td className="td text-xs text-muted">{(e.ts || "").slice(0, 19).replace("T", " ")}</td>
                  <td className="td font-mono text-xs">{e.service}</td>
                  <td className="td font-mono">{e.src_ip}</td>
                  <td className="td text-xs">{e.username_tried || "–"}</td>
                  <td className="td text-xs font-mono">{e.password_tried || "–"}</td>
                  <td className="td tabular-nums">{e.abuse_score ?? "–"}</td>
                  <td className="td tabular-nums">{e.otx_pulses ?? "–"}</td>
                  <td className="td"><span className={`badge ${REP_CLS[e.reputation] || REP_CLS.unknown}`}>{e.reputation}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
          {!rows.length && <Empty msg="No honeypot hits yet." />}
        </div>
      </div>
    </div>
  );
}
