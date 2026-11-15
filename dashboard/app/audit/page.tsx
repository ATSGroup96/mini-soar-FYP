"use client";
import { useEffect, useState } from "react";
import Topbar from "@/components/Topbar";
import ConfigNotice from "@/components/ConfigNotice";
import { useTable } from "@/lib/useData";
import { api } from "@/lib/api";
import { Empty } from "@/lib/ui";
import { ShieldCheck, ShieldAlert } from "lucide-react";

export default function AuditPage() {
  const { rows } = useTable<any>("audit_log", { orderBy: "ts" });
  const [verify, setVerify] = useState<any>(null);

  useEffect(() => {
    api.verifyAudit().then(setVerify).catch(() => setVerify(null));
  }, []);

  return (
    <div>
      <Topbar title="Tamper-Evident Audit Log" />
      <div className="p-6 space-y-4">
        <ConfigNotice />
        {verify && (
          <div className={`card flex items-center gap-3 ${verify.ok ? "border-low/40" : "border-critical/40"}`}>
            {verify.ok ? <ShieldCheck className="text-low" /> : <ShieldAlert className="text-critical" />}
            <div>
              <div className="font-semibold text-sm">{verify.ok ? "Hash chain intact" : "Tampering detected"}</div>
              <div className="text-xs text-muted">{verify.message}</div>
            </div>
          </div>
        )}
        <div className="card p-0 overflow-hidden">
          <table className="w-full">
            <thead className="bg-panel2">
              <tr>
                <th className="th">Time</th><th className="th">Actor</th><th className="th">Action</th>
                <th className="th">Target</th><th className="th">Hash</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((e) => (
                <tr key={e.id} className="hover:bg-panel2/50">
                  <td className="td text-xs text-muted">{(e.ts || "").slice(0, 19).replace("T", " ")}</td>
                  <td className="td text-xs">{e.actor}</td>
                  <td className="td font-mono text-xs text-accent">{e.action}</td>
                  <td className="td font-mono text-xs">{e.target || "–"}</td>
                  <td className="td font-mono text-[10px] text-muted">{(e.curr_hash || "").slice(0, 16)}…</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!rows.length && <Empty msg="No audit entries yet." />}
        </div>
      </div>
    </div>
  );
}
