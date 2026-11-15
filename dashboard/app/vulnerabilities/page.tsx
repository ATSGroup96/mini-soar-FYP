"use client";
import { useState, Fragment } from "react";
import Topbar from "@/components/Topbar";
import ConfigNotice from "@/components/ConfigNotice";
import { useTable } from "@/lib/useData";
import { SeverityBadge, KevBadge, RiskBar, Empty } from "@/lib/ui";

export default function VulnPage() {
  const { rows } = useTable<any>("vulnerabilities", { orderBy: "ml_risk_score", limit: 1000 });
  const [kevOnly, setKevOnly] = useState(false);
  const [showClosed, setShowClosed] = useState(false);
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<string | null>(null);

  const filtered = rows.filter(
    (v) =>
      (!kevOnly || v.in_kev) &&
      (showClosed || (v.status || "open") === "open") &&
      (!q || v.cve_id?.toLowerCase().includes(q.toLowerCase()))
  );

  return (
    <div>
      <Topbar title="Vulnerabilities" />
      <div className="p-6 space-y-4">
        <ConfigNotice />
        <div className="flex gap-3 items-center">
          <input
            className="bg-panel border border-edge rounded-lg px-3 py-2 text-sm w-64"
            placeholder="Search CVE…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
          <label className="flex items-center gap-2 text-sm text-muted">
            <input type="checkbox" checked={kevOnly} onChange={(e) => setKevOnly(e.target.checked)} />
            KEV only
          </label>
          <label className="flex items-center gap-2 text-sm text-muted">
            <input type="checkbox" checked={showClosed} onChange={(e) => setShowClosed(e.target.checked)} />
            show remediated
          </label>
          <span className="text-xs text-muted ml-auto">{filtered.length} findings</span>
        </div>

        <div className="card p-0 overflow-hidden">
          <table className="w-full">
            <thead className="bg-panel2">
              <tr>
                <th className="th">CVE</th><th className="th">Severity</th><th className="th">CVSS</th>
                <th className="th">EPSS</th><th className="th">KEV</th><th className="th">ML risk</th><th className="th">Why</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((v) => (
                <Fragment key={v.id}>
                  <tr className="hover:bg-panel2/50 cursor-pointer" onClick={() => setOpen(open === v.id ? null : v.id)}>
                    <td className="td font-mono text-accent">
                      {v.cve_id}
                      {v.confidence === "version-unconfirmed" && (
                        <span className="ml-2 badge bg-panel2 text-muted border border-edge" title="Matched only through an open-ended NVD range; likely not affected">unconfirmed</span>
                      )}
                      {v.status && v.status !== "open" && (
                        <span className="ml-2 badge bg-low/20 text-low border border-low/40">{v.status}</span>
                      )}
                    </td>
                    <td className="td"><SeverityBadge level={v.severity} /></td>
                    <td className="td tabular-nums">{v.cvss_score ?? "–"}</td>
                    <td className="td tabular-nums">{v.epss_score != null ? (v.epss_score * 100).toFixed(1) + "%" : "–"}</td>
                    <td className="td"><KevBadge on={v.in_kev} /></td>
                    <td className="td"><RiskBar score={v.ml_risk_score} /></td>
                    <td className="td text-xs text-accent">{open === v.id ? "hide" : "explain"}</td>
                  </tr>
                  {open === v.id && (
                    <tr>
                      <td className="td" colSpan={7}>
                        <div className="text-sm text-muted mb-2">{v.description || "No description."}</div>
                        {Array.isArray(v.ml_reasons) && v.ml_reasons.length > 0 && (
                          <div>
                            <div className="text-xs uppercase text-muted mb-1">Why this score (explainable AI)</div>
                            <ul className="text-sm space-y-1">
                              {v.ml_reasons.map((r: string, i: number) => (
                                <li key={i} className="font-mono text-xs">• {r}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
          {!filtered.length && <Empty msg="No matching vulnerabilities." />}
        </div>
      </div>
    </div>
  );
}
