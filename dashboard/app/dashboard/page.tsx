"use client";
import { useMemo } from "react";
import {
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid,
  BarChart, Bar, Cell,
} from "recharts";
import Topbar from "@/components/Topbar";
import ConfigNotice from "@/components/ConfigNotice";
import { useTable } from "@/lib/useData";
import { StatCard, GradeBadge, SeverityBadge, KevBadge, RiskBar, Empty } from "@/lib/ui";

const CHANGE_LABEL: Record<string, string> = {
  new_asset: "new device",
  port_opened: "port opened",
  port_closed: "port closed",
  version_changed: "version changed",
};
const CHANGE_TONE: Record<string, string> = {
  new_asset: "bg-high/20 text-high border border-high/40",
  port_opened: "bg-medium/20 text-medium border border-medium/40",
  port_closed: "bg-low/20 text-low border border-low/40",
  version_changed: "bg-info/20 text-info border border-info/40",
};

function gradeFromScore(s: number) {
  if (s >= 80) return "F";
  if (s >= 60) return "D";
  if (s >= 40) return "C";
  if (s >= 20) return "B";
  return "A";
}

export default function DashboardPage() {
  const assets = useTable<any>("assets", { orderBy: "risk_score" });
  const vulns = useTable<any>("vulnerabilities", { orderBy: "ml_risk_score", limit: 1000 });
  const tickets = useTable<any>("tickets");
  // risk-trend tracking: one row per host and one for the whole network (asset_id = null)
  // after every scan. Both tables arrive with database migration 004.
  const history = useTable<any>("risk_history", { orderBy: "created_at", ascending: true, limit: 1000 });
  const changes = useTable<any>("asset_changes", { orderBy: "created_at", limit: 12 });

  const netScore = useMemo(() => {
    const a = assets.rows;
    if (!a.length) return 0;
    return a.reduce((s, x) => s + (x.risk_score || 0), 0) / a.length;
  }, [assets.rows]);

  // only findings that are still open count toward the live posture
  const openVulns = useMemo(
    () => vulns.rows.filter((v) => (v.status || "open") === "open"),
    [vulns.rows]
  );
  const kevCount = openVulns.filter((v) => v.in_kev).length;
  const criticalCount = openVulns.filter((v) => (v.severity || "") === "critical").length;
  const rogueCount = assets.rows.filter((a) => a.is_rogue).length;
  const openTickets = tickets.rows.filter((t) => !["resolved", "rejected"].includes(t.status)).length;

  const trend = useMemo(() => {
    return history.rows
      .filter((h: any) => h.asset_id == null)
      .slice(-30)
      .map((h: any) => ({
        t: (h.created_at || "").slice(5, 16).replace("T", " "),
        risk: Number(h.risk_score) || 0,
        vulns: h.open_vulns || 0,
        grade: h.risk_grade || "",
      }));
  }, [history.rows]);

  const ipOf = useMemo(() => {
    const m: Record<string, string> = {};
    assets.rows.forEach((a: any) => { m[a.id] = a.ip; });
    return m;
  }, [assets.rows]);

  // one row per CVE, confirmed matches first
  const topVulns = useMemo(() => {
    const seen = new Set<string>();
    const sorted = [...openVulns].sort(
      (a, b) =>
        Number(b.confidence !== "version-unconfirmed") - Number(a.confidence !== "version-unconfirmed") ||
        (b.ml_risk_score || 0) - (a.ml_risk_score || 0)
    );
    return sorted.filter((v) => (seen.has(v.cve_id) ? false : (seen.add(v.cve_id), true))).slice(0, 8);
  }, [openVulns]);
  const sevData = ["critical", "high", "medium", "low", "info"].map((s) => ({
    sev: s,
    n: openVulns.filter((v) => (v.severity || "info") === s).length,
  }));
  const SEV_FILL: Record<string, string> = {
    critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e", info: "#38bdf8",
  };

  return (
    <div>
      <Topbar title="Security Overview" />
      <div className="p-6 space-y-6">
        <ConfigNotice />

        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <div className="card flex items-center gap-4">
            <GradeBadge grade={gradeFromScore(netScore)} />
            <div>
              <div className="text-xs uppercase text-muted">Security grade</div>
              <div className="text-sm text-muted">Avg risk {netScore.toFixed(0)}/100</div>
            </div>
          </div>
          <StatCard label="Assets" value={assets.rows.length} sub={`${rogueCount} rogue`} tone={rogueCount ? "high" : "default"} />
          <StatCard label="On CISA KEV" value={kevCount} tone={kevCount ? "critical" : "low"} />
          <StatCard label="Critical vulns" value={criticalCount} tone={criticalCount ? "critical" : "low"} />
          <StatCard label="Open tickets" value={openTickets} tone={openTickets ? "high" : "low"} />
        </div>

        <div className="grid md:grid-cols-3 gap-4">
          <div className="card md:col-span-2">
            <div className="text-sm font-semibold mb-3">Risk trend (network average after each scan)</div>
            {trend.length ? (
              <ResponsiveContainer width="100%" height={240}>
                <AreaChart data={trend}>
                  <defs>
                    <linearGradient id="g" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.5} />
                      <stop offset="100%" stopColor="#3b82f6" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#273349" />
                  <XAxis dataKey="t" stroke="#8ea0c0" fontSize={11} />
                  <YAxis stroke="#8ea0c0" fontSize={11} domain={[0, 100]} />
                  <Tooltip contentStyle={{ background: "#111827", border: "1px solid #273349" }} />
                  <Area type="monotone" dataKey="risk" stroke="#3b82f6" fill="url(#g)" name="risk (0-100)" />
                  <Area type="monotone" dataKey="vulns" stroke="#f97316" fillOpacity={0} name="open findings" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <Empty msg={history.error
                ? "Risk history table not found: run supabase/migrations/004_trend_changes.sql once."
                : "No risk history yet. Run a scan."} />
            )}
          </div>
          <div className="card">
            <div className="text-sm font-semibold mb-3">Vulnerabilities by severity</div>
            {vulns.rows.length ? (
              <ResponsiveContainer width="100%" height={240}>
                <BarChart data={sevData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#273349" />
                  <XAxis dataKey="sev" stroke="#8ea0c0" fontSize={11} />
                  <YAxis stroke="#8ea0c0" fontSize={11} allowDecimals={false} />
                  <Tooltip contentStyle={{ background: "#111827", border: "1px solid #273349" }} />
                  <Bar dataKey="n">
                    {sevData.map((d) => (
                      <Cell key={d.sev} fill={SEV_FILL[d.sev]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <Empty msg="No vulnerabilities yet." />
            )}
          </div>
        </div>

        <div className="card">
          <div className="text-sm font-semibold mb-3">Recent changes (change detection)</div>
          {changes.rows.length ? (
            <table className="w-full">
              <thead>
                <tr>
                  <th className="th">When</th><th className="th">Host</th>
                  <th className="th">Change</th><th className="th">Detail</th>
                </tr>
              </thead>
              <tbody>
                {changes.rows.map((c: any) => (
                  <tr key={c.id}>
                    <td className="td text-xs text-muted tabular-nums">
                      {(c.created_at || "").slice(0, 16).replace("T", " ")}
                    </td>
                    <td className="td font-mono text-sm">{ipOf[c.asset_id] || "–"}</td>
                    <td className="td">
                      <span className={`badge ${CHANGE_TONE[c.kind] || CHANGE_TONE.version_changed}`}>
                        {CHANGE_LABEL[c.kind] || c.kind}
                      </span>
                    </td>
                    <td className="td text-sm">
                      {c.port != null && <span className="font-mono">port {c.port} </span>}
                      {c.detail?.service && <span className="text-muted">({c.detail.service}) </span>}
                      {c.detail?.from && <span className="text-muted">{c.detail.from} → {c.detail.to}</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty msg={changes.error
              ? "Change table not found: run supabase/migrations/004_trend_changes.sql once."
              : "No changes recorded yet. They appear from the second scan of a host."} />
          )}
        </div>

        <div className="card">
          <div className="text-sm font-semibold mb-3">Top risks (KEV &amp; EPSS prioritized)</div>
          {topVulns.length ? (
            <table className="w-full">
              <thead>
                <tr>
                  <th className="th">CVE</th><th className="th">Sev</th><th className="th">CVSS</th>
                  <th className="th">EPSS</th><th className="th">KEV</th><th className="th">ML risk</th>
                </tr>
              </thead>
              <tbody>
                {topVulns.map((v) => (
                  <tr key={v.id}>
                    <td className="td font-mono text-accent">
                      {v.cve_id}
                      {v.confidence === "version-unconfirmed" && (
                        <span className="ml-2 badge bg-panel2 text-muted border border-edge">unconfirmed</span>
                      )}
                    </td>
                    <td className="td"><SeverityBadge level={v.severity} /></td>
                    <td className="td tabular-nums">{v.cvss_score ?? "–"}</td>
                    <td className="td tabular-nums">{v.epss_score != null ? (v.epss_score * 100).toFixed(1) + "%" : "–"}</td>
                    <td className="td"><KevBadge on={v.in_kev} /></td>
                    <td className="td"><RiskBar score={v.ml_risk_score} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty msg="No findings yet." />
          )}
        </div>
      </div>
    </div>
  );
}
