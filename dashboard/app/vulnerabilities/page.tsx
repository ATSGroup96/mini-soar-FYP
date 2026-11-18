"use client";
import { useState, Fragment } from "react";
import Topbar from "@/components/Topbar";
import ConfigNotice from "@/components/ConfigNotice";
import { useTable } from "@/lib/useData";
import { getSupabase } from "@/lib/supabaseClient";
import { SeverityBadge, KevBadge, RiskBar, Empty } from "@/lib/ui";

const CVE_ID = /^CVE-\d{4}-\d{4,}$/i;

// CVE watchlist: CVEs the team wants an alert for the moment a scan finds them.
function WatchlistCard({ rows, error, reload }: { rows: any[]; error: string | null; reload: () => void }) {
  const [cve, setCve] = useState("");
  const [note, setNote] = useState("");
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);
  const id = cve.trim().toUpperCase();

  function explain(e: { code?: string; message: string }) {
    if (e.code === "23505") return "That CVE is already on the watchlist.";
    if (/row-level security/i.test(e.message)) return "Only analysts and admins can change the watchlist.";
    return e.message;
  }

  async function add() {
    const sb = getSupabase();
    if (!sb || !CVE_ID.test(id)) return;
    setBusy(true);
    const { error: e } = await sb.from("cve_watchlist").insert({ cve_id: id, note: note.trim() || null });
    setBusy(false);
    if (e) { setMsg(explain(e)); return; }
    setMsg(`${id} added. You get an alert (and a ticket) when a scan finds it.`);
    setCve(""); setNote("");
    reload();
  }

  async function remove(rowId: string, cveId: string) {
    const sb = getSupabase();
    if (!sb) return;
    const { error: e } = await sb.from("cve_watchlist").delete().eq("id", rowId);
    setMsg(e ? explain(e) : `${cveId} removed.`);
    reload();
  }

  return (
    <div className="card">
      <div className="text-sm font-semibold mb-1">CVE watchlist</div>
      <p className="text-xs text-muted mb-3">
        Add a CVE you are worried about. When a scan finds it on any host you get an alert and a ticket,
        whatever its score. If the installed version cannot be confirmed, the ticket is marked
        &quot;[unconfirmed]&quot;: check the version on the host first.
      </p>
      <div className="flex flex-wrap gap-2 items-center">
        <input className="bg-panel2 border border-edge rounded-lg px-3 py-2 text-sm w-48 font-mono"
          placeholder="CVE-2011-2523" value={cve} onChange={(e) => setCve(e.target.value)} />
        <input className="bg-panel2 border border-edge rounded-lg px-3 py-2 text-sm flex-1 min-w-[12rem]"
          placeholder="Note (optional), e.g. why it matters" value={note} maxLength={200}
          onChange={(e) => setNote(e.target.value)} />
        <button className="btn btn-primary" onClick={add} disabled={busy || !CVE_ID.test(id)}>Add</button>
      </div>
      {msg && <div className="text-xs text-muted mt-2">{msg}</div>}
      {error && <div className="text-xs text-critical mt-2">{error}</div>}
      {rows.length > 0 && (
        <div className="flex flex-wrap gap-2 mt-3">
          {rows.map((w) => (
            <span key={w.id} className="badge bg-accent/20 text-accent border border-accent/40" title={w.note || ""}>
              {w.cve_id}
              <button className="ml-2 text-muted hover:text-critical" aria-label={`Remove ${w.cve_id}`}
                onClick={() => remove(w.id, w.cve_id)}>×</button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

export default function VulnPage() {
  const { rows } = useTable<any>("vulnerabilities", { orderBy: "ml_risk_score", limit: 1000 });
  const watch = useTable<any>("cve_watchlist", { orderBy: "created_at" });
  const watched = new Set(watch.rows.map((w) => w.cve_id));
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
        <WatchlistCard rows={watch.rows} error={watch.error} reload={watch.reload} />
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
                      {watched.has(v.cve_id) && (
                        <span className="ml-2 badge bg-accent/20 text-accent border border-accent/40">watchlist</span>
                      )}
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
