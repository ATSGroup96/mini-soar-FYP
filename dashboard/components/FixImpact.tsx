"use client";
// Fix Impact Preview: what a fix changes on the host and on the whole network,
// worked out by the patch-prioritization model before anything is executed.
// Used on the Patch Prioritization page and on the remediation approval card.

function Row({ label, before, after, good = "down" }: {
  label: string; before: any; after: any; good?: "down" | "up";
}) {
  const changed = before !== after;
  const better = good === "down" ? Number(after) < Number(before) : Number(after) > Number(before);
  return (
    <div className="flex justify-between text-sm">
      <span className="text-muted">{label}</span>
      <span>
        {String(before ?? "–")} →{" "}
        <span className={changed ? (better ? "text-low font-semibold" : "text-critical font-semibold") : ""}>
          {String(after ?? "–")}
        </span>
      </span>
    </div>
  );
}

export default function FixImpact({ p, title = "Fix Impact Preview" }: { p: any; title?: string }) {
  if (!p) return null;
  const cb = p.counts_before || {};
  const ca = p.counts_after || {};
  return (
    <div className="border border-edge rounded-lg p-3 space-y-1">
      <div className="text-sm font-semibold">{title}</div>
      <div className="text-xs text-muted mb-1">
        Host <span className="font-mono">{p.ip}</span> · nothing has been executed
      </div>
      <Row label="Host risk (CRS)" before={`${p.host_crs_before} (${p.host_grade_before})`}
           after={`${p.host_crs_after} (${p.host_grade_after})`} />
      <Row label="Network risk total" before={p.network_total_before} after={p.network_total_after} />
      <Row label="Network avg host risk" before={p.network_avg_before} after={p.network_avg_after} />
      <Row label="Open ports" before={cb.open_ports} after={ca.open_ports} />
      <Row label="Open findings" before={cb.findings} after={ca.findings} />
      <Row label="KEV findings" before={cb.kev} after={ca.kev} />
      <Row label="Working default passwords" before={cb.default_creds} after={ca.default_creds} />
      <div className="flex justify-between text-sm pt-1">
        <span className="text-muted">Risk removed</span>
        <span className={p.drop > 0 ? "text-low font-semibold" : "text-critical font-semibold"}>
          {p.drop > 0 ? `-${p.drop}` : p.drop === 0 ? "0" : `+${Math.abs(p.drop)}`}
        </span>
      </div>
      {(p.closed_ports?.length > 0 || p.removed_findings?.length > 0 || p.cleared_default_creds?.length > 0) && (
        <div className="text-xs text-muted pt-1">
          Expected after the fix:
          {p.closed_ports?.length > 0 && <> port(s) {p.closed_ports.join(", ")} closed;</>}
          {p.removed_findings?.length > 0 && (
            <> {p.removed_findings.length} finding(s) gone
              ({p.removed_findings.slice(0, 4).join(", ")}{p.removed_findings.length > 4 ? ", …" : ""});</>
          )}
          {p.cleared_default_creds?.length > 0 && <> default password off on :{p.cleared_default_creds.join(", :")}</>}
        </div>
      )}
      {p.note && <div className="mt-2 p-2 rounded-lg bg-high/10 border border-high/30 text-xs">{p.note}</div>}
      {p.top_remaining?.length > 0 && (
        <div className="text-xs text-muted pt-1">
          Riskiest components left: {p.top_remaining.map((c: any) => `${c.component} (${c.crs})`).join(" · ")}
        </div>
      )}
    </div>
  );
}

export function FixCheck({ c }: { c: any }) {
  if (!c) return null;
  return (
    <div className={`border rounded-lg p-3 text-xs ${c.match ? "border-low/40" : "border-critical/40"}`}>
      <div className="font-semibold text-sm mb-1">
        Checked by the next scan: {c.match ? <span className="text-low">✓ as predicted</span>
                                           : <span className="text-critical">✗ not as predicted</span>}
      </div>
      <div>Predicted host risk {c.predicted_crs} · actual {c.actual_crs} · error {c.error}</div>
      {c.misses?.length > 0 && <div className="text-critical mt-1">{c.misses.join(", ")}</div>}
    </div>
  );
}
