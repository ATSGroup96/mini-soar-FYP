"use client";
// Dependency-based digital twin: component risk (CRS = CCS x CVS), ranked fixes,
// baseline comparison with the paper's own formula, and the twin's accuracy.
import { useEffect, useState } from "react";
import { useSession } from "@/components/AuthGate";
import { api } from "@/lib/api";
import { Empty } from "@/lib/ui";

const RULES = ["network", "data", "interaction", "embedding"];

function Stat({ label, value, sub }: { label: string; value: any; sub?: string }) {
  return (
    <div className="border border-edge rounded-lg p-3">
      <div className="text-xs text-muted">{label}</div>
      <div className="text-xl font-semibold">{value ?? "–"}</div>
      {sub && <div className="text-xs text-muted mt-1">{sub}</div>}
    </div>
  );
}

function FixList({ rows, showRemoves }: { rows: any[]; showRemoves?: boolean }) {
  if (!rows?.length) return <Empty msg="Nothing to fix: no finding would lower the risk." />;
  return (
    <table className="w-full text-sm">
      <thead className="bg-panel2">
        <tr>
          <th className="th">#</th><th className="th">Fix</th><th className="th">Host</th>
          <th className="th">Risk drop</th><th className="th">Host CRS</th>
          {showRemoves && <th className="th">Removes</th>}
        </tr>
      </thead>
      <tbody>
        {rows.map((r: any) => (
          <tr key={`${r.ip}-${r.label}`}>
            <td className="td">{r.rank}</td>
            <td className="td">
              {r.label}{" "}
              {r.executable ? (
                <span className="badge bg-low/20 text-low border border-low/40">playbook</span>
              ) : (
                <span className="badge bg-panel2 text-muted border border-edge">manual</span>
              )}
            </td>
            <td className="td font-mono text-xs">{r.ip}</td>
            <td className="td text-low font-semibold">-{r.drop}</td>
            <td className="td text-xs">{r.host_crs_before} → {r.host_crs_after}</td>
            {showRemoves && (
              <td className="td text-xs">
                {r.removes?.kev ? <span className="text-critical">KEV ×{r.removes.kev} </span> : null}
                {r.removes?.default_creds ? <span className="text-high">default pw ×{r.removes.default_creds} </span> : null}
                {r.removes?.findings ? <span className="text-muted">{r.removes.findings} findings</span> : null}
              </td>
            )}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function TwinPanel() {
  const session = useSession();
  const [t, setT] = useState<any>(null);
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");
  const [dep, setDep] = useState({ from: "", to: "", rule: "network", note: "" });
  const [showBase, setShowBase] = useState(false);

  function load() {
    api.twin().then(setT).catch((e) => setErr(e.message));
  }
  useEffect(load, []);

  async function addDep(enabled = true, from = dep.from, to = dep.to, rule = dep.rule) {
    setMsg("");
    try {
      await api.setDependency({
        admin_user_id: session?.user?.id || "", from_component: from.trim(),
        to_component: to.trim(), rule, enabled, note: dep.note,
      });
      setMsg(enabled ? "Dependency saved." : "Automatic dependency hidden.");
      setDep({ from: "", to: "", rule: "network", note: "" });
      load();
    } catch (e: any) { setMsg(e.message); }
  }

  async function removeDep(id: string) {
    setMsg("");
    try {
      await api.removeDependency(session?.user?.id || "", id);
      load();
    } catch (e: any) { setMsg(e.message); }
  }

  if (err) return <div className="card border-critical/40 text-critical text-sm">Digital twin: {err}</div>;
  if (!t) return <div className="card text-sm text-muted">Loading digital twin…</div>;

  const acc = t.accuracy || {};
  const cmp = t.comparison || {};
  const comps = t.improved?.components || [];
  const deps = t.improved?.dependencies || [];

  return (
    <div className="card space-y-4">
      <div>
        <div className="text-sm font-semibold">Digital twin — dependency model and patch priority</div>
        <p className="text-xs text-muted mt-1">
          Component risk CRS = criticality (CCS, from dependencies and asset weight) × vulnerability
          score (CVS, from our EPSS/KEV-aware finding risk). Adapted from {t.paper}. Fixes are
          tried on the twin first; nothing here is executed.
        </p>
        {!t.ready && (
          <div className="mt-2 p-2 rounded-lg bg-high/10 border border-high/30 text-xs">
            Running with defaults. Run <span className="font-mono">supabase/migrations/005_digital_twin.sql</span> in
            Supabase to save asset weights, manual dependencies and predictions.
          </div>
        )}
      </div>

      <div className="grid md:grid-cols-4 gap-3">
        <Stat label="Network risk (avg host CRS)" value={t.improved?.network_avg}
              sub={`total ${t.improved?.network_total}`} />
        <Stat label="Twin accuracy" value={acc.accuracy_pct != null ? `${acc.accuracy_pct}%` : "–"}
              sub={acc.checked ? `${acc.matched}/${acc.checked} fixes predicted right · mean error ${acc.mean_error}`
                               : "no verified fix checked yet"} />
        <Stat label={`Dangerous fixes in top ${cmp.k ?? 5} (ours)`} value={cmp.ours?.dangerous_in_top_k}
              sub={`first at #${cmp.ours?.first_dangerous_rank ?? "–"}`} />
        <Stat label={`Dangerous fixes in top ${cmp.k ?? 5} (paper baseline)`} value={cmp.baseline?.dangerous_in_top_k}
              sub={`first at #${cmp.baseline?.first_dangerous_rank ?? "–"} · overlap ${cmp.overlap ?? 0}`} />
      </div>
      <div className="text-xs text-muted">{cmp.note}</div>

      <div>
        <div className="flex justify-between items-center mb-2">
          <div className="text-sm font-semibold">
            {showBase ? "Patch priority — paper baseline (CVSS only)" : "Patch priority — our model"}
          </div>
          <div className="flex gap-2">
            <button className="btn text-xs" onClick={() => setShowBase(!showBase)}>
              {showBase ? "Show our model" : "Compare with paper baseline"}
            </button>
            <button className="btn text-xs" onClick={load}>Refresh</button>
          </div>
        </div>
        <FixList rows={showBase ? t.baseline_ranking : t.ranking} showRemoves />
      </div>

      <div className="grid lg:grid-cols-2 gap-4">
        <div>
          <div className="text-sm font-semibold mb-2">Components (highest CRS first)</div>
          {comps.length ? (
            <table className="w-full text-sm">
              <thead className="bg-panel2">
                <tr>
                  <th className="th">Component</th><th className="th">Weight</th>
                  <th className="th">Depend on it</th><th className="th">CCS</th>
                  <th className="th">CVS</th><th className="th">CRS</th>
                </tr>
              </thead>
              <tbody>
                {comps.slice(0, 20).map((c: any) => (
                  <tr key={c.id}>
                    <td className="td">
                      <div>{c.name}</div>
                      <div className="font-mono text-xs text-muted">{c.id}</div>
                    </td>
                    <td className="td text-xs">{c.criticality}</td>
                    <td className="td">{c.dependents}</td>
                    <td className="td">{c.ccs}</td>
                    <td className="td">{c.cvs}</td>
                    <td className="td font-semibold">{c.crs}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <Empty msg="No components yet. Run a scan." />}
        </div>

        <div>
          <div className="text-sm font-semibold mb-2">Dependencies ("A depends on B")</div>
          <div className="max-h-72 overflow-auto border border-edge rounded-lg">
            {deps.length ? (
              <table className="w-full text-xs">
                <tbody>
                  {deps.map((d: any) => (
                    <tr key={`${d.from}-${d.to}`}>
                      <td className="td font-mono">{d.from}</td>
                      <td className="td">→</td>
                      <td className="td font-mono">{d.to}</td>
                      <td className="td">{d.rule}</td>
                      <td className="td text-muted">{d.source}</td>
                      <td className="td">
                        {d.source === "manual" && d.id ? (
                          <button className="btn text-xs" onClick={() => removeDep(d.id)}>Remove</button>
                        ) : (
                          <button className="btn text-xs" onClick={() => addDep(false, d.from, d.to, d.rule)}>Hide</button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : <div className="p-3"><Empty msg="No dependencies yet." /></div>}
          </div>
          <div className="mt-3 text-xs text-muted">Add one (admin). Component id: IP|os or IP|port, e.g. 192.168.56.101|80</div>
          <div className="flex flex-wrap gap-2 mt-1">
            <input className="bg-panel2 border border-edge rounded-lg px-2 py-1 text-xs w-44"
                   placeholder="from (depends…)" value={dep.from}
                   onChange={(e) => setDep({ ...dep, from: e.target.value })} />
            <input className="bg-panel2 border border-edge rounded-lg px-2 py-1 text-xs w-44"
                   placeholder="to (…on this)" value={dep.to}
                   onChange={(e) => setDep({ ...dep, to: e.target.value })} />
            <select className="bg-panel2 border border-edge rounded-lg px-2 py-1 text-xs"
                    value={dep.rule} onChange={(e) => setDep({ ...dep, rule: e.target.value })}>
              {RULES.map((r) => <option key={r} value={r}>{r}</option>)}
            </select>
            <button className="btn btn-primary text-xs" disabled={!dep.from || !dep.to}
                    onClick={() => addDep(true)}>Add</button>
          </div>
          {msg && <div className="text-xs mt-2">{msg}</div>}
        </div>
      </div>

      {t.recent_checks?.length > 0 && (
        <div>
          <div className="text-sm font-semibold mb-2">Twin checks (prediction vs. real re-scan)</div>
          <ul className="text-xs space-y-1">
            {t.recent_checks.map((c: any) => (
              <li key={c.remediation_id} className="flex justify-between border border-edge rounded-lg p-2">
                <span>
                  {c.action} {JSON.stringify(c.params)} on <span className="font-mono">{c.ip}</span>
                  {c.result.misses?.length ? <span className="text-critical"> · {c.result.misses.join(", ")}</span> : null}
                </span>
                <span className={c.result.match ? "text-low" : "text-critical"}>
                  {c.result.match ? "✓ matched" : "✗ missed"} · predicted {c.result.predicted_crs} / actual {c.result.actual_crs}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
