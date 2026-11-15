"use client";
import { useEffect, useState } from "react";
import Topbar from "@/components/Topbar";
import ConfigNotice from "@/components/ConfigNotice";
import TopologyGraph from "@/components/TopologyGraph";
import { api } from "@/lib/api";
import { Empty } from "@/lib/ui";

export default function TopologyPage() {
  const [data, setData] = useState<any>(null);
  const [err, setErr] = useState("");
  const [sim, setSim] = useState<any>(null);
  const [target, setTarget] = useState("");
  const [fixType, setFixType] = useState("block_port");
  const [fixVal, setFixVal] = useState("23");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.attackGraph().then(setData).catch((e) => setErr(e.message));
  }, []);

  async function runWhatIf() {
    setBusy(true);
    setSim(null);
    try {
      // several values separated by commas = several fixes simulated together
      const fixes = fixVal.split(",").map((v) => v.trim()).filter(Boolean).map((v) => {
        const fix: any = { type: fixType };
        if (fixType === "patch_cve") fix.cve_id = v;
        else if (fixType === "stop_service") fix.service = v;
        else fix.port = parseInt(v, 10);
        return fix;
      });
      const r = await api.whatIfMany(target.trim(), fixes);
      setSim(r);
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }

  const paths = data?.paths || [];

  return (
    <div>
      <Topbar title="Topology & Attack Paths" />
      <div className="p-6 space-y-4">
        <ConfigNotice />
        {err && <div className="card border-critical/40 text-critical text-sm">{err}</div>}

        <div className="grid lg:grid-cols-3 gap-4">
          <div className="card lg:col-span-2">
            <div className="text-sm font-semibold mb-3">
              Network graph — red = attacker / critical, dashed = lateral movement
            </div>
            {data?.graph?.nodes?.length ? (
              <TopologyGraph graph={data.graph} />
            ) : (
              <Empty msg="No graph yet. Run a scan, then reload." />
            )}
          </div>

          <div className="space-y-4">
            <div className="card">
              <div className="text-sm font-semibold mb-2">Digital-twin what-if</div>
              <p className="text-xs text-muted mb-3">
                Preview a fix&apos;s impact before approving it. Nothing is executed.
              </p>
              <input
                className="bg-panel2 border border-edge rounded-lg px-3 py-2 text-sm w-full mb-2"
                placeholder="target IP e.g. 192.168.103.105"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
              />
              <div className="flex gap-2 mb-2">
                <select
                  className="bg-panel2 border border-edge rounded-lg px-2 py-2 text-sm flex-1"
                  value={fixType}
                  onChange={(e) => { setFixType(e.target.value); setFixVal(""); }}
                >
                  <option value="block_port">block_port</option>
                  <option value="stop_service">stop_service</option>
                  <option value="patch_cve">patch_cve</option>
                </select>
                <input
                  className="bg-panel2 border border-edge rounded-lg px-2 py-2 text-sm w-40"
                  placeholder={fixType === "patch_cve" ? "e.g. CVE-2011-2523" : fixType === "stop_service" ? "e.g. telnet or 23" : "e.g. 21,6667,3632"}
                  value={fixVal}
                  onChange={(e) => setFixVal(e.target.value)}
                />
              </div>
              <button className="btn btn-primary w-full" onClick={runWhatIf} disabled={busy || !target}>
                {busy ? "Simulating…" : "Simulate"}
              </button>
              {sim && (
                <div className="mt-3 text-sm space-y-1">
                  {[
                    ["Host risk", `${sim.host.before.risk_score} (${sim.host.before.grade})`, `${sim.host.after.risk_score} (${sim.host.after.grade})`],
                    ["Total exposure", sim.host.before.exposure, sim.host.after.exposure],
                    ["Open ports", sim.host.before.open_ports, sim.host.after.open_ports],
                    ["Open CVEs", sim.host.before.vuln_count, sim.host.after.vuln_count],
                    ["Critical (80+)", sim.host.before.critical, sim.host.after.critical],
                    ["KEV", sim.host.before.kev, sim.host.after.kev],
                    ["Default creds", sim.host.before.default_creds, sim.host.after.default_creds],
                    ["Network avg risk", sim.network.network_risk_before, sim.network.network_risk_after],
                    ["Attack paths", sim.network.attack_paths_before, sim.network.attack_paths_after],
                  ].map(([label, b, a]) => (
                    <div key={String(label)} className="flex justify-between">
                      <span className="text-muted">{label}</span>
                      <span>{String(b)} → <span className="text-low">{String(a)}</span></span>
                    </div>
                  ))}
                  <div className="flex justify-between">
                    <span className="text-muted">Risk reduction</span>
                    <span className="text-low font-semibold">-{sim.host.risk_reduction} (exposure -{sim.host.exposure_reduction})</span>
                  </div>
                  {sim.host.note && (
                    <div className="mt-2 p-2 rounded-lg bg-high/10 border border-high/30 text-xs">{sim.host.note}</div>
                  )}
                  {sim.host.after.top_remaining?.length > 0 && (
                    <div className="mt-2 text-xs text-muted">
                      Worst findings left:{" "}
                      {sim.host.after.top_remaining.map((t: any) => `${t.cve_id} :${t.port} (${t.score})`).join(" · ")}
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="card">
              <div className="text-sm font-semibold mb-2">Most dangerous paths</div>
              {paths.length ? (
                <ol className="space-y-2 text-sm">
                  {paths.map((p: any, i: number) => (
                    <li key={i} className="border border-edge rounded-lg p-2">
                      <div className="flex justify-between">
                        <span className="font-mono">{p.target}</span>
                        <span className="text-critical text-xs">risk {p.target_risk}</span>
                      </div>
                      <div className="text-xs text-muted mt-1">
                        {p.steps.map((s: any) => `${s.from} → ${s.to}`).join("  ·  ") || "direct"}
                      </div>
                    </li>
                  ))}
                </ol>
              ) : (
                <Empty msg="No attack paths found." />
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
