"use client";
import { useCallback, useEffect, useState } from "react";
import Topbar from "@/components/Topbar";
import ConfigNotice from "@/components/ConfigNotice";
import TopologyGraph from "@/components/TopologyGraph";
import { api } from "@/lib/api";
import { getSupabase } from "@/lib/supabaseClient";
import { Empty } from "@/lib/ui";

// tables whose changes redraw the graph (Supabase Realtime)
const LIVE_TABLES = ["assets", "services", "vulnerabilities", "component_dependencies"];

export default function TopologyPage() {
  const [graph, setGraph] = useState<any>(null);
  const [err, setErr] = useState("");
  const [updated, setUpdated] = useState<string>("");
  const [selected, setSelected] = useState<any>(null);

  const load = useCallback(() => {
    api.topology()
      .then((g) => { setGraph(g); setErr(""); setUpdated(new Date().toLocaleTimeString()); })
      .catch((e) => setErr(e.message));
  }, []);

  useEffect(() => {
    load();
    const sb = getSupabase();
    if (!sb) return;
    // a scan writes hundreds of rows: redraw at most once every 2 seconds
    let timer: ReturnType<typeof setTimeout> | null = null;
    const channel = sb.channel(`topology-${Math.random().toString(36).slice(2)}`);
    for (const table of LIVE_TABLES) {
      channel.on("postgres_changes", { event: "*", schema: "public", table }, () => {
        if (timer) clearTimeout(timer);
        timer = setTimeout(load, 2000);
      });
    }
    channel.subscribe();
    return () => {
      if (timer) clearTimeout(timer);
      sb.removeChannel(channel);
    };
  }, [load]);

  const hosts = (graph?.nodes || []).filter((n: any) => n.type === "host");

  return (
    <div>
      <Topbar title="Topology" />
      <div className="p-6 space-y-4">
        <ConfigNotice />
        {err && <div className="card border-critical/40 text-critical text-sm">{err}</div>}
        <div className="grid lg:grid-cols-3 gap-4">
          <div className="card lg:col-span-2">
            <div className="flex justify-between items-center mb-3">
              <div className="text-sm font-semibold">
                Hosts, their components (OS + open services) and the dependencies between them
              </div>
              <div className="text-xs text-muted">live · updated {updated || "–"}</div>
            </div>
            {graph?.nodes?.length ? (
              <TopologyGraph graph={graph} onSelect={setSelected} />
            ) : (
              <Empty msg="No hosts yet. Run a scan: the graph fills in by itself." />
            )}
            <div className="text-xs text-muted mt-2">
              Colour = component risk (CRS). Lines: grey = runs on the host, orange = data,
              blue = interaction, purple dashed = network (e.g. a domain controller everyone logs in to).
            </div>
          </div>
          <div className="space-y-4">
            <div className="card">
              <div className="text-sm font-semibold mb-2">Selected</div>
              {selected ? (
                <div className="text-sm space-y-1">
                  <div className="font-mono">{selected.id}</div>
                  <div className="text-muted">{selected.label} · {selected.type}</div>
                  <div>Risk (CRS): <b>{selected.risk}</b></div>
                  {selected.type === "host" && <div>Grade {selected.grade} · {selected.os || "unknown OS"}
                    {selected.rogue && <span className="text-critical"> · rogue</span>}</div>}
                  {selected.type !== "host" && <div>{selected.findings} finding(s), {selected.kev} KEV</div>}
                </div>
              ) : <Empty msg="Click a node in the graph." />}
            </div>
            <div className="card">
              <div className="text-sm font-semibold mb-2">Hosts by risk</div>
              {hosts.length ? (
                <ul className="text-sm space-y-1">
                  {[...hosts].sort((a: any, b: any) => b.risk - a.risk).map((h: any) => (
                    <li key={h.id} className="flex justify-between border border-edge rounded-lg px-2 py-1">
                      <span className="font-mono">{h.ip}</span>
                      <span>{h.risk} ({h.grade}){h.rogue && <span className="text-critical"> rogue</span>}</span>
                    </li>
                  ))}
                </ul>
              ) : <Empty msg="No hosts." />}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
