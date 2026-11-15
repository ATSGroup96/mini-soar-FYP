"use client";
import { useEffect, useState } from "react";
import { Play, RefreshCw, Wifi, WifiOff } from "lucide-react";
import { api } from "@/lib/api";

export default function Topbar({ title }: { title: string }) {
  const [scanning, setScanning] = useState(false);
  const [health, setHealth] = useState<{ authorized?: boolean; scope?: string[]; cloud?: boolean } | null>(null);
  const [msg, setMsg] = useState("");

  useEffect(() => {
    api.health().then(setHealth).catch(() => setHealth(null));
  }, []);

  async function runScan() {
    setScanning(true);
    setMsg("Scanning authorized scope…");
    try {
      const r = await api.runScan();
      setMsg(`Scan complete: ${r.meta?.host_count ?? 0} hosts, ${r.uplink?.rogue ?? 0} rogue.`);
    } catch (e: any) {
      setMsg(`Scan failed: ${e.message}`);
    } finally {
      setScanning(false);
    }
  }

  return (
    <div className="flex items-center justify-between border-b border-edge bg-panel/60 px-6 py-3 sticky top-0 z-10 backdrop-blur">
      <div>
        <h1 className="text-lg font-semibold">{title}</h1>
        {msg && <div className="text-xs text-muted">{msg}</div>}
      </div>
      <div className="flex items-center gap-3">
        <span className="text-xs text-muted flex items-center gap-1">
          {health?.cloud ? <Wifi size={14} className="text-low" /> : <WifiOff size={14} className="text-high" />}
          {health?.scope?.length ? health.scope.join(", ") : "no scope"}
        </span>
        <button className="btn" onClick={() => location.reload()}>
          <RefreshCw size={15} /> Refresh
        </button>
        <button className="btn btn-primary" onClick={runScan} disabled={scanning}>
          <Play size={15} /> {scanning ? "Scanning…" : "Run scan"}
        </button>
      </div>
    </div>
  );
}
