"use client";
import { useState } from "react";
import Topbar from "@/components/Topbar";
import ConfigNotice from "@/components/ConfigNotice";
import PrioritizationPanel from "@/components/PrioritizationPanel";
import FixImpact from "@/components/FixImpact";
import { api, Fix } from "@/lib/api";

const TYPES = ["block_port", "stop_service", "disable_account", "patch_cve"];
const PLACEHOLDER: Record<string, string> = {
  block_port: "e.g. 21,6667,3632",
  stop_service: "e.g. telnet or 23",
  disable_account: "port, e.g. 22",
  patch_cve: "e.g. CVE-2011-2523",
};

export default function PrioritizationPage() {
  const [target, setTarget] = useState("");
  const [fixType, setFixType] = useState("block_port");
  const [fixVal, setFixVal] = useState("");
  const [preview, setPreview] = useState<any>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function show(ip: string, fixes: Fix[]) {
    setBusy(true);
    setErr("");
    setPreview(null);
    try {
      setPreview(await api.fixPreview(ip.trim(), fixes));
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }

  function fromForm() {
    // several values separated by commas = several fixes previewed together
    const fixes = fixVal.split(",").map((v) => v.trim()).filter(Boolean).map((v) => {
      const params: Record<string, unknown> =
        fixType === "patch_cve" ? { cve_id: v }
          : fixType === "stop_service" ? { service: v }
          : { port: parseInt(v, 10) };
      return { type: fixType, params };
    });
    show(target, fixes);
  }

  return (
    <div>
      <Topbar title="Patch Prioritization" />
      <div className="p-6 space-y-4">
        <ConfigNotice />
        <div className="grid lg:grid-cols-3 gap-4">
          <div className="lg:col-span-2">
            <PrioritizationPanel onPreview={(ip, fix) => { setTarget(ip); show(ip, [fix]); }} />
          </div>
          <div className="space-y-4">
            <div className="card">
              <div className="text-sm font-semibold mb-1">Fix Impact Preview</div>
              <p className="text-xs text-muted mb-3">
                See what a fix would change before it is approved — the same numbers the ranking
                uses. Press <b>Preview</b> on a ranked fix, or try your own. Nothing is executed.
              </p>
              <input
                className="bg-panel2 border border-edge rounded-lg px-3 py-2 text-sm w-full mb-2"
                placeholder="target IP e.g. 192.168.103.105" value={target}
                onChange={(e) => setTarget(e.target.value)}
              />
              <div className="flex gap-2 mb-2">
                <select
                  className="bg-panel2 border border-edge rounded-lg px-2 py-2 text-sm flex-1"
                  value={fixType} onChange={(e) => { setFixType(e.target.value); setFixVal(""); }}
                >
                  {TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
                </select>
                <input
                  className="bg-panel2 border border-edge rounded-lg px-2 py-2 text-sm w-40"
                  placeholder={PLACEHOLDER[fixType]} value={fixVal}
                  onChange={(e) => setFixVal(e.target.value)}
                />
              </div>
              <button className="btn btn-primary w-full" onClick={fromForm} disabled={busy || !target || !fixVal}>
                {busy ? "Working…" : "Preview"}
              </button>
              {err && <div className="mt-3 text-sm text-critical">{err}</div>}
            </div>
            {preview && <div className="card"><FixImpact p={preview} /></div>}
          </div>
        </div>
      </div>
    </div>
  );
}
