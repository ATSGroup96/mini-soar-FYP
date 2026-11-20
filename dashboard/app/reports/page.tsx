"use client";
import { useState } from "react";
import Topbar from "@/components/Topbar";
import { api } from "@/lib/api";
import { FileDown } from "lucide-react";

export default function ReportsPage() {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  async function download() {
    setBusy(true);
    setErr("");
    try {
      await api.downloadReport();
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <Topbar title="Reports" />
      <div className="p-6 space-y-4">
        <div className="card max-w-xl">
          <div className="text-sm font-semibold mb-2">Security assessment report</div>
          <p className="text-xs text-muted mb-4">
            Generates a PDF of the latest scan: asset inventory, prioritized findings
            (KEV/EPSS, Nuclei, NetExec), security grade, remediation history, and a MITRE
            ATT&amp;CK technique mapping of the findings.
          </p>
          <button className="btn btn-primary" onClick={download} disabled={busy}>
            <FileDown size={15} /> {busy ? "Building…" : "Download latest PDF"}
          </button>
          {err && <div className="mt-3 text-sm text-critical">{err}</div>}
        </div>
      </div>
    </div>
  );
}
