"use client";
import Topbar from "@/components/Topbar";
import { api } from "@/lib/api";
import { FileDown } from "lucide-react";

export default function ReportsPage() {
  return (
    <div>
      <Topbar title="Reports" />
      <div className="p-6 space-y-4">
        <div className="card max-w-xl">
          <div className="text-sm font-semibold mb-2">Security assessment report</div>
          <p className="text-xs text-muted mb-4">
            Generates a PDF of the latest scan: asset inventory, prioritized vulnerabilities
            (KEV/EPSS), security grade, remediation history, and a MITRE ATT&amp;CK technique
            mapping of the findings.
          </p>
          <a className="btn btn-primary" href={api.reportUrl()} target="_blank" rel="noreferrer">
            <FileDown size={15} /> Download latest PDF
          </a>
        </div>
      </div>
    </div>
  );
}
