import React from "react";

const SEV_COLOR: Record<string, string> = {
  critical: "bg-critical/20 text-critical border border-critical/40",
  high: "bg-high/20 text-high border border-high/40",
  medium: "bg-medium/20 text-medium border border-medium/40",
  low: "bg-low/20 text-low border border-low/40",
  info: "bg-info/20 text-info border border-info/40",
};

export function SeverityBadge({ level }: { level?: string }) {
  const l = (level || "info").toLowerCase();
  return <span className={`badge ${SEV_COLOR[l] || SEV_COLOR.info}`}>{l}</span>;
}

const GRADE_COLOR: Record<string, string> = {
  A: "text-low border-low/50",
  B: "text-low border-low/50",
  C: "text-medium border-medium/50",
  D: "text-high border-high/50",
  F: "text-critical border-critical/50",
};

export function GradeBadge({ grade }: { grade?: string }) {
  const g = (grade || "A").toUpperCase();
  return (
    <span
      className={`inline-flex h-9 w-9 items-center justify-center rounded-lg border-2 text-lg font-bold ${
        GRADE_COLOR[g] || GRADE_COLOR.A
      }`}
    >
      {g}
    </span>
  );
}

export function RiskBar({ score }: { score?: number | null }) {
  const s = Math.max(0, Math.min(100, score || 0));
  const color =
    s >= 80 ? "bg-critical" : s >= 60 ? "bg-high" : s >= 40 ? "bg-medium" : "bg-low";
  return (
    <div className="flex items-center gap-2">
      <div className="h-2 w-24 rounded-full bg-panel2 overflow-hidden">
        <div className={`h-full ${color}`} style={{ width: `${s}%` }} />
      </div>
      <span className="text-xs text-muted tabular-nums">{s.toFixed(0)}</span>
    </div>
  );
}

export function KevBadge({ on }: { on?: boolean }) {
  if (!on) return null;
  return <span className="badge bg-critical/20 text-critical border border-critical/40">KEV</span>;
}

export function StatCard({
  label,
  value,
  sub,
  tone = "default",
}: {
  label: string;
  value: React.ReactNode;
  sub?: string;
  tone?: "default" | "critical" | "high" | "low";
}) {
  const toneColor =
    tone === "critical"
      ? "text-critical"
      : tone === "high"
      ? "text-high"
      : tone === "low"
      ? "text-low"
      : "text-ink";
  return (
    <div className="card">
      <div className="text-xs uppercase tracking-wide text-muted">{label}</div>
      <div className={`mt-1 text-3xl font-bold ${toneColor}`}>{value}</div>
      {sub && <div className="mt-1 text-xs text-muted">{sub}</div>}
    </div>
  );
}

export function Empty({ msg }: { msg: string }) {
  return <div className="text-sm text-muted py-8 text-center">{msg}</div>;
}
