"use client";
import Topbar from "@/components/Topbar";
import ConfigNotice from "@/components/ConfigNotice";
import { useTable } from "@/lib/useData";
import { Empty } from "@/lib/ui";
import { useMemo } from "react";

// show just the CN of a long X.509 name (full name on hover)
function cn(name?: string) {
  if (!name) return "–";
  const m = name.match(/CN=([^,]+)/);
  return <span title={name}>{m ? m[1] : name}</span>;
}

export default function TlsPage() {
  const { rows } = useTable<any>("tls_certs", { orderBy: "days_to_expiry", ascending: true });
  const assets = useTable<any>("assets");
  const ipOf = useMemo(() => {
    const m: Record<string, string> = {};
    assets.rows.forEach((a: any) => (m[a.id] = String(a.ip)));
    return m;
  }, [assets.rows]);
  return (
    <div>
      <Topbar title="TLS / SSL Certificates" />
      <div className="p-6 space-y-4">
        <ConfigNotice />
        <div className="card p-0 overflow-hidden">
          <table className="w-full">
            <thead className="bg-panel2">
              <tr>
                <th className="th">Host:Port</th><th className="th">Subject</th><th className="th">Issuer</th>
                <th className="th">Expires in</th><th className="th">TLS</th><th className="th">Flags</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((c) => (
                <tr key={c.id} className="hover:bg-panel2/50">
                  <td className="td font-mono text-xs">{ipOf[c.asset_id] || ""}:{c.port}</td>
                  <td className="td text-xs">{cn(c.subject)}</td>
                  <td className="td text-xs text-muted">{cn(c.issuer)}</td>
                  <td className={`td text-sm ${c.is_expired ? "text-critical" : (c.days_to_expiry ?? 99) < 30 ? "text-high" : "text-low"}`}>
                    {c.is_expired ? "expired" : `${c.days_to_expiry ?? "?"}d`}
                  </td>
                  <td className="td text-xs">{c.tls_version || "–"}</td>
                  <td className="td space-x-1">
                    {c.is_self_signed && <span className="badge bg-medium/20 text-medium border border-medium/40">self-signed</span>}
                    {c.weak_sig_alg && <span className="badge bg-high/20 text-high border border-high/40">weak sig</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!rows.length && <Empty msg="No certificates inspected yet." />}
        </div>
      </div>
    </div>
  );
}
