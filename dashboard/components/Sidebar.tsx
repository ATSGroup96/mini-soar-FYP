"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { getSupabase } from "@/lib/supabaseClient";
import { useSession } from "@/components/AuthGate";
import {
  LayoutDashboard, Server, ShieldAlert, Network, Ticket, Wrench,
  Bug, Lock, ScrollText, FileText, Settings, ShieldCheck, LogOut,
} from "lucide-react";

const NAV = [
  { href: "/dashboard", label: "Overview", icon: LayoutDashboard },
  { href: "/assets", label: "Assets", icon: Server },
  { href: "/vulnerabilities", label: "Vulnerabilities", icon: ShieldAlert },
  { href: "/topology", label: "Topology & Paths", icon: Network },
  { href: "/tickets", label: "Tickets", icon: Ticket },
  { href: "/remediation", label: "Remediation", icon: Wrench },
  { href: "/honeypot", label: "Honeypot", icon: Bug },
  { href: "/tls", label: "TLS Certs", icon: Lock },
  { href: "/audit", label: "Audit Log", icon: ScrollText },
  { href: "/reports", label: "Reports", icon: FileText },
  { href: "/settings", label: "Settings", icon: Settings },
];

export default function Sidebar() {
  const path = usePathname();
  const session = useSession();
  return (
    <aside className="w-60 shrink-0 border-r border-edge bg-panel min-h-screen p-3 hidden md:block">
      <div className="flex items-center gap-2 px-2 py-3 mb-2">
        <ShieldCheck className="text-accent" size={22} />
        <div>
          <div className="font-bold leading-tight">Mini-SOAR</div>
          <div className="text-[10px] text-muted leading-tight">CAASM Platform</div>
        </div>
      </div>
      <nav className="space-y-1">
        {NAV.map(({ href, label, icon: Icon }) => {
          const active = path === href || path?.startsWith(href + "/");
          return (
            <Link
              key={href}
              href={href}
              className={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
                active
                  ? "bg-accent/15 text-ink border border-accent/40"
                  : "text-muted hover:text-ink hover:bg-panel2"
              }`}
            >
              <Icon size={17} />
              {label}
            </Link>
          );
        })}
      </nav>
      {session && (
        <div className="mt-6 px-3">
          <div className="text-[11px] text-muted truncate">{session.user.email}</div>
          <button className="btn mt-2 w-full justify-center" onClick={() => getSupabase()?.auth.signOut()}>
            <LogOut size={14} /> Sign out
          </button>
        </div>
      )}
      <div className="mt-6 px-3 text-[10px] text-muted leading-relaxed">
        Lab-only · scans &amp; fixes restricted to the allowlisted scope.
      </div>
    </aside>
  );
}
