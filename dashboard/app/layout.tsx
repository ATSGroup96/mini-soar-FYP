import type { Metadata, Viewport } from "next";
import "./globals.css";
import Sidebar from "@/components/Sidebar";
import AuthGate from "@/components/AuthGate";

export const metadata: Metadata = {
  title: "Mini-SOAR · CAASM Platform",
  description: "Network Vulnerability Management & Auto-Remediation (lab-only)",
  manifest: "/manifest.json",
};

export const viewport: Viewport = {
  themeColor: "#0b0f17",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-base text-ink">
        <AuthGate>
          <div className="flex">
            <Sidebar />
            <main className="flex-1 min-w-0">{children}</main>
          </div>
        </AuthGate>
      </body>
    </html>
  );
}
