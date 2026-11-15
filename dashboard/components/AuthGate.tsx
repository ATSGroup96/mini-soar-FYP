"use client";
import { createContext, useContext, useEffect, useState } from "react";
import type { Session } from "@supabase/supabase-js";
import { ShieldCheck } from "lucide-react";
import { getSupabase, supabaseConfigured } from "@/lib/supabaseClient";

const SessionCtx = createContext<Session | null>(null);
export const useSession = () => useContext(SessionCtx);

export default function AuthGate({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [ready, setReady] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const sb = getSupabase();
    if (!sb) { setReady(true); return; }
    sb.auth.getSession().then(({ data }) => { setSession(data.session); setReady(true); });
    const { data: sub } = sb.auth.onAuthStateChange((_e, s) => setSession(s));
    return () => sub.subscription.unsubscribe();
  }, []);

  // Without Supabase configured, render the app so the config notice is visible.
  if (!supabaseConfigured) return <>{children}</>;
  if (!ready) return <div className="min-h-screen flex items-center justify-center text-muted">Loading…</div>;

  if (!session) {
    async function login(e: React.FormEvent) {
      e.preventDefault();
      setBusy(true); setErr("");
      const sb = getSupabase();
      const { error } = await sb!.auth.signInWithPassword({ email, password });
      if (error) setErr(error.message);
      setBusy(false);
    }
    return (
      <div className="min-h-screen flex items-center justify-center p-6">
        <form onSubmit={login} className="card w-full max-w-sm space-y-4">
          <div className="flex items-center gap-2">
            <ShieldCheck className="text-accent" />
            <div>
              <div className="font-bold">Mini-SOAR</div>
              <div className="text-xs text-muted">Sign in to the dashboard</div>
            </div>
          </div>
          <label className="block text-sm">
            Email
            <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)}
              className="mt-1 w-full bg-panel2 border border-edge rounded-lg px-3 py-2 text-sm" />
          </label>
          <label className="block text-sm">
            Password
            <input type="password" required value={password} onChange={(e) => setPassword(e.target.value)}
              className="mt-1 w-full bg-panel2 border border-edge rounded-lg px-3 py-2 text-sm" />
          </label>
          {err && <div className="text-sm text-critical">{err}</div>}
          <button type="submit" className="btn btn-primary w-full justify-center" disabled={busy}>
            {busy ? "Signing in…" : "Sign in"}
          </button>
          <p className="text-xs text-muted">
            Users are created in Supabase → Authentication → Users. The first user becomes admin.
          </p>
        </form>
      </div>
    );
  }

  return <SessionCtx.Provider value={session}>{children}</SessionCtx.Provider>;
}
