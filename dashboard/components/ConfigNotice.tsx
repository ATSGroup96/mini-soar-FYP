"use client";
import { supabaseConfigured } from "@/lib/supabaseClient";

export default function ConfigNotice() {
  if (supabaseConfigured) return null;
  return (
    <div className="card border-medium/50 bg-medium/10 mb-4">
      <div className="text-medium font-semibold text-sm">Supabase not configured</div>
      <p className="text-xs text-muted mt-1">
        Set <code className="font-mono">NEXT_PUBLIC_SUPABASE_URL</code> and{" "}
        <code className="font-mono">NEXT_PUBLIC_SUPABASE_ANON_KEY</code> in your{" "}
        <code className="font-mono">.env</code>, load{" "}
        <code className="font-mono">supabase/schema.sql</code>, then run a scan.
        The UI renders with empty data until then.
      </p>
    </div>
  );
}
