"use client";
import { useEffect, useState, useCallback } from "react";
import { getSupabase, supabaseConfigured } from "./supabaseClient";

type Opts = {
  orderBy?: string;
  ascending?: boolean;
  limit?: number;
  realtime?: boolean;
};

export function useTable<T = any>(table: string, opts: Opts = {}) {
  const { orderBy, ascending = false, limit = 500, realtime = true } = opts;
  const [rows, setRows] = useState<T[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    const sb = getSupabase();
    if (!sb) {
      setLoading(false);
      return;
    }
    let q = sb.from(table).select("*").limit(limit);
    if (orderBy) q = q.order(orderBy, { ascending });
    const { data, error } = await q;
    if (error) setError(error.message);
    else setRows((data as T[]) || []);
    setLoading(false);
  }, [table, orderBy, ascending, limit]);

  useEffect(() => {
    load();
    if (!realtime) return;
    const sb = getSupabase();
    if (!sb) return;
    // a scan writes hundreds of rows; batch them into one reload per second
    let timer: ReturnType<typeof setTimeout> | null = null;
    const channel = sb
      .channel(`rt-${table}-${Math.random().toString(36).slice(2)}`)
      .on("postgres_changes", { event: "*", schema: "public", table }, () => {
        if (timer) clearTimeout(timer);
        timer = setTimeout(() => load(), 1000);
      })
      .subscribe();
    return () => {
      if (timer) clearTimeout(timer);
      sb.removeChannel(channel);
    };
  }, [load, table, realtime]);

  return { rows, loading, error, reload: load, configured: supabaseConfigured };
}
