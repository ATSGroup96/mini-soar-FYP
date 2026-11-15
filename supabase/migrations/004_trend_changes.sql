-- =============================================================================
-- Mini-SOAR migration 004 — run ONCE in Supabase SQL Editor on an existing DB.
-- Safe to re-run (idempotent). Fresh installs get this from schema.sql.
--   * risk_history   : risk-trend tracking (one point per host and one for the
--                      whole network after every scan)
--   * asset_changes  : change detection (new device, port opened / closed,
--                      software version changed)
-- Until this is run the engine still works; it just cannot store these two.
-- =============================================================================

-- 1) risk trend ----------------------------------------------------------------
create table if not exists public.risk_history (
  id          uuid primary key default gen_random_uuid(),
  scan_id     uuid references public.scans(id) on delete cascade,
  asset_id    uuid references public.assets(id) on delete cascade,  -- NULL = whole network
  risk_score  numeric(5,2) not null,                                -- 0..100
  risk_grade  char(1),                                              -- A..F
  open_vulns  int not null default 0,
  kev_count   int not null default 0,
  created_at  timestamptz not null default now()
);
create index if not exists idx_risk_history_time  on public.risk_history (created_at);
create index if not exists idx_risk_history_asset on public.risk_history (asset_id, created_at);

-- 2) change detection ------------------------------------------------------------
create table if not exists public.asset_changes (
  id          uuid primary key default gen_random_uuid(),
  asset_id    uuid references public.assets(id) on delete cascade,
  scan_id     uuid references public.scans(id) on delete set null,
  kind        text not null check (kind in
                ('new_asset','port_opened','port_closed','version_changed')),
  port        int,
  detail      jsonb not null default '{}'::jsonb,
  created_at  timestamptz not null default now()
);
create index if not exists idx_asset_changes_time  on public.asset_changes (created_at desc);
create index if not exists idx_asset_changes_asset on public.asset_changes (asset_id);

-- 3) security: any signed-in user may read; only the engine (service key) writes
alter table public.risk_history  enable row level security;
alter table public.asset_changes enable row level security;
drop policy if exists risk_history_read on public.risk_history;
create policy risk_history_read on public.risk_history
  for select using (auth.role() = 'authenticated');
drop policy if exists asset_changes_read on public.asset_changes;
create policy asset_changes_read on public.asset_changes
  for select using (auth.role() = 'authenticated');

-- 4) live updates in the dashboard ----------------------------------------------
do $$ begin
  alter publication supabase_realtime add table public.risk_history;
exception when duplicate_object then null; end $$;
do $$ begin
  alter publication supabase_realtime add table public.asset_changes;
exception when duplicate_object then null; end $$;
do $$ begin
  alter publication supabase_realtime add table public.cve_watchlist;
exception when duplicate_object then null; end $$;
