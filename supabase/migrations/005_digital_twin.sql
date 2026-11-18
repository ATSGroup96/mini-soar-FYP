-- =============================================================================
-- Mini-SOAR migration 005 — dependency-based digital twin
-- Run ONCE in the Supabase SQL Editor on an existing DB. Safe to re-run.
-- Fresh installs get this from schema.sql.
--   * assets.criticality      : admin's weight per asset (critical/normal/low)
--   * twin_dependencies       : dependencies the admin adds (or hides) by hand
--   * remediations.twin_*     : what the twin predicted for a fix, and whether
--                               the next scan confirmed it (twin accuracy)
-- Until this is run the twin still works with defaults; it just cannot store
-- weights, manual dependencies or predictions.
-- =============================================================================

-- 1) asset weight (the paper's "stakeholder" step) -----------------------------
alter table public.assets
  add column if not exists criticality text not null default 'normal';
do $$ begin
  alter table public.assets add constraint assets_criticality_check
    check (criticality in ('critical','normal','low'));
exception when duplicate_object then null; end $$;

-- 2) manual dependencies --------------------------------------------------------
-- component ids: '<ip>|os' for the operating system, '<ip>|<port>' for a service
-- "from_component depends on to_component"
create table if not exists public.twin_dependencies (
  id              uuid primary key default gen_random_uuid(),
  from_component  text not null,
  to_component    text not null,
  rule            text not null default 'network'
                  check (rule in ('embedding','interaction','data','network')),
  enabled         boolean not null default true,   -- false = hide an automatic one
  note            text,
  created_at      timestamptz not null default now(),
  unique (from_component, to_component),
  check (from_component <> to_component)
);

-- 3) predictions and their check --------------------------------------------------
alter table public.remediations add column if not exists twin_prediction jsonb;
alter table public.remediations add column if not exists twin_result     jsonb;

-- 4) security: signed-in users may read; only the engine / API (service key) writes
alter table public.twin_dependencies enable row level security;
drop policy if exists twin_dependencies_read on public.twin_dependencies;
create policy twin_dependencies_read on public.twin_dependencies
  for select using (auth.role() = 'authenticated');

-- 5) live updates in the dashboard ------------------------------------------------
do $$ begin
  alter publication supabase_realtime add table public.twin_dependencies;
exception when duplicate_object then null; end $$;
