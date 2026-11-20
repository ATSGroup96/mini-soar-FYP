-- =============================================================================
-- Mini-SOAR migration 006 — align with the final FYDP proposal (v14)
-- Run ONCE in the Supabase SQL Editor on an existing DB. Safe to re-run.
-- Fresh installs get all of this from schema.sql.
--
--   1. honeypot removed            : drop public.honeypot_events
--   2. "digital twin" renamed       : Patch Prioritization + Fix Impact Preview
--        assets.criticality        -> assets.importance
--        twin_dependencies         -> component_dependencies
--        remediations.twin_prediction / twin_result -> fix_prediction / fix_check
--   3. findings without a CVE      : Nuclei / NetExec results in public.vulnerabilities
--   4. security fixes              : a user can no longer make himself admin, the
--        browser can no longer approve a fix (2FA bypass), a TOTP code works once
--   5. realtime                    : services + component_dependencies (live topology)
-- =============================================================================

-- 1) honeypot removed ------------------------------------------------------------
drop table if exists public.honeypot_events cascade;

-- 2a) asset importance (was "criticality") ----------------------------------------
do $$ begin
  if exists (select 1 from information_schema.columns where table_schema = 'public'
             and table_name = 'assets' and column_name = 'criticality')
     and not exists (select 1 from information_schema.columns where table_schema = 'public'
             and table_name = 'assets' and column_name = 'importance') then
    alter table public.assets rename column criticality to importance;
  end if;
end $$;
alter table public.assets add column if not exists importance text not null default 'normal';
alter table public.assets drop constraint if exists assets_criticality_check;
do $$ begin
  alter table public.assets add constraint assets_importance_check
    check (importance in ('critical','normal','low'));
exception when duplicate_object then null; end $$;

-- 2b) manual dependencies (was twin_dependencies) ----------------------------------
do $$ begin
  if to_regclass('public.twin_dependencies') is not null
     and to_regclass('public.component_dependencies') is null then
    alter table public.twin_dependencies rename to component_dependencies;
  end if;
end $$;
-- component ids: '<ip>|os' for the operating system, '<ip>|<port>' for a service
-- "from_component depends on to_component"
create table if not exists public.component_dependencies (
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
alter table public.component_dependencies enable row level security;
drop policy if exists twin_dependencies_read on public.component_dependencies;
drop policy if exists component_dependencies_read on public.component_dependencies;
create policy component_dependencies_read on public.component_dependencies
  for select using (auth.role() = 'authenticated');

-- 2c) Fix Impact Preview kept with each fix (was twin_prediction / twin_result) ------
do $$ begin
  if exists (select 1 from information_schema.columns where table_schema = 'public'
             and table_name = 'remediations' and column_name = 'twin_prediction') then
    alter table public.remediations rename column twin_prediction to fix_prediction;
  end if;
  if exists (select 1 from information_schema.columns where table_schema = 'public'
             and table_name = 'remediations' and column_name = 'twin_result') then
    alter table public.remediations rename column twin_result to fix_check;
  end if;
end $$;
alter table public.remediations add column if not exists fix_prediction jsonb;
alter table public.remediations add column if not exists fix_check      jsonb;

-- 3) findings without a CVE (Nuclei templates, NetExec posture checks) ---------------
alter table public.vulnerabilities alter column cve_id drop not null;
alter table public.vulnerabilities add column if not exists source text not null default 'cve';
do $$ begin
  alter table public.vulnerabilities add constraint vulnerabilities_source_check
    check (source in ('cve','nuclei','netexec'));
exception when duplicate_object then null; end $$;
alter table public.vulnerabilities add column if not exists finding_key text;  -- CVE id / template id / check id
alter table public.vulnerabilities add column if not exists title       text;
alter table public.vulnerabilities add column if not exists evidence    text;
update public.vulnerabilities set finding_key = cve_id where finding_key is null;
do $$ begin
  alter table public.vulnerabilities add constraint vulnerabilities_has_identity
    check (cve_id is not null or finding_key is not null);
exception when duplicate_object then null; end $$;
create index if not exists idx_vuln_finding on public.vulnerabilities (asset_id, source, finding_key);

-- 4a) a user cannot change his own role or 2FA columns -----------------------------
-- (before: profiles_self_update let ANY signed-in viewer set role = 'admin')
alter table public.profiles add column if not exists totp_last_step bigint;  -- TOTP replay guard
-- SECURITY INVOKER on purpose: current_user must be the caller's role
-- ('authenticated' for a browser), not the function owner
create or replace function public.protect_profile_columns()
returns trigger language plpgsql security invoker set search_path = public as $$
begin
  -- only browser sessions are limited; the engine / API (service key) and the
  -- SQL Editor (postgres) may change anything
  if current_user not in ('authenticated', 'anon') then
    return new;
  end if;
  -- 2FA columns are written only by the API
  new.totp_secret    := old.totp_secret;
  new.totp_enrolled  := old.totp_enrolled;
  new.totp_last_step := old.totp_last_step;
  -- only an admin may change a role (promote / demote a user)
  if new.role is distinct from old.role and not public.is_admin() then
    raise exception 'only an admin can change a role';
  end if;
  new.id := old.id;
  return new;
end $$;
drop trigger if exists protect_profile_columns on public.profiles;
create trigger protect_profile_columns
  before update on public.profiles
  for each row execute function public.protect_profile_columns();

-- 4b) remediations are written only by the API (service key) -----------------------
-- (before: an admin's browser could set status = 'approved', totp_verified = true
--  directly and the worker ran it without any 2FA code)
drop policy if exists remediations_request on public.remediations;
drop policy if exists remediations_admin_update on public.remediations;
-- no insert / update / delete policy: browsers can only read remediations

-- 5) live updates in the dashboard ------------------------------------------------
do $$ begin
  alter publication supabase_realtime add table public.component_dependencies;
exception when duplicate_object then null; end $$;
do $$ begin
  alter publication supabase_realtime add table public.services;
exception when duplicate_object then null; end $$;
