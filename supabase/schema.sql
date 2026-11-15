-- =============================================================================
-- Mini-SOAR / CAASM  —  Supabase (PostgreSQL) schema
-- Tables + Row Level Security (RBAC) + indexes.
--
-- Apply with either:
--   * Supabase Studio  -> SQL Editor -> paste this file -> Run
--   * psql "$SUPABASE_DB_URL" -f supabase/schema.sql
--
-- RBAC model (stored in public.profiles.role):
--   admin    -> full read/write, can approve remediations, manage allowlist
--   analyst  -> read everything, create tickets, request remediation (no approve)
--   viewer   -> read-only
--
-- The scanner/SOAR engine authenticates with the SERVICE ROLE key, which
-- bypasses RLS by design (it is the trusted ingestor). The browser/dashboard
-- uses the ANON key + a logged-in user, so RLS below governs human access.
-- =============================================================================

create extension if not exists "pgcrypto";

-- -----------------------------------------------------------------------------
-- Enums
-- -----------------------------------------------------------------------------
do $$ begin
  create type user_role        as enum ('admin','analyst','viewer');
exception when duplicate_object then null; end $$;
do $$ begin
  create type severity_level    as enum ('info','low','medium','high','critical');
exception when duplicate_object then null; end $$;
do $$ begin
  create type ticket_status     as enum ('open','in_progress','awaiting_approval','approved','remediating','resolved','rejected','escalated');
exception when duplicate_object then null; end $$;
do $$ begin
  create type remediation_status as enum ('planned','dry_run','approved','executing','succeeded','failed','rolled_back');
exception when duplicate_object then null; end $$;

-- -----------------------------------------------------------------------------
-- profiles : 1:1 with auth.users, holds role for RBAC
-- -----------------------------------------------------------------------------
create table if not exists public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  email       text,
  full_name   text,
  role        user_role not null default 'viewer',
  totp_secret text,                       -- encrypted at rest by app before store
  totp_enrolled boolean not null default false,
  created_at  timestamptz not null default now()
);

-- Helper: current user's role (used by RLS policies)
create or replace function public.current_role()
returns user_role
language sql stable security definer set search_path = public as $$
  select role from public.profiles where id = auth.uid()
$$;

create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce((select role = 'admin' from public.profiles where id = auth.uid()), false)
$$;

create or replace function public.is_analyst_or_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce((select role in ('analyst','admin') from public.profiles where id = auth.uid()), false)
$$;

-- -----------------------------------------------------------------------------
-- allowlist : authorized CIDR scope (mirrors .env ALLOWED_RANGES, admin-managed)
-- -----------------------------------------------------------------------------
create table if not exists public.allowlist (
  id         uuid primary key default gen_random_uuid(),
  cidr       cidr not null,
  label      text,
  enabled    boolean not null default true,
  created_by uuid references public.profiles(id),
  created_at timestamptz not null default now(),
  unique (cidr)
);

-- -----------------------------------------------------------------------------
-- assets : discovered hosts/devices (CAASM inventory)
-- -----------------------------------------------------------------------------
create table if not exists public.assets (
  id            uuid primary key default gen_random_uuid(),
  ip            inet not null,
  mac           macaddr,
  hostname      text,
  os_guess      text,
  os_accuracy   int,
  first_seen    timestamptz not null default now(),
  last_seen     timestamptz not null default now(),
  is_rogue      boolean not null default false,   -- appeared without being approved
  is_authorized boolean not null default false,   -- admin-blessed known device
  risk_grade    char(1),                          -- A..F from latest scoring
  risk_score    numeric(5,2),                     -- 0..100
  tags          text[] default '{}',
  unique (ip, mac)
);

-- -----------------------------------------------------------------------------
-- scans : one row per scan run
-- -----------------------------------------------------------------------------
create table if not exists public.scans (
  id          uuid primary key default gen_random_uuid(),
  started_at  timestamptz not null default now(),
  finished_at timestamptz,
  scope       text not null,                       -- CIDR(s) actually scanned
  host_count  int default 0,
  status      text not null default 'running',     -- running|completed|failed
  summary     jsonb default '{}'::jsonb
);

-- -----------------------------------------------------------------------------
-- services : open ports / services found per asset per scan
-- -----------------------------------------------------------------------------
create table if not exists public.services (
  id           uuid primary key default gen_random_uuid(),
  asset_id     uuid not null references public.assets(id) on delete cascade,
  scan_id      uuid references public.scans(id) on delete set null,
  port         int not null,
  protocol     text not null default 'tcp',
  state        text,                               -- open|filtered|closed
  service_name text,
  product      text,
  version      text,
  cpe          text,                               -- e.g. cpe:/a:openbsd:openssh:7.2
  banner       text,
  has_default_cred boolean not null default false,
  created_at   timestamptz not null default now()
);

-- -----------------------------------------------------------------------------
-- vulnerabilities : CVE matches for a service, enriched with EPSS/KEV + ML
-- -----------------------------------------------------------------------------
create table if not exists public.vulnerabilities (
  id             uuid primary key default gen_random_uuid(),
  asset_id       uuid not null references public.assets(id) on delete cascade,
  service_id     uuid references public.services(id) on delete set null,
  cve_id         text not null,
  cvss_score     numeric(3,1),
  cvss_vector    text,
  severity       severity_level,
  epss_score     numeric(6,5),                      -- 0..1 probability of exploitation
  epss_percentile numeric(6,5),
  in_kev         boolean not null default false,    -- on CISA Known Exploited list
  kev_due_date   date,
  ml_risk_score  numeric(5,2),                       -- 0..100 from PyTorch model
  ml_reasons     jsonb default '[]'::jsonb,          -- explainability: feature contributions
  description    text,
  status         text not null default 'open',       -- open|remediated|accepted|false_positive
  detected_at    timestamptz not null default now(),
  unique (asset_id, cve_id, service_id)
);

-- -----------------------------------------------------------------------------
-- cve_watchlist : CVEs the team wants an alert on if ever seen
-- -----------------------------------------------------------------------------
create table if not exists public.cve_watchlist (
  id         uuid primary key default gen_random_uuid(),
  cve_id     text not null unique,
  note       text,
  created_by uuid references public.profiles(id),
  created_at timestamptz not null default now()
);

-- -----------------------------------------------------------------------------
-- tls_certs : TLS/SSL certificate findings
-- -----------------------------------------------------------------------------
create table if not exists public.tls_certs (
  id           uuid primary key default gen_random_uuid(),
  asset_id     uuid not null references public.assets(id) on delete cascade,
  port         int not null,
  subject      text,
  issuer       text,
  not_before   timestamptz,
  not_after    timestamptz,
  days_to_expiry int,
  is_self_signed boolean,
  is_expired   boolean,
  weak_sig_alg text,                                 -- e.g. sha1WithRSAEncryption
  tls_version  text,
  created_at   timestamptz not null default now()
);

-- -----------------------------------------------------------------------------
-- tickets : SLA-tracked work items
-- -----------------------------------------------------------------------------
create table if not exists public.tickets (
  id            uuid primary key default gen_random_uuid(),
  vuln_id       uuid references public.vulnerabilities(id) on delete set null,
  asset_id      uuid references public.assets(id) on delete set null,
  title         text not null,
  description   text,
  severity      severity_level not null default 'medium',
  status        ticket_status not null default 'open',
  assigned_to   uuid references public.profiles(id),
  sla_due_at    timestamptz,                         -- computed from severity
  escalated     boolean not null default false,
  created_by    uuid references public.profiles(id),
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

-- -----------------------------------------------------------------------------
-- remediations : a planned/approved/executed fix for a ticket
-- -----------------------------------------------------------------------------
create table if not exists public.remediations (
  id             uuid primary key default gen_random_uuid(),
  ticket_id      uuid not null references public.tickets(id) on delete cascade,
  asset_id       uuid references public.assets(id) on delete set null,
  action_type    text not null,                      -- block_port|stop_service|disable_account|custom
  action_params  jsonb not null default '{}'::jsonb, -- e.g. {"port":23,"proto":"tcp"}
  command_preview text,                              -- exact command(s) shown in dry-run
  status         remediation_status not null default 'planned',
  dry_run_output text,
  requested_by   uuid references public.profiles(id),
  approved_by    uuid references public.profiles(id),
  approved_at    timestamptz,
  totp_verified  boolean not null default false,
  executed_at    timestamptz,
  result_output  text,
  rollback_plan  jsonb default '{}'::jsonb,
  rolled_back_at timestamptz,
  verified_fixed boolean,                            -- set true after a confirming re-scan
  created_at     timestamptz not null default now()
);

-- -----------------------------------------------------------------------------
-- audit_log : tamper-evident hash chain. Each row hashes itself + prev hash.
-- The ingest service computes curr_hash; verification recomputes the chain.
-- -----------------------------------------------------------------------------
create table if not exists public.audit_log (
  id         bigint generated always as identity primary key,
  ts         timestamptz not null default now(),
  actor      text,                                   -- user email or "engine"
  action     text not null,                          -- e.g. scan.start, remediation.execute
  target     text,
  detail     jsonb default '{}'::jsonb,
  prev_hash  text,
  curr_hash  text not null
);

-- -----------------------------------------------------------------------------
-- honeypot_events : hits on the fake SSH/HTTP decoys
-- -----------------------------------------------------------------------------
create table if not exists public.honeypot_events (
  id            uuid primary key default gen_random_uuid(),
  ts            timestamptz not null default now(),
  service       text not null,                        -- ssh|http
  src_ip        inet not null,
  src_port      int,
  username_tried text,
  password_tried text,
  path_or_cmd   text,
  abuse_score   int,                                  -- AbuseIPDB confidence 0..100
  otx_pulses    int,                                  -- AlienVault OTX pulse count
  reputation    text                                  -- clean|suspicious|malicious
);

-- -----------------------------------------------------------------------------
-- notifications : queue for PWA web-push / in-app alerts
-- -----------------------------------------------------------------------------
create table if not exists public.notifications (
  id         uuid primary key default gen_random_uuid(),
  level      severity_level not null default 'info',
  title      text not null,
  body       text,
  link       text,
  read       boolean not null default false,
  created_at timestamptz not null default now()
);

-- -----------------------------------------------------------------------------
-- push_subscriptions : browser PushManager subscriptions for web-push
-- -----------------------------------------------------------------------------
create table if not exists public.push_subscriptions (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid references public.profiles(id) on delete cascade,
  endpoint   text not null unique,
  p256dh     text not null,
  auth       text not null,
  created_at timestamptz not null default now()
);

-- =============================================================================
-- Indexes
-- =============================================================================
create index if not exists idx_assets_ip           on public.assets (ip);
create unique index if not exists assets_ip_unique on public.assets (ip);
create index if not exists idx_assets_risk          on public.assets (risk_score desc);
create index if not exists idx_assets_rogue         on public.assets (is_rogue) where is_rogue;
create index if not exists idx_services_asset       on public.services (asset_id);
create index if not exists idx_services_scan        on public.services (scan_id);
create index if not exists idx_vulns_asset          on public.vulnerabilities (asset_id);
create index if not exists idx_vulns_cve            on public.vulnerabilities (cve_id);
create index if not exists idx_vulns_kev            on public.vulnerabilities (in_kev) where in_kev;
create index if not exists idx_vulns_mlrisk         on public.vulnerabilities (ml_risk_score desc);
create index if not exists idx_vulns_status         on public.vulnerabilities (status);
create index if not exists idx_tickets_status       on public.tickets (status);
create index if not exists idx_tickets_sla          on public.tickets (sla_due_at);
create index if not exists idx_remed_ticket         on public.remediations (ticket_id);
create index if not exists idx_remed_status         on public.remediations (status);
create index if not exists idx_audit_ts             on public.audit_log (ts);
create index if not exists idx_honeypot_ts          on public.honeypot_events (ts desc);
create index if not exists idx_honeypot_src         on public.honeypot_events (src_ip);
create index if not exists idx_tls_expiry           on public.tls_certs (days_to_expiry);
create index if not exists idx_notif_unread         on public.notifications (read) where not read;

-- =============================================================================
-- Row Level Security  (RBAC)
-- =============================================================================
alter table public.profiles           enable row level security;
alter table public.allowlist          enable row level security;
alter table public.assets             enable row level security;
alter table public.scans              enable row level security;
alter table public.services           enable row level security;
alter table public.vulnerabilities    enable row level security;
alter table public.cve_watchlist      enable row level security;
alter table public.tls_certs          enable row level security;
alter table public.tickets            enable row level security;
alter table public.remediations       enable row level security;
alter table public.audit_log          enable row level security;
alter table public.honeypot_events    enable row level security;
alter table public.notifications      enable row level security;
alter table public.push_subscriptions enable row level security;

-- profiles: a user sees & edits only their own row; admins see all.
drop policy if exists profiles_self_read on public.profiles;
create policy profiles_self_read on public.profiles
  for select using (id = auth.uid() or public.is_admin());
drop policy if exists profiles_self_update on public.profiles;
create policy profiles_self_update on public.profiles
  for update using (id = auth.uid());
drop policy if exists profiles_admin_all on public.profiles;
create policy profiles_admin_all on public.profiles
  for all using (public.is_admin()) with check (public.is_admin());

-- Generic READ for any authenticated user (viewer+) on the operational tables.
do $$
declare t text;
begin
  foreach t in array array[
    'assets','scans','services','vulnerabilities','cve_watchlist',
    'tls_certs','tickets','remediations','audit_log','honeypot_events','notifications'
  ] loop
    execute format('drop policy if exists %I_read on public.%I;', t, t);
    execute format(
      'create policy %I_read on public.%I for select using (auth.role() = ''authenticated'');',
      t, t);
  end loop;
end $$;

-- allowlist: read for all authenticated; write only admin.
drop policy if exists allowlist_read on public.allowlist;
create policy allowlist_read on public.allowlist
  for select using (auth.role() = 'authenticated');
drop policy if exists allowlist_admin_write on public.allowlist;
create policy allowlist_admin_write on public.allowlist
  for all using (public.is_admin()) with check (public.is_admin());

-- tickets: analyst/admin can create & update; viewer read-only (covered above).
drop policy if exists tickets_write on public.tickets;
create policy tickets_write on public.tickets
  for insert with check (public.is_analyst_or_admin());
drop policy if exists tickets_update on public.tickets;
create policy tickets_update on public.tickets
  for update using (public.is_analyst_or_admin());

-- cve_watchlist: analyst/admin manage.
drop policy if exists watchlist_write on public.cve_watchlist;
create policy watchlist_write on public.cve_watchlist
  for all using (public.is_analyst_or_admin()) with check (public.is_analyst_or_admin());

-- remediations: analyst/admin may REQUEST (insert as 'planned'); only admin may
-- move a row to 'approved'/'executing' (approval gate). Enforced in app too.
drop policy if exists remediations_request on public.remediations;
create policy remediations_request on public.remediations
  for insert with check (public.is_analyst_or_admin());
drop policy if exists remediations_admin_update on public.remediations;
create policy remediations_admin_update on public.remediations
  for update using (public.is_admin());

-- push_subscriptions: each user manages their own.
drop policy if exists push_self on public.push_subscriptions;
create policy push_self on public.push_subscriptions
  for all using (user_id = auth.uid()) with check (user_id = auth.uid());

-- =============================================================================
-- Trigger: auto-create a profile row when a new auth user signs up
-- (first ever user becomes admin; everyone after is viewer until promoted)
-- =============================================================================
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
declare existing int;
begin
  select count(*) into existing from public.profiles;
  insert into public.profiles (id, email, role)
  values (new.id, new.email,
          (case when existing = 0 then 'admin' else 'viewer' end)::public.user_role);
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- =============================================================================
-- Realtime: expose the tables the dashboard subscribes to
-- =============================================================================
do $$ begin
  alter publication supabase_realtime add table
    public.assets, public.vulnerabilities, public.tickets,
    public.remediations, public.honeypot_events, public.notifications;
exception when duplicate_object then null; end $$;

-- Done.

-- -----------------------------------------------------------------------------
-- v2 additions (also shipped as supabase/migrations/002_v2_fixes.sql)
-- -----------------------------------------------------------------------------
alter table public.vulnerabilities add column if not exists confidence text
  not null default 'version-confirmed';
alter table public.tickets add column if not exists suggested_action jsonb;
create unique index if not exists services_asset_port_unique
  on public.services (asset_id, port, protocol);
-- 003: network scope managed from the dashboard (Settings -> Network scope)
-- One row only (id = 1). The engine reads it; only the API (service key) writes it,
-- after checking that the user is an admin and the TOTP code is valid.
create table if not exists public.scope_config (
  id                  int primary key default 1 check (id = 1),
  allowed_ranges      text[] not null default '{}',
  deny_hosts          text[] not null default '{}',
  authorized          boolean not null default false,
  authorization_note  text,
  updated_by          uuid references public.profiles(id),
  updated_at          timestamptz not null default now()
);
alter table public.scope_config enable row level security;
drop policy if exists scope_config_read on public.scope_config;
create policy scope_config_read on public.scope_config
  for select using (auth.role() = 'authenticated');
-- no insert/update/delete policy: browsers cannot change it directly

-- -----------------------------------------------------------------------------
-- 004: risk-trend tracking + change detection
-- (also shipped as supabase/migrations/004_trend_changes.sql)
-- -----------------------------------------------------------------------------
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
