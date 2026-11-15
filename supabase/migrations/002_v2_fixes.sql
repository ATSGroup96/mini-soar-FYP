-- =============================================================================
-- Mini-SOAR v2 migration — run ONCE in Supabase SQL Editor on an existing DB.
-- Safe to re-run (idempotent). Fresh installs get this from schema.sql.
--   * one row per (asset, port, protocol) in services   -> no duplicates
--   * one row per (asset, cve, service) in vulnerabilities
--   * vulnerabilities.confidence  (version-confirmed / version-unconfirmed)
--   * tickets.suggested_action    (auto-suggested remediation playbook)
-- =============================================================================

-- 1) new columns --------------------------------------------------------------
alter table public.vulnerabilities add column if not exists confidence text
  not null default 'version-confirmed';
alter table public.tickets add column if not exists suggested_action jsonb;

-- 2) de-duplicate services: keep the newest row per (asset, port, protocol) ----
with ranked as (
  select id, asset_id, port, protocol,
         first_value(id) over (partition by asset_id, port, protocol
                               order by created_at desc, id desc) as keep_id
  from public.services
)
update public.vulnerabilities v
   set service_id = r.keep_id
  from ranked r
 where v.service_id = r.id and r.id <> r.keep_id;

-- vulns that now collide on (asset, cve, service): keep the newest
delete from public.vulnerabilities v
 using public.vulnerabilities w
 where v.asset_id = w.asset_id and v.cve_id = w.cve_id
   and v.service_id is not distinct from w.service_id
   and (v.detected_at, v.id) < (w.detected_at, w.id);

delete from public.services s
 using public.services t
 where s.asset_id = t.asset_id and s.port = t.port and s.protocol = t.protocol
   and (s.created_at, s.id) < (t.created_at, t.id);

create unique index if not exists services_asset_port_unique
  on public.services (asset_id, port, protocol);

-- 3) asset ip must be unique (one row per device) ------------------------------
create unique index if not exists assets_ip_unique on public.assets (ip);
