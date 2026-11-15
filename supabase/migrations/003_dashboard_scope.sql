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
