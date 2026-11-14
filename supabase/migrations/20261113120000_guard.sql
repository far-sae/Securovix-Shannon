-- Securovix Guard: identity and cloud defence (Microsoft 365, Google Workspace) joined to Shannon.
-- Raw provider events are never stored. Alerts live inside incidents with a trimmed evidence
-- snapshot; per-person baselines hold only countries, device ids, the last located sign-in and
-- download statistics.

create table if not exists public.shannon_guard_connections (
  id text primary key,
  org_id text not null references public.shannon_organizations(id) on delete cascade,
  provider text not null check (provider in ('microsoft', 'google', 'simulation')),
  name text not null,
  config jsonb not null default '{}'::jsonb,
  secret_enc text,
  state jsonb not null default '{}'::jsonb,
  enabled boolean not null default true,
  status text,
  last_sync_at bigint,
  last_error text,
  last_event_count integer,
  total_events bigint,
  created_by text,
  created_at bigint not null,
  updated_at bigint not null
);
create index if not exists shannon_guard_connections_org_idx on public.shannon_guard_connections (org_id, created_at desc);

create table if not exists public.shannon_guard_incidents (
  id text primary key,
  org_id text not null references public.shannon_organizations(id) on delete cascade,
  key text not null,
  status text not null check (status in ('open', 'contained', 'closed')),
  severity text not null,
  title text not null,
  summary text,
  ai_summary text,
  mitre jsonb not null default '[]'::jsonb,
  kinds jsonb not null default '[]'::jsonb,
  alerts jsonb not null default '[]'::jsonb,
  alert_count integer,
  actions jsonb not null default '[]'::jsonb,
  actions_taken jsonb not null default '[]'::jsonb,
  reopened integer,
  first_seen_at bigint not null,
  last_seen_at bigint not null,
  detected_at bigint,
  contained_at bigint,
  closed_at bigint,
  closed_by text,
  close_note text,
  forced_close boolean,
  created_at bigint not null,
  updated_at bigint not null
);
create index if not exists shannon_guard_incidents_org_idx on public.shannon_guard_incidents (org_id, last_seen_at desc);

create table if not exists public.shannon_guard_actions (
  id text primary key,
  org_id text not null references public.shannon_organizations(id) on delete cascade,
  incident_id text,
  connection_id text,
  type text not null,
  params jsonb not null default '{}'::jsonb,
  status text not null,
  error text,
  detail text,
  undo jsonb,
  actor text,
  mode text,
  created_at bigint not null,
  undone_at bigint,
  undone_by text,
  undo_detail text
);
create index if not exists shannon_guard_actions_org_idx on public.shannon_guard_actions (org_id, incident_id, created_at desc);

create table if not exists public.shannon_guard_state (
  id text primary key,
  org_id text not null references public.shannon_organizations(id) on delete cascade,
  baselines jsonb not null default '{}'::jsonb,
  org_state jsonb not null default '{}'::jsonb,
  exploit_since bigint,
  updated_at bigint not null
);

create table if not exists public.shannon_guard_settings (
  id text primary key,
  org_id text not null references public.shannon_organizations(id) on delete cascade,
  domains jsonb not null default '[]'::jsonb,
  trusted_apps jsonb not null default '[]'::jsonb,
  blocklist jsonb not null default '[]'::jsonb,
  autopilot jsonb not null default '{}'::jsonb,
  created_at bigint not null,
  updated_at bigint not null
);

alter table public.shannon_guard_connections enable row level security;
alter table public.shannon_guard_incidents enable row level security;
alter table public.shannon_guard_actions enable row level security;
alter table public.shannon_guard_state enable row level security;
alter table public.shannon_guard_settings enable row level security;
