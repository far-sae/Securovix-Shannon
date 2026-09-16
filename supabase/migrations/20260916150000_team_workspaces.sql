-- Team-ready workspaces, RBAC, durable findings, audit trail, settings and scan ownership.
create table if not exists public.shannon_organizations (
  id text primary key,
  name text not null,
  slug text unique not null,
  created_by text not null references public.shannon_users(id) on delete restrict,
  created_at bigint not null
);

create table if not exists public.shannon_memberships (
  org_id text not null references public.shannon_organizations(id) on delete cascade,
  user_id text not null references public.shannon_users(id) on delete cascade,
  role text not null check (role in ('owner','admin','engineer','analyst','developer','viewer')),
  created_at bigint not null,
  primary key (org_id, user_id)
);
create index if not exists shannon_memberships_user_idx on public.shannon_memberships(user_id);

create table if not exists public.shannon_projects (
  id text primary key,
  org_id text not null references public.shannon_organizations(id) on delete cascade,
  name text not null,
  description text,
  environment text not null default 'production',
  criticality text not null default 'medium' check (criticality in ('low','medium','high','critical')),
  created_at bigint not null
);
create index if not exists shannon_projects_org_idx on public.shannon_projects(org_id, created_at desc);

create table if not exists public.shannon_findings (
  id text primary key,
  org_id text not null references public.shannon_organizations(id) on delete cascade,
  project_id text references public.shannon_projects(id) on delete set null,
  fingerprint text not null,
  title text not null,
  severity text not null check (severity in ('info','low','medium','high','critical')),
  status text not null check (status in ('new','triaged','assigned','in-progress','ready-for-retest','resolved','risk-accepted','false-positive')),
  assignee_user_id text references public.shannon_users(id) on delete set null,
  source text not null default 'manual',
  details jsonb not null default '{}'::jsonb,
  decision jsonb,
  created_at bigint not null,
  updated_at bigint not null,
  unique (org_id, fingerprint)
);
create index if not exists shannon_findings_org_status_idx on public.shannon_findings(org_id, status, updated_at desc);
create index if not exists shannon_findings_project_idx on public.shannon_findings(project_id, updated_at desc);

create table if not exists public.shannon_audit_events (
  id text primary key,
  org_id text not null references public.shannon_organizations(id) on delete cascade,
  actor_user_id text references public.shannon_users(id) on delete set null,
  action text not null,
  resource_type text not null,
  resource_id text,
  metadata jsonb not null default '{}'::jsonb,
  created_at bigint not null
);
create index if not exists shannon_audit_org_idx on public.shannon_audit_events(org_id, created_at desc);

create table if not exists public.shannon_user_settings (
  user_id text primary key references public.shannon_users(id) on delete cascade,
  settings jsonb not null default '{}'::jsonb,
  updated_at bigint not null
);

create table if not exists public.shannon_scan_owners (
  scan_id text primary key,
  org_id text not null references public.shannon_organizations(id) on delete cascade,
  user_id text not null references public.shannon_users(id) on delete restrict,
  project_id text references public.shannon_projects(id) on delete set null,
  created_at bigint not null
);
create index if not exists shannon_scan_owners_org_idx on public.shannon_scan_owners(org_id, created_at desc);

create table if not exists public.shannon_edge_routes (
  host text primary key,
  org_id text not null references public.shannon_organizations(id) on delete cascade,
  user_id text not null references public.shannon_users(id) on delete restrict,
  origin text not null,
  mode text not null check (mode in ('monitor','enforce')),
  created_at bigint not null
);
create index if not exists shannon_edge_routes_org_idx on public.shannon_edge_routes(org_id);

create table if not exists public.shannon_defense_events (
  id text primary key,
  org_id text not null references public.shannon_organizations(id) on delete cascade,
  user_id text not null references public.shannon_users(id) on delete restrict,
  at text not null,
  method text,
  url text,
  cls text,
  enforced boolean not null default false,
  src_ip text,
  created_at bigint not null
);
create index if not exists shannon_defense_events_org_idx on public.shannon_defense_events(org_id, created_at desc);

alter table public.shannon_organizations enable row level security;
alter table public.shannon_memberships enable row level security;
alter table public.shannon_projects enable row level security;
alter table public.shannon_findings enable row level security;
alter table public.shannon_audit_events enable row level security;
alter table public.shannon_user_settings enable row level security;
alter table public.shannon_scan_owners enable row level security;
alter table public.shannon_edge_routes enable row level security;
alter table public.shannon_defense_events enable row level security;
