-- Tenant-isolated continuous defense inventory, scheduler and learning history.
-- Learning records outcomes and priorities; enforcement changes remain explicit.

create table if not exists public.shannon_defense_programs (
  org_id text primary key references public.shannon_organizations(id) on delete cascade,
  enabled boolean not null default false,
  cadence_hours integer not null default 24 check (cadence_hours between 1 and 168),
  response_mode text not null default 'recommend' check (response_mode in ('recommend','bounded-auto')),
  next_run_at bigint,
  last_run_at bigint,
  last_cycle_id text,
  created_by text references public.shannon_users(id) on delete set null,
  created_at bigint not null,
  updated_at bigint not null
);

create table if not exists public.shannon_defense_assets (
  id text primary key,
  org_id text not null references public.shannon_organizations(id) on delete cascade,
  project_id text references public.shannon_projects(id) on delete set null,
  type text not null check (type in ('web','api','domain','cidr','cloud','repository','identity','endpoint')),
  name text not null,
  locator text not null,
  criticality text not null default 'medium' check (criticality in ('low','medium','high','critical')),
  status text not null default 'active' check (status in ('active','paused')),
  coverage text not null default 'inventory' check (coverage in ('inventory','online')),
  config jsonb not null default '{}'::jsonb,
  created_by text references public.shannon_users(id) on delete set null,
  created_at bigint not null,
  updated_at bigint not null,
  unique (org_id, type, locator)
);

create table if not exists public.shannon_defense_cycles (
  id text primary key,
  org_id text not null references public.shannon_organizations(id) on delete cascade,
  job_id text references public.shannon_jobs(id) on delete set null,
  status text not null check (status in ('running','completed','failed')),
  window jsonb not null default '{}'::jsonb,
  snapshot jsonb not null default '{}'::jsonb,
  learning jsonb not null default '{}'::jsonb,
  actions jsonb not null default '{}'::jsonb,
  error text,
  started_at bigint not null,
  completed_at bigint,
  created_at bigint not null
);

create index if not exists shannon_defense_programs_due_idx on public.shannon_defense_programs(enabled, next_run_at);
create index if not exists shannon_defense_assets_org_idx on public.shannon_defense_assets(org_id, status, type);
create index if not exists shannon_defense_cycles_org_idx on public.shannon_defense_cycles(org_id, created_at desc);

create or replace function public.shannon_claim_due_defense_programs(
  p_limit integer default 20,
  p_now bigint default (extract(epoch from clock_timestamp()) * 1000)::bigint
)
returns setof public.shannon_defense_programs
language plpgsql
security definer
set search_path = public
as $$
begin
  return query
  with due as (
    select org_id
    from public.shannon_defense_programs
    where enabled = true and coalesce(next_run_at, 0) <= p_now
    order by coalesce(next_run_at, 0) asc
    for update skip locked
    limit greatest(1, least(coalesce(p_limit, 20), 100))
  )
  update public.shannon_defense_programs p
  set last_run_at = p_now,
      next_run_at = p_now + (p.cadence_hours::bigint * 3600000),
      updated_at = p_now
  from due
  where p.org_id = due.org_id
  returning p.*;
end;
$$;

revoke all on function public.shannon_claim_due_defense_programs(integer, bigint) from public;
grant execute on function public.shannon_claim_due_defense_programs(integer, bigint) to service_role;

alter table public.shannon_defense_programs enable row level security;
alter table public.shannon_defense_assets enable row level security;
alter table public.shannon_defense_cycles enable row level security;

-- Analyst feedback is part of bounded learning. It lowers priority but never
-- automatically disables a rule or broadens an allowlist.
alter table public.shannon_defense_events drop constraint if exists shannon_defense_events_status_check;
alter table public.shannon_defense_events
  add constraint shannon_defense_events_status_check
  check (status in ('open','investigating','contained','closed','false-positive'));
