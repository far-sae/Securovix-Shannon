-- Railway + Supabase enterprise runtime: durable work, artifacts, identities,
-- integrations, delivery history and operational telemetry.

alter table public.shannon_users
  add column if not exists email_verified_at bigint,
  add column if not exists disabled_at bigint,
  add column if not exists session_invalid_before bigint,
  add column if not exists mfa_enabled boolean not null default false,
  add column if not exists mfa_secret_enc text,
  add column if not exists mfa_recovery_codes jsonb not null default '[]'::jsonb;

create table if not exists public.shannon_auth_tokens (
  id text primary key,
  token_hash text not null unique,
  kind text not null check (kind in ('email-verification', 'password-reset', 'invitation')),
  user_id text references public.shannon_users(id) on delete cascade,
  email text not null,
  org_id text references public.shannon_organizations(id) on delete cascade,
  role text,
  created_by text references public.shannon_users(id) on delete set null,
  expires_at bigint not null,
  used_at bigint,
  created_at bigint not null
);
create index if not exists shannon_auth_tokens_lookup_idx
  on public.shannon_auth_tokens(token_hash, kind, expires_at);

create table if not exists public.shannon_sso_identities (
  provider text not null,
  subject text not null,
  user_id text not null references public.shannon_users(id) on delete cascade,
  email text,
  created_at bigint not null,
  last_login_at bigint,
  primary key (provider, subject)
);
create index if not exists shannon_sso_identities_user_idx
  on public.shannon_sso_identities(user_id);

create table if not exists public.shannon_integrations (
  id text primary key,
  org_id text not null references public.shannon_organizations(id) on delete cascade,
  type text not null check (type in ('webhook', 'slack', 'teams', 'jira', 'linear', 'siem-http')),
  name text not null,
  config jsonb not null default '{}'::jsonb,
  secret_enc text,
  enabled boolean not null default true,
  created_by text references public.shannon_users(id) on delete set null,
  created_at bigint not null,
  updated_at bigint not null
);
create index if not exists shannon_integrations_org_idx
  on public.shannon_integrations(org_id, enabled, type);

create table if not exists public.shannon_jobs (
  id text primary key,
  org_id text references public.shannon_organizations(id) on delete cascade,
  user_id text references public.shannon_users(id) on delete set null,
  type text not null,
  status text not null default 'queued'
    check (status in ('queued', 'running', 'succeeded', 'failed', 'cancelled', 'dead-letter')),
  payload jsonb not null default '{}'::jsonb,
  secret_enc text,
  result jsonb,
  error text,
  attempts integer not null default 0,
  max_attempts integer not null default 5,
  run_at bigint not null,
  locked_by text,
  locked_at bigint,
  heartbeat_at bigint,
  idempotency_key text,
  created_at bigint not null,
  updated_at bigint not null
);
create unique index if not exists shannon_jobs_idempotency_idx
  on public.shannon_jobs(org_id, idempotency_key)
  where idempotency_key is not null;
create index if not exists shannon_jobs_claim_idx
  on public.shannon_jobs(status, run_at, created_at);
create index if not exists shannon_jobs_org_idx
  on public.shannon_jobs(org_id, created_at desc);

create or replace function public.shannon_claim_jobs(
  p_worker_id text,
  p_limit integer default 1,
  p_now bigint default (extract(epoch from clock_timestamp()) * 1000)::bigint
)
returns setof public.shannon_jobs
language plpgsql
security definer
set search_path = public
as $$
begin
  return query
  with claimable as (
    select id
    from public.shannon_jobs
    where status = 'queued' and run_at <= p_now
    order by run_at asc, created_at asc
    for update skip locked
    limit greatest(1, least(coalesce(p_limit, 1), 20))
  )
  update public.shannon_jobs j
  set status = 'running',
      locked_by = p_worker_id,
      locked_at = p_now,
      heartbeat_at = p_now,
      attempts = j.attempts + 1,
      updated_at = p_now
  from claimable c
  where j.id = c.id
  returning j.*;
end;
$$;

create or replace function public.shannon_consume_auth_token(
  p_token_hash text,
  p_kind text,
  p_now bigint default (extract(epoch from clock_timestamp()) * 1000)::bigint
)
returns setof public.shannon_auth_tokens
language sql
security definer
set search_path = public
as $$
  update public.shannon_auth_tokens
  set used_at = p_now
  where token_hash = p_token_hash
    and kind = p_kind
    and used_at is null
    and expires_at > p_now
  returning *;
$$;

create or replace function public.shannon_requeue_stale_jobs(
  p_stale_before bigint,
  p_now bigint default (extract(epoch from clock_timestamp()) * 1000)::bigint
)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  affected integer;
begin
  update public.shannon_jobs
  set status = case when attempts >= max_attempts then 'dead-letter' else 'queued' end,
      error = concat_ws(E'\n', nullif(error, ''), 'Worker lease expired; job recovered.'),
      run_at = p_now,
      locked_by = null,
      locked_at = null,
      updated_at = p_now
  where status = 'running'
    and coalesce(heartbeat_at, locked_at, 0) < p_stale_before;
  get diagnostics affected = row_count;
  return affected;
end;
$$;

revoke all on function public.shannon_claim_jobs(text, integer, bigint) from public;
revoke all on function public.shannon_consume_auth_token(text, text, bigint) from public;
revoke all on function public.shannon_requeue_stale_jobs(bigint, bigint) from public;
grant execute on function public.shannon_claim_jobs(text, integer, bigint) to service_role;
grant execute on function public.shannon_consume_auth_token(text, text, bigint) to service_role;
grant execute on function public.shannon_requeue_stale_jobs(bigint, bigint) to service_role;

create table if not exists public.shannon_artifacts (
  id text primary key,
  org_id text not null references public.shannon_organizations(id) on delete cascade,
  scan_id text,
  job_id text references public.shannon_jobs(id) on delete set null,
  bucket text not null default 'shannon-artifacts',
  object_path text not null unique,
  content_type text,
  size_bytes bigint,
  sha256 text,
  metadata jsonb not null default '{}'::jsonb,
  created_at bigint not null
);
create index if not exists shannon_artifacts_org_scan_idx
  on public.shannon_artifacts(org_id, scan_id, created_at desc);

create table if not exists public.shannon_delivery_events (
  id text primary key,
  org_id text not null references public.shannon_organizations(id) on delete cascade,
  integration_id text references public.shannon_integrations(id) on delete set null,
  event_type text not null,
  status text not null check (status in ('queued', 'succeeded', 'failed', 'dead-letter')),
  attempt integer not null default 0,
  response_status integer,
  error text,
  created_at bigint not null,
  completed_at bigint
);
create index if not exists shannon_delivery_events_org_idx
  on public.shannon_delivery_events(org_id, created_at desc);

create table if not exists public.shannon_operational_events (
  id text primary key,
  service text not null,
  instance_id text,
  level text not null check (level in ('info', 'warning', 'error')),
  event text not null,
  org_id text references public.shannon_organizations(id) on delete set null,
  metadata jsonb not null default '{}'::jsonb,
  created_at bigint not null
);
create index if not exists shannon_operational_events_created_idx
  on public.shannon_operational_events(created_at desc);

alter table public.shannon_auth_tokens enable row level security;
alter table public.shannon_sso_identities enable row level security;
alter table public.shannon_integrations enable row level security;
alter table public.shannon_jobs enable row level security;
alter table public.shannon_artifacts enable row level security;
alter table public.shannon_delivery_events enable row level security;
alter table public.shannon_operational_events enable row level security;

-- The dashboard and worker use the service-role key. The bucket remains private;
-- downloads are exposed only through short-lived signed URLs after an RBAC check.
insert into storage.buckets (id, name, public, file_size_limit)
values ('shannon-artifacts', 'shannon-artifacts', false, 104857600)
on conflict (id) do update set public = false, file_size_limit = excluded.file_size_limit;
