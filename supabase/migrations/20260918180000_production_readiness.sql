-- Production-readiness foundations: encrypted organization secrets and one-time
-- authenticated-scan grants. Service-role access only; no anonymous policies.

create table if not exists public.shannon_org_secrets (
  id text primary key,
  org_id text not null references public.shannon_organizations(id) on delete cascade,
  kind text not null check (kind in ('ai-provider', 'oidc', 'scim', 'billing')),
  name text not null,
  config jsonb not null default '{}'::jsonb,
  secret_enc text not null,
  created_by text references public.shannon_users(id) on delete set null,
  created_at bigint not null,
  updated_at bigint not null,
  unique (org_id, kind, name)
);
create index if not exists shannon_org_secrets_org_kind_idx
  on public.shannon_org_secrets(org_id, kind);

create table if not exists public.shannon_scan_auth_grants (
  id text primary key,
  user_id text not null references public.shannon_users(id) on delete cascade,
  org_id text not null references public.shannon_organizations(id) on delete cascade,
  target_origin text not null,
  secret_enc text not null,
  expires_at bigint not null,
  consumed_at bigint,
  created_at bigint not null
);
create index if not exists shannon_scan_auth_grants_lookup_idx
  on public.shannon_scan_auth_grants(id, user_id, org_id, expires_at);

create or replace function public.shannon_consume_scan_auth_grant(
  p_id text,
  p_user_id text,
  p_org_id text,
  p_target_origin text,
  p_now bigint default (extract(epoch from clock_timestamp()) * 1000)::bigint
)
returns setof public.shannon_scan_auth_grants
language sql
security definer
set search_path = public
as $$
  delete from public.shannon_scan_auth_grants
  where id = p_id
    and user_id = p_user_id
    and org_id = p_org_id
    and target_origin = p_target_origin
    and expires_at > p_now
  returning *;
$$;

revoke all on function public.shannon_consume_scan_auth_grant(text, text, text, text, bigint) from public;
grant execute on function public.shannon_consume_scan_auth_grant(text, text, text, text, bigint) to service_role;

alter table public.shannon_org_secrets enable row level security;
alter table public.shannon_scan_auth_grants enable row level security;

create table if not exists public.shannon_org_entitlements (
  org_id text primary key references public.shannon_organizations(id) on delete cascade,
  plan text not null default 'free',
  status text not null default 'active',
  provider text,
  provider_customer_id text,
  provider_subscription_id text,
  current_period_end bigint,
  limits jsonb not null default '{}'::jsonb,
  updated_at bigint not null
);

create table if not exists public.shannon_usage_daily (
  org_id text not null references public.shannon_organizations(id) on delete cascade,
  day date not null,
  metric text not null,
  quantity bigint not null default 0 check (quantity >= 0),
  updated_at bigint not null,
  primary key (org_id, day, metric)
);

create or replace function public.shannon_consume_usage(
  p_org_id text,
  p_day date,
  p_metric text,
  p_amount bigint,
  p_limit bigint,
  p_now bigint default (extract(epoch from clock_timestamp()) * 1000)::bigint
)
returns bigint
language plpgsql
security definer
set search_path = public
as $$
declare v_quantity bigint;
begin
  insert into public.shannon_usage_daily(org_id, day, metric, quantity, updated_at)
  select p_org_id, p_day, p_metric, p_amount, p_now
  where p_amount > 0 and p_amount <= p_limit
  on conflict (org_id, day, metric) do update
    set quantity = shannon_usage_daily.quantity + excluded.quantity,
        updated_at = excluded.updated_at
    where shannon_usage_daily.quantity + excluded.quantity <= p_limit
  returning quantity into v_quantity;
  return v_quantity;
end;
$$;

revoke all on function public.shannon_consume_usage(text, date, text, bigint, bigint, bigint) from public;
grant execute on function public.shannon_consume_usage(text, date, text, bigint, bigint, bigint) to service_role;
alter table public.shannon_org_entitlements enable row level security;
alter table public.shannon_usage_daily enable row level security;
