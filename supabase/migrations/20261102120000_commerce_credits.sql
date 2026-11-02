-- Commerce: fixed-price scan offers / credit packs, manual payment review, prepaid credits.
-- Inert until the operator sets SHANNON_COMMERCE_ENABLED=1.

create table if not exists public.shannon_commerce_orders (
  id text primary key,
  org_id text not null references public.shannon_organizations(id) on delete cascade,
  user_id text not null,
  item_id text not null,
  item_name text not null,
  kind text not null check (kind in ('offer', 'pack')),
  method text not null check (method in ('card', 'crypto', 'qr', 'bank')),
  amount numeric(12, 2) not null check (amount >= 0),
  currency text not null,
  grants jsonb not null default '{}'::jsonb,
  reference text not null,
  status text not null check (status in ('pending_payment', 'pending_evidence', 'pending_review', 'approved', 'rejected', 'cancelled')),
  evidence jsonb,
  review jsonb,
  provider_ref text,
  history jsonb not null default '[]'::jsonb,
  created_at bigint not null,
  updated_at bigint not null
);

create index if not exists shannon_commerce_orders_org_idx on public.shannon_commerce_orders (org_id, created_at desc);
create index if not exists shannon_commerce_orders_status_idx on public.shannon_commerce_orders (status, created_at desc);

create table if not exists public.shannon_credit_grants (
  id text primary key,
  org_id text not null references public.shannon_organizations(id) on delete cascade,
  order_id text not null references public.shannon_commerce_orders(id) on delete cascade,
  grants jsonb not null,
  remaining jsonb not null,
  expires_at bigint not null,
  created_at bigint not null
);

create index if not exists shannon_credit_grants_org_idx on public.shannon_credit_grants (org_id, expires_at);

-- All-or-nothing spend of p_amount credits of p_metric, soonest-expiring grants first.
-- Returns the remaining balance for that metric, or -1 when the balance is insufficient.
create or replace function public.shannon_consume_credit(
  p_org_id text,
  p_metric text,
  p_amount bigint,
  p_now bigint default (extract(epoch from clock_timestamp()) * 1000)::bigint
)
returns bigint
language plpgsql
security definer
set search_path = public
as $$
declare
  v_available bigint;
  v_left bigint := p_amount;
  v_take bigint;
  v_have bigint;
  r record;
begin
  if p_amount <= 0 or p_metric not in ('scans', 'codeFiles', 'agentRuns') then
    return -1;
  end if;

  -- Lock every live grant for this org so concurrent spends serialize.
  perform 1 from public.shannon_credit_grants
    where org_id = p_org_id and expires_at > p_now
    for update;

  select coalesce(sum(greatest(0, coalesce((remaining ->> p_metric)::bigint, 0))), 0)
    into v_available
    from public.shannon_credit_grants
    where org_id = p_org_id and expires_at > p_now;

  if v_available < p_amount then
    return -1;
  end if;

  for r in
    select id, greatest(0, coalesce((remaining ->> p_metric)::bigint, 0)) as have
      from public.shannon_credit_grants
      where org_id = p_org_id and expires_at > p_now
      order by expires_at asc, id asc
  loop
    exit when v_left = 0;
    v_have := r.have;
    continue when v_have = 0;
    v_take := least(v_have, v_left);
    update public.shannon_credit_grants
      set remaining = jsonb_set(remaining, array[p_metric], to_jsonb(v_have - v_take), true)
      where id = r.id;
    v_left := v_left - v_take;
  end loop;

  return v_available - p_amount;
end;
$$;

revoke all on function public.shannon_consume_credit(text, text, bigint, bigint) from public;
grant execute on function public.shannon_consume_credit(text, text, bigint, bigint) to service_role;

alter table public.shannon_commerce_orders enable row level security;
alter table public.shannon_credit_grants enable row level security;
