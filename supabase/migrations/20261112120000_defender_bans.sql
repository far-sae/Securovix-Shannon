-- Platform self-defense bans, persisted so a redeploy does not forgive a scanner and every
-- dashboard instance enforces the same list. Keyed by IP; expired rows are removed on load.

create table if not exists public.shannon_defender_bans (
  id text primary key,
  ip text not null,
  until_at bigint not null,
  reason text,
  created_at bigint not null
);

create index if not exists shannon_defender_bans_until_idx on public.shannon_defender_bans (until_at desc);

alter table public.shannon_defender_bans enable row level security;
