-- Verified domains — the domain-ownership gate for scanning. One row per (user, domain)
-- the user has proven they control. Persisted in the DB so verifications survive redeploys
-- (previously a local ~/.shannon/verified-domains.json file that Railway wiped per deploy).
create table if not exists public.shannon_verified_domains (
  user_id      text not null,
  domain       text not null,
  method       text,                 -- 'dns' | 'file' | 'meta'
  verified_at  text,
  primary key (user_id, domain)
);
create index if not exists shannon_verified_domains_user_idx on public.shannon_verified_domains (user_id);

-- Deny-all RLS (the server uses the service_role key, which bypasses RLS).
alter table public.shannon_verified_domains enable row level security;
