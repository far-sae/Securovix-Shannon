-- Agent run history — one row per completed AI-Agent run, so scans can be compared over time
-- (regression tracking: new / fixed / still-present findings between runs). Findings and leads are
-- stored as JSONB. Hydration in db.mjs is NON-FATAL, so the server boots even before this migration.
create table if not exists public.shannon_agent_runs (
  id          text primary key,
  user_id     text not null,
  target      text,
  created_at  bigint not null,
  stats       jsonb,
  findings    jsonb,
  leads       jsonb
);
create index if not exists shannon_agent_runs_user_idx
  on public.shannon_agent_runs (user_id, created_at desc);

-- Deny-all RLS (the server uses the service_role key, which bypasses RLS).
alter table public.shannon_agent_runs enable row level security;
