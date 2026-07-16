-- Continuous-monitoring schedules — one row per monitor. The server's scheduler runs the agent on each
-- due monitor, diffs against the previous run, and fires the webhook on NEW findings. Hydration in
-- db.mjs is NON-FATAL, so the server boots even before this migration is applied.
create table if not exists public.shannon_monitors (
  id             text primary key,
  user_id        text not null,
  target         text,
  interval_hours integer not null default 24,
  webhook_url    text,
  enabled        boolean not null default true,
  last_run_at    bigint  not null default 0,
  created_at     bigint  not null
);
create index if not exists shannon_monitors_user_idx on public.shannon_monitors (user_id);

-- Deny-all RLS (the server uses the service_role key, which bypasses RLS).
alter table public.shannon_monitors enable row level security;
