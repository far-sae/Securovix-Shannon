-- Securovix dashboard — initial schema (users + provider leaderboard).
-- Mirrors packages/dashboard/supabase/schema.sql. Idempotent (create if not exists),
-- so it is safe to push to a fresh project or re-run. Apply with: supabase db push

-- ============================================================
-- 1. Users
-- ============================================================
create table if not exists public.shannon_users (
  id              text primary key,
  email           text unique not null,
  name            text,
  password_hash   text,                 -- nullable (Google-only users have no pw)
  salt            text,
  google_id       text unique,
  picture         text,
  subscription    jsonb,                -- legacy column, kept for compat
  consent         jsonb,                -- { termsVersion, privacyVersion, acceptedAt, ip, userAgent }
  created_at      bigint not null
);
create index if not exists shannon_users_email_idx     on public.shannon_users (email);
create index if not exists shannon_users_google_id_idx on public.shannon_users (google_id);

-- ============================================================
-- 2. Provider leaderboard (4 rows: claude / openai / gemini / glm)
-- ============================================================
create table if not exists public.shannon_leaderboard (
  provider     text primary key,
  score        numeric not null,
  runs         integer  not null default 0,
  wins         integer  not null default 0,
  total_ms     bigint   not null default 0,
  total_chars  bigint   not null default 0,
  last_run     bigint,
  updated_at   bigint
);

-- ============================================================
-- 3. Row-Level Security
-- The server uses the SERVICE_ROLE key, which bypasses RLS, so we just need the
-- tables to exist. RLS is enabled with NO policies → the anon role gets nothing
-- (deny-all is the safe default). Add explicit policies before exposing the anon key.
-- ============================================================
alter table public.shannon_users       enable row level security;
alter table public.shannon_leaderboard enable row level security;
