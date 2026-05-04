-- Securovix dashboard — Supabase schema (run once in the SQL editor).
-- Replaces ~/.shannon/users.json and ~/.shannon/leaderboard.json.

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
-- We use the SERVICE_ROLE key from the server, which bypasses RLS, so we just
-- need the tables to exist. If you ever expose them to the anon key, add
-- explicit policies — by default deny-all is the safe stance.
-- ============================================================
alter table public.shannon_users       enable row level security;
alter table public.shannon_leaderboard enable row level security;
-- (No policies defined → anon role gets nothing. Service role bypasses RLS.)
