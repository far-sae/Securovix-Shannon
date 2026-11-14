-- Securovix Guard Phase 2: endpoint agents, commands, malware sandbox samples, the shared
-- malicious-hash list, and per-organization endpoint policy and detection state.
-- Agents authenticate with a secret whose SHA-256 is stored here; the secret itself never is.

create table if not exists public.shannon_guard_agents (
  id text primary key,
  org_id text not null references public.shannon_organizations(id) on delete cascade,
  hostname text not null,
  os text,
  os_version text,
  arch text,
  version text,
  machine_id text,
  secret_hash text not null,
  status text not null check (status in ('active', 'retired')),
  isolated boolean not null default false,
  last_seen_at bigint,
  last_ip text,
  enrolled_at bigint not null,
  stats jsonb,
  tamper_alerted_at bigint,
  updated_at bigint not null
);
create index if not exists shannon_guard_agents_org_idx on public.shannon_guard_agents (org_id, last_seen_at desc);
create index if not exists shannon_guard_agents_status_idx on public.shannon_guard_agents (status, last_seen_at desc);

create table if not exists public.shannon_guard_commands (
  id text primary key,
  org_id text not null references public.shannon_organizations(id) on delete cascade,
  agent_id text not null references public.shannon_guard_agents(id) on delete cascade,
  type text not null,
  params jsonb,
  undo_data jsonb,
  action_id text,
  status text not null check (status in ('queued', 'sent', 'done', 'failed')),
  detail text,
  result jsonb,
  actor text,
  created_at bigint not null,
  sent_at bigint,
  completed_at bigint
);
create index if not exists shannon_guard_commands_agent_idx on public.shannon_guard_commands (org_id, agent_id, created_at desc);
create index if not exists shannon_guard_commands_status_idx on public.shannon_guard_commands (status, created_at desc);

create table if not exists public.shannon_guard_samples (
  id text primary key,
  org_id text not null references public.shannon_organizations(id) on delete cascade,
  agent_id text,
  hostname text,
  sha256 text not null,
  filename text,
  size bigint,
  command_id text,
  task_id text,
  status text not null,
  verdict text,
  score double precision,
  family text,
  reasons jsonb,
  signatures jsonb,
  error text,
  created_at bigint not null,
  updated_at bigint not null
);
create index if not exists shannon_guard_samples_org_idx on public.shannon_guard_samples (org_id, created_at desc);
create index if not exists shannon_guard_samples_status_idx on public.shannon_guard_samples (status, created_at desc);

-- Shared across customers on purpose: a file proven malicious at one customer is blocked at all.
-- Only the hash, verdict, score and family are kept: no file name, no organization.
create table if not exists public.shannon_guard_hashes (
  id text primary key check (id ~ '^[a-f0-9]{64}$'),
  verdict text not null,
  score double precision,
  family text,
  source text,
  added_at bigint not null
);
create index if not exists shannon_guard_hashes_added_idx on public.shannon_guard_hashes (added_at desc);

create table if not exists public.shannon_guard_endpoint (
  id text primary key,
  org_id text not null references public.shannon_organizations(id) on delete cascade,
  enroll_hash text,
  enroll_hint text,
  enroll_created_at bigint,
  policy jsonb,
  hosts jsonb,
  org_state jsonb,
  updated_at bigint not null
);

alter table public.shannon_guard_agents enable row level security;
alter table public.shannon_guard_commands enable row level security;
alter table public.shannon_guard_samples enable row level security;
alter table public.shannon_guard_hashes enable row level security;
alter table public.shannon_guard_endpoint enable row level security;
