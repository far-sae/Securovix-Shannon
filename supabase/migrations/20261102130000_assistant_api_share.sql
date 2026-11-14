-- Security assistant conversations + memory, research reports, developer API keys, share links.

create table if not exists public.shannon_assistant_conversations (
  id text primary key,
  org_id text not null references public.shannon_organizations(id) on delete cascade,
  user_id text not null,
  title text not null,
  messages jsonb not null default '[]'::jsonb,
  created_at bigint not null,
  updated_at bigint not null
);
create index if not exists shannon_assistant_conversations_owner_idx on public.shannon_assistant_conversations (org_id, user_id, updated_at desc);

create table if not exists public.shannon_assistant_memory (
  id text primary key,
  org_id text not null references public.shannon_organizations(id) on delete cascade,
  text text not null check (char_length(text) between 3 and 500),
  created_by text not null,
  created_at bigint not null
);
create index if not exists shannon_assistant_memory_org_idx on public.shannon_assistant_memory (org_id, created_at desc);

create table if not exists public.shannon_research_reports (
  id text primary key,
  org_id text not null references public.shannon_organizations(id) on delete cascade,
  user_id text not null,
  domain text not null,
  status text not null check (status in ('running', 'completed', 'failed')),
  markdown text,
  model text,
  error text,
  sources jsonb,
  created_at bigint not null,
  updated_at bigint not null
);
create index if not exists shannon_research_reports_org_idx on public.shannon_research_reports (org_id, created_at desc);

create table if not exists public.shannon_api_keys (
  id text primary key,
  org_id text not null references public.shannon_organizations(id) on delete cascade,
  name text not null,
  hint text not null,
  secret_hash text not null,
  scopes jsonb not null default '[]'::jsonb,
  created_by text not null,
  created_at bigint not null,
  last_used_at bigint,
  revoked_at bigint
);
create index if not exists shannon_api_keys_org_idx on public.shannon_api_keys (org_id, created_at desc);

create table if not exists public.shannon_share_links (
  id text primary key,
  org_id text not null references public.shannon_organizations(id) on delete cascade,
  resource_type text not null check (resource_type in ('research', 'conversation', 'scan-report')),
  resource_id text not null,
  title text,
  secret_hash text not null,
  created_by text not null,
  created_at bigint not null,
  expires_at bigint not null,
  revoked_at bigint,
  views bigint not null default 0
);
create index if not exists shannon_share_links_org_idx on public.shannon_share_links (org_id, created_at desc);

alter table public.shannon_assistant_conversations enable row level security;
alter table public.shannon_assistant_memory enable row level security;
alter table public.shannon_research_reports enable row level security;
alter table public.shannon_api_keys enable row level security;
alter table public.shannon_share_links enable row level security;
