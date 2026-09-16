-- Enterprise Defender operations: revocable SDK credentials and durable SOC incident workflow.

alter table public.shannon_users
  add column if not exists defender_key_version integer not null default 0;

alter table public.shannon_defense_events
  add column if not exists severity text not null default 'medium',
  add column if not exists source text not null default 'sdk',
  add column if not exists status text not null default 'open',
  add column if not exists metadata jsonb not null default '{}'::jsonb;

do $$ begin
  alter table public.shannon_defense_events
    add constraint shannon_defense_events_severity_check
    check (severity in ('info','low','medium','high','critical'));
exception when duplicate_object then null;
end $$;

do $$ begin
  alter table public.shannon_defense_events
    add constraint shannon_defense_events_status_check
    check (status in ('open','investigating','contained','closed'));
exception when duplicate_object then null;
end $$;

create index if not exists shannon_defense_events_workflow_idx
  on public.shannon_defense_events(org_id, status, severity, created_at desc);
