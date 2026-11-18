-- shannon_org_secrets.kind allowed only the four kinds that existed when the table was created.
-- Two kinds added since were refused by the database (the local store used in tests has no such
-- rule), so saving either one answered 500:
--   repository-provider : the organization's GitHub credential (Settings)
--   defender-policy     : website protection settings (Settings -> Website protection)
-- Keep this list equal to ORG_SECRET_KINDS in packages/dashboard/enterprise-db.mjs; a test checks it.

alter table public.shannon_org_secrets drop constraint if exists shannon_org_secrets_kind_check;
alter table public.shannon_org_secrets
  add constraint shannon_org_secrets_kind_check
  check (kind in ('ai-provider', 'oidc', 'scim', 'billing', 'repository-provider', 'defender-policy'));
