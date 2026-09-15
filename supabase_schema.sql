-- Run this once in your Supabase project's SQL editor (Database -> SQL Editor)
-- before starting the stack for the first time.

create table if not exists projects (
  project_id    text primary key,
  name          text not null,
  domain        text not null,
  monitoring    boolean default false,
  created_at    timestamptz default now(),
  last_checked_at timestamptz
);

create table if not exists scans (
  scan_id       text primary key,
  domain        text not null,
  status        text not null,
  tools         jsonb default '[]',
  subdomains    jsonb default '[]',
  unresolved    jsonb default '[]',
  alive         jsonb default '[]',
  ports         jsonb default '[]',
  vulnerabilities jsonb default '[]',
  endpoints     jsonb default '[]',
  secrets       jsonb default '[]',
  directories   jsonb default '[]',
  errors        jsonb default '[]',
  project_id    text references projects(project_id) on delete set null,
  added_assets  jsonb default '[]',
  removed_assets jsonb default '[]',
  new_js_dependencies jsonb default '[]',
  js_cve_findings jsonb default '[]',
  created_at    timestamptz default now(),
  completed_at  timestamptz
);

create index if not exists scans_domain_idx on scans (domain);
create index if not exists scans_completed_at_idx on scans (completed_at desc);

-- If you already created "projects"/"scans" before these columns existed,
-- run these instead of the CREATE TABLEs above:
-- alter table scans add column if not exists unresolved jsonb default '[]';
-- alter table scans add column if not exists project_id text references projects(project_id) on delete set null;
-- alter table scans add column if not exists added_assets jsonb default '[]';
-- alter table scans add column if not exists removed_assets jsonb default '[]';
-- alter table scans add column if not exists new_js_dependencies jsonb default '[]';
-- alter table scans add column if not exists js_cve_findings jsonb default '[]';

create table if not exists asset_history (
  id            bigserial primary key,
  project_id    text references projects(project_id) on delete cascade,
  subdomain     text not null,
  first_seen    timestamptz default now(),
  last_seen     timestamptz default now(),
  unique (project_id, subdomain)
);
create index if not exists asset_history_project_idx on asset_history (project_id);

create table if not exists js_dependencies (
  id            bigserial primary key,
  project_id    text references projects(project_id) on delete cascade,
  script_url    text not null,
  library_name  text,
  library_version text,
  known_cves    jsonb default '[]',
  first_seen    timestamptz default now(),
  last_seen     timestamptz default now(),
  unique (project_id, script_url)
);
create index if not exists js_dependencies_project_idx on js_dependencies (project_id);

-- Row Level Security: since only the backend/worker/monitor (using the
-- service role key) talk to these tables, RLS can stay enabled with no
-- public policies -- the service role key bypasses RLS entirely. This keeps
-- the tables inaccessible to anyone using the anon/public key.
alter table projects enable row level security;
alter table scans enable row level security;
alter table asset_history enable row level security;
alter table js_dependencies enable row level security;
