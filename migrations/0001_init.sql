-- WADJET initial schema.
-- Conventions:
--   * UUID primary keys via gen_random_uuid() (PostgreSQL 13+).
--   * No stored procedures. No triggers. All business logic lives in Go.
--   * updated_at columns are maintained by application code.

-- ───────────────────────────────────────────── users

CREATE TABLE users (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email         text NOT NULL UNIQUE,
    name          text NOT NULL DEFAULT '',
    password_hash text NOT NULL,
    role          text NOT NULL DEFAULT 'user' CHECK (role IN ('admin','user')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sessions_user_idx ON sessions(user_id);

-- ───────────────────────────────────────────── projects

CREATE TABLE projects (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name             text NOT NULL,
    description      text NOT NULL DEFAULT '',
    status           text NOT NULL DEFAULT 'active' CHECK (status IN ('active','archived')),
    tags             text[] NOT NULL DEFAULT '{}',
    settings         jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_by       uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    last_activity_at timestamptz
);
CREATE INDEX projects_status_idx ON projects(status);

CREATE TABLE project_targets (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    target      text NOT NULL,           -- CIDR, IP, hostname, domain, or URL
    target_type text NOT NULL DEFAULT 'auto' CHECK (target_type IN ('auto','ip','ipv6','hostname','domain','cidr','url')),
    excluded    boolean NOT NULL DEFAULT false,
    note        text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (project_id, target, excluded)
);
CREATE INDEX project_targets_project_idx ON project_targets(project_id);

CREATE TABLE project_settings (
    project_id uuid PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    settings   jsonb NOT NULL DEFAULT '{}'::jsonb,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- ───────────────────────────────────────────── assets

CREATE TABLE assets (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id       uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    identity         text NOT NULL,       -- normalized dedup key: ip, or lowercased hostname/domain
    asset_type       text NOT NULL DEFAULT 'ip' CHECK (asset_type IN
                       ('ipv4','ipv6','hostname','domain','server','endpoint','web_app','container','other')),
    ip               inet,
    ipv6             inet,
    hostname         text,
    domain           text,
    mac              text,
    os_name          text,
    os_accuracy      integer,
    status           text NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive','retired')),
    discovery_source text NOT NULL DEFAULT 'manual' CHECK (discovery_source IN ('manual','scanner','import')),
    description      text NOT NULL DEFAULT '',
    tags             text[] NOT NULL DEFAULT '{}',
    first_seen       timestamptz NOT NULL DEFAULT now(),
    last_seen        timestamptz NOT NULL DEFAULT now(),
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (project_id, identity)
);
CREATE INDEX assets_project_idx ON assets(project_id);
CREATE INDEX assets_identity_idx ON assets(identity);

CREATE TABLE asset_observations (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id              uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    scan_session_id       uuid,           -- FK added after scan_sessions exists
    scanner_execution_id  uuid,           -- FK added after scanner_executions exists
    observation_type      text NOT NULL DEFAULT 'network' CHECK (observation_type IN
                            ('network','service','tls','web','vulnerability','manual')),
    observed_at           timestamptz NOT NULL DEFAULT now(),
    raw                   jsonb NOT NULL DEFAULT '{}'::jsonb,   -- ports, services, hostnames as reported
    source                text NOT NULL DEFAULT '',             -- scanner name or 'manual'
    created_at            timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX asset_observations_asset_idx ON asset_observations(asset_id, observed_at DESC);
CREATE INDEX asset_observations_session_idx ON asset_observations(scan_session_id);

-- ───────────────────────────────────────────── scanner registry

CREATE TABLE scanners (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name           text NOT NULL UNIQUE,
    display_name   text NOT NULL,
    description    text NOT NULL DEFAULT '',
    version        text NOT NULL DEFAULT '',
    executable     text NOT NULL DEFAULT '',
    adapter        text NOT NULL DEFAULT 'command' CHECK (adapter IN ('command','native')),
    enabled        boolean NOT NULL DEFAULT true,
    asset_types    text[] NOT NULL DEFAULT '{}',
    capabilities   text[] NOT NULL DEFAULT '{}',
    manifest       jsonb NOT NULL DEFAULT '{}'::jsonb,   -- full YAML manifest as JSON
    status         text NOT NULL DEFAULT 'unknown' CHECK (status IN ('available','missing','disabled','error','unknown')),
    status_detail  text NOT NULL DEFAULT '',
    last_checked_at timestamptz,
    documentation  text NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE scanner_configurations (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    scanner_id uuid NOT NULL REFERENCES scanners(id) ON DELETE CASCADE,
    config     jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (project_id, scanner_id)
);

-- ───────────────────────────────────────────── scan profiles

CREATE TABLE scan_profiles (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id       uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name             text NOT NULL,
    description      text NOT NULL DEFAULT '',
    target_selection text[] NOT NULL DEFAULT '{}',   -- empty = all authorized targets
    excluded_targets text[] NOT NULL DEFAULT '{}',
    timeout_seconds  integer NOT NULL DEFAULT 1800,
    report_prefs     jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (project_id, name)
);

CREATE TABLE scan_profile_scanners (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_id   uuid NOT NULL REFERENCES scan_profiles(id) ON DELETE CASCADE,
    scanner_id   uuid NOT NULL REFERENCES scanners(id) ON DELETE CASCADE,
    config       jsonb NOT NULL DEFAULT '{}'::jsonb,   -- scanner-specific options
    sort_order   integer NOT NULL DEFAULT 0,
    UNIQUE (profile_id, scanner_id)
);

-- ───────────────────────────────────────────── scan sessions

CREATE TABLE scan_sessions (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id         uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    profile_id         uuid REFERENCES scan_profiles(id) ON DELETE SET NULL,
    name               text NOT NULL DEFAULT '',
    status             text NOT NULL DEFAULT 'draft' CHECK (status IN
                         ('draft','queued','running','completed','completed_with_errors','failed','cancelled')),
    targets            text[] NOT NULL DEFAULT '{}',
    scanner_names      text[] NOT NULL DEFAULT '{}',
    assets_processed   integer NOT NULL DEFAULT 0,
    findings_created   integer NOT NULL DEFAULT 0,
    findings_updated   integer NOT NULL DEFAULT 0,
    error              text NOT NULL DEFAULT '',
    started_at         timestamptz,
    finished_at        timestamptz,
    duration_ms        bigint,
    created_by         uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX scan_sessions_project_idx ON scan_sessions(project_id, created_at DESC);
CREATE INDEX scan_sessions_status_idx ON scan_sessions(status);

ALTER TABLE asset_observations
    ADD CONSTRAINT asset_obs_session_fk FOREIGN KEY (scan_session_id)
    REFERENCES scan_sessions(id) ON DELETE SET NULL;

CREATE TABLE scan_session_targets (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id   uuid NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
    target       text NOT NULL,
    status       text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','completed','failed','skipped','denied')),
    error        text NOT NULL DEFAULT '',
    UNIQUE (session_id, target)
);

CREATE TABLE scanner_executions (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id       uuid NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
    scanner_name     text NOT NULL,
    status           text NOT NULL DEFAULT 'queued' CHECK (status IN
                       ('queued','running','completed','completed_with_errors','failed','cancelled')),
    config           jsonb NOT NULL DEFAULT '{}'::jsonb,
    targets          text[] NOT NULL DEFAULT '{}',
    raw_output_path  text NOT NULL DEFAULT '',
    raw_output_bytes bigint NOT NULL DEFAULT 0,
    assets_observed  integer NOT NULL DEFAULT 0,
    findings_found   integer NOT NULL DEFAULT 0,
    error            text NOT NULL DEFAULT '',
    log              text NOT NULL DEFAULT '',
    started_at       timestamptz,
    finished_at      timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX scanner_exec_session_idx ON scanner_executions(session_id);

ALTER TABLE asset_observations
    ADD CONSTRAINT asset_obs_exec_fk FOREIGN KEY (scanner_execution_id)
    REFERENCES scanner_executions(id) ON DELETE SET NULL;

-- ───────────────────────────────────────────── findings

CREATE TABLE findings (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id        uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    asset_id          uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    title             text NOT NULL,
    description       text NOT NULL DEFAULT '',
    technical_details text NOT NULL DEFAULT '',
    evidence          text NOT NULL DEFAULT '',
    scanner           text NOT NULL DEFAULT '',
    port              integer,
    protocol          text,
    service           text,
    cves              text[] NOT NULL DEFAULT '{}',
    cvss_score        numeric(3,1),
    severity          text NOT NULL DEFAULT 'info' CHECK (severity IN
                        ('critical','high','medium','low','info')),
    status            text NOT NULL DEFAULT 'open' CHECK (status IN
                        ('open','confirmed','remediated','accepted_risk','false_positive')),
    remediation       text NOT NULL DEFAULT '',
    references        jsonb NOT NULL DEFAULT '[]'::jsonb,
    fingerprint       text NOT NULL,
    first_detected    timestamptz NOT NULL DEFAULT now(),
    last_detected     timestamptz NOT NULL DEFAULT now(),
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (project_id, asset_id, fingerprint)
);
CREATE INDEX findings_project_severity_idx ON findings(project_id, severity);
CREATE INDEX findings_project_status_idx ON findings(project_id, status);
CREATE INDEX findings_asset_idx ON findings(asset_id);

CREATE TABLE finding_observations (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id           uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    scan_session_id      uuid REFERENCES scan_sessions(id) ON DELETE SET NULL,
    scanner_execution_id uuid REFERENCES scanner_executions(id) ON DELETE SET NULL,
    observed_at          timestamptz NOT NULL DEFAULT now(),
    status_at_detection  text NOT NULL DEFAULT '',
    raw                  jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX finding_obs_finding_idx ON finding_observations(finding_id, observed_at DESC);

CREATE TABLE finding_status_history (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id   uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    from_status  text NOT NULL DEFAULT '',
    to_status    text NOT NULL,
    changed_by   uuid REFERENCES users(id) ON DELETE SET NULL,
    note         text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX finding_status_hist_idx ON finding_status_history(finding_id, created_at DESC);

-- ───────────────────────────────────────────── reports

CREATE TABLE reports (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id   uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    session_id   uuid REFERENCES scan_sessions(id) ON DELETE SET NULL,
    finding_id   uuid REFERENCES findings(id) ON DELETE SET NULL,
    type         text NOT NULL CHECK (type IN ('scan','finding','findings_consolidated','findings_zip')),
    status       text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','generating','completed','failed')),
    file_path    text NOT NULL DEFAULT '',
    file_size    bigint NOT NULL DEFAULT 0,
    error        text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz
);
CREATE INDEX reports_project_idx ON reports(project_id, created_at DESC);

-- ───────────────────────────────────────────── audit

CREATE TABLE audit_logs (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid REFERENCES users(id) ON DELETE SET NULL,
    action        text NOT NULL,          -- e.g. 'project.create', 'scan.start'
    resource_type text NOT NULL DEFAULT '',
    resource_id   text NOT NULL DEFAULT '',
    details       jsonb NOT NULL DEFAULT '{}'::jsonb,
    ip            text NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_logs_created_idx ON audit_logs(created_at DESC);
