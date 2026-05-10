CREATE TABLE IF NOT EXISTS admin_users (
    id                    UUID PRIMARY KEY,
    email                 TEXT NOT NULL,
    display_name          TEXT NOT NULL DEFAULT '',
    password_hash         TEXT NOT NULL DEFAULT '',
    roles                 TEXT[] NOT NULL DEFAULT '{}',
    scope_type            TEXT NOT NULL DEFAULT 'all',
    scope_client_id       UUID REFERENCES clients(id) ON DELETE CASCADE,
    scope_organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    mfa_required          BOOLEAN NOT NULL DEFAULT TRUE,
    totp_secret           TEXT NOT NULL DEFAULT '',
    totp_enabled          BOOLEAN NOT NULL DEFAULT FALSE,
    sso_provider          TEXT NOT NULL DEFAULT '',
    sso_subject           TEXT NOT NULL DEFAULT '',
    status                TEXT NOT NULL DEFAULT 'active',
    last_login_at         TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (scope_type IN ('all', 'client', 'organization')),
    CHECK (status IN ('active', 'suspended'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_admin_users_email
    ON admin_users (LOWER(email));

CREATE UNIQUE INDEX IF NOT EXISTS idx_admin_users_sso_identity
    ON admin_users (LOWER(sso_provider), sso_subject)
    WHERE sso_provider <> '' AND sso_subject <> '';

CREATE INDEX IF NOT EXISTS idx_admin_users_scope_client
    ON admin_users (scope_client_id);

CREATE INDEX IF NOT EXISTS idx_admin_users_scope_org
    ON admin_users (scope_organization_id);

ALTER TABLE login_audit_log
    ALTER COLUMN client_id DROP NOT NULL;

ALTER TABLE login_audit_log
    ADD COLUMN IF NOT EXISTS actor_type TEXT NOT NULL DEFAULT 'user',
    ADD COLUMN IF NOT EXISTS actor_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS actor_email TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS target_type TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS target_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS request_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS before_metadata JSONB NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS after_metadata JSONB NOT NULL DEFAULT '{}';

CREATE INDEX IF NOT EXISTS idx_audit_actor
    ON login_audit_log (actor_type, actor_id);

CREATE INDEX IF NOT EXISTS idx_audit_target
    ON login_audit_log (target_type, target_id);

CREATE INDEX IF NOT EXISTS idx_audit_request_id
    ON login_audit_log (request_id);
