ALTER TABLE enterprise_sso_connections
    ADD COLUMN IF NOT EXISTS organization_id UUID NULL REFERENCES organizations(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS provider TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS last_error_at TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS last_error TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS metadata_refreshed_at TIMESTAMPTZ NULL;

CREATE INDEX IF NOT EXISTS idx_enterprise_sso_connections_org
    ON enterprise_sso_connections (client_id, organization_id);

ALTER TABLE scim_directories
    ADD COLUMN IF NOT EXISTS organization_id UUID NULL REFERENCES organizations(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS provider TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS last_sync_at TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS last_error_at TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS last_error TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_scim_directories_org
    ON scim_directories (client_id, organization_id);

CREATE TABLE IF NOT EXISTS enterprise_domain_verifications (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id       UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    domain          TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'verified', 'failed')),
    txt_name        TEXT NOT NULL,
    txt_value       TEXT NOT NULL,
    last_error      TEXT NOT NULL DEFAULT '',
    verified_at     TIMESTAMPTZ NULL,
    last_checked_at TIMESTAMPTZ NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, organization_id, domain)
);

CREATE INDEX IF NOT EXISTS idx_enterprise_domain_verifications_org
    ON enterprise_domain_verifications (client_id, organization_id);
CREATE INDEX IF NOT EXISTS idx_enterprise_domain_verifications_status
    ON enterprise_domain_verifications (status);
