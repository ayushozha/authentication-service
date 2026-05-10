CREATE TABLE IF NOT EXISTS organization_authorization_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id       UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    version         INTEGER NOT NULL DEFAULT 1,
    description     TEXT NOT NULL DEFAULT '',
    resources       JSONB NOT NULL DEFAULT '[]'::jsonb,
    permissions     JSONB NOT NULL DEFAULT '[]'::jsonb,
    roles           JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id)
);

CREATE INDEX IF NOT EXISTS idx_org_authz_policies_client_org
    ON organization_authorization_policies (client_id, organization_id);

CREATE TABLE IF NOT EXISTS organization_group_mappings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id       UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    source          TEXT NOT NULL CHECK (source IN ('sso', 'scim')),
    source_id       TEXT NOT NULL DEFAULT '',
    group_name      TEXT NOT NULL,
    role            TEXT NOT NULL,
    permissions     TEXT[] NOT NULL DEFAULT '{}',
    description     TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, source, source_id, group_name)
);

CREATE INDEX IF NOT EXISTS idx_org_group_mappings_client_org
    ON organization_group_mappings (client_id, organization_id);
CREATE INDEX IF NOT EXISTS idx_org_group_mappings_source
    ON organization_group_mappings (client_id, source, source_id, group_name);
