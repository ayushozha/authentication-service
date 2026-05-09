CREATE TABLE IF NOT EXISTS enterprise_sso_connections (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id           UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    name                TEXT NOT NULL,
    slug                TEXT NOT NULL,
    protocol            TEXT NOT NULL CHECK (protocol IN ('oidc', 'saml')),
    status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
    domains             TEXT[] NOT NULL DEFAULT '{}',
    enforce_for_domains BOOLEAN NOT NULL DEFAULT FALSE,
    oidc_config         JSONB NOT NULL DEFAULT '{}'::jsonb,
    saml_config         JSONB NOT NULL DEFAULT '{}'::jsonb,
    attribute_mapping   JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, slug)
);

CREATE INDEX IF NOT EXISTS idx_enterprise_sso_connections_client_id
    ON enterprise_sso_connections (client_id);
CREATE INDEX IF NOT EXISTS idx_enterprise_sso_connections_status
    ON enterprise_sso_connections (status);
CREATE INDEX IF NOT EXISTS idx_enterprise_sso_connections_domains
    ON enterprise_sso_connections USING GIN (domains);

CREATE TABLE IF NOT EXISTS enterprise_sso_identities (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id     UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    connection_id UUID NOT NULL REFERENCES enterprise_sso_connections(id) ON DELETE CASCADE,
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    external_id   TEXT NOT NULL,
    email         TEXT NOT NULL,
    raw_profile   JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_login_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (connection_id, external_id)
);

CREATE INDEX IF NOT EXISTS idx_enterprise_sso_identities_client_id
    ON enterprise_sso_identities (client_id);
CREATE INDEX IF NOT EXISTS idx_enterprise_sso_identities_user_id
    ON enterprise_sso_identities (user_id);
