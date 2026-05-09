CREATE TABLE IF NOT EXISTS service_accounts (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id   UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    scopes      TEXT[] NOT NULL DEFAULT '{}',
    status      TEXT NOT NULL DEFAULT 'active',
    last_used_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_service_accounts_client_id ON service_accounts (client_id);
CREATE INDEX IF NOT EXISTS idx_service_accounts_status ON service_accounts (status);

CREATE TABLE IF NOT EXISTS service_account_keys (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id          UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    service_account_id UUID NOT NULL REFERENCES service_accounts(id) ON DELETE CASCADE,
    name               TEXT NOT NULL DEFAULT '',
    key_prefix         TEXT NOT NULL,
    secret_hash        TEXT NOT NULL,
    scopes             TEXT[] NOT NULL DEFAULT '{}',
    status             TEXT NOT NULL DEFAULT 'active',
    last_used_at       TIMESTAMPTZ,
    expires_at         TIMESTAMPTZ,
    revoked_at         TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_service_account_keys_secret_hash ON service_account_keys (secret_hash);
CREATE INDEX IF NOT EXISTS idx_service_account_keys_account_status ON service_account_keys (service_account_id, status);
CREATE INDEX IF NOT EXISTS idx_service_account_keys_client_id ON service_account_keys (client_id);
