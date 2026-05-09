CREATE TABLE IF NOT EXISTS scim_directories (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id    UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    token_hash   TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    domains      TEXT[] NOT NULL DEFAULT '{}',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scim_directories_client_id
    ON scim_directories (client_id);
CREATE INDEX IF NOT EXISTS idx_scim_directories_status
    ON scim_directories (status);

CREATE TABLE IF NOT EXISTS scim_users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id     UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    directory_id  UUID NOT NULL REFERENCES scim_directories(id) ON DELETE CASCADE,
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    external_id   TEXT NOT NULL,
    user_name     TEXT NOT NULL,
    active        BOOLEAN NOT NULL DEFAULT TRUE,
    raw_resource  JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (directory_id, external_id)
);

CREATE INDEX IF NOT EXISTS idx_scim_users_client_directory
    ON scim_users (client_id, directory_id);
CREATE INDEX IF NOT EXISTS idx_scim_users_user_id
    ON scim_users (user_id);

CREATE TABLE IF NOT EXISTS scim_groups (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id     UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    directory_id  UUID NOT NULL REFERENCES scim_directories(id) ON DELETE CASCADE,
    external_id   TEXT NOT NULL,
    display_name  TEXT NOT NULL,
    members       TEXT[] NOT NULL DEFAULT '{}',
    raw_resource  JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (directory_id, external_id)
);

CREATE INDEX IF NOT EXISTS idx_scim_groups_client_directory
    ON scim_groups (client_id, directory_id);
