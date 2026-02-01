CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS clients (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name             TEXT NOT NULL,
    slug             TEXT NOT NULL,
    jwt_secret       TEXT NOT NULL,
    allowed_origins  TEXT[] NOT NULL DEFAULT '{}',
    webhook_url      TEXT NOT NULL DEFAULT '',
    settings         JSONB NOT NULL DEFAULT '{}',
    status           TEXT NOT NULL DEFAULT 'active',
    api_key_hash     TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_clients_slug ON clients (slug);
CREATE UNIQUE INDEX IF NOT EXISTS idx_clients_api_key ON clients (api_key_hash);
CREATE INDEX IF NOT EXISTS idx_clients_status ON clients (status);
