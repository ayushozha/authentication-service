CREATE TABLE IF NOT EXISTS user_devices (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id        UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    fingerprint      TEXT NOT NULL,
    name             TEXT NOT NULL DEFAULT 'Device',
    user_agent       TEXT NOT NULL DEFAULT '',
    ip_address       TEXT NOT NULL DEFAULT '',
    trusted          BOOLEAN NOT NULL DEFAULT FALSE,
    remembered       BOOLEAN NOT NULL DEFAULT FALSE,
    trust_expires_at TIMESTAMPTZ,
    last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata         JSONB NOT NULL DEFAULT '{}',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_user_devices_user_fingerprint
    ON user_devices (client_id, user_id, fingerprint);

CREATE INDEX IF NOT EXISTS idx_user_devices_user_last_seen
    ON user_devices (client_id, user_id, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_user_devices_trusted
    ON user_devices (client_id, user_id, trusted)
    WHERE trusted = TRUE;
