CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id     BYTEA NOT NULL,
    public_key        BYTEA NOT NULL,
    attestation_type  TEXT NOT NULL DEFAULT '',
    transport         TEXT[] NOT NULL DEFAULT '{}',
    aaguid            BYTEA,
    sign_count        BIGINT NOT NULL DEFAULT 0,
    friendly_name     TEXT NOT NULL DEFAULT '',
    backed_up         BOOLEAN NOT NULL DEFAULT FALSE,
    last_used_at      TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_webauthn_credential_id ON webauthn_credentials (credential_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_user_id ON webauthn_credentials (user_id);
