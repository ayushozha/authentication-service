-- Per-client email transport overrides. When a row exists for a client_id,
-- the auth service uses the client's own provider/API key/from-address/templates
-- instead of the global RESEND_API_KEY + EMAIL_FROM_* environment fallback.
--
-- api_key_ciphertext / api_key_nonce: AES-256-GCM encryption of the provider
-- API key using the master key from EMAIL_CONFIG_KMS_KEY env var. Cleartext
-- keys never sit on disk.
--
-- URL templates use {token} placeholder substitution. When empty, the auth
-- service emits its default URL (BASE_URL/{flow}.html?token=...).

CREATE TABLE IF NOT EXISTS client_email_configs (
    client_id                    UUID PRIMARY KEY REFERENCES clients(id) ON DELETE CASCADE,
    provider                     TEXT NOT NULL DEFAULT 'resend',
    api_key_ciphertext           BYTEA,
    api_key_nonce                BYTEA,
    api_key_last_four            TEXT NOT NULL DEFAULT '',
    from_address                 TEXT NOT NULL DEFAULT '',
    from_name                    TEXT NOT NULL DEFAULT '',
    reply_to                     TEXT NOT NULL DEFAULT '',
    reset_password_url_template  TEXT NOT NULL DEFAULT '',
    verify_email_url_template    TEXT NOT NULL DEFAULT '',
    magic_link_url_template      TEXT NOT NULL DEFAULT '',
    created_at                   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT email_provider_supported CHECK (provider IN ('resend'))
);

CREATE INDEX IF NOT EXISTS idx_client_email_configs_provider ON client_email_configs (provider);
