-- Per-client OAuth provider overrides. When a row exists for a
-- (client_id, provider) pair, the auth service uses that client's own OAuth
-- application credentials (e.g. its own GitHub OAuth App, branded with the
-- client's name + logo) instead of the global GITHUB_CLIENT_ID / GOOGLE_* /
-- MICROSOFT_* environment fallback. This lets each project present its own
-- consent screen while sharing a single auth service + callback URL.
--
-- client_secret_ciphertext / client_secret_nonce: AES-256-GCM encryption of
-- the OAuth client secret using the master key from EMAIL_CONFIG_KMS_KEY (the
-- same generic secret cipher used for per-client email API keys). Cleartext
-- secrets never sit on disk.
--
-- The redirect/callback URL is NOT stored here: it is always derived from
-- BASE_URL (https://<base>/api/auth/oauth/<provider>/callback). Every
-- per-client OAuth App must register that same shared callback, because the
-- callback handler resolves the originating client from the signed state.
--
-- Apple is intentionally excluded from per-client overrides: it uses a
-- private-key/JWT client-secret flow that does not fit the id+secret model.

CREATE TABLE IF NOT EXISTS client_oauth_configs (
    client_id                 UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    provider                  TEXT NOT NULL,
    client_id_plain           TEXT NOT NULL DEFAULT '',
    client_secret_ciphertext  BYTEA,
    client_secret_nonce       BYTEA,
    secret_last_four          TEXT NOT NULL DEFAULT '',
    scopes                    TEXT NOT NULL DEFAULT '',
    enabled                   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (client_id, provider),
    CONSTRAINT oauth_provider_supported CHECK (provider IN ('github', 'google', 'microsoft'))
);

CREATE INDEX IF NOT EXISTS idx_client_oauth_configs_provider ON client_oauth_configs (provider);
