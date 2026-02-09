ALTER TABLE clients
    ADD COLUMN IF NOT EXISTS token_mode TEXT NOT NULL DEFAULT 'v1_hs256';

CREATE INDEX IF NOT EXISTS idx_clients_token_mode ON clients (token_mode);

CREATE TABLE IF NOT EXISTS client_signing_keys (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id        UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    kid              TEXT NOT NULL,
    alg              TEXT NOT NULL DEFAULT 'RS256',
    public_key_pem   TEXT NOT NULL,
    private_key_pem  TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'active',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rotated_at       TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_signing_keys_client_kid ON client_signing_keys (client_id, kid);
CREATE INDEX IF NOT EXISTS idx_signing_keys_client_status ON client_signing_keys (client_id, status);
