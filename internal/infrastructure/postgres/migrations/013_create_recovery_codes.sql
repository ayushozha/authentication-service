CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash   TEXT NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_mfa_recovery_codes_user_hash ON mfa_recovery_codes (user_id, code_hash);
CREATE INDEX IF NOT EXISTS idx_mfa_recovery_codes_user_unused ON mfa_recovery_codes (user_id) WHERE used_at IS NULL;
