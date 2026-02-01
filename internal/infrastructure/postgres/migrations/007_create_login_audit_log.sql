CREATE TABLE IF NOT EXISTS login_audit_log (
    id              BIGSERIAL PRIMARY KEY,
    client_id       UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type      TEXT NOT NULL,
    ip_address      TEXT NOT NULL DEFAULT '',
    user_agent      TEXT NOT NULL DEFAULT '',
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_client_id ON login_audit_log (client_id);
CREATE INDEX IF NOT EXISTS idx_audit_user_id ON login_audit_log (user_id);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON login_audit_log (event_type);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON login_audit_log (created_at);
