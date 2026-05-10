ALTER TABLE login_audit_log
    ADD COLUMN IF NOT EXISTS retention_until TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS legal_hold BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS legal_hold_reason TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS legal_hold_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS chain_scope TEXT NOT NULL DEFAULT 'global',
    ADD COLUMN IF NOT EXISTS previous_hash TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS event_hash TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS hash_algorithm TEXT NOT NULL DEFAULT 'sha256:v1';

UPDATE login_audit_log
SET
    retention_until = COALESCE(retention_until, created_at + INTERVAL '2555 days'),
    chain_scope = CASE
        WHEN client_id IS NULL THEN 'global'
        ELSE client_id::text
    END,
    hash_algorithm = COALESCE(NULLIF(hash_algorithm, ''), 'sha256:v1')
WHERE retention_until IS NULL
   OR chain_scope = 'global'
   OR hash_algorithm = '';

CREATE INDEX IF NOT EXISTS idx_audit_retention_purge
    ON login_audit_log (retention_until)
    WHERE legal_hold = FALSE;

CREATE INDEX IF NOT EXISTS idx_audit_legal_hold
    ON login_audit_log (legal_hold, legal_hold_at);

CREATE INDEX IF NOT EXISTS idx_audit_chain_scope
    ON login_audit_log (chain_scope, id);

CREATE INDEX IF NOT EXISTS idx_audit_event_hash
    ON login_audit_log (event_hash)
    WHERE event_hash <> '';
