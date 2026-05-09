CREATE TABLE IF NOT EXISTS organizations (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id          UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    name               TEXT NOT NULL,
    slug               TEXT NOT NULL,
    metadata           JSONB NOT NULL DEFAULT '{}',
    created_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_organizations_client_slug ON organizations (client_id, LOWER(slug));
CREATE INDEX IF NOT EXISTS idx_organizations_client_id ON organizations (client_id);

CREATE TABLE IF NOT EXISTS organization_memberships (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id       UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role            TEXT NOT NULL DEFAULT 'member',
    permissions     TEXT[] NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_org_memberships_org_user ON organization_memberships (organization_id, user_id);
CREATE INDEX IF NOT EXISTS idx_org_memberships_client_user ON organization_memberships (client_id, user_id);
CREATE INDEX IF NOT EXISTS idx_org_memberships_org_role ON organization_memberships (organization_id, role);
CREATE INDEX IF NOT EXISTS idx_org_memberships_status ON organization_memberships (status);

CREATE TABLE IF NOT EXISTS organization_invitations (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id          UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    organization_id    UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email              TEXT NOT NULL,
    role               TEXT NOT NULL DEFAULT 'member',
    permissions        TEXT[] NOT NULL DEFAULT '{}',
    token_hash         TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT 'pending',
    invited_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    expires_at         TIMESTAMPTZ NOT NULL,
    accepted_at        TIMESTAMPTZ,
    revoked_at         TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_org_invitations_token_hash ON organization_invitations (token_hash);
CREATE INDEX IF NOT EXISTS idx_org_invitations_org_status ON organization_invitations (organization_id, status);
CREATE INDEX IF NOT EXISTS idx_org_invitations_client_email ON organization_invitations (client_id, LOWER(email));
