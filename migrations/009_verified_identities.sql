-- ============================================================
-- Migration: 009_verified_identities
-- Phone + carrier verified identity state (Vonage Silent Auth + SMS)
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
-- Core: one active row per user (partial unique index where not revoked)
-- ============================================================
CREATE TABLE IF NOT EXISTS verified_identities (
    id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id              UUID        NOT NULL,
    phone_number         VARCHAR(20) NOT NULL,                   -- E.164 e.g. +447911123456
    trust_level          VARCHAR(10) NOT NULL
                             CHECK (trust_level IN ('HIGH', 'MED')),
    verification_method  VARCHAR(15) NOT NULL
                             CHECK (verification_method IN ('silent_auth', 'sms')),
    hardware_id          TEXT,                                   -- Optional: hashed device key id (App Attest)
    verified_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at           TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '90 days'),
    revoked_at           TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- Audit log — append-only
-- ============================================================
CREATE TABLE IF NOT EXISTS verification_attempts (
    id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id              UUID,
    phone_number         VARCHAR(20) NOT NULL,
    vonage_request_id    VARCHAR(100),
    channel              VARCHAR(15)
                             CHECK (channel IN ('silent_auth', 'sms')),
    status               VARCHAR(20) NOT NULL DEFAULT 'pending'
                             CHECK (status IN ('pending','completed','failed','expired','cancelled')),
    failure_reason       TEXT,
    ip_address           INET,
    user_agent           TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at         TIMESTAMPTZ
);

-- ============================================================
-- Indexes — critical for scale
-- ============================================================
CREATE UNIQUE INDEX IF NOT EXISTS idx_vi_user_id_active
    ON verified_identities (user_id)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_vi_phone_active
    ON verified_identities (phone_number)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_vi_expires_at
    ON verified_identities (expires_at)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_va_phone_created
    ON verification_attempts (phone_number, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_va_user_id_created
    ON verification_attempts (user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_va_vonage_request_id
    ON verification_attempts (vonage_request_id)
    WHERE vonage_request_id IS NOT NULL;

-- ============================================================
-- Auto-update updated_at
-- ============================================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_vi_updated_at ON verified_identities;
CREATE TRIGGER trg_vi_updated_at
    BEFORE UPDATE ON verified_identities
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

COMMENT ON TABLE verified_identities   IS 'One active row per user. Highest trust level achieved.';
COMMENT ON TABLE verification_attempts IS 'Append-only audit log. Never delete rows.';

