-- ============================================================
-- Migration: 010_phone_identity
-- Phone identity binding (App Attest + SMS OTP). Replaces Vonage Verify for binding.
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS phone_identities (
    id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID         NOT NULL UNIQUE,
    real_phone          VARCHAR(20)  NOT NULL UNIQUE,
    real_phone_hash     VARCHAR(64)  NOT NULL UNIQUE,
    trust_level         VARCHAR(10)  NOT NULL
                            CHECK (trust_level IN ('HIGH', 'MED')),
    verification_method VARCHAR(15)  NOT NULL
                            CHECK (verification_method IN ('app_attest', 'sms')),
    hardware_id         TEXT,
    bound_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    revoked_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS phone_verification_attempts (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID        NOT NULL,
    real_phone      VARCHAR(20) NOT NULL,
    channel         VARCHAR(15) NOT NULL CHECK (channel IN ('app_attest', 'sms')),
    status          VARCHAR(20) NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'completed', 'failed')),
    failure_reason  TEXT,
    ip_address      INET,
    user_agent      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS attest_challenges (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge   TEXT NOT NULL UNIQUE,
    user_id     UUID NOT NULL,
    used        BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '10 minutes')
);

CREATE INDEX IF NOT EXISTS idx_pi_user_id
    ON phone_identities (user_id)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_pi_real_phone
    ON phone_identities (real_phone)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_pi_real_phone_hash
    ON phone_identities (real_phone_hash)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_pva_phone_created
    ON phone_verification_attempts (real_phone, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_pva_user_created
    ON phone_verification_attempts (user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ac_challenge
    ON attest_challenges (challenge)
    WHERE used = FALSE;

CREATE INDEX IF NOT EXISTS idx_ac_expires
    ON attest_challenges (expires_at);

CREATE OR REPLACE FUNCTION cleanup_attest_challenges() RETURNS void AS $$
BEGIN
    DELETE FROM attest_challenges WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

COMMENT ON TABLE phone_identities IS
    'One row per user. Created once when phone is bound. real_phone never changes.';
COMMENT ON TABLE phone_verification_attempts IS
    'Append-only audit log for phone binding attempts.';
COMMENT ON TABLE attest_challenges IS
    'One-time nonces for App Attest challenge-response.';
