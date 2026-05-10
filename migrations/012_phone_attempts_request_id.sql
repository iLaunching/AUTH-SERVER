-- ============================================================
-- Migration: 012_phone_attempts_request_id
-- Add request_id to phone_verification_attempts so one OTP attempt = one row.
-- ============================================================

ALTER TABLE phone_verification_attempts
    ADD COLUMN IF NOT EXISTS request_id TEXT;

-- One row per OTP request_id (only for SMS attempts; App Attest rows may be NULL)
CREATE UNIQUE INDEX IF NOT EXISTS idx_pva_request_id_unique
    ON phone_verification_attempts (request_id)
    WHERE request_id IS NOT NULL;

