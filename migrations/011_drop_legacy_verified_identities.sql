-- ============================================================
-- Migration: 011_drop_legacy_verified_identities
-- Removes Vonage Verify era tables from 009_verified_identities.
-- Phone binding now uses 010_phone_identity (phone_identities, etc.).
-- Idempotent: safe if tables were never created.
-- ============================================================

DROP TABLE IF EXISTS verification_attempts CASCADE;

DROP TABLE IF EXISTS verified_identities CASCADE;

-- update_updated_at_column() may still be used by other triggers; do not drop here.
