-- Migration 015: ISO 3166-1 alpha-2 region on phone_identities & phone_verification_attempts
-- Populated from client region hint + libphonenumber at bind time; OTP Redis carries it through confirm.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'phone_identities'
    ) THEN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'phone_identities'
              AND column_name = 'country_code'
        ) THEN
            ALTER TABLE phone_identities
                ADD COLUMN country_code VARCHAR(5);
            COMMENT ON COLUMN phone_identities.country_code IS
                'ISO 3166-1 alpha-2 region for real_phone (from client region + validation)';
        END IF;
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'phone_verification_attempts'
    ) THEN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'phone_verification_attempts'
              AND column_name = 'country_code'
        ) THEN
            ALTER TABLE phone_verification_attempts
                ADD COLUMN country_code VARCHAR(5);
            COMMENT ON COLUMN phone_verification_attempts.country_code IS
                'ISO region at attempt time (matches bind/resend hint where available)';
        END IF;
    END IF;
END $$;
