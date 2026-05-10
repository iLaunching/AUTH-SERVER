-- Migration 014: user_profiles.phone_varified (legacy spelling; aligns with api-server 035)
-- Set TRUE when identity binding completes; FALSE on revoke.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'user_profiles'
    ) THEN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'user_profiles'
              AND column_name = 'phone_varified'
        ) THEN
            ALTER TABLE user_profiles
                ADD COLUMN phone_varified BOOLEAN NOT NULL DEFAULT FALSE;
            COMMENT ON COLUMN user_profiles.phone_varified IS
                'Whether phone has been verified via identity binding';
        END IF;

        UPDATE user_profiles up
        SET phone_varified = TRUE
        WHERE up.phone_identity_id IS NOT NULL
          AND up.phone_varified IS NOT TRUE;
    END IF;
END $$;
