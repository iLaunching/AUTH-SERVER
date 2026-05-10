-- Migration 013: user_profiles.phone_identity_id -> phone_identities.id (optional 1:1)

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'phone_identities'
    ) THEN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'user_profiles'
              AND column_name = 'phone_identity_id'
        ) THEN
            ALTER TABLE user_profiles
                ADD COLUMN phone_identity_id UUID
                    REFERENCES phone_identities(id) ON DELETE SET NULL;
            COMMENT ON COLUMN user_profiles.phone_identity_id IS
                'FK to phone_identities.id (optional 1:1 verified phone binding)';
        END IF;

        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'user_profiles'
              AND column_name = 'phone_identity_id'
        ) THEN
            CREATE UNIQUE INDEX IF NOT EXISTS idx_user_profiles_phone_identity_id
                ON user_profiles (phone_identity_id);

            UPDATE user_profiles up
            SET phone_identity_id = pi.id
            FROM phone_identities pi
            WHERE pi.user_id = up.user_id
              AND up.phone_identity_id IS NULL
              AND pi.revoked_at IS NULL;
        END IF;
    END IF;
END $$;
