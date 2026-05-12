-- Migration 014: Active Chat onboarding completion flag on user_profiles

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'user_profiles'
          AND column_name = 'activeChat_onBoarding_complete'
    ) THEN
        ALTER TABLE user_profiles
            ADD COLUMN "activeChat_onBoarding_complete" BOOLEAN DEFAULT FALSE NOT NULL;
        COMMENT ON COLUMN user_profiles."activeChat_onBoarding_complete" IS
            'True when the user has finished Active Chat onboarding';
    END IF;
END $$;
