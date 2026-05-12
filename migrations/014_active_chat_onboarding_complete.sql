-- Migration 014: Active Chat onboarding completion flag on user_profiles

ALTER TABLE user_profiles
ADD COLUMN IF NOT EXISTS "activeChat_onBoarding_complete" BOOLEAN DEFAULT FALSE NOT NULL;

COMMENT ON COLUMN user_profiles."activeChat_onBoarding_complete" IS
    'True when the user has finished Active Chat onboarding';
