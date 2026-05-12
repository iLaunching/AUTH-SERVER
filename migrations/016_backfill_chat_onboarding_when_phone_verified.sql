-- Migration 016: Align activeChat_onBoarding_complete with phone_varified for legacy rows
-- (Users who verified phone before chat flag existed or before bind set both columns together.)

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'user_profiles'
          AND column_name = 'activeChat_onBoarding_complete'
    ) AND EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'user_profiles'
          AND column_name = 'phone_varified'
    ) THEN
        UPDATE user_profiles
        SET "activeChat_onBoarding_complete" = TRUE
        WHERE phone_varified IS TRUE
          AND "activeChat_onBoarding_complete" IS NOT TRUE;
    END IF;
END $$;
