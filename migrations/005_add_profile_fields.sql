-- Migration: Add additional profile fields
-- Date: 2025-11-24
-- Description: Adds first_name, last_name, avatar_icon, avatar_image, agree_to_marketing, agree_to_terms

ALTER TABLE user_profiles
ADD COLUMN IF NOT EXISTS first_name TEXT,
ADD COLUMN IF NOT EXISTS last_name TEXT,
ADD COLUMN IF NOT EXISTS avatar_icon TEXT,
ADD COLUMN IF NOT EXISTS avatar_image TEXT,
ADD COLUMN IF NOT EXISTS agree_to_marketing BOOLEAN DEFAULT false NOT NULL,
ADD COLUMN IF NOT EXISTS agree_to_terms BOOLEAN DEFAULT false NOT NULL;

-- Add comments for documentation
COMMENT ON COLUMN user_profiles.first_name IS 'User first name';
COMMENT ON COLUMN user_profiles.last_name IS 'User last name';
COMMENT ON COLUMN user_profiles.avatar_icon IS 'Icon identifier for avatar display';
COMMENT ON COLUMN user_profiles.avatar_image IS 'Image URL for avatar display';
COMMENT ON COLUMN user_profiles.agree_to_marketing IS 'User consent for marketing communications';
COMMENT ON COLUMN user_profiles.agree_to_terms IS 'User acceptance of terms and conditions';
