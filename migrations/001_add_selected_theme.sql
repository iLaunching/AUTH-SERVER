😊-- Migration: Add selected_theme column to user_profiles table
-- This column was added to support appearance theme selection
-- Run this SQL directly on the Railway PostgreSQL database

-- Add selected_theme column to user_profiles table
ALTER TABLE user_profiles 
ADD COLUMN IF NOT EXISTS selected_theme VARCHAR(50) DEFAULT 'sun';

-- Add comment
COMMENT ON COLUMN user_profiles.selected_theme IS 'User selected appearance theme (e.g., sun, moon, earth)';

-- Verify the column was added
SELECT column_name, data_type, column_default 
FROM information_schema.columns 
WHERE table_name = 'user_profiles' AND column_name = 'selected_theme';
