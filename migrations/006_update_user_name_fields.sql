-- Migration: Update user name fields
-- Date: 2025-11-24
-- Description: Replace single 'name' field with 'first_name' and 'last_name'

-- Add new columns
ALTER TABLE users
ADD COLUMN IF NOT EXISTS first_name VARCHAR(255),
ADD COLUMN IF NOT EXISTS last_name VARCHAR(255);

-- Migrate existing data (split name into first_name, keep empty last_name)
UPDATE users
SET first_name = name
WHERE name IS NOT NULL AND first_name IS NULL;

-- Drop dependent views first (they can be recreated later if needed)
DROP VIEW IF EXISTS active_sessions CASCADE;
DROP VIEW IF EXISTS user_statistics CASCADE;

-- Now drop old column
ALTER TABLE users
DROP COLUMN IF EXISTS name;

-- Add comments
COMMENT ON COLUMN users.first_name IS 'User first name';
COMMENT ON COLUMN users.last_name IS 'User last name';
