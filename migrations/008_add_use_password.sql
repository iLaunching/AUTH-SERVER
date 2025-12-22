-- Add use_password field to users table
-- Migration: 008_add_use_password
-- Date: 2025-12-22

-- Add use_password column with default value true
ALTER TABLE users ADD COLUMN IF NOT EXISTS use_password BOOLEAN NOT NULL DEFAULT true;

-- Add comment explaining the column
COMMENT ON COLUMN users.use_password IS 'Indicates whether user has a password (true for email/password auth, false for OAuth-only users)';
