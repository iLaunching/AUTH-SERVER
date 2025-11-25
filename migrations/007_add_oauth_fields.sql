-- Add OAuth fields to users table
-- Migration: 007_add_oauth_fields
-- Date: 2025-11-25

-- Add oauth_provider column
ALTER TABLE users ADD COLUMN IF NOT EXISTS oauth_provider VARCHAR(50);

-- Add oauth_provider_id column
ALTER TABLE users ADD COLUMN IF NOT EXISTS oauth_provider_id VARCHAR(255);

-- Create index on oauth_provider for faster lookups
CREATE INDEX IF NOT EXISTS ix_users_oauth_provider ON users(oauth_provider);

-- Create composite index on oauth_provider and oauth_provider_id for uniqueness per provider
CREATE INDEX IF NOT EXISTS ix_users_oauth_provider_id ON users(oauth_provider, oauth_provider_id);

-- Make password_hash nullable for OAuth users (if not already nullable)
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;
