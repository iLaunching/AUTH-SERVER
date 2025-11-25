-- Migration: Add avatar_display_option_value_id to user_profiles
-- This creates a foreign key reference to the avatar_display option_values

-- Add the column as nullable
ALTER TABLE user_profiles 
ADD COLUMN avatar_display_option_value_id INTEGER;

-- Set default to 'default' option value ID
UPDATE user_profiles 
SET avatar_display_option_value_id = (
    SELECT id FROM option_values 
    WHERE value_name = 'default' 
    AND option_set_id = (SELECT id FROM option_sets WHERE name = 'avatar_display')
    LIMIT 1
);

-- Add foreign key constraint
ALTER TABLE user_profiles
ADD CONSTRAINT fk_avatar_display_option_value
FOREIGN KEY (avatar_display_option_value_id) 
REFERENCES option_values(id)
ON DELETE SET NULL;

-- Create index for performance
CREATE INDEX idx_user_profiles_avatar_display ON user_profiles(avatar_display_option_value_id);

-- Set default for new records
ALTER TABLE user_profiles 
ALTER COLUMN avatar_display_option_value_id 
SET DEFAULT (
    SELECT id FROM option_values 
    WHERE value_name = 'default' 
    AND option_set_id = (SELECT id FROM option_sets WHERE name = 'avatar_display')
    LIMIT 1
);
