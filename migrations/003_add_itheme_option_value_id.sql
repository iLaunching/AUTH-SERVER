-- Migration: Add itheme_option_value_id to user_profiles
-- This creates a foreign key reference to the itheme option_values

-- Add the column as nullable
ALTER TABLE user_profiles 
ADD COLUMN itheme_option_value_id INTEGER;

-- Set default to 'ipurple' option value ID
UPDATE user_profiles 
SET itheme_option_value_id = (
    SELECT id FROM option_values 
    WHERE value_name = 'ipurple' 
    AND option_set_id = (SELECT id FROM option_sets WHERE name = 'itheme')
    LIMIT 1
);

-- Add foreign key constraint
ALTER TABLE user_profiles
ADD CONSTRAINT fk_itheme_option_value
FOREIGN KEY (itheme_option_value_id) 
REFERENCES option_values(id)
ON DELETE SET NULL;

-- Create index for performance
CREATE INDEX idx_user_profiles_itheme ON user_profiles(itheme_option_value_id);

-- Set default for new records
ALTER TABLE user_profiles 
ALTER COLUMN itheme_option_value_id 
SET DEFAULT (
    SELECT id FROM option_values 
    WHERE value_name = 'ipurple' 
    AND option_set_id = (SELECT id FROM option_sets WHERE name = 'itheme')
    LIMIT 1
);
