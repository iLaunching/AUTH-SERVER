-- Migration: Add appearance_option_value_id to user_profiles
-- This creates a foreign key reference to the option_values table
-- Default is set to the 'sun' option value (ID needs to be looked up)

-- First, add the column as nullable
ALTER TABLE user_profiles 
ADD COLUMN appearance_option_value_id INTEGER;

-- Set default to 'sun' option value ID
-- We'll update this to reference the actual ID from option_values where value_name = 'sun'
UPDATE user_profiles 
SET appearance_option_value_id = (
    SELECT id FROM option_values 
    WHERE value_name = 'sun' 
    AND option_set_id = (SELECT id FROM option_sets WHERE name = 'appearance')
    LIMIT 1
);

-- Add foreign key constraint
ALTER TABLE user_profiles
ADD CONSTRAINT fk_appearance_option_value
FOREIGN KEY (appearance_option_value_id) 
REFERENCES option_values(id)
ON DELETE SET NULL;

-- Create index for performance
CREATE INDEX idx_user_profiles_appearance ON user_profiles(appearance_option_value_id);

-- Set default for new records
ALTER TABLE user_profiles 
ALTER COLUMN appearance_option_value_id 
SET DEFAULT (
    SELECT id FROM option_values 
    WHERE value_name = 'sun' 
    AND option_set_id = (SELECT id FROM option_sets WHERE name = 'appearance')
    LIMIT 1
);
