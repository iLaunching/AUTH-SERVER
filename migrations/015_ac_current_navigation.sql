-- Migration 015: Active Chat navigation columns on user_navigation

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'user_navigation'
          AND column_name = 'ac_current_smart_hub_id'
    ) THEN
        ALTER TABLE user_navigation
            ADD COLUMN ac_current_smart_hub_id UUID UNIQUE
                REFERENCES smart_hubs(id) ON DELETE SET NULL;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'user_navigation'
          AND column_name = 'ac_current_smart_matrix_id'
    ) THEN
        ALTER TABLE user_navigation
            ADD COLUMN ac_current_smart_matrix_id UUID UNIQUE
                REFERENCES smart_matrices(id) ON DELETE SET NULL;
    END IF;

    CREATE INDEX IF NOT EXISTS idx_user_navigation_ac_current_smart_hub_id
        ON user_navigation(ac_current_smart_hub_id);
    CREATE INDEX IF NOT EXISTS idx_user_navigation_ac_current_smart_matrix_id
        ON user_navigation(ac_current_smart_matrix_id);
END $$;
