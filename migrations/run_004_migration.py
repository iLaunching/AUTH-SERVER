"""
Run migration to add avatar_display_option_value_id to user_profiles
"""
import asyncio
import asyncpg

DATABASE_URL = "postgresql://postgres:TVzCDcmIDhjbquUUbrUMQExHEfXIwiNm@tramway.proxy.rlwy.net:12050/railway"

async def run_migration():
    conn = await asyncpg.connect(DATABASE_URL)
    
    try:
        print("🚀 Running migration: Add avatar_display_option_value_id to user_profiles\n")
        
        # Check if column already exists
        column_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT FROM information_schema.columns 
                WHERE table_name = 'user_profiles' 
                AND column_name = 'avatar_display_option_value_id'
            )
        """)
        
        if column_exists:
            print("⚠️  Column avatar_display_option_value_id already exists, skipping migration")
            return
        
        # Get the 'default' option value ID
        default_id = await conn.fetchval("""
            SELECT ov.id FROM option_values ov
            JOIN option_sets os ON ov.option_set_id = os.id
            WHERE ov.value_name = 'default' AND os.name = 'avatar_display'
        """)
        
        if not default_id:
            print("❌ Error: 'default' option value not found. Please seed avatar_display option set first.")
            return
        
        print(f"✅ Found 'default' option value with ID: {default_id}")
        
        # Add the column
        print("📝 Adding avatar_display_option_value_id column...")
        await conn.execute("""
            ALTER TABLE user_profiles 
            ADD COLUMN avatar_display_option_value_id INTEGER
        """)
        
        # Set default for existing records
        print(f"📝 Setting default to 'default' (ID: {default_id}) for existing records...")
        updated = await conn.execute(f"""
            UPDATE user_profiles 
            SET avatar_display_option_value_id = {default_id}
        """)
        print(f"✅ Updated {updated} existing user profiles")
        
        # Add foreign key constraint
        print("📝 Adding foreign key constraint...")
        await conn.execute("""
            ALTER TABLE user_profiles
            ADD CONSTRAINT fk_avatar_display_option_value
            FOREIGN KEY (avatar_display_option_value_id) 
            REFERENCES option_values(id)
            ON DELETE SET NULL
        """)
        
        # Create index
        print("📝 Creating index...")
        await conn.execute("""
            CREATE INDEX idx_user_profiles_avatar_display 
            ON user_profiles(avatar_display_option_value_id)
        """)
        
        # Set default for new records
        print("📝 Setting default for new records...")
        await conn.execute(f"""
            ALTER TABLE user_profiles 
            ALTER COLUMN avatar_display_option_value_id 
            SET DEFAULT {default_id}
        """)
        
        print("\n🎉 Migration completed successfully!")
        print(f"✅ user_profiles.avatar_display_option_value_id now references option_values")
        print(f"✅ Default set to 'default' (ID: {default_id})")
        
        # Verify
        count = await conn.fetchval("""
            SELECT COUNT(*) FROM user_profiles 
            WHERE avatar_display_option_value_id IS NOT NULL
        """)
        print(f"✅ Verification: {count} user profiles have avatar_display option value set")
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        await conn.close()

if __name__ == "__main__":
    asyncio.run(run_migration())
