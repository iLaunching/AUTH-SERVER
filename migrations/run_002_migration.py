"""
Run migration to add appearance_option_value_id to user_profiles
"""
import asyncio
import asyncpg

DATABASE_URL = "postgresql://postgres:TVzCDcmIDhjbquUUbrUMQExHEfXIwiNm@tramway.proxy.rlwy.net:12050/railway"

async def run_migration():
    conn = await asyncpg.connect(DATABASE_URL)
    
    try:
        print("🚀 Running migration: Add appearance_option_value_id to user_profiles\n")
        
        # Check if column already exists
        column_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT FROM information_schema.columns 
                WHERE table_name = 'user_profiles' 
                AND column_name = 'appearance_option_value_id'
            )
        """)
        
        if column_exists:
            print("⚠️  Column appearance_option_value_id already exists, skipping migration")
            return
        
        # Get the 'sun' option value ID
        sun_id = await conn.fetchval("""
            SELECT ov.id FROM option_values ov
            JOIN option_sets os ON ov.option_set_id = os.id
            WHERE ov.value_name = 'sun' AND os.name = 'appearance'
        """)
        
        if not sun_id:
            print("❌ Error: 'sun' option value not found. Please seed appearance option set first.")
            return
        
        print(f"✅ Found 'sun' option value with ID: {sun_id}")
        
        # Add the column as nullable
        print("📝 Adding appearance_option_value_id column...")
        await conn.execute("""
            ALTER TABLE user_profiles 
            ADD COLUMN appearance_option_value_id INTEGER
        """)
        
        # Set default to 'sun' for existing records
        print(f"📝 Setting default to 'sun' (ID: {sun_id}) for existing records...")
        updated = await conn.execute(f"""
            UPDATE user_profiles 
            SET appearance_option_value_id = {sun_id}
        """)
        print(f"✅ Updated {updated} existing user profiles")
        
        # Add foreign key constraint
        print("📝 Adding foreign key constraint...")
        await conn.execute("""
            ALTER TABLE user_profiles
            ADD CONSTRAINT fk_appearance_option_value
            FOREIGN KEY (appearance_option_value_id) 
            REFERENCES option_values(id)
            ON DELETE SET NULL
        """)
        
        # Create index for performance
        print("📝 Creating index...")
        await conn.execute("""
            CREATE INDEX idx_user_profiles_appearance 
            ON user_profiles(appearance_option_value_id)
        """)
        
        # Set default for new records
        print("📝 Setting default for new records...")
        await conn.execute(f"""
            ALTER TABLE user_profiles 
            ALTER COLUMN appearance_option_value_id 
            SET DEFAULT {sun_id}
        """)
        
        print("\n🎉 Migration completed successfully!")
        print(f"✅ user_profiles.appearance_option_value_id now references option_values")
        print(f"✅ Default set to 'sun' (ID: {sun_id})")
        
        # Verify
        count = await conn.fetchval("""
            SELECT COUNT(*) FROM user_profiles 
            WHERE appearance_option_value_id IS NOT NULL
        """)
        print(f"✅ Verification: {count} user profiles have appearance option value set")
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        await conn.close()

if __name__ == "__main__":
    asyncio.run(run_migration())
