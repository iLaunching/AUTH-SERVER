"""
Run migration to add itheme_option_value_id to user_profiles
"""
import asyncio
import asyncpg

DATABASE_URL = "postgresql://postgres:TVzCDcmIDhjbquUUbrUMQExHEfXIwiNm@tramway.proxy.rlwy.net:12050/railway"

async def run_migration():
    conn = await asyncpg.connect(DATABASE_URL)
    
    try:
        print("🚀 Running migration: Add itheme_option_value_id to user_profiles\n")
        
        # Check if column already exists
        column_exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT FROM information_schema.columns 
                WHERE table_name = 'user_profiles' 
                AND column_name = 'itheme_option_value_id'
            )
        """)
        
        if column_exists:
            print("⚠️  Column itheme_option_value_id already exists, skipping migration")
            return
        
        # Get the 'ipurple' option value ID
        ipurple_id = await conn.fetchval("""
            SELECT ov.id FROM option_values ov
            JOIN option_sets os ON ov.option_set_id = os.id
            WHERE ov.value_name = 'ipurple' AND os.name = 'itheme'
        """)
        
        if not ipurple_id:
            print("❌ Error: 'ipurple' option value not found. Please seed itheme option set first.")
            return
        
        print(f"✅ Found 'ipurple' option value with ID: {ipurple_id}")
        
        # Add the column as nullable
        print("📝 Adding itheme_option_value_id column...")
        await conn.execute("""
            ALTER TABLE user_profiles 
            ADD COLUMN itheme_option_value_id INTEGER
        """)
        
        # Set default to 'ipurple' for existing records
        print(f"📝 Setting default to 'ipurple' (ID: {ipurple_id}) for existing records...")
        updated = await conn.execute(f"""
            UPDATE user_profiles 
            SET itheme_option_value_id = {ipurple_id}
        """)
        print(f"✅ Updated {updated} existing user profiles")
        
        # Add foreign key constraint
        print("📝 Adding foreign key constraint...")
        await conn.execute("""
            ALTER TABLE user_profiles
            ADD CONSTRAINT fk_itheme_option_value
            FOREIGN KEY (itheme_option_value_id) 
            REFERENCES option_values(id)
            ON DELETE SET NULL
        """)
        
        # Create index for performance
        print("📝 Creating index...")
        await conn.execute("""
            CREATE INDEX idx_user_profiles_itheme 
            ON user_profiles(itheme_option_value_id)
        """)
        
        # Set default for new records
        print("📝 Setting default for new records...")
        await conn.execute(f"""
            ALTER TABLE user_profiles 
            ALTER COLUMN itheme_option_value_id 
            SET DEFAULT {ipurple_id}
        """)
        
        print("\n🎉 Migration completed successfully!")
        print(f"✅ user_profiles.itheme_option_value_id now references option_values")
        print(f"✅ Default set to 'ipurple' (ID: {ipurple_id})")
        
        # Verify
        count = await conn.fetchval("""
            SELECT COUNT(*) FROM user_profiles 
            WHERE itheme_option_value_id IS NOT NULL
        """)
        print(f"✅ Verification: {count} user profiles have itheme option value set")
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        await conn.close()

if __name__ == "__main__":
    asyncio.run(run_migration())
