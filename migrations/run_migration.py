"""
Database migration script to add selected_theme column
Run this to update the production database schema
"""
import asyncio
import asyncpg

DATABASE_URL = "postgresql://postgres:TVzCDcmIDhjbquUUbrUMQExHEfXIwiNm@tramway.proxy.rlwy.net:12050/railway"

async def run_migration():
    """Add selected_theme column to user_profiles table"""
    conn = await asyncpg.connect(DATABASE_URL)
    
    try:
        print("Running migration: Add selected_theme column...")
        
        # Add column
        await conn.execute("""
            ALTER TABLE user_profiles 
            ADD COLUMN IF NOT EXISTS selected_theme VARCHAR(50) DEFAULT 'sun'
        """)
        
        print("✅ Migration completed successfully!")
        
        # Verify
        result = await conn.fetchrow("""
            SELECT column_name, data_type, column_default 
            FROM information_schema.columns 
            WHERE table_name = 'user_profiles' AND column_name = 'selected_theme'
        """)
        
        if result:
            print(f"✅ Verified: {result['column_name']} - {result['data_type']} - default: {result['column_default']}")
        else:
            print("❌ Column not found after migration")
            
    except Exception as e:
        print(f"❌ Migration failed: {e}")
    finally:
        await conn.close()

if __name__ == "__main__":
    asyncio.run(run_migration())
