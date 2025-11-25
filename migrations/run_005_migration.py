"""
Run migration 005: Add additional profile fields
"""
import asyncio
import asyncpg
import os
from pathlib import Path

async def run_migration():
    """Execute the migration"""
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise ValueError("DATABASE_URL environment variable not set")
    
    # Read migration SQL
    migration_file = Path(__file__).parent / "005_add_profile_fields.sql"
    with open(migration_file, 'r') as f:
        migration_sql = f.read()
    
    # Connect and execute
    conn = await asyncpg.connect(database_url)
    try:
        print("Starting migration 005: Add additional profile fields...")
        await conn.execute(migration_sql)
        print("✅ Migration 005 completed successfully")
        
        # Verify columns were added
        result = await conn.fetch("""
            SELECT column_name, data_type, column_default
            FROM information_schema.columns
            WHERE table_name = 'user_profiles'
            AND column_name IN ('first_name', 'last_name', 'avatar_icon', 'avatar_image', 'agree_to_marketing', 'agree_to_terms')
            ORDER BY column_name;
        """)
        
        print("\nVerification - New columns:")
        for row in result:
            print(f"  - {row['column_name']}: {row['data_type']} (default: {row['column_default']})")
            
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        raise
    finally:
        await conn.close()

if __name__ == "__main__":
    asyncio.run(run_migration())
