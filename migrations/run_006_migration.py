"""
Run migration 006: Update user name fields
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
    migration_file = Path(__file__).parent / "006_update_user_name_fields.sql"
    with open(migration_file, 'r') as f:
        migration_sql = f.read()
    
    # Connect and execute
    conn = await asyncpg.connect(database_url)
    try:
        print("Starting migration 006: Update user name fields...")
        
        # Check existing data
        count = await conn.fetchval("SELECT COUNT(*) FROM users WHERE name IS NOT NULL")
        print(f"Found {count} users with name data to migrate")
        
        await conn.execute(migration_sql)
        print("✅ Migration 006 completed successfully")
        
        # Verify columns
        result = await conn.fetch("""
            SELECT column_name, data_type
            FROM information_schema.columns
            WHERE table_name = 'users'
            AND column_name IN ('first_name', 'last_name', 'name')
            ORDER BY column_name;
        """)
        
        print("\nVerification - User table columns:")
        for row in result:
            print(f"  - {row['column_name']}: {row['data_type']}")
            
        # Check migrated data
        migrated = await conn.fetchval("SELECT COUNT(*) FROM users WHERE first_name IS NOT NULL")
        print(f"\n{migrated} users have first_name set after migration")
            
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        raise
    finally:
        await conn.close()

if __name__ == "__main__":
    asyncio.run(run_migration())
