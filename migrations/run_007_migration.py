"""
Run migration 007 - Add OAuth fields to users table
"""
import asyncio
import asyncpg
import os
from pathlib import Path

async def run_migration():
    """Run the migration script"""
    # Get database URL from environment
    database_url = os.getenv('DATABASE_URL')
    
    if not database_url:
        print("ERROR: DATABASE_URL environment variable not set")
        return False
    
    # Convert to asyncpg format if using postgresql+asyncpg
    if database_url.startswith('postgresql+asyncpg://'):
        database_url = database_url.replace('postgresql+asyncpg://', 'postgresql://')
    
    print(f"Connecting to database...")
    
    try:
        # Connect to database
        conn = await asyncpg.connect(database_url)
        
        # Read migration file
        migration_file = Path(__file__).parent / '007_add_oauth_fields.sql'
        with open(migration_file, 'r') as f:
            sql = f.read()
        
        print("Running migration 007_add_oauth_fields...")
        
        # Execute migration
        await conn.execute(sql)
        
        print("✅ Migration completed successfully!")
        
        # Verify columns exist
        result = await conn.fetch("""
            SELECT column_name, data_type, is_nullable
            FROM information_schema.columns
            WHERE table_name = 'users'
            AND column_name IN ('oauth_provider', 'oauth_provider_id', 'password_hash')
            ORDER BY column_name;
        """)
        
        print("\nVerified columns:")
        for row in result:
            print(f"  - {row['column_name']}: {row['data_type']} (nullable: {row['is_nullable']})")
        
        await conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        return False

if __name__ == '__main__':
    asyncio.run(run_migration())
