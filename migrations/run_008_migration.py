"""
Run migration 008 - Add use_password field to users table
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
        migration_file = Path(__file__).parent / '008_add_use_password.sql'
        with open(migration_file, 'r') as f:
            sql = f.read()
        
        print("Running migration 008_add_use_password...")
        
        # Execute migration
        await conn.execute(sql)
        
        print("✅ Migration completed successfully!")
        
        # Verify column exists
        result = await conn.fetch("""
            SELECT column_name, data_type, is_nullable, column_default
            FROM information_schema.columns
            WHERE table_name = 'users'
            AND column_name = 'use_password'
            ORDER BY column_name;
        """)
        
        print("\nVerified column:")
        for row in result:
            print(f"  - {row['column_name']}: {row['data_type']}, nullable={row['is_nullable']}, default={row['column_default']}")
        
        # Count users with use_password
        count_result = await conn.fetchrow("""
            SELECT 
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE use_password = true) as with_password,
                COUNT(*) FILTER (WHERE use_password = false) as without_password
            FROM users;
        """)
        
        print(f"\nUser statistics:")
        print(f"  Total users: {count_result['total']}")
        print(f"  With password: {count_result['with_password']}")
        print(f"  Without password: {count_result['without_password']}")
        
        await conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Migration failed: {str(e)}")
        return False

if __name__ == "__main__":
    success = asyncio.run(run_migration())
    exit(0 if success else 1)
