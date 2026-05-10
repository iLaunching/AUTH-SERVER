"""
Run migration 015 - country_code on phone_identities & phone_verification_attempts
"""
import asyncio
import asyncpg
import os
from pathlib import Path


async def run_migration():
    database_url = os.getenv("DATABASE_URL")

    if not database_url:
        print("ERROR: DATABASE_URL environment variable not set")
        return False

    if database_url.startswith("postgresql+asyncpg://"):
        database_url = database_url.replace("postgresql+asyncpg://", "postgresql://")

    print("Connecting to database...")

    try:
        conn = await asyncpg.connect(database_url)

        migration_file = Path(__file__).parent / "015_country_code_identity_attempts.sql"
        with open(migration_file, "r") as f:
            sql = f.read()

        print("Running migration 015_country_code_identity_attempts...")
        await conn.execute(sql)

        print("Migration completed successfully.")

        for table in ("phone_identities", "phone_verification_attempts"):
            rows = await conn.fetch(
                """
                SELECT column_name, data_type, is_nullable
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = $1
                  AND column_name = 'country_code';
                """,
                table,
            )
            if rows:
                r = rows[0]
                print(
                    f"  {table}.country_code: {r['data_type']}, nullable={r['is_nullable']}"
                )
            else:
                print(f"  WARNING: country_code not found on {table} (table missing?)")

        await conn.close()
        return True

    except Exception as e:
        print(f"Migration failed: {e}")
        return False


if __name__ == "__main__":
    success = asyncio.run(run_migration())
    raise SystemExit(0 if success else 1)
