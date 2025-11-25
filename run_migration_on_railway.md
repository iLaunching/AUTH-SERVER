# Run OAuth Migration on Railway

## Option 1: Using Railway CLI (Recommended)

```bash
# Install Railway CLI if not already installed
npm i -g @railway/cli

# Login to Railway
railway login

# Link to your project
railway link

# Run the migration
railway run python migrations/run_007_migration.py
```

## Option 2: Using Railway Web Interface

1. Go to your Railway project: https://railway.app
2. Select your auth-api service
3. Go to the "Settings" tab
4. Scroll to "One-off Commands"
5. Run this command:
   ```
   python migrations/run_007_migration.py
   ```

## Option 3: Temporary - Add to Startup (Auto-run once)

You can temporarily modify the startCommand in `railway.json` to run the migration on startup:

```json
{
  "build": {
    "builder": "NIXPACKS"
  },
  "deploy": {
    "startCommand": "python migrations/run_007_migration.py && uvicorn main:app --host 0.0.0.0 --port 8000",
    "restartPolicyType": "ON_FAILURE",
    "restartPolicyMaxRetries": 10
  }
}
```

**Important:** After the migration runs successfully once, change it back to:
```json
{
  "build": {
    "builder": "NIXPACKS"
  },
  "deploy": {
    "startCommand": "uvicorn main:app --host 0.0.0.0 --port 8000",
    "restartPolicyType": "ON_FAILURE",
    "restartPolicyMaxRetries": 10
  }
}
```

## Verify Migration

After running, verify the columns exist by checking the logs. You should see:

```
✅ Migration completed successfully!

Verified columns:
  - oauth_provider: character varying (nullable: YES)
  - oauth_provider_id: character varying (nullable: YES)
  - password_hash: character varying (nullable: YES)
```
