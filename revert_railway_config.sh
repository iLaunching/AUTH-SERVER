#!/bin/bash
# Remove migration from Railway startup command after it runs successfully

cd /workspaces/Ilaunching-SERVERS/auth-api

# Revert railway.json to normal startup
cat > railway.json << 'EOF'
{
  "$schema": "https://railway.app/railway.schema.json",
  "build": {
    "builder": "NIXPACKS"
  },
  "deploy": {
    "numReplicas": 1,
    "restartPolicyType": "ON_FAILURE",
    "startCommand": "uvicorn main:app --host 0.0.0.0 --port 8000"
  }
}
EOF

git add railway.json
git commit -m "chore: Remove migration from startup after successful run"
git push origin main

echo "✅ Railway config reverted. Migration will not run on next deploy."
