# Railway Environment Variables for AUTH-SERVER

## Required Variables (Copy from API-SERVER)

Add these environment variables to your AUTH-SERVER Railway service:

### Database & Cache
```bash
DATABASE_URL="postgresql://postgres:TVzCDcmIDhjbquUUbrUMQExHEfXIwiNm@tramway.proxy.rlwy.net:12050/railway"
REDIS_URL="redis://default:YtfvDgmjvFQXKUVVXJCscNRSbQxtumLz@shinkansen.proxy.rlwy.net:58472"
```

### JWT Configuration
```bash
JWT_SECRET_KEY="fgN9zdVoZGRbZNXXzE0cPt2vLn1_H2_E82lqFjrhPq51FV02oXksUDeklrPY30AIuKpSYsqKc0fRiI8xaGjjXQ"
ACCESS_TOKEN_EXPIRE_MINUTES="15"
REFRESH_TOKEN_EXPIRE_DAYS="30"
```

### Server Configuration
```bash
ENVIRONMENT="production"
HOST="0.0.0.0"
PORT="8000"
LOG_LEVEL="INFO"
```

### CORS Origins
```bash
ALLOWED_ORIGINS="http://localhost:5174,https://ubiquitous-giggle-4jpgpj799pvv3w97-5174.app.github.dev"
```

## How to Add Variables in Railway

### Method 1: Bulk Add (Recommended)
1. Go to Railway project → AUTH-SERVER service
2. Click **"Variables"** tab
3. Click **"RAW Editor"** button (top right)
4. Paste all variables in format: `KEY=value` (one per line)
5. Click **"Update Variables"**

### Method 2: Individual Add
1. Go to Railway project → AUTH-SERVER service
2. Click **"Variables"** tab
3. Click **"+ New Variable"**
4. Enter name and value
5. Repeat for each variable

## Verification

After adding variables and redeployment, check health:

```bash
curl https://auth-server-production-b51c.up.railway.app/health
```

Expected output:
```json
{
  "status": "healthy",
  "version": "1.1.0-phase1",
  "database_mode": "persistent",
  "database": {
    "status": "healthy",
    "type": "postgresql"
  },
  "redis": {
    "status": "healthy"
  }
}
```

## Notes

- **Same DATABASE_URL**: Auth and API servers share the same PostgreSQL database
- **Same REDIS_URL**: Auth and API servers share the same Redis instance
- **Same JWT_SECRET_KEY**: Critical for token compatibility between services
- **ALLOWED_ORIGINS**: Update with your production frontend domain when deployed

## What This Enables

✅ Persistent user storage (survives restarts)
✅ Redis caching for sessions and rate limiting
✅ JWT tokens work across auth-api and api-server
✅ Shared database schema (users, sessions, profiles)
✅ Production-ready security
