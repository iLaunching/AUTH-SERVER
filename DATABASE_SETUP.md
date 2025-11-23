# AUTH-SERVER Database Setup for Railway

## Quick Setup Steps

### 1. Add PostgreSQL Database to Railway Project

1. Go to your Railway project: https://railway.app/project/auth-server-production-b51c
2. Click **"+ New"** button
3. Select **"Database"** → **"Add PostgreSQL"**
4. Railway will create a new PostgreSQL service

### 2. Link Database to Auth Service

1. Click on your **auth-api service**
2. Go to **"Variables"** tab
3. Click **"+ New Variable"** → **"Reference"**
4. Select your PostgreSQL database
5. Choose **DATABASE_URL** from the dropdown
6. Click **"Add"**

Railway will automatically:
- Connect the services
- Set the `DATABASE_URL` environment variable
- Redeploy your auth service

### 3. Verify Database Connection

After redeployment (takes ~2 minutes), check the health endpoint:

```bash
curl https://auth-server-production-b51c.up.railway.app/health
```

You should see:
```json
{
  "status": "healthy",
  "version": "1.1.0-phase1",
  "database_mode": "persistent",
  "database": {
    "status": "connected",
    "type": "postgresql"
  }
}
```

### 4. Test User Creation

```bash
# Create a new user (stored in PostgreSQL)
curl -X POST https://auth-server-production-b51c.up.railway.app/api/v1/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123",
    "name": "Production User"
  }'
```

This user will persist across server restarts!

## Alternative: Manual DATABASE_URL Setup

If you prefer to manually add the DATABASE_URL:

1. Get the PostgreSQL connection URL from the database service
2. Add it as a variable in your auth service:
   ```
   DATABASE_URL=postgresql+asyncpg://user:pass@host:port/dbname
   ```

## Redis Setup (Optional)

For caching and session management:

1. Click **"+ New"** → **"Database"** → **"Add Redis"**
2. Link to auth service with variable name **REDIS_URL**

## What Happens After Setup

✅ Users stored in PostgreSQL (persistent)
✅ Sessions stored in database
✅ Passwords securely hashed with bcrypt
✅ JWT tokens with refresh capability
✅ Login attempts logged
✅ User profiles with theme preferences

## Database Schema

The app will auto-create these tables on first connection:

- **users** - User accounts (email, password_hash, name, role)
- **user_profiles** - User preferences (phone, avatar, theme)
- **sessions** - Active sessions (refresh tokens, device info)
- **login_attempts** - Security audit log

## Environment Variables Summary

Required for production:
- `DATABASE_URL` - PostgreSQL connection string (Railway provides this)

Optional:
- `REDIS_URL` - Redis connection string (for caching)
- `JWT_SECRET_KEY` - Custom JWT secret (default provided)
- `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` - Token expiry (default: 15)
- `JWT_REFRESH_TOKEN_EXPIRE_DAYS` - Refresh token expiry (default: 30)

---

**Next Step**: Go to Railway dashboard and add PostgreSQL to your project!
