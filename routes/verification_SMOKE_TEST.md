## Step-by-step integration + test plan (Auth API)

This module is **feature-flagged**. Until enabled, endpoints return 404.

### 0) Enable the feature flag (local or Railway)

Set:
- `VERIFICATION_ENABLED=true`

### 1) Run DB migration

Apply:
- `migrations/009_verified_identities.sql`

On Railway you can run it via `psql` against `DATABASE_URL`.

### 2) Ensure Redis is configured

Set:
- `REDIS_URL=...`

### 3) Configure Vonage

Set:
- `VONAGE_API_KEY=...`
- `VONAGE_API_SECRET=...`
- `VONAGE_WEBHOOK_SECRET=...` (random hex)
- `VONAGE_BRAND_NAME=iLaunching` (optional)

Webhook URL to set in Vonage:
- `/api/v1/webhooks/vonage/verify`

### 4) Smoke test (no Vonage yet)

Start Auth API, then hit:
- `GET /api/v1/verify/status` (with Bearer access token)

Expected response for new users:
- `{ "verified": false }`

### 5) Smoke test (start verification)

Call:
- `POST /api/v1/verify/start`

Body:
```json
{ "phone_number": "+447911123456", "region": "GB" }
```

Expected:
- `status=pending`, `request_id=...`
- `channel` is `silent_auth` if `check_url` present else `sms`

### 6) Silent Auth path

If response includes `check_url`, the mobile app should GET it **over cellular**.
Vonage should then POST webhook → server will mark user verified with `HIGH`.

### 7) SMS fallback path

If no `check_url`, you’ll receive an OTP by SMS and then call:
- `POST /api/v1/verify/check`

Body:
```json
{ "request_id": "<request_id>", "code": "123456" }
```

Expected:
- `{ "status": "verified", "trust_level": "MED" }`

