# Authentication API

Minimal FastAPI service focused on user authentication.

## Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run server
uvicorn main:app --reload --port 8000
```

Visit http://localhost:8000/docs for API documentation.

## Deploy to Railway

1. Create new Railway project
2. Create new service from GitHub repo
3. Railway will auto-detect the Dockerfile
4. Deploy!

No environment variables required for basic deployment.

## Endpoints

- `GET /` - Service info
- `GET /health` - Health check
- `GET /docs` - Interactive API documentation
- `GET /redoc` - Alternative API documentation

## Project Structure

```
auth-api/
├── main.py           # FastAPI application
├── requirements.txt  # Python dependencies
├── Dockerfile        # Container definition
├── railway.json      # Railway deployment config
└── README.md         # This file
```
