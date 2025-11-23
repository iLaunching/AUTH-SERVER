"""
Authentication API Server
Phase 1: Adding database foundation while maintaining backward compatibility
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Dict, Optional
from contextlib import asynccontextmanager
import os
import structlog

# Phase 1: Import database configuration
from config.database import init_database, init_redis, close_database, check_database_health, check_redis_health

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

logger = structlog.get_logger()

# In-memory user storage (Phase 1: Keep for backward compatibility, Phase 2: Remove)
users_db: Dict[str, dict] = {}

# Global flag to track if database is available
database_available = False

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle management"""
    global database_available
    
    # Startup
    logger.info("Starting Auth API server...")
    
    # Phase 1: Try to initialize database (graceful fallback if not available)
    try:
        database_available = await init_database()
        if database_available:
            logger.info("Database initialized successfully")
        else:
            logger.warning("Running without database - using in-memory storage")
    except Exception as e:
        logger.error("Database initialization failed", error=str(e))
        database_available = False
    
    # Phase 1: Try to initialize Redis (graceful fallback if not available)
    try:
        await init_redis()
        logger.info("Redis initialized successfully")
    except Exception as e:
        logger.warning("Redis initialization failed - continuing without cache", error=str(e))
    
    yield
    
    # Shutdown
    logger.info("Shutting down Auth API server...")
    await close_database()

# Pydantic models
class CheckEmailRequest(BaseModel):
    email: EmailStr

class CheckEmailResponse(BaseModel):
    exists: bool
    message: str

class SignupRequest(BaseModel):
    email: EmailStr
    password: str
    name: str = None

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class AuthResponse(BaseModel):
    user: dict
    message: str

# Create FastAPI app with lifecycle management
app = FastAPI(
    title="Authentication API",
    description="Authentication service with database support",
    version="1.1.0-phase1",
    lifespan=lifespan
)

# CORS - allow all origins for now
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "Authentication API",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "health": "/health",
            "docs": "/docs",
            "auth": {
                "check_email": "POST /api/v1/auth/check-email",
                "signup": "POST /api/v1/auth/signup",
                "login": "POST /api/v1/auth/login"
            }
        }
    }

@app.get("/health")
async def health():
    """Health check endpoint with database and Redis status"""
    health_status = {
        "status": "healthy",
        "service": "auth-api",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.1.0-phase1",
        "users_count": len(users_db),
        "database_mode": "database" if database_available else "in-memory"
    }
    
    # Check database health
    try:
        db_health = await check_database_health()
        health_status["database"] = db_health
        if db_health["status"] == "unhealthy":
            health_status["status"] = "degraded"
    except Exception as e:
        health_status["database"] = {"status": "error", "message": str(e)}
        health_status["status"] = "degraded"
    
    # Check Redis health
    try:
        redis_health = await check_redis_health()
        health_status["redis"] = redis_health
    except Exception as e:
        health_status["redis"] = {"status": "error", "message": str(e)}
    
    logger.info("Health check performed", **health_status)
    return health_status

@app.post("/api/v1/auth/check-email", response_model=CheckEmailResponse)
async def check_email(request: CheckEmailRequest):
    """Check if email exists in system"""
    email = request.email.lower()
    exists = email in users_db
    
    if exists:
        return CheckEmailResponse(
            exists=True,
            message="Welcome back! Please enter your password to login."
        )
    else:
        return CheckEmailResponse(
            exists=False,
            message="Welcome! Let's create your account."
        )

@app.post("/api/v1/auth/signup", response_model=AuthResponse)
async def signup(request: SignupRequest):
    """Create new user account"""
    email = request.email.lower()
    
    # Check if user already exists
    if email in users_db:
        raise HTTPException(
            status_code=400,
            detail="Email already registered. Please login instead."
        )
    
    # Basic password validation
    if len(request.password) < 8:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 characters long"
        )
    
    # Create user (storing plain password for now - will hash later)
    user_data = {
        "email": email,
        "name": request.name or email.split("@")[0],
        "password": request.password,  # TODO: Hash this
        "created_at": datetime.utcnow().isoformat()
    }
    
    users_db[email] = user_data
    
    # Return user without password
    return AuthResponse(
        user={
            "email": user_data["email"],
            "name": user_data["name"],
            "created_at": user_data["created_at"]
        },
        message="Account created successfully!"
    )

@app.post("/api/v1/auth/login", response_model=AuthResponse)
async def login(request: LoginRequest):
    """Login existing user"""
    email = request.email.lower()
    
    # Check if user exists
    if email not in users_db:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )
    
    user = users_db[email]
    
    # Check password (plain text for now - will add hashing later)
    if user["password"] != request.password:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )
    
    # Return user without password
    return AuthResponse(
        user={
            "email": user["email"],
            "name": user["name"],
            "created_at": user["created_at"]
        },
        message="Login successful!"
    )

