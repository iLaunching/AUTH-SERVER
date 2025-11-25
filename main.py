"""
Authentication API Server
Phase 1: Adding database foundation while maintaining backward compatibility
"""

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
from typing import Dict, Optional
from contextlib import asynccontextmanager
import os
import uuid
import structlog

# Phase 1: Import database configuration
from config.database import init_database, init_redis, close_database, check_database_health, check_redis_health, get_db

# Phase 2: Import authentication utilities
from auth.jwt_manager import JWTManager
from auth.password_handler import PasswordHandler

# Phase 2: Import database models
from models.user import User, Session as UserSession, LoginAttempt, UserProfile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

# Import OAuth routes
from routes.oauth_routes import router as oauth_router

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
    first_name: str = None
    last_name: str = None

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class AuthResponse(BaseModel):
    """Response model for authentication (signup/login)"""
    user: dict
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
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

# Include OAuth routes
app.include_router(oauth_router, prefix="/api/v1")

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

# Phase 2: Helper functions
def get_client_ip(request: Request) -> str:
    """Extract client IP from request"""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return "unknown"

def get_device_info(request: Request) -> dict:
    """Extract device information from request"""
    user_agent = request.headers.get("User-Agent", "unknown")
    return {
        "user_agent": user_agent,
        "platform": "web",
    }

async def log_login_attempt(
    db: AsyncSession,
    email: str,
    ip_address: str,
    user_agent: str,
    success: bool,
    failure_reason: Optional[str] = None
):
    """Log a login attempt for security tracking"""
    try:
        login_attempt = LoginAttempt(
            email=email,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            failure_reason=failure_reason
        )
        db.add(login_attempt)
        await db.commit()
        logger.info("Login attempt logged", email=email, success=success)
    except Exception as e:
        logger.error("Failed to log login attempt", error=str(e))
        await db.rollback()

@app.post("/api/v1/auth/check-email", response_model=CheckEmailResponse)
async def check_email(request: CheckEmailRequest):
    """Check if an email exists in the database (Phase 2: Uses database if available)"""
    email = request.email.lower()
    
    # Phase 2: Try database first if available
    if database_available:
        try:
            from config.database import async_session_maker
            if async_session_maker:
                async with async_session_maker() as db:
                    result = await db.execute(
                        select(User).where(User.email == email)
                    )
                    user = result.scalar_one_or_none()
                    
                    if user:
                        logger.info("Email check - exists (database)", email=email)
                        return CheckEmailResponse(
                            exists=True,
                            message="Welcome back! Please enter your password to login."
                        )
                    else:
                        logger.info("Email check - new user (database)", email=email)
                        return CheckEmailResponse(
                            exists=False,
                            message="Welcome! Let's create your account."
                        )
        except Exception as e:
            logger.error("Database email check failed, falling back to in-memory", error=str(e))
            # Fall through to in-memory check
    
    # Phase 1: Fallback to in-memory storage
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

@app.post("/api/v1/auth/signup", response_model=AuthResponse, status_code=201)
async def signup(signup_data: SignupRequest, request: Request):
    """Create new user account (Phase 2: Uses database with password hashing)"""
    email = signup_data.email.lower()
    
    # Phase 2: Database-based signup if available
    if database_available:
        try:
            from config.database import async_session_maker
            from config.database import async_session_maker
            if async_session_maker:
                async with async_session_maker() as db:
                    # Check if user already exists
                    result = await db.execute(
                        select(User).where(User.email == email)
                    )
                    existing_user = result.scalar_one_or_none()
                    
                    if existing_user:
                        logger.warning("Signup attempt with existing email", email=email)
                        raise HTTPException(
                            status_code=400,
                            detail="Email already registered. Please login instead."
                        )
                    
                    # Validate password strength
                    is_valid, errors = PasswordHandler.validate_password_strength(signup_data.password)
                    if not is_valid:
                        logger.info("Signup failed - weak password", errors=errors)
                        raise HTTPException(
                            status_code=400,
                            detail={"message": "Password does not meet requirements", "errors": errors}
                        )
                    
                    # Check for common passwords
                    if PasswordHandler.check_common_passwords(signup_data.password):
                        raise HTTPException(
                            status_code=400,
                            detail="This password is too common. Please choose a more unique password."
                        )
                    
                    # Hash password
                    password_hash = PasswordHandler.hash_password(signup_data.password)
                    
                    # Create user
                    new_user = User(
                        email=email,
                        password_hash=password_hash,
                        first_name=signup_data.first_name,
                        last_name=signup_data.last_name
                    )
                    db.add(new_user)
                    await db.flush()
                    
                    # Create user profile
                    user_profile = UserProfile(user_id=new_user.id)
                    db.add(user_profile)
                    
                    # Create session and tokens
                    ip_address = get_client_ip(request)
                    device_info = get_device_info(request)
                    
                    session = UserSession(
                        user_id=new_user.id,
                        refresh_token_hash="",
                        device_info=device_info,
                        ip_address=ip_address,
                        user_agent=request.headers.get("User-Agent", ""),
                        expires_at=datetime.utcnow() + timedelta(days=30)
                    )
                    db.add(session)
                    await db.flush()
                    
                    # Generate tokens
                    access_token = JWTManager.create_access_token(
                        user_id=str(new_user.id),
                        email=new_user.email,
                        role=new_user.role
                    )
                    refresh_token = JWTManager.create_refresh_token(
                        user_id=str(new_user.id),
                        session_id=str(session.session_id)
                    )
                    
                    # Hash and store refresh token
                    refresh_token_hash = PasswordHandler.hash_password(refresh_token)
                    session.refresh_token_hash = refresh_token_hash
                    
                    # Log successful signup
                    await log_login_attempt(
                        db=db,
                        email=email,
                        ip_address=ip_address,
                        user_agent=request.headers.get("User-Agent", ""),
                        success=True
                    )
                    
                    await db.commit()
                    
                    logger.info("User signup successful (database)", user_id=str(new_user.id), email=email)
                    
                    return AuthResponse(
                        user=new_user.to_dict(),
                        access_token=access_token,
                        refresh_token=refresh_token,
                        message="Account created successfully!"
                    )
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Signup failed", email=email, error=str(e), exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=f"Signup failed: {str(e)}"
            )
    
    # Phase 1: Fallback to in-memory storage
    if email in users_db:
        raise HTTPException(
            status_code=400,
            detail="Email already registered. Please login instead."
        )
    
    if len(signup_data.password) < 8:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 characters long"
        )
    
    user_data = {
        "email": email,
        "first_name": signup_data.first_name or email.split("@")[0],
        "last_name": signup_data.last_name,
        "password": signup_data.password,
        "created_at": datetime.utcnow().isoformat()
    }
    
    users_db[email] = user_data
    
    # Generate simple tokens for in-memory mode
    fake_user_id = str(uuid.uuid4())
    fake_session_id = str(uuid.uuid4())
    access_token = JWTManager.create_access_token(
        user_id=fake_user_id,
        email=email,
        role="user"
    )
    refresh_token = JWTManager.create_refresh_token(
        user_id=fake_user_id,
        session_id=fake_session_id
    )
    
    logger.info("User signup successful (in-memory)", email=email)
    
    return AuthResponse(
        user={
            "email": user_data["email"],
            "name": user_data["name"],
            "created_at": user_data["created_at"]
        },
        access_token=access_token,
        refresh_token=refresh_token,
        message="Account created successfully!"
    )

@app.post("/api/v1/auth/login", response_model=AuthResponse)
async def login(login_data: LoginRequest, request: Request):
    """Login existing user (Phase 2: Uses database with password verification)"""
    email = login_data.email.lower()
    
    # Phase 2: Database-based login if available
    if database_available:
        try:
            from config.database import async_session_maker
            from config.database import async_session_maker
            if async_session_maker:
                async with async_session_maker() as db:
                    ip_address = get_client_ip(request)
                    user_agent = request.headers.get("User-Agent", "")
                    
                    # Find user by email
                    result = await db.execute(
                        select(User).where(User.email == email)
                    )
                    user = result.scalar_one_or_none()
                    
                    if not user:
                        await log_login_attempt(
                            db=db,
                            email=email,
                            ip_address=ip_address,
                            user_agent=user_agent,
                            success=False,
                            failure_reason="email_not_found"
                        )
                        logger.warning("Login failed - email not found", email=email)
                        raise HTTPException(
                            status_code=401,
                            detail="Invalid email or password"
                        )
                    
                    # Verify password
                    is_valid_password = PasswordHandler.verify_password(
                        login_data.password,
                        user.password_hash
                    )
                    
                    if not is_valid_password:
                        await log_login_attempt(
                            db=db,
                            email=email,
                            ip_address=ip_address,
                            user_agent=user_agent,
                            success=False,
                            failure_reason="invalid_password"
                        )
                        logger.warning("Login failed - invalid password", email=email)
                        raise HTTPException(
                            status_code=401,
                            detail="Invalid email or password"
                        )
                    
                    # Update last login
                    user.last_login = datetime.utcnow()
                    
                    # Create new session
                    device_info = get_device_info(request)
                    session = UserSession(
                        user_id=user.id,
                        refresh_token_hash="",
                        device_info=device_info,
                        ip_address=ip_address,
                        user_agent=user_agent,
                        expires_at=datetime.utcnow() + timedelta(days=30)
                    )
                    db.add(session)
                    await db.flush()
                    
                    # Generate tokens
                    access_token = JWTManager.create_access_token(
                        user_id=str(user.id),
                        email=user.email,
                        role=user.role
                    )
                    refresh_token = JWTManager.create_refresh_token(
                        user_id=str(user.id),
                        session_id=str(session.session_id)
                    )
                    
                    # Hash and store refresh token
                    refresh_token_hash = PasswordHandler.hash_password(refresh_token)
                    session.refresh_token_hash = refresh_token_hash
                    
                    # Log successful login
                    await log_login_attempt(
                        db=db,
                        email=email,
                        ip_address=ip_address,
                        user_agent=user_agent,
                        success=True
                    )
                    
                    await db.commit()
                    
                    logger.info("User login successful (database)", user_id=str(user.id), email=email)
                    
                    return AuthResponse(
                        user=user.to_dict(),
                        access_token=access_token,
                        refresh_token=refresh_token,
                        message="Login successful!"
                    )
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Login failed", email=email, error=str(e))
            raise HTTPException(
                status_code=500,
                detail="Login failed. Please try again."
            )
    
    # Phase 1: Fallback to in-memory storage
    if email not in users_db:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )
    
    user = users_db[email]
    
    if user["password"] != login_data.password:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )
    
    # Generate tokens for in-memory mode
    fake_user_id = str(uuid.uuid4())
    fake_session_id = str(uuid.uuid4())
    access_token = JWTManager.create_access_token(
        user_id=fake_user_id,
        email=email,
        role="user"
    )
    refresh_token = JWTManager.create_refresh_token(
        user_id=fake_user_id,
        session_id=fake_session_id
    )
    
    logger.info("User login successful (in-memory)", email=email)
    
    return AuthResponse(
        user={
            "email": user["email"],
            "first_name": user.get("first_name"),
            "last_name": user.get("last_name"),
            "created_at": user["created_at"]
        },
        access_token=access_token,
        refresh_token=refresh_token,
        message="Login successful!"
    )

