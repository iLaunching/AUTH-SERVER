"""
Authentication Routes
Handles user signup, login, token refresh, and email checking.
"""

from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import structlog

from models.user import User, Session as UserSession, LoginAttempt, UserProfile
from auth.jwt_manager import JWTManager
from auth.password_handler import PasswordHandler
from config.database import get_db

logger = structlog.get_logger()
router = APIRouter()
security = HTTPBearer()

# ============================================
# Request/Response Models
# ============================================

class CheckEmailRequest(BaseModel):
    """Request model for checking if email exists"""
    email: EmailStr

class CheckEmailResponse(BaseModel):
    """Response model for email check"""
    exists: bool
    message: str

class SignupRequest(BaseModel):
    """Request model for user signup"""
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    name: Optional[str] = None

class LoginRequest(BaseModel):
    """Request model for user login"""
    email: EmailStr
    password: str

class AuthResponse(BaseModel):
    """Response model for authentication (signup/login)"""
    user: dict
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"

class RefreshTokenRequest(BaseModel):
    """Request model for token refresh"""
    refresh_token: str

class TokenResponse(BaseModel):
    """Response model for token refresh"""
    access_token: str
    token_type: str = "Bearer"

# ============================================
# Helper Functions
# ============================================

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

def get_client_ip(request: Request) -> str:
    """Extract client IP from request"""
    # Check for X-Forwarded-For header (when behind proxy/load balancer)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    
    # Fallback to direct client
    if request.client:
        return request.client.host
    
    return "unknown"

def get_device_info(request: Request) -> dict:
    """Extract device information from request"""
    user_agent = request.headers.get("User-Agent", "unknown")
    return {
        "user_agent": user_agent,
        "platform": "web",  # Could parse user agent for more details
    }

# ============================================
# Authentication Routes
# ============================================

@router.post("/auth/check-email", response_model=CheckEmailResponse)
async def check_email(
    request: CheckEmailRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Check if an email exists in the database.
    Used by frontend to determine if user should login or signup.
    """
    try:
        # Query database for user with this email
        result = await db.execute(
            select(User).where(User.email == request.email.lower())
        )
        user = result.scalar_one_or_none()
        
        if user:
            logger.info("Email check - exists", email=request.email)
            return CheckEmailResponse(
                exists=True,
                message="Email found. Please enter your password to login."
            )
        else:
            logger.info("Email check - new user", email=request.email)
            return CheckEmailResponse(
                exists=False,
                message="Welcome! Let's create your account."
            )
            
    except Exception as e:
        logger.error("Email check failed", email=request.email, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to check email"
        )

@router.post("/auth/signup", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
async def signup(
    signup_data: SignupRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """
    Register a new user account.
    Creates user, generates tokens, and returns authentication credentials.
    """
    try:
        email = signup_data.email.lower()
        
        # Check if user already exists
        result = await db.execute(
            select(User).where(User.email == email)
        )
        existing_user = result.scalar_one_or_none()
        
        if existing_user:
            logger.warning("Signup attempt with existing email", email=email)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered. Please login instead."
            )
        
        # Validate password strength
        is_valid, errors = PasswordHandler.validate_password_strength(signup_data.password)
        if not is_valid:
            logger.info("Signup failed - weak password", errors=errors)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "Password does not meet requirements", "errors": errors}
            )
        
        # Check for common passwords
        if PasswordHandler.check_common_passwords(signup_data.password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This password is too common. Please choose a more unique password."
            )
        
        # Hash password
        password_hash = PasswordHandler.hash_password(signup_data.password)
        
        # Create user
        new_user = User(
            email=email,
            password_hash=password_hash,
            name=signup_data.name
        )
        db.add(new_user)
        await db.flush()  # Get user ID without committing
        
        # Create user profile
        user_profile = UserProfile(
            user_id=new_user.id
        )
        db.add(user_profile)
        
        # Create session and tokens
        ip_address = get_client_ip(request)
        device_info = get_device_info(request)
        
        session = UserSession(
            user_id=new_user.id,
            refresh_token_hash="",  # Will be updated below
            device_info=device_info,
            ip_address=ip_address,
            user_agent=request.headers.get("User-Agent", ""),
            expires_at=datetime.utcnow() + timedelta(days=30)
        )
        db.add(session)
        await db.flush()  # Get session ID
        
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
        
        # Commit all changes
        await db.commit()
        
        logger.info("User signup successful", user_id=str(new_user.id), email=email)
        
        return AuthResponse(
            user=new_user.to_dict(),
            access_token=access_token,
            refresh_token=refresh_token
        )
        
    except HTTPException:
        await db.rollback()
        raise
    except Exception as e:
        await db.rollback()
        logger.error("Signup failed", email=signup_data.email, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Signup failed. Please try again."
        )

@router.post("/auth/login", response_model=AuthResponse)
async def login(
    login_data: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """
    Login existing user.
    Validates credentials and returns authentication tokens.
    """
    try:
        email = login_data.email.lower()
        ip_address = get_client_ip(request)
        user_agent = request.headers.get("User-Agent", "")
        
        # Find user by email
        result = await db.execute(
            select(User).where(User.email == email)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            # Log failed attempt
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
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        # Verify password
        is_valid_password = PasswordHandler.verify_password(
            login_data.password,
            user.password_hash
        )
        
        if not is_valid_password:
            # Log failed attempt
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
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        # Update last login
        user.last_login = datetime.utcnow()
        
        # Create new session
        device_info = get_device_info(request)
        session = UserSession(
            user_id=user.id,
            refresh_token_hash="",  # Will be updated below
            device_info=device_info,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=datetime.utcnow() + timedelta(days=30)
        )
        db.add(session)
        await db.flush()  # Get session ID
        
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
        
        # Commit all changes
        await db.commit()
        
        logger.info("User login successful", user_id=str(user.id), email=email)
        
        return AuthResponse(
            user=user.to_dict(),
            access_token=access_token,
            refresh_token=refresh_token
        )
        
    except HTTPException:
        await db.rollback()
        raise
    except Exception as e:
        await db.rollback()
        logger.error("Login failed", email=login_data.email, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed. Please try again."
        )

@router.post("/auth/refresh", response_model=TokenResponse)
async def refresh_access_token(
    refresh_data: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Refresh access token using refresh token.
    Validates refresh token and generates new access token.
    """
    try:
        # Verify refresh token
        payload = JWTManager.verify_refresh_token(refresh_data.refresh_token)
        
        if not payload:
            logger.warning("Invalid refresh token")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token"
            )
        
        user_id = payload.get("sub")
        session_id = payload.get("session_id")
        
        # Verify session exists and is not revoked
        result = await db.execute(
            select(UserSession).where(
                UserSession.session_id == session_id,
                UserSession.revoked == False
            )
        )
        session = result.scalar_one_or_none()
        
        if not session:
            logger.warning("Session not found or revoked", session_id=session_id)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired or revoked"
            )
        
        # Check if session expired
        if session.expires_at < datetime.utcnow():
            logger.warning("Session expired", session_id=session_id)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired"
            )
        
        # Verify refresh token hash matches
        if not PasswordHandler.verify_password(refresh_data.refresh_token, session.refresh_token_hash):
            logger.warning("Refresh token hash mismatch", session_id=session_id)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        # Get user
        result = await db.execute(
            select(User).where(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            logger.error("User not found for valid session", user_id=user_id)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )
        
        # Generate new access token
        access_token = JWTManager.create_access_token(
            user_id=str(user.id),
            email=user.email,
            role=user.role
        )
        
        # Update session last accessed
        session.last_accessed = datetime.utcnow()
        await db.commit()
        
        logger.info("Access token refreshed", user_id=user_id, session_id=session_id)
        
        return TokenResponse(
            access_token=access_token
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Token refresh failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh failed"
        )

@router.post("/auth/logout")
async def logout(
    refresh_data: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Logout user by revoking refresh token session.
    """
    try:
        # Verify refresh token
        payload = JWTManager.verify_refresh_token(refresh_data.refresh_token)
        
        if payload:
            session_id = payload.get("session_id")
            
            # Revoke session
            result = await db.execute(
                select(UserSession).where(UserSession.session_id == session_id)
            )
            session = result.scalar_one_or_none()
            
            if session:
                session.revoked = True
                session.revoked_at = datetime.utcnow()
                await db.commit()
                
                logger.info("User logged out", session_id=session_id)
        
        return {"message": "Logged out successfully"}
        
    except Exception as e:
        await db.rollback()
        logger.error("Logout failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )

# ============================================
# Protected Route Example
# ============================================

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    Dependency to get current authenticated user from access token.
    Use this as a dependency in protected routes.
    """
    try:
        token = credentials.credentials
        
        # Verify access token
        payload = JWTManager.verify_access_token(token)
        
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        user_id = payload.get("sub")
        
        # Get user from database
        result = await db.execute(
            select(User).where(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        return user
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get current user", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Bearer"}
        )

@router.get("/auth/me")
async def get_me(
    current_user: User = Depends(get_current_user)
):
    """
    Get current authenticated user information.
    Protected route example.
    """
    return {
        "user": current_user.to_dict(),
        "message": "Authenticated successfully"
    }
