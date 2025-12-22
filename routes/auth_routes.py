"""
Authentication Routes
Handles user signup, login, token refresh, and email checking.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
import structlog

from models.user import User, Session as UserSession, LoginAttempt, UserProfile, UserNavigation, OptionSet, OptionValue
from auth.jwt_manager import JWTManager
from auth.password_handler import PasswordHandler
from config.database import get_db
from config.oauth import OAuthConfig
from services.email_service import email_service

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
    oauth_provider: Optional[str] = None  # e.g., 'google', 'microsoft' if user signed up via OAuth
    
    class Config:
        # Always include fields even when None
        json_schema_extra = {"example": {"exists": True, "message": "Email found", "oauth_provider": None}}

class SignupRequest(BaseModel):
    """Request model for user signup"""
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    account_type: Optional[str] = 'personal'  # 'personal', 'business', or 'education'

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

class CheckEmailSignupRequest(BaseModel):
    """Request model for checking email during signup flow"""
    email: EmailStr
    password: str = Field(..., min_length=8)

class CheckEmailSignupResponse(BaseModel):
    """Response model for email check during signup"""
    action: str  # 'login' or 'signup'
    message: str
    logged_in: bool = False
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    user: Optional[dict] = None

class SendVerificationCodeRequest(BaseModel):
    """Request model for sending verification code"""
    email: EmailStr

class VerifyCodeRequest(BaseModel):
    """Request model for verifying code"""
    email: EmailStr
    code: str = Field(..., min_length=6, max_length=6)

class VerifyCodeResponse(BaseModel):
    """Response model for code verification"""
    verified: bool
    message: str

class AddPasswordRequest(BaseModel):
    """Request model for adding password to OAuth account"""
    password: str = Field(..., min_length=8, max_length=128)

class AddPasswordResponse(BaseModel):
    """Response model for add password"""
    success: bool
    message: str

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

@router.get("/auth/oauth/config")
async def get_oauth_config():
    """
    Get OAuth configuration for client-side OAuth flows.
    Returns public information only (client IDs are safe to expose).
    """
    return {
        "google": {
            "client_id": OAuthConfig.GOOGLE_CLIENT_ID,
            "configured": OAuthConfig.is_google_configured()
        },
        "microsoft": {
            "client_id": OAuthConfig.MICROSOFT_CLIENT_ID,
            "configured": OAuthConfig.is_microsoft_configured()
        }
    }

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
            # Check if user signed up via OAuth
            if user.oauth_provider:
                logger.info("Email check - OAuth user", email=request.email, provider=user.oauth_provider)
                return CheckEmailResponse(
                    exists=True,
                    message=f"This account was created using {user.oauth_provider.title()}. Please sign in with {user.oauth_provider.title()} instead.",
                    oauth_provider=user.oauth_provider
                )
            else:
                logger.info("Email check - exists", email=request.email)
                return CheckEmailResponse(
                    exists=True,
                    message="Email found. Please enter your password to login.",
                    oauth_provider=None
                )
        else:
            logger.info("Email check - new user", email=request.email)
            return CheckEmailResponse(
                exists=False,
                message="Welcome! Let's create your account.",
                oauth_provider=None
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
        
        # Log account type for debugging
        logger.info("Signup request received", email=email, account_type=signup_data.account_type)
        
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
            first_name=signup_data.first_name,
            last_name=signup_data.last_name,
            email_verified=True,  # Mark as verified since they completed email verification
            oauth_provider="iLaunching",
            oauth_provider_id=None,  # Will be set to user.id after flush
            use_password=True  # iLaunching users use password authentication
        )
        db.add(new_user)
        await db.flush()  # Get user ID without committing
        
        # Set oauth_provider_id to user's own ID
        new_user.oauth_provider_id = str(new_user.id)
        
        # Get account type from request (default to personal)
        account_type_value = signup_data.account_type or 'personal'
        logger.info("Looking up account type", account_type_value=account_type_value)
        
        account_type = await db.execute(
            select(OptionValue)
            .join(OptionSet)
            .where(OptionSet.name == 'account_type')
            .where(OptionValue.value_name == account_type_value)
        )
        account_type = account_type.scalar_one_or_none()
        
        logger.info("Account type lookup result", 
                   account_type_id=account_type.id if account_type else None,
                   account_type_value=account_type.value_name if account_type else None)
        
        # Fallback to personal if specified account type not found
        if not account_type:
            account_type = await db.execute(
                select(OptionValue)
                .join(OptionSet)
                .where(OptionSet.name == 'account_type')
                .where(OptionValue.value_name == 'personal')
            )
            account_type = account_type.scalar_one_or_none()
        
        # Create user profile
        user_profile = UserProfile(
            user_id=new_user.id,
            account_type_id=account_type.id if account_type else None
        )
        db.add(user_profile)
        await db.flush()  # Get profile ID
        
        # Create user navigation
        user_navigation = UserNavigation(user_profile_id=user_profile.id)
        db.add(user_navigation)
        await db.flush()  # Get navigation ID
        
        # Link navigation to profile
        user_profile.user_navigation_id = user_navigation.id
        
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
        
        # Reload user with profile relationship eagerly loaded
        result = await db.execute(
            select(User).where(User.id == new_user.id).options(selectinload(User.profile))
        )
        new_user = result.scalar_one()
        
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
        
        # Find user by email with profile loaded
        result = await db.execute(
            select(User).where(User.email == email).options(selectinload(User.profile))
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
        
        # Check if user signed up via OAuth (has no password)
        if user.oauth_provider:
            # Log failed attempt
            await log_login_attempt(
                db=db,
                email=email,
                ip_address=ip_address,
                user_agent=user_agent,
                success=False,
                failure_reason="oauth_user_password_login_blocked"
            )
            logger.warning("Login blocked - OAuth user trying password login", 
                          email=email, 
                          oauth_provider=user.oauth_provider)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"This account was created using {user.oauth_provider.title()}. Please sign in with {user.oauth_provider.title()} instead."
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
        
        # Reload user with profile to ensure fresh data
        result = await db.execute(
            select(User).where(User.id == user.id).options(selectinload(User.profile))
        )
        user = result.scalar_one()
        
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
        if session.expires_at < datetime.now(timezone.utc):
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
        
        # Get user from database with profile eagerly loaded
        result = await db.execute(
            select(User).where(User.id == user_id).options(selectinload(User.profile))
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


# ============================================
# Email Verification Endpoints
# ============================================

@router.post("/auth/check-email-signup", response_model=CheckEmailSignupResponse)
async def check_email_for_signup(
    request_data: CheckEmailSignupRequest,
    req: Request,
    db: AsyncSession = Depends(get_db)
):
    """
    Check if user exists during signup flow.
    If user exists with matching password, log them in.
    If user exists with wrong password, return error.
    If user doesn't exist, proceed with signup.
    """
    try:
        email = request_data.email.lower()
        password = request_data.password
        
        # Check if user exists
        result = await db.execute(
            select(User).where(User.email == email)
        )
        existing_user = result.scalar_one_or_none()
        
        if existing_user:
            # User exists - try to log them in
            if not existing_user.password_hash:
                # OAuth user trying to use password
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"This email is registered with {existing_user.oauth_provider}. Please use that to login."
                )
            
            # Verify password
            if not PasswordHandler.verify_password(password, existing_user.password_hash):
                # Wrong password
                await log_login_attempt(
                    db=db,
                    email=email,
                    ip_address=req.client.host,
                    user_agent=req.headers.get("user-agent", "unknown"),
                    success=False,
                    failure_reason="incorrect_password"
                )
                await db.commit()
                
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect password"
                )
            
            # Password correct - log user in
            access_token = JWTManager.create_access_token(existing_user.id)
            refresh_token = JWTManager.create_refresh_token(existing_user.id)
            
            # Create session
            session = UserSession(
                user_id=existing_user.id,
                refresh_token=refresh_token,
                ip_address=req.client.host,
                user_agent=req.headers.get("user-agent", "unknown")
            )
            db.add(session)
            
            # Log successful login
            await log_login_attempt(
                db=db,
                email=email,
                ip_address=req.client.host,
                user_agent=req.headers.get("user-agent", "unknown"),
                success=True
            )
            
            await db.commit()
            await db.refresh(existing_user)
            
            # Get user profile
            profile_result = await db.execute(
                select(UserProfile).where(UserProfile.user_id == existing_user.id)
            )
            profile = profile_result.scalar_one_or_none()
            
            logger.info("User logged in during signup flow", user_id=existing_user.id, email=email)
            
            return CheckEmailSignupResponse(
                action="login",
                message="Welcome back! Logged in successfully.",
                logged_in=True,
                access_token=access_token,
                refresh_token=refresh_token,
                user={
                    "id": existing_user.id,
                    "email": existing_user.email,
                    "email_verified": existing_user.email_verified,
                    "first_name": profile.first_name if profile else None,
                    "last_name": profile.last_name if profile else None,
                    "created_at": existing_user.created_at.isoformat(),
                }
            )
        
        else:
            # User doesn't exist - proceed with signup
            logger.info("New user starting signup", email=email)
            return CheckEmailSignupResponse(
                action="signup",
                message="Email available. Please verify your email to complete signup.",
                logged_in=False
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to check email for signup", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process request"
        )

@router.post("/auth/send-verification-code")
async def send_verification_code(
    request_data: SendVerificationCodeRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Send a verification code to the user's email.
    Used during signup to verify email ownership.
    """
    try:
        email = request_data.email.lower()
        
        # Check if email already exists
        result = await db.execute(
            select(User).where(User.email == email)
        )
        existing_user = result.scalar_one_or_none()
        
        if existing_user and existing_user.email_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered and verified. Please login instead."
            )
        
        # Generate and store verification code
        code = email_service.generate_verification_code()
        email_service.store_verification_code(email, code, expires_minutes=10)
        
        # Send verification email
        await email_service.send_verification_email(email, code)
        
        logger.info("Verification code sent", email=email)
        
        return {
            "success": True,
            "message": "Verification code sent to your email",
            "expires_in_minutes": 10
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to send verification code", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send verification code"
        )


@router.post("/auth/verify-code", response_model=VerifyCodeResponse)
async def verify_email_code(
    request_data: VerifyCodeRequest
):
    """
    Verify the email verification code.
    Returns success if code is valid and not expired.
    """
    try:
        email = request_data.email.lower()
        code = request_data.code
        
        # Verify the code
        is_valid, error_message = email_service.verify_code(email, code)
        
        if not is_valid:
            logger.warning("Verification code invalid", email=email, error=error_message)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error_message
            )
        
        logger.info("Email verified successfully", email=email)
        
        return VerifyCodeResponse(
            verified=True,
            message="Email verified successfully"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to verify code", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify code"
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


@router.post("/auth/add-password", response_model=AddPasswordResponse)
async def add_password(
    request_data: AddPasswordRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Add password to OAuth user account.
    Allows OAuth users to add password authentication as a backup login method.
    """
    try:
        # Check if user already has a password
        if current_user.use_password:
            logger.warning("User already has password", user_id=str(current_user.id))
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Account already has password authentication enabled"
            )
        
        # Hash the new password
        password_hash = PasswordHandler.hash_password(request_data.password)
        
        # Update user record
        current_user.password_hash = password_hash
        current_user.use_password = True
        
        await db.commit()
        await db.refresh(current_user)
        
        logger.info("Password added to OAuth account", user_id=str(current_user.id))
        
        return AddPasswordResponse(
            success=True,
            message="Password added successfully. You can now sign in with either method."
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to add password", user_id=str(current_user.id), error=str(e))
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to add password to account"
        )


@router.patch("/profile/onboarding")
async def update_onboarding_status(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Mark user's onboarding as completed.
    Called by api-server after successful Smart Hub/Matrix creation.
    """
    try:
        # Get or create user profile
        if not current_user.profile:
            profile = UserProfile(
                user_id=current_user.id,
                onboarding_completed=True
            )
            db.add(profile)
        else:
            current_user.profile.onboarding_completed = True
        
        await db.commit()
        await db.refresh(current_user)
        
        logger.info("Onboarding status updated", user_id=str(current_user.id))
        
        return {
            "success": True,
            "message": "Onboarding status updated",
            "onboarding_completed": True
        }
        
    except Exception as e:
        logger.error("Failed to update onboarding status", user_id=str(current_user.id), error=str(e))
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Failed to update onboarding status"
        )
