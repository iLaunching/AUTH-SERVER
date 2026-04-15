"""
OAuth Routes
Handles OAuth authentication endpoints for Google, Facebook, etc.
"""

from fastapi import APIRouter, HTTPException, Request, Depends
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional
import secrets
import structlog

from services.oauth_service import oauth_service
from config.oauth import OAuthConfig
from config.database import get_db, async_session_maker
from auth.jwt_manager import JWTManager
from auth.token_claims import synapse_claims_for_user_id
from auth.password_handler import PasswordHandler
from models.user import Session as UserSession

logger = structlog.get_logger()

router = APIRouter(prefix="/auth", tags=["OAuth Authentication"])

# Store state tokens temporarily (in production, use Redis)
# state -> {'created_at': timestamp, 'redirect_uri': optional_frontend_url}
oauth_states = {}


def generate_state() -> str:
    """Generate a random state token for CSRF protection"""
    return secrets.token_urlsafe(32)


def validate_state(state: str) -> bool:
    """Validate that a state token exists and hasn't expired"""
    if state not in oauth_states:
        return False
    
    # States expire after 10 minutes
    state_data = oauth_states[state]
    created_at = state_data['created_at']
    if datetime.utcnow() - created_at > timedelta(minutes=10):
        del oauth_states[state]
        return False
    
    return True


def cleanup_expired_states():
    """Remove expired state tokens"""
    now = datetime.utcnow()
    expired = [
        state for state, data in oauth_states.items()
        if now - data['created_at'] > timedelta(minutes=10)
    ]
    for state in expired:
        del oauth_states[state]


# ============================================
# Google OAuth Endpoints
# ============================================

@router.get("/google/login")
async def google_login(request: Request, redirect_url: Optional[str] = None):
    """
    Initiate Google OAuth login flow
    
    Query params:
        redirect_url: Optional frontend URL to redirect to after authentication
    
    Returns redirect to Google's OAuth consent page
    """
    if not OAuthConfig.is_google_configured():
        raise HTTPException(
            status_code=503,
            detail="Google OAuth is not configured on the server"
        )
    
    # Generate state for CSRF protection
    state = generate_state()
    oauth_states[state] = {
        'created_at': datetime.utcnow(),
        'redirect_url': redirect_url or OAuthConfig.FRONTEND_URL
    }
    
    # Clean up old states
    cleanup_expired_states()
    
    # Generate authorization URL
    try:
        auth_url = oauth_service.get_google_auth_url(
            redirect_uri=OAuthConfig.GOOGLE_REDIRECT_URI,
            state=state
        )
        
        logger.info("Initiating Google OAuth login", state=state)
        return RedirectResponse(url=auth_url)
        
    except Exception as e:
        logger.error("Failed to generate Google auth URL", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to initiate Google login")


@router.get("/google/callback")
async def google_callback(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None
):
    """
    Handle Google OAuth callback
    
    Query params:
        code: Authorization code from Google
        state: State token for CSRF protection
        error: Error message if authentication failed
    
    Returns redirect to frontend with tokens or error
    """
    # Check for OAuth errors
    if error:
        logger.warning("Google OAuth error", error=error)
        redirect_url = f"{OAuthConfig.FRONTEND_URL}?auth_error={error}"
        return RedirectResponse(url=redirect_url)
    
    # Validate required parameters
    if not code or not state:
        logger.warning("Missing code or state in Google callback")
        redirect_url = f"{OAuthConfig.FRONTEND_URL}?auth_error=missing_parameters"
        return RedirectResponse(url=redirect_url)
    
    # Validate state token
    if not validate_state(state):
        logger.warning("Invalid or expired state token", state=state)
        redirect_url = f"{OAuthConfig.FRONTEND_URL}?auth_error=invalid_state"
        return RedirectResponse(url=redirect_url)
    
    # Get the redirect URL from state
    state_data = oauth_states.pop(state)
    frontend_redirect = state_data['redirect_url']
    
    try:
        # Exchange code for tokens
        token_response = await oauth_service.exchange_google_code(
            code=code,
            redirect_uri=OAuthConfig.GOOGLE_REDIRECT_URI
        )
        
        access_token = token_response.get('access_token')
        if not access_token:
            raise ValueError("No access token in response")
        
        # Get user info from Google
        google_user = await oauth_service.get_google_user_info(access_token)
        
        # Extract user information
        email = google_user.get('email')
        google_id = google_user.get('sub')
        first_name = google_user.get('given_name')
        last_name = google_user.get('family_name')
        picture = google_user.get('picture')
        hd = google_user.get('hd')  # Hosted domain for Google Workspace accounts
        
        if not email or not google_id:
            raise ValueError("Missing required user information from Google")
        
        # Determine account type based on hd parameter or email domain
        account_type_value = 'personal'
        if hd:  # Google Workspace account
            account_type_value = 'business'
            logger.info("Detected Google Workspace account", email=email, domain=hd)
        elif not email.endswith('@gmail.com'):  # Custom domain but not gmail
            account_type_value = 'business'
            logger.info("Detected custom domain email", email=email)
        
        # Process user (create or get existing)
        db = None
        user_dict = None
        is_new_user = False
        
        if async_session_maker:
            async with async_session_maker() as db:
                user_dict, is_new_user = await oauth_service.process_oauth_user(
                    provider='google',
                    provider_user_id=google_id,
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    picture=picture,
                    account_type=account_type_value,
                    db=db
                )
                
                # Create session and generate JWT tokens
                ip_address = request.headers.get("X-Forwarded-For", "unknown")
                user_agent = request.headers.get("User-Agent", "")
                
                session = UserSession(
                    user_id=user_dict['id'],
                    refresh_token_hash="",
                    device_info={'user_agent': user_agent, 'platform': 'web'},
                    ip_address=ip_address,
                    user_agent=user_agent,
                    expires_at=datetime.utcnow() + timedelta(days=30)
                )
                db.add(session)
                await db.flush()
                
                # Generate JWT tokens
                extra = await synapse_claims_for_user_id(db, user_dict["id"])
                jwt_access_token = JWTManager.create_access_token(
                    user_id=str(user_dict['id']),
                    email=email,
                    role=user_dict.get('role', 'user'),
                    extra_claims=extra,
                )
                jwt_refresh_token = JWTManager.create_refresh_token(
                    user_id=str(user_dict['id']),
                    session_id=str(session.session_id)
                )
                
                # Hash and store refresh token
                refresh_token_hash = PasswordHandler.hash_password(jwt_refresh_token)
                session.refresh_token_hash = refresh_token_hash
                
                await db.commit()
        else:
            # Fallback to in-memory mode
            user_dict, is_new_user = await oauth_service.process_oauth_user(
                provider='google',
                provider_user_id=google_id,
                email=email,
                first_name=first_name,
                last_name=last_name,
                picture=picture,
                db=None
            )
            
            # Generate simple tokens for in-memory mode
            jwt_access_token = JWTManager.create_access_token(
                user_id=google_id,
                email=email,
                role='user'
            )
            jwt_refresh_token = JWTManager.create_refresh_token(
                user_id=google_id,
                session_id=secrets.token_urlsafe(16)
            )
        
        # Redirect to frontend with tokens
        action = 'signup' if is_new_user else 'login'
        redirect_url = (
            f"{frontend_redirect}?auth_success=true"
            f"&access_token={jwt_access_token}"
            f"&refresh_token={jwt_refresh_token}"
            f"&action={action}"
            f"&provider=google"
        )
        
        logger.info(
            "Google OAuth successful",
            email=email,
            is_new_user=is_new_user
        )
        
        return RedirectResponse(url=redirect_url)
        
    except Exception as e:
        error_type = type(e).__name__
        error_detail = str(e)
        logger.error("Google OAuth callback failed", 
                    error_type=error_type,
                    error=error_detail, 
                    exc_info=True)
        # Include more specific error in redirect for debugging
        redirect_url = f"{frontend_redirect}?auth_error=authentication_failed&error_detail={error_type}"
        return RedirectResponse(url=redirect_url)


# ============================================
# Facebook OAuth Endpoints
# ============================================

@router.get("/facebook/login")
async def facebook_login(request: Request, redirect_url: Optional[str] = None):
    """
    Initiate Facebook OAuth login flow
    
    Query params:
        redirect_url: Optional frontend URL to redirect to after authentication
    
    Returns redirect to Facebook's OAuth consent page
    """
    if not OAuthConfig.is_facebook_configured():
        raise HTTPException(
            status_code=503,
            detail="Facebook OAuth is not configured on the server"
        )
    
    # Generate state for CSRF protection
    state = generate_state()
    oauth_states[state] = {
        'created_at': datetime.utcnow(),
        'redirect_url': redirect_url or OAuthConfig.FRONTEND_URL
    }
    
    # Clean up old states
    cleanup_expired_states()
    
    # Generate authorization URL
    try:
        auth_url = oauth_service.get_facebook_auth_url(
            redirect_uri=OAuthConfig.FACEBOOK_REDIRECT_URI,
            state=state
        )
        
        logger.info("Initiating Facebook OAuth login", state=state)
        return RedirectResponse(url=auth_url)
        
    except Exception as e:
        logger.error("Failed to generate Facebook auth URL", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to initiate Facebook login")


@router.get("/facebook/callback")
async def facebook_callback(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None
):
    """
    Handle Facebook OAuth callback
    
    Query params:
        code: Authorization code from Facebook
        state: State token for CSRF protection
        error: Error message if authentication failed
    
    Returns redirect to frontend with tokens or error
    """
    # Check for OAuth errors
    if error:
        logger.warning("Facebook OAuth error", error=error, description=error_description)
        redirect_url = f"{OAuthConfig.FRONTEND_URL}?auth_error={error}"
        return RedirectResponse(url=redirect_url)
    
    # Validate required parameters
    if not code or not state:
        logger.warning("Missing code or state in Facebook callback")
        redirect_url = f"{OAuthConfig.FRONTEND_URL}?auth_error=missing_parameters"
        return RedirectResponse(url=redirect_url)
    
    # Validate state token
    if not validate_state(state):
        logger.warning("Invalid or expired state token", state=state)
        redirect_url = f"{OAuthConfig.FRONTEND_URL}?auth_error=invalid_state"
        return RedirectResponse(url=redirect_url)
    
    # Get the redirect URL from state
    state_data = oauth_states.pop(state)
    frontend_redirect = state_data['redirect_url']
    
    try:
        # Exchange code for tokens
        token_response = await oauth_service.exchange_facebook_code(
            code=code,
            redirect_uri=OAuthConfig.FACEBOOK_REDIRECT_URI
        )
        
        access_token = token_response.get('access_token')
        if not access_token:
            raise ValueError("No access token in response")
        
        # Get user info from Facebook
        facebook_user = await oauth_service.get_facebook_user_info(access_token)
        
        # Extract user information
        email = facebook_user.get('email')
        facebook_id = facebook_user.get('id')
        first_name = facebook_user.get('first_name')
        last_name = facebook_user.get('last_name')
        picture = facebook_user.get('picture', {}).get('data', {}).get('url')
        
        if not email or not facebook_id:
            raise ValueError("Missing required user information from Facebook")
        
        # Process user (create or get existing)
        db = None
        user_dict = None
        is_new_user = False
        
        if async_session_maker:
            async with async_session_maker() as db:
                user_dict, is_new_user = await oauth_service.process_oauth_user(
                    provider='facebook',
                    provider_user_id=facebook_id,
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    picture=picture,
                    db=db
                )
                
                # Create session and generate JWT tokens
                ip_address = request.headers.get("X-Forwarded-For", "unknown")
                user_agent = request.headers.get("User-Agent", "")
                
                session = UserSession(
                    user_id=user_dict['id'],
                    refresh_token_hash="",
                    device_info={'user_agent': user_agent, 'platform': 'web'},
                    ip_address=ip_address,
                    user_agent=user_agent,
                    expires_at=datetime.utcnow() + timedelta(days=30)
                )
                db.add(session)
                await db.flush()
                
                # Generate JWT tokens
                extra = await synapse_claims_for_user_id(db, user_dict["id"])
                jwt_access_token = JWTManager.create_access_token(
                    user_id=str(user_dict['id']),
                    email=email,
                    role=user_dict.get('role', 'user'),
                    extra_claims=extra,
                )
                jwt_refresh_token = JWTManager.create_refresh_token(
                    user_id=str(user_dict['id']),
                    session_id=str(session.session_id)
                )
                
                # Hash and store refresh token
                refresh_token_hash = PasswordHandler.hash_password(jwt_refresh_token)
                session.refresh_token_hash = refresh_token_hash
                
                await db.commit()
        else:
            # Fallback to in-memory mode
            user_dict, is_new_user = await oauth_service.process_oauth_user(
                provider='facebook',
                provider_user_id=facebook_id,
                email=email,
                first_name=first_name,
                last_name=last_name,
                picture=picture,
                db=None
            )
            
            # Generate simple tokens for in-memory mode
            jwt_access_token = JWTManager.create_access_token(
                user_id=facebook_id,
                email=email,
                role='user'
            )
            jwt_refresh_token = JWTManager.create_refresh_token(
                user_id=facebook_id,
                session_id=secrets.token_urlsafe(16)
            )
        
        # Redirect to frontend with tokens
        action = 'signup' if is_new_user else 'login'
        redirect_url = (
            f"{frontend_redirect}?auth_success=true"
            f"&access_token={jwt_access_token}"
            f"&refresh_token={jwt_refresh_token}"
            f"&action={action}"
            f"&provider=facebook"
        )
        
        logger.info(
            "Facebook OAuth successful",
            email=email,
            is_new_user=is_new_user
        )
        
        return RedirectResponse(url=redirect_url)
        
    except Exception as e:
        error_type = type(e).__name__
        error_detail = str(e)
        logger.error("Facebook OAuth callback failed", 
                    error_type=error_type,
                    error=error_detail, 
                    exc_info=True)
        # Include more specific error in redirect for debugging
        redirect_url = f"{frontend_redirect}?auth_error=authentication_failed&error_detail={error_type}"
        return RedirectResponse(url=redirect_url)


# ============================================
# Microsoft OAuth Endpoints
# ============================================

@router.get("/microsoft/login")
async def microsoft_login(request: Request, redirect_url: Optional[str] = None):
    """
    Initiate Microsoft OAuth login flow
    
    Query params:
        redirect_url: Optional frontend URL to redirect to after authentication
    
    Returns redirect to Microsoft's OAuth consent page
    """
    if not OAuthConfig.is_microsoft_configured():
        raise HTTPException(
            status_code=503,
            detail="Microsoft OAuth is not configured on the server"
        )
    
    # Generate state for CSRF protection
    state = generate_state()
    oauth_states[state] = {
        'created_at': datetime.utcnow(),
        'redirect_url': redirect_url or OAuthConfig.FRONTEND_URL
    }
    
    # Clean up old states
    cleanup_expired_states()
    
    # Generate authorization URL
    try:
        auth_url = oauth_service.get_microsoft_auth_url(
            redirect_uri=OAuthConfig.MICROSOFT_REDIRECT_URI,
            state=state
        )
        
        logger.info("Initiating Microsoft OAuth login", state=state)
        return RedirectResponse(url=auth_url)
        
    except Exception as e:
        logger.error("Failed to generate Microsoft auth URL", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to initiate Microsoft login")


@router.get("/microsoft/callback")
async def microsoft_callback(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None
):
    """
    Handle Microsoft OAuth callback
    
    Query params:
        code: Authorization code from Microsoft
        state: State token for CSRF protection
        error: Error message if authentication failed
    
    Returns redirect to frontend with tokens or error
    """
    # Check for OAuth errors
    if error:
        logger.warning("Microsoft OAuth error", error=error, description=error_description)
        redirect_url = f"{OAuthConfig.FRONTEND_URL}?auth_error={error}"
        return RedirectResponse(url=redirect_url)
    
    # Validate required parameters
    if not code or not state:
        logger.warning("Missing code or state in Microsoft callback")
        redirect_url = f"{OAuthConfig.FRONTEND_URL}?auth_error=missing_parameters"
        return RedirectResponse(url=redirect_url)
    
    # Validate state token
    if not validate_state(state):
        logger.warning("Invalid or expired state token", state=state)
        redirect_url = f"{OAuthConfig.FRONTEND_URL}?auth_error=invalid_state"
        return RedirectResponse(url=redirect_url)
    
    # Get the redirect URL from state
    state_data = oauth_states.pop(state)
    frontend_redirect = state_data['redirect_url']
    
    try:
        # Exchange code for tokens
        token_response = await oauth_service.exchange_microsoft_code(
            code=code,
            redirect_uri=OAuthConfig.MICROSOFT_REDIRECT_URI
        )
        
        access_token = token_response.get('access_token')
        if not access_token:
            raise ValueError("No access token in response")
        
        # Get user info from Microsoft
        microsoft_user = await oauth_service.get_microsoft_user_info(access_token)
        
        # Extract user information (Microsoft uses different field names)
        email = microsoft_user.get('mail') or microsoft_user.get('userPrincipalName')
        microsoft_id = microsoft_user.get('id')
        given_name = microsoft_user.get('givenName')
        surname = microsoft_user.get('surname')
        
        if not email or not microsoft_id:
            raise ValueError("Missing required user information from Microsoft")
        
        # Microsoft accounts are typically business/work accounts
        account_type_value = 'business'
        logger.info("Microsoft OAuth user", email=email, account_type=account_type_value)
        
        # Process user (create or get existing)
        db = None
        user_dict = None
        is_new_user = False
        
        if async_session_maker:
            async with async_session_maker() as db:
                user_dict, is_new_user = await oauth_service.process_oauth_user(
                    provider='microsoft',
                    provider_user_id=microsoft_id,
                    email=email,
                    first_name=given_name,
                    last_name=surname,
                    picture=None,  # Microsoft Graph doesn't provide picture URL directly
                    account_type=account_type_value,
                    db=db
                )
                
                # Create session and generate JWT tokens
                ip_address = request.headers.get("X-Forwarded-For", "unknown")
                user_agent = request.headers.get("User-Agent", "")
                
                session = UserSession(
                    user_id=user_dict['id'],
                    refresh_token_hash="",
                    device_info={'user_agent': user_agent, 'platform': 'web'},
                    ip_address=ip_address,
                    user_agent=user_agent,
                    expires_at=datetime.utcnow() + timedelta(days=30)
                )
                db.add(session)
                await db.flush()
                
                # Generate JWT tokens
                extra = await synapse_claims_for_user_id(db, user_dict["id"])
                jwt_access_token = JWTManager.create_access_token(
                    user_id=str(user_dict['id']),
                    email=email,
                    role=user_dict.get('role', 'user'),
                    extra_claims=extra,
                )
                jwt_refresh_token = JWTManager.create_refresh_token(
                    user_id=str(user_dict['id']),
                    session_id=str(session.session_id)
                )
                
                # Hash and store refresh token
                refresh_token_hash = PasswordHandler.hash_password(jwt_refresh_token)
                session.refresh_token_hash = refresh_token_hash
                
                await db.commit()
        else:
            # Fallback to in-memory mode
            user_dict, is_new_user = await oauth_service.process_oauth_user(
                provider='microsoft',
                provider_user_id=microsoft_id,
                email=email,
                first_name=given_name,
                last_name=surname,
                picture=None,
                db=None
            )
            
            # Generate simple tokens for in-memory mode
            jwt_access_token = JWTManager.create_access_token(
                user_id=microsoft_id,
                email=email,
                role='user'
            )
            jwt_refresh_token = JWTManager.create_refresh_token(
                user_id=microsoft_id,
                session_id=secrets.token_urlsafe(16)
            )
        
        # Redirect to frontend with tokens
        action = 'signup' if is_new_user else 'login'
        redirect_url = (
            f"{frontend_redirect}?auth_success=true"
            f"&access_token={jwt_access_token}"
            f"&refresh_token={jwt_refresh_token}"
            f"&action={action}"
            f"&provider=microsoft"
        )
        
        logger.info(
            "Microsoft OAuth successful",
            email=email,
            is_new_user=is_new_user
        )
        
        return RedirectResponse(url=redirect_url)
        
    except Exception as e:
        error_type = type(e).__name__
        error_detail = str(e)
        logger.error("Microsoft OAuth callback failed", 
                    error_type=error_type,
                    error=error_detail, 
                    exc_info=True)
        # Include more specific error in redirect for debugging
        redirect_url = f"{frontend_redirect}?auth_error=authentication_failed&error_detail={error_type}"
        return RedirectResponse(url=redirect_url)


# ============================================
# OAuth Status Endpoint
# ============================================

class OAuthStatusResponse(BaseModel):
    google_enabled: bool
    facebook_enabled: bool = False
    microsoft_enabled: bool = False


@router.get("/oauth/status", response_model=OAuthStatusResponse)
async def oauth_status():
    """
    Get status of available OAuth providers
    
    Returns which OAuth providers are configured and available
    """
    config_status = OAuthConfig.validate_config()
    
    return OAuthStatusResponse(
        google_enabled=config_status['google'],
        facebook_enabled=config_status['facebook'],
        microsoft_enabled=config_status['microsoft']
    )
