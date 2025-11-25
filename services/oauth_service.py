"""
OAuth Service
Handles OAuth authentication flows for various providers
"""

from typing import Dict, Optional, Tuple
import httpx
import structlog
from authlib.integrations.starlette_client import OAuth
from starlette.config import Config
from datetime import datetime

from config.oauth import OAuthConfig
from auth.jwt_manager import JWTManager
from auth.password_handler import PasswordHandler

logger = structlog.get_logger()


class OAuthService:
    """Service for handling OAuth authentication flows"""
    
    def __init__(self):
        """Initialize OAuth service"""
        self.oauth = OAuth()
        self._setup_google()
    
    def _setup_google(self):
        """Setup Google OAuth provider"""
        if OAuthConfig.is_google_configured():
            try:
                # Create a config for authlib
                config = Config(environ={
                    'GOOGLE_CLIENT_ID': OAuthConfig.GOOGLE_CLIENT_ID,
                    'GOOGLE_CLIENT_SECRET': OAuthConfig.GOOGLE_CLIENT_SECRET,
                })
                
                self.oauth.register(
                    name='google',
                    client_id=OAuthConfig.GOOGLE_CLIENT_ID,
                    client_secret=OAuthConfig.GOOGLE_CLIENT_SECRET,
                    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
                    client_kwargs={
                        'scope': ' '.join(OAuthConfig.GOOGLE_SCOPES),
                        'prompt': 'select_account',  # Force account selection
                    }
                )
                logger.info("Google OAuth provider configured successfully")
            except Exception as e:
                logger.error("Failed to setup Google OAuth", error=str(e))
        else:
            logger.warning("Google OAuth not configured - skipping setup")
    
    def get_google_auth_url(self, redirect_uri: str, state: str) -> str:
        """
        Generate Google OAuth authorization URL
        
        Args:
            redirect_uri: Where Google should redirect after authentication
            state: Random state for CSRF protection
            
        Returns:
            Authorization URL string
        """
        if not OAuthConfig.is_google_configured():
            raise ValueError("Google OAuth is not configured")
        
        params = {
            'client_id': OAuthConfig.GOOGLE_CLIENT_ID,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'scope': ' '.join(OAuthConfig.GOOGLE_SCOPES),
            'state': state,
            'access_type': 'offline',
            'prompt': 'select_account',
        }
        
        query_string = '&'.join([f"{k}={v}" for k, v in params.items()])
        auth_url = f"{OAuthConfig.GOOGLE_AUTHORIZE_URL}?{query_string}"
        
        logger.info("Generated Google auth URL", state=state)
        return auth_url
    
    async def exchange_google_code(self, code: str, redirect_uri: str) -> Dict:
        """
        Exchange Google authorization code for access token
        
        Args:
            code: Authorization code from Google
            redirect_uri: Redirect URI used in the initial request
            
        Returns:
            Token response from Google
        """
        if not OAuthConfig.is_google_configured():
            raise ValueError("Google OAuth is not configured")
        
        token_data = {
            'code': code,
            'client_id': OAuthConfig.GOOGLE_CLIENT_ID,
            'client_secret': OAuthConfig.GOOGLE_CLIENT_SECRET,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code',
        }
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    OAuthConfig.GOOGLE_TOKEN_URL,
                    data=token_data,
                    headers={'Content-Type': 'application/x-www-form-urlencoded'}
                )
                response.raise_for_status()
                token_response = response.json()
                logger.info("Successfully exchanged Google code for token")
                return token_response
            except httpx.HTTPError as e:
                logger.error("Failed to exchange Google code", error=str(e))
                raise ValueError(f"Failed to exchange authorization code: {str(e)}")
    
    async def get_google_user_info(self, access_token: str) -> Dict:
        """
        Get user information from Google using access token
        
        Args:
            access_token: Google access token
            
        Returns:
            User information from Google
        """
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    OAuthConfig.GOOGLE_USERINFO_URL,
                    headers={'Authorization': f'Bearer {access_token}'}
                )
                response.raise_for_status()
                user_info = response.json()
                logger.info("Successfully fetched Google user info", email=user_info.get('email'))
                return user_info
            except httpx.HTTPError as e:
                logger.error("Failed to fetch Google user info", error=str(e))
                raise ValueError(f"Failed to fetch user info: {str(e)}")
    
    async def process_oauth_user(
        self,
        provider: str,
        provider_user_id: str,
        email: str,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        picture: Optional[str] = None,
        db = None
    ) -> Tuple[Dict, bool]:
        """
        Process OAuth user - create new user or return existing user
        
        Args:
            provider: OAuth provider name (e.g., 'google')
            provider_user_id: User ID from the OAuth provider
            email: User's email address
            first_name: User's first name
            last_name: User's last name
            picture: User's profile picture URL
            db: Database session (optional, for database mode)
            
        Returns:
            Tuple of (user_dict, is_new_user)
        """
        from models.user import User, UserProfile
        from sqlalchemy import select
        
        email = email.lower()
        
        # Database mode
        if db:
            try:
                # Check if user exists by email
                result = await db.execute(
                    select(User).where(User.email == email)
                )
                user = result.scalar_one_or_none()
                
                if user:
                    # Existing user - update last login
                    user.last_login = datetime.utcnow()
                    
                    # Update OAuth provider info if not set
                    if not user.oauth_provider:
                        user.oauth_provider = provider
                        user.oauth_provider_id = provider_user_id
                    
                    # Create profile if it doesn't exist
                    if not user.profile:
                        user_profile = UserProfile(
                            user_id=user.id,
                            avatar_url=picture,
                            first_name=first_name,
                            last_name=last_name
                        )
                        db.add(user_profile)
                    
                    await db.commit()
                    logger.info("Existing OAuth user logged in", user_id=str(user.id), email=email)
                    return user.to_dict(), False
                
                else:
                    # New user - create account
                    new_user = User(
                        email=email,
                        first_name=first_name,
                        last_name=last_name,
                        oauth_provider=provider,
                        oauth_provider_id=provider_user_id,
                        email_verified=True,  # OAuth emails are pre-verified
                        password_hash=None  # No password for OAuth users
                    )
                    db.add(new_user)
                    await db.flush()
                    
                    # Create user profile
                    user_profile = UserProfile(
                        user_id=new_user.id,
                        avatar_url=picture,
                        first_name=first_name,
                        last_name=last_name
                    )
                    db.add(user_profile)
                    
                    await db.commit()
                    logger.info("New OAuth user created", user_id=str(new_user.id), email=email, provider=provider)
                    return new_user.to_dict(), True
                    
            except Exception as e:
                await db.rollback()
                logger.error("Failed to process OAuth user in database", error=str(e))
                raise
        
        # In-memory mode (fallback)
        # This is a simplified implementation for development
        user_dict = {
            "email": email,
            "first_name": first_name or email.split("@")[0],
            "last_name": last_name or "",
            "oauth_provider": provider,
            "oauth_provider_id": provider_user_id,
            "email_verified": True,
            "created_at": datetime.utcnow().isoformat(),
            "picture": picture
        }
        
        logger.info("OAuth user processed (in-memory mode)", email=email, provider=provider)
        return user_dict, False  # Assume existing user in memory mode


# Global OAuth service instance
oauth_service = OAuthService()
