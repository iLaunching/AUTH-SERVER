"""
OAuth Configuration
Manages OAuth provider settings and credentials
"""

import os
from typing import Dict, Optional
import structlog

logger = structlog.get_logger()


class OAuthConfig:
    """OAuth configuration for supported providers"""
    
    # Google OAuth Configuration
    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
    GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/api/v1/auth/google/callback")
    
    # Facebook OAuth Configuration
    FACEBOOK_CLIENT_ID = os.getenv("FACEBOOK_CLIENT_ID")
    FACEBOOK_CLIENT_SECRET = os.getenv("FACEBOOK_CLIENT_SECRET")
    FACEBOOK_REDIRECT_URI = os.getenv("FACEBOOK_REDIRECT_URI", "http://localhost:8000/api/v1/auth/facebook/callback")
    
    # Microsoft OAuth Configuration
    MICROSOFT_CLIENT_ID = os.getenv("MICROSOFT_CLIENT_ID")
    MICROSOFT_CLIENT_SECRET = os.getenv("MICROSOFT_CLIENT_SECRET")
    MICROSOFT_REDIRECT_URI = os.getenv("MICROSOFT_REDIRECT_URI", "http://localhost:8000/api/v1/auth/microsoft/callback")
    
    # OAuth Scopes
    GOOGLE_SCOPES = [
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
    ]
    
    FACEBOOK_SCOPES = [
        "email",
        "public_profile",
    ]
    
    MICROSOFT_SCOPES = [
        "openid",
        "email",
        "profile",
        "User.Read",
    ]
    
    # OAuth endpoints
    GOOGLE_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
    GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
    
    FACEBOOK_AUTHORIZE_URL = "https://www.facebook.com/v18.0/dialog/oauth"
    FACEBOOK_TOKEN_URL = "https://graph.facebook.com/v18.0/oauth/access_token"
    FACEBOOK_USERINFO_URL = "https://graph.facebook.com/v18.0/me"
    
    MICROSOFT_AUTHORIZE_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    MICROSOFT_TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    MICROSOFT_USERINFO_URL = "https://graph.microsoft.com/v1.0/me"
    
    # Frontend URL for redirects after OAuth
    FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")
    
    @classmethod
    def is_google_configured(cls) -> bool:
        """Check if Google OAuth is properly configured"""
        is_configured = bool(cls.GOOGLE_CLIENT_ID and cls.GOOGLE_CLIENT_SECRET)
        if not is_configured:
            logger.warning(
                "Google OAuth not configured",
                has_client_id=bool(cls.GOOGLE_CLIENT_ID),
                has_client_secret=bool(cls.GOOGLE_CLIENT_SECRET)
            )
        return is_configured
    
    @classmethod
    def is_facebook_configured(cls) -> bool:
        """Check if Facebook OAuth is properly configured"""
        is_configured = bool(cls.FACEBOOK_CLIENT_ID and cls.FACEBOOK_CLIENT_SECRET)
        if not is_configured:
            logger.warning(
                "Facebook OAuth not configured",
                has_client_id=bool(cls.FACEBOOK_CLIENT_ID),
                has_client_secret=bool(cls.FACEBOOK_CLIENT_SECRET)
            )
        return is_configured
    
    @classmethod
    def is_microsoft_configured(cls) -> bool:
        """Check if Microsoft OAuth is properly configured"""
        is_configured = bool(cls.MICROSOFT_CLIENT_ID and cls.MICROSOFT_CLIENT_SECRET)
        if not is_configured:
            logger.warning(
                "Microsoft OAuth not configured",
                has_client_id=bool(cls.MICROSOFT_CLIENT_ID),
                has_client_secret=bool(cls.MICROSOFT_CLIENT_SECRET)
            )
        return is_configured
    
    @classmethod
    def get_google_config(cls) -> Dict[str, str]:
        """Get Google OAuth configuration as dictionary"""
        return {
            "client_id": cls.GOOGLE_CLIENT_ID,
            "client_secret": cls.GOOGLE_CLIENT_SECRET,
            "redirect_uri": cls.GOOGLE_REDIRECT_URI,
            "authorize_url": cls.GOOGLE_AUTHORIZE_URL,
            "token_url": cls.GOOGLE_TOKEN_URL,
            "userinfo_url": cls.GOOGLE_USERINFO_URL,
        }
    
    @classmethod
    def get_facebook_config(cls) -> Dict[str, str]:
        """Get Facebook OAuth configuration as dictionary"""
        return {
            "client_id": cls.FACEBOOK_CLIENT_ID,
            "client_secret": cls.FACEBOOK_CLIENT_SECRET,
            "redirect_uri": cls.FACEBOOK_REDIRECT_URI,
            "authorize_url": cls.FACEBOOK_AUTHORIZE_URL,
            "token_url": cls.FACEBOOK_TOKEN_URL,
            "userinfo_url": cls.FACEBOOK_USERINFO_URL,
        }
    
    @classmethod
    def get_microsoft_config(cls) -> Dict[str, str]:
        """Get Microsoft OAuth configuration as dictionary"""
        return {
            "client_id": cls.MICROSOFT_CLIENT_ID,
            "client_secret": cls.MICROSOFT_CLIENT_SECRET,
            "redirect_uri": cls.MICROSOFT_REDIRECT_URI,
            "authorize_url": cls.MICROSOFT_AUTHORIZE_URL,
            "token_url": cls.MICROSOFT_TOKEN_URL,
            "userinfo_url": cls.MICROSOFT_USERINFO_URL,
        }
    
    @classmethod
    def validate_config(cls) -> Dict[str, bool]:
        """Validate OAuth configuration for all providers"""
        return {
            "google": cls.is_google_configured(),
            "facebook": cls.is_facebook_configured(),
            "microsoft": cls.is_microsoft_configured(),
        }
