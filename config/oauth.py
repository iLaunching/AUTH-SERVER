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
    
    # OAuth Scopes
    GOOGLE_SCOPES = [
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
    ]
    
    # OAuth endpoints
    GOOGLE_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
    GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
    
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
    def validate_config(cls) -> Dict[str, bool]:
        """Validate OAuth configuration for all providers"""
        return {
            "google": cls.is_google_configured(),
        }
