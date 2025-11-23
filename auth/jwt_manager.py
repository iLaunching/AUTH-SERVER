"""
JWT Token Management
Handles creation, validation, and refresh of JWT access and refresh tokens.
"""

import os
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import jwt
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError
import structlog

logger = structlog.get_logger()

# JWT Configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))  # 15 minutes
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "30"))  # 30 days

class JWTManager:
    """Manage JWT token creation and validation"""
    
    @staticmethod
    def create_access_token(user_id: str, email: str, role: str = "user", extra_claims: Optional[Dict] = None) -> str:
        """
        Create a short-lived access token for API authentication
        
        Args:
            user_id: User's UUID
            email: User's email
            role: User's role (user, admin, etc.)
            extra_claims: Additional claims to include in token
            
        Returns:
            JWT access token string
        """
        now = datetime.utcnow()
        expires_at = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        
        payload = {
            "sub": user_id,  # Subject (user ID)
            "email": email,
            "role": role,
            "type": "access",
            "iat": now,  # Issued at
            "exp": expires_at,  # Expiration
        }
        
        # Add extra claims if provided
        if extra_claims:
            payload.update(extra_claims)
        
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        
        logger.info("Access token created", user_id=user_id, expires_in_minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        return token
    
    @staticmethod
    def create_refresh_token(user_id: str, session_id: str) -> str:
        """
        Create a long-lived refresh token for obtaining new access tokens
        
        Args:
            user_id: User's UUID
            session_id: Session UUID for this device/login
            
        Returns:
            JWT refresh token string
        """
        now = datetime.utcnow()
        expires_at = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        
        payload = {
            "sub": user_id,  # Subject (user ID)
            "session_id": session_id,
            "type": "refresh",
            "iat": now,  # Issued at
            "exp": expires_at,  # Expiration
        }
        
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        
        logger.info("Refresh token created", user_id=user_id, session_id=session_id, expires_in_days=REFRESH_TOKEN_EXPIRE_DAYS)
        return token
    
    @staticmethod
    def verify_access_token(token: str) -> Optional[Dict[str, Any]]:
        """
        Verify and decode an access token
        
        Args:
            token: JWT token string
            
        Returns:
            Decoded token payload if valid, None if invalid
        """
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            
            # Verify it's an access token
            if payload.get("type") != "access":
                logger.warning("Token type mismatch", expected="access", actual=payload.get("type"))
                return None
            
            logger.debug("Access token verified", user_id=payload.get("sub"))
            return payload
            
        except ExpiredSignatureError:
            logger.info("Access token expired")
            return None
        except InvalidTokenError as e:
            logger.warning("Invalid access token", error=str(e))
            return None
        except Exception as e:
            logger.error("Unexpected error verifying access token", error=str(e))
            return None
    
    @staticmethod
    def verify_refresh_token(token: str) -> Optional[Dict[str, Any]]:
        """
        Verify and decode a refresh token
        
        Args:
            token: JWT token string
            
        Returns:
            Decoded token payload if valid, None if invalid
        """
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            
            # Verify it's a refresh token
            if payload.get("type") != "refresh":
                logger.warning("Token type mismatch", expected="refresh", actual=payload.get("type"))
                return None
            
            logger.debug("Refresh token verified", user_id=payload.get("sub"), session_id=payload.get("session_id"))
            return payload
            
        except ExpiredSignatureError:
            logger.info("Refresh token expired")
            return None
        except InvalidTokenError as e:
            logger.warning("Invalid refresh token", error=str(e))
            return None
        except Exception as e:
            logger.error("Unexpected error verifying refresh token", error=str(e))
            return None
    
    @staticmethod
    def decode_token_without_verification(token: str) -> Optional[Dict[str, Any]]:
        """
        Decode a token without verifying signature (useful for debugging)
        WARNING: Never use for authentication! Only for inspection.
        
        Args:
            token: JWT token string
            
        Returns:
            Decoded token payload (unverified)
        """
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            return payload
        except Exception as e:
            logger.error("Failed to decode token", error=str(e))
            return None
    
    @staticmethod
    def get_token_expiration(token: str) -> Optional[datetime]:
        """
        Get the expiration time of a token
        
        Args:
            token: JWT token string
            
        Returns:
            Expiration datetime if valid, None if invalid
        """
        payload = JWTManager.decode_token_without_verification(token)
        if payload and "exp" in payload:
            return datetime.fromtimestamp(payload["exp"])
        return None
    
    @staticmethod
    def is_token_expired(token: str) -> bool:
        """
        Check if a token is expired
        
        Args:
            token: JWT token string
            
        Returns:
            True if expired, False if valid
        """
        expiration = JWTManager.get_token_expiration(token)
        if expiration:
            return datetime.utcnow() > expiration
        return True  # If we can't get expiration, consider it expired
