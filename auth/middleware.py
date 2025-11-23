"""
Authentication and session management middleware.
"""

import os
import uuid
from datetime import datetime, timedelta
from typing import Optional
from fastapi import HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import structlog

logger = structlog.get_logger()

# Simple session-based auth for now (can be enhanced with JWT later)
security = HTTPBearer(auto_error=False)

async def get_current_session(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> str:
    """Extract and validate session ID from Bearer token"""
    
    if not credentials:
        raise HTTPException(
            status_code=401,
            detail="Missing authorization token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    session_id = credentials.credentials
    
    # Validate UUID format for session ID
    try:
        uuid.UUID(session_id)
    except ValueError:
        raise HTTPException(
            status_code=401,
            detail="Invalid session ID format",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return session_id

def validate_bubble_request(request: Request) -> bool:
    """
    Validate that the request is coming from a Bubble app.
    This is a basic validation - enhance with proper API keys in production.
    """
    
    # Check for Bubble-specific headers
    user_agent = request.headers.get("user-agent", "")
    referer = request.headers.get("referer", "")
    origin = request.headers.get("origin", "")
    
    # Allow requests from Bubble domains
    bubble_domains = [
        "bubbleapps.io",
        "localhost",  # For development
        "127.0.0.1"   # For local testing
    ]
    
    # Check if request is from a valid domain
    for domain in bubble_domains:
        if domain in referer or domain in origin:
            return True
    
    # Allow if no origin/referer (API testing tools)
    if not referer and not origin:
        return True
    
    return False

async def validate_api_key(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> bool:
    """
    Validate API key for production use.
    Currently disabled for development - enable in production.
    """
    
    # Get API key from environment
    valid_api_key = os.getenv("API_KEY")
    
    # Skip validation if no API key is set (development mode)
    if not valid_api_key:
        return True
    
    # Check for API key in Authorization header
    if credentials:
        provided_key = credentials.credentials
        if provided_key == valid_api_key:
            return True
    
    # Check for API key in custom header
    api_key_header = request.headers.get("X-API-Key")
    if api_key_header == valid_api_key:
        return True
    
    # Check for API key in query parameter
    api_key_param = request.query_params.get("api_key")
    if api_key_param == valid_api_key:
        return True
    
    return False