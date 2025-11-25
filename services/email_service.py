"""
Email Service
Handles sending emails for verification, password reset, etc.
"""

import os
import secrets
import structlog
from datetime import datetime, timedelta
from typing import Optional

logger = structlog.get_logger()


class EmailService:
    """Service for sending emails"""
    
    # In-memory storage for verification codes (use Redis in production)
    _verification_codes = {}
    
    @classmethod
    def generate_verification_code(cls) -> str:
        """Generate a 6-digit verification code"""
        return str(secrets.randbelow(1000000)).zfill(6)
    
    @classmethod
    def store_verification_code(cls, email: str, code: str, expires_minutes: int = 10):
        """
        Store verification code with expiration
        
        Args:
            email: User's email address
            code: Verification code
            expires_minutes: Minutes until code expires
        """
        cls._verification_codes[email] = {
            'code': code,
            'expires_at': datetime.utcnow() + timedelta(minutes=expires_minutes),
            'attempts': 0
        }
        logger.info("Verification code stored", email=email, expires_in_minutes=expires_minutes)
    
    @classmethod
    def verify_code(cls, email: str, code: str) -> tuple[bool, Optional[str]]:
        """
        Verify a code for an email
        
        Args:
            email: User's email address
            code: Verification code to check
            
        Returns:
            Tuple of (success: bool, error_message: Optional[str])
        """
        if email not in cls._verification_codes:
            return False, "No verification code found. Please request a new one."
        
        stored_data = cls._verification_codes[email]
        
        # Check if expired
        if datetime.utcnow() > stored_data['expires_at']:
            del cls._verification_codes[email]
            return False, "Verification code has expired. Please request a new one."
        
        # Check attempts
        if stored_data['attempts'] >= 5:
            del cls._verification_codes[email]
            return False, "Too many failed attempts. Please request a new code."
        
        # Verify code
        if stored_data['code'] == code:
            del cls._verification_codes[email]
            logger.info("Verification code verified successfully", email=email)
            return True, None
        else:
            stored_data['attempts'] += 1
            logger.warning("Incorrect verification code", email=email, attempts=stored_data['attempts'])
            return False, f"Incorrect code. {5 - stored_data['attempts']} attempts remaining."
    
    @classmethod
    def delete_verification_code(cls, email: str):
        """Delete verification code for email"""
        if email in cls._verification_codes:
            del cls._verification_codes[email]
            logger.info("Verification code deleted", email=email)
    
    @classmethod
    async def send_verification_email(cls, email: str, code: str) -> bool:
        """
        Send verification code via email
        
        Args:
            email: Recipient email address
            code: Verification code to send
            
        Returns:
            True if email sent successfully, False otherwise
        """
        # TODO: Integrate with actual email service (SendGrid, AWS SES, etc.)
        # For now, just log the code (FOR DEVELOPMENT ONLY)
        logger.info(
            "📧 VERIFICATION CODE (DEV MODE)",
            email=email,
            code=code,
            message=f"Send this code to {email}: {code}"
        )
        
        # In production, you would send actual email here:
        # try:
        #     await send_email_via_provider(
        #         to=email,
        #         subject="Verify your email",
        #         body=f"Your verification code is: {code}"
        #     )
        #     return True
        # except Exception as e:
        #     logger.error("Failed to send verification email", error=str(e))
        #     return False
        
        return True  # Simulate success for development
    
    @classmethod
    async def send_welcome_email(cls, email: str, first_name: Optional[str] = None):
        """Send welcome email to new user"""
        logger.info("📧 WELCOME EMAIL (DEV MODE)", email=email, first_name=first_name)
        # TODO: Implement actual email sending
        return True


# Global email service instance
email_service = EmailService()
