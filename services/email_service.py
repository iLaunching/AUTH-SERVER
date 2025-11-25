"""
Email Service
Handles sending emails for verification, password reset, etc.
"""

import os
import secrets
import structlog
from datetime import datetime, timedelta
from typing import Optional
import resend

logger = structlog.get_logger()

# Configure Resend API key
resend.api_key = os.getenv("RESEND_API_KEY")


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
        Send verification code via email using Resend
        
        Args:
            email: Recipient email address
            code: Verification code to send
            
        Returns:
            True if email sent successfully, False otherwise
        """
        # Check if Resend is configured
        if not resend.api_key:
            logger.warning("RESEND_API_KEY not configured - logging code instead")
            logger.info(
                "📧 VERIFICATION CODE (DEV MODE - No Resend API Key)",
                email=email,
                code=code,
                message=f"Send this code to {email}: {code}"
            )
            return True
        
        try:
            # Send email via Resend
            params = {
                "from": os.getenv("EMAIL_FROM", "noreply@yourdomain.com"),
                "to": [email],
                "subject": "Verify your iLaunching account",
                "html": f"""
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <h2 style="color: #333;">Verify Your Email</h2>
                        <p style="color: #666; font-size: 16px;">
                            Thank you for signing up! Please use the verification code below to complete your registration:
                        </p>
                        <div style="background-color: #f5f5f5; padding: 20px; text-align: center; border-radius: 8px; margin: 20px 0;">
                            <h1 style="color: #2563eb; font-size: 36px; letter-spacing: 8px; margin: 0;">
                                {code}
                            </h1>
                        </div>
                        <p style="color: #666; font-size: 14px;">
                            This code will expire in 10 minutes.
                        </p>
                        <p style="color: #999; font-size: 12px; margin-top: 30px;">
                            If you didn't request this code, please ignore this email.
                        </p>
                    </div>
                """
            }
            
            response = resend.Emails.send(params)
            logger.info("Verification email sent via Resend", email=email, email_id=response.get('id'))
            return True
            
        except Exception as e:
            logger.error("Failed to send verification email via Resend", error=str(e), email=email)
            # Fallback to logging in case of error
            logger.info(
                "📧 VERIFICATION CODE (Fallback - Resend failed)",
                email=email,
                code=code,
                message=f"Send this code to {email}: {code}"
            )
            return False
    
    @classmethod
    async def send_welcome_email(cls, email: str, first_name: Optional[str] = None):
        """Send welcome email to new user"""
        if not resend.api_key:
            logger.info("📧 WELCOME EMAIL (DEV MODE - No Resend API Key)", email=email, first_name=first_name)
            return True
            
        try:
            name = first_name or email.split('@')[0]
            params = {
                "from": os.getenv("EMAIL_FROM", "noreply@yourdomain.com"),
                "to": [email],
                "subject": "Welcome to iLaunching!",
                "html": f"""
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <h2 style="color: #333;">Welcome to iLaunching, {name}! 🚀</h2>
                        <p style="color: #666; font-size: 16px;">
                            We're excited to have you on board. Your account has been successfully created.
                        </p>
                        <p style="color: #666; font-size: 16px;">
                            Get started by exploring our features and setting up your profile.
                        </p>
                        <a href="{os.getenv('FRONTEND_URL', 'http://localhost:5173')}" 
                           style="display: inline-block; background-color: #2563eb; color: white; padding: 12px 24px; 
                                  text-decoration: none; border-radius: 8px; margin: 20px 0;">
                            Go to Dashboard
                        </a>
                        <p style="color: #999; font-size: 12px; margin-top: 30px;">
                            Need help? Contact us at support@yourdomain.com
                        </p>
                    </div>
                """
            }
            
            response = resend.Emails.send(params)
            logger.info("Welcome email sent via Resend", email=email, email_id=response.get('id'))
            return True
            
        except Exception as e:
            logger.error("Failed to send welcome email", error=str(e))
            return False


# Global email service instance
email_service = EmailService()
