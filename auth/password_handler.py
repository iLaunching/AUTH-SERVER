"""
Password Hashing and Verification
Handles secure password hashing using bcrypt and password validation.
"""

import re
from typing import Tuple
import bcrypt
import structlog

logger = structlog.get_logger()

class PasswordHandler:
    """Handle password hashing, verification, and validation"""
    
    # Password requirements
    MIN_LENGTH = 8
    MAX_LENGTH = 128
    REQUIRE_UPPERCASE = True
    REQUIRE_LOWERCASE = True
    REQUIRE_DIGIT = True
    REQUIRE_SPECIAL = False  # Optional for better UX
    
    # bcrypt work factor (cost) - higher = more secure but slower
    # 12 is a good balance for 2024
    BCRYPT_ROUNDS = 12
    
    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash a password using bcrypt
        
        Args:
            password: Plain text password
            
        Returns:
            bcrypt hashed password string
        """
        # Convert password to bytes
        password_bytes = password.encode('utf-8')
        
        # Generate salt and hash
        salt = bcrypt.gensalt(rounds=PasswordHandler.BCRYPT_ROUNDS)
        hashed = bcrypt.hashpw(password_bytes, salt)
        
        # Convert back to string for storage
        hashed_str = hashed.decode('utf-8')
        
        logger.debug("Password hashed successfully")
        return hashed_str
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash
        
        Args:
            plain_password: Plain text password to verify
            hashed_password: bcrypt hashed password from database
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            # Convert to bytes
            password_bytes = plain_password.encode('utf-8')
            hashed_bytes = hashed_password.encode('utf-8')
            
            # Verify password
            is_valid = bcrypt.checkpw(password_bytes, hashed_bytes)
            
            logger.debug("Password verification", is_valid=is_valid)
            return is_valid
            
        except Exception as e:
            logger.error("Password verification failed", error=str(e))
            return False
    
    @staticmethod
    def validate_password_strength(password: str) -> Tuple[bool, list]:
        """
        Validate password meets security requirements
        
        Args:
            password: Plain text password to validate
            
        Returns:
            Tuple of (is_valid: bool, errors: list of error messages)
        """
        errors = []
        
        # Check length
        if len(password) < PasswordHandler.MIN_LENGTH:
            errors.append(f"Password must be at least {PasswordHandler.MIN_LENGTH} characters long")
        
        if len(password) > PasswordHandler.MAX_LENGTH:
            errors.append(f"Password must be at most {PasswordHandler.MAX_LENGTH} characters long")
        
        # Check for uppercase letter
        if PasswordHandler.REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        # Check for lowercase letter
        if PasswordHandler.REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        # Check for digit
        if PasswordHandler.REQUIRE_DIGIT and not re.search(r'\d', password):
            errors.append("Password must contain at least one number")
        
        # Check for special character (optional)
        if PasswordHandler.REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
            errors.append("Password must contain at least one special character")
        
        is_valid = len(errors) == 0
        
        if not is_valid:
            logger.info("Password validation failed", error_count=len(errors))
        
        return is_valid, errors
    
    @staticmethod
    def generate_temp_password(length: int = 12) -> str:
        """
        Generate a temporary password (useful for password resets)
        
        Args:
            length: Length of password to generate
            
        Returns:
            Random password string that meets requirements
        """
        import secrets
        import string
        
        # Ensure password meets requirements
        alphabet = string.ascii_letters + string.digits
        if PasswordHandler.REQUIRE_SPECIAL:
            alphabet += "!@#$%^&*"
        
        # Generate random password
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        
        # Ensure it has at least one of each required type
        if PasswordHandler.REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
            password = password[:-1] + secrets.choice(string.ascii_uppercase)
        
        if PasswordHandler.REQUIRE_LOWERCASE and not any(c.islower() for c in password):
            password = password[:-1] + secrets.choice(string.ascii_lowercase)
        
        if PasswordHandler.REQUIRE_DIGIT and not any(c.isdigit() for c in password):
            password = password[:-1] + secrets.choice(string.digits)
        
        logger.info("Temporary password generated")
        return password
    
    @staticmethod
    def check_common_passwords(password: str) -> bool:
        """
        Check if password is in list of common passwords
        (For production, load from a file of common passwords)
        
        Args:
            password: Password to check
            
        Returns:
            True if password is common (should be rejected), False if OK
        """
        # Basic list - in production, load from a comprehensive list
        common_passwords = [
            "password", "123456", "12345678", "password123", 
            "qwerty", "abc123", "111111", "123123",
            "admin", "letmein", "welcome", "monkey"
        ]
        
        is_common = password.lower() in common_passwords
        
        if is_common:
            logger.warning("Common password detected")
        
        return is_common
