"""
SQLAlchemy User Models for Auth API
Phase 2: Core authentication models
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Text, Integer
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
import uuid

from config.database import Base

class User(Base):
    """User account model"""
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=True)  # Nullable for OAuth users
    first_name = Column(String(255))
    last_name = Column(String(255))
    role = Column(String(50), default="user")
    subscription_tier = Column(String(50), default="free")
    email_verified = Column(Boolean, default=False)
    
    # OAuth fields
    oauth_provider = Column(String(50))  # e.g., 'google', 'facebook', 'microsoft'
    oauth_provider_id = Column(String(255))  # User ID from OAuth provider
    
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime(timezone=True))
    
    # Relationships
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    profile = relationship("UserProfile", back_populates="user", uselist=False, cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<User(id={self.id}, email={self.email}, role={self.role})>"
    
    def to_dict(self, include_sensitive=False):
        """Convert user to dictionary (exclude password by default)"""
        data = {
            "id": str(self.id),
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "role": self.role,
            "subscription_tier": self.subscription_tier,
            "email_verified": self.email_verified,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
        }
        
        # Include profile info if available
        if self.profile:
            data["onboarding_completed"] = self.profile.onboarding_completed
        else:
            data["onboarding_completed"] = False
        
        if include_sensitive:
            data["password_hash"] = self.password_hash
        
        return data


class Session(Base):
    """User session model for refresh tokens"""
    __tablename__ = "sessions"
    
    session_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    refresh_token_hash = Column(String(255), nullable=False)
    device_info = Column(JSONB, default={})
    ip_address = Column(String(45))
    user_agent = Column(Text)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    revoked = Column(Boolean, default=False, index=True)
    revoked_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    last_accessed = Column(DateTime(timezone=True), default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="sessions")
    
    def __repr__(self):
        return f"<Session(session_id={self.session_id}, user_id={self.user_id}, revoked={self.revoked})>"
    
    def to_dict(self):
        """Convert session to dictionary"""
        return {
            "session_id": str(self.session_id),
            "user_id": str(self.user_id),
            "device_info": self.device_info,
            "ip_address": self.ip_address,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "revoked": self.revoked,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_accessed": self.last_accessed.isoformat() if self.last_accessed else None,
        }


class UserProfile(Base):
    """Extended user profile information"""
    __tablename__ = "user_profiles"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True)
    
    # Basic profile fields
    first_name = Column(Text)
    last_name = Column(Text)
    phone = Column(String(20))
    bio = Column(Text)
    timezone = Column(String(50), default="UTC")
    language = Column(String(10), default="en")
    
    # Avatar fields
    avatar_url = Column(Text)  # Legacy field
    avatar_icon = Column(Text)
    avatar_image = Column(Text)
    
    # Preferences and settings
    preferences = Column(JSONB, default={})
    selected_theme = Column(String(50), default="sun")  # Legacy field, kept for backwards compatibility
    
    # Option set foreign keys (temporarily without FK constraint until option_values table exists)
    appearance_option_value_id = Column(Integer, nullable=True, index=True)
    itheme_option_value_id = Column(Integer, nullable=True, index=True)
    avatar_display_option_value_id = Column(Integer, nullable=True, index=True)
    
    # Marketing and legal agreements
    agree_to_marketing = Column(Boolean, default=False)
    agree_to_terms = Column(Boolean, default=False)
    
    # Onboarding
    onboarding_completed = Column(Boolean, default=False)
    
    # Navigation (one-to-one with user_navigation table)
    user_navigation_id = Column(UUID(as_uuid=True), nullable=True, unique=True, index=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="profile")
    
    def __repr__(self):
        return f"<UserProfile(id={self.id}, user_id={self.user_id})>"
    
    def to_dict(self):
        """Convert profile to dictionary"""
        return {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "first_name": self.first_name,
            "last_name": self.last_name,
            "phone": self.phone,
            "avatar_url": self.avatar_url,
            "avatar_icon": self.avatar_icon,
            "avatar_image": self.avatar_image,
            "bio": self.bio,
            "timezone": self.timezone,
            "language": self.language,
            "preferences": self.preferences,
            "selected_theme": self.selected_theme,
            "appearance_option_value_id": self.appearance_option_value_id,
            "itheme_option_value_id": self.itheme_option_value_id,
            "avatar_display_option_value_id": self.avatar_display_option_value_id,
            "agree_to_marketing": self.agree_to_marketing,
            "agree_to_terms": self.agree_to_terms,
            "onboarding_completed": self.onboarding_completed,
        }


class LoginAttempt(Base):
    """Login attempt tracking for security"""
    __tablename__ = "login_attempts"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(45), nullable=False, index=True)
    success = Column(Boolean, nullable=False)
    failure_reason = Column(String(100))
    user_agent = Column(Text)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    
    def __repr__(self):
        return f"<LoginAttempt(email={self.email}, success={self.success}, ip={self.ip_address})>"
    
    def to_dict(self):
        """Convert login attempt to dictionary"""
        return {
            "id": str(self.id),
            "email": self.email,
            "ip_address": self.ip_address,
            "success": self.success,
            "failure_reason": self.failure_reason,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class PasswordResetToken(Base):
    """Password reset token model"""
    __tablename__ = "password_reset_tokens"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String(255), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    used = Column(Boolean, default=False)
    used_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    
    def __repr__(self):
        return f"<PasswordResetToken(user_id={self.user_id}, used={self.used})>"


class EmailVerificationToken(Base):
    """Email verification token model"""
    __tablename__ = "email_verification_tokens"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String(255), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    used = Column(Boolean, default=False)
    used_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    
    def __repr__(self):
        return f"<EmailVerificationToken(user_id={self.user_id}, used={self.used})>"


class UserNavigation(Base):
    """User navigation tracking - stores current user context and navigation state"""
    __tablename__ = "user_navigation"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_profile_id = Column(UUID(as_uuid=True), ForeignKey("user_profiles.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    current_smart_hub_id = Column(UUID(as_uuid=True), nullable=True, unique=True, index=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<UserNavigation(id={self.id}, user_profile_id={self.user_profile_id}, current_smart_hub_id={self.current_smart_hub_id})>"
    
    def to_dict(self):
        """Convert user navigation to dictionary"""
        return {
            "id": str(self.id),
            "user_profile_id": str(self.user_profile_id),
            "current_smart_hub_id": str(self.current_smart_hub_id) if self.current_smart_hub_id else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
