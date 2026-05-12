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
    membership = Column(String(50), default="Individual")  # Individual or Enterprise
    email_verified = Column(Boolean, default=False)
    use_password = Column(Boolean, nullable=False, default=True)  # True for password auth, False for OAuth-only
    
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
            "membership": self.membership,
            "email_verified": self.email_verified,
            "oauth_provider": self.oauth_provider,
            "use_password": self.use_password,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
        }
        
        # Include profile info if available (shared DB column spellings where legacy)
        if self.profile:
            data["onboarding_completed"] = self.profile.onboarding_completed
            data["has_user_profile"] = True
            data["phone_varified"] = self.profile.phone_varified
            # DB column: "activeChat_onBoarding_complete" — stable JSON name for clients
            data["chat_onboarding_complete"] = self.profile.activeChat_onBoarding_complete
        else:
            data["onboarding_completed"] = False
            data["has_user_profile"] = False
            data["phone_varified"] = False
            data["chat_onboarding_complete"] = False
        
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
    country_code = Column(String(5), nullable=True)
    # Ear / routing — synapse_number moved to api-server smart_hubs table (keep auth-api resilient)
    phone = Column(String(20))
    phone_identity_id = Column(
        UUID(as_uuid=True),
        ForeignKey("phone_identities.id", ondelete="SET NULL"),
        nullable=True,
        unique=True,
    )
    # Matches shared DB column name (legacy spelling)
    phone_varified = Column(Boolean, default=False, nullable=False)
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
    
    # Option set foreign keys - actual column names in database
    appearance_id = Column(Integer, ForeignKey("option_values.id", ondelete="SET NULL"), nullable=True, index=True, default=6)
    itheme_id = Column(Integer, ForeignKey("option_values.id", ondelete="SET NULL"), nullable=True, index=True, default=10)
    avatar_display_option_value_id = Column(Integer, nullable=True, index=True)
    account_type_id = Column(Integer, ForeignKey("option_values.id", ondelete="SET NULL"), nullable=True, index=True)
    
    # Marketing and legal agreements
    agree_to_marketing = Column(Boolean, default=False)
    agree_to_terms = Column(Boolean, default=False)
    
    # Onboarding
    onboarding_completed = Column(Boolean, default=False)
    activeChat_onBoarding_complete = Column(
        "activeChat_onBoarding_complete",
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
    )

    # Navigation (one-to-one with user_navigation table)
    user_navigation_id = Column(UUID(as_uuid=True), nullable=True, unique=True, index=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="profile")
    phone_identity = relationship(
        "PhoneIdentity",
        foreign_keys=[phone_identity_id],
        back_populates="user_profile",
        uselist=False,
    )
    appearance = relationship("OptionValue", foreign_keys=[appearance_id])
    itheme = relationship("OptionValue", foreign_keys=[itheme_id])
    account_type = relationship("OptionValue", foreign_keys=[account_type_id])
    
    def __repr__(self):
        return f"<UserProfile(id={self.id}, user_id={self.user_id})>"
    
    def to_dict(self):
        """Convert profile to dictionary"""
        return {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "first_name": self.first_name,
            "last_name": self.last_name,
            "country_code": self.country_code,
            "phone": self.phone,
            "phone_identity_id": (
                str(self.phone_identity_id) if self.phone_identity_id else None
            ),
            "phone_varified": self.phone_varified,
            "avatar_url": self.avatar_url,
            "avatar_icon": self.avatar_icon,
            "avatar_image": self.avatar_image,
            "bio": self.bio,
            "timezone": self.timezone,
            "language": self.language,
            "preferences": self.preferences,
            "selected_theme": self.selected_theme,
            "appearance_id": self.appearance_id,
            "itheme_id": self.itheme_id,
            "avatar_display_option_value_id": self.avatar_display_option_value_id,
            "agree_to_marketing": self.agree_to_marketing,
            "agree_to_terms": self.agree_to_terms,
            "onboarding_completed": self.onboarding_completed,
            "activeChat_onBoarding_complete": self.activeChat_onBoarding_complete,
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


class OptionSet(Base):
    """Option set categories (e.g., itheme, appearance, account_type)"""
    __tablename__ = "option_sets"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    
    def __repr__(self):
        return f"<OptionSet(id={self.id}, name={self.name})>"


class OptionValue(Base):
    """Individual option values within option sets"""
    __tablename__ = "option_values"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    option_set_id = Column(Integer, ForeignKey("option_sets.id", ondelete="CASCADE"), nullable=False, index=True)
    value_name = Column(String(100), nullable=False)
    display_name = Column(String(200))
    sort_order = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    
    # Relationship to theme_config
    theme_config = relationship("ThemeConfig", back_populates="option_value", uselist=False)
    
    def __repr__(self):
        return f"<OptionValue(id={self.id}, value_name={self.value_name})>"


class ThemeConfig(Base):
    """Theme configuration attributes for appearance option values"""
    __tablename__ = "theme_configs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    option_value_id = Column(Integer, ForeignKey("option_values.id", ondelete="CASCADE"), nullable=False, unique=True)
    name = Column(String(100), nullable=False)
    text_color = Column(String(7), nullable=False)
    background_color = Column(String(7), nullable=False)
    menu_color = Column(String(7), nullable=False)
    border_line_color = Column(String(7), nullable=False)
    header_overlay_color = Column(String(9))
    theme_metadata = Column(JSONB, default={})
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    
    # Relationship
    option_value = relationship("OptionValue", back_populates="theme_config")
    
    def __repr__(self):
        return f"<ThemeConfig(id={self.id}, name={self.name})>"


