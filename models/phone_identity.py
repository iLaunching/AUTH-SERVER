"""
phone_identities — see migrations/010_phone_identity.sql
"""

import uuid

from sqlalchemy import Column, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from config.database import Base


class PhoneIdentity(Base):
    __tablename__ = "phone_identities"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    country_code = Column(String(5), nullable=True)

    user_profile = relationship(
        "UserProfile",
        back_populates="phone_identity",
        uselist=False,
    )
