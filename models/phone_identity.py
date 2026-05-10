"""
phone_identities — see migrations/010_phone_identity.sql
"""

import uuid

from sqlalchemy import Column
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from config.database import Base


class PhoneIdentity(Base):
    __tablename__ = "phone_identities"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    user_profile = relationship(
        "UserProfile",
        back_populates="phone_identity",
        uselist=False,
    )
