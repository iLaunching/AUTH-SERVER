"""
Optional JWT access-token claims derived from user_profiles (shared DB with API server).
"""

from __future__ import annotations

from typing import Dict, Optional, Union
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models.user import User, UserProfile


def synapse_claims_from_profile(profile: Optional[UserProfile]) -> Optional[Dict[str, str]]:
    if not profile:
        return None
    sn = getattr(profile, "synapse_number", None)
    if sn is None or not str(sn).strip():
        return None
    return {"synapse_number": str(sn).strip()}


def synapse_claims_from_user(user: Optional[User]) -> Optional[Dict[str, str]]:
    if not user:
        return None
    return synapse_claims_from_profile(user.profile)


async def synapse_claims_for_user_id(
    db: AsyncSession, user_id: Union[str, UUID]
) -> Optional[Dict[str, str]]:
    uid = UUID(str(user_id))
    r = await db.execute(select(UserProfile.synapse_number).where(UserProfile.user_id == uid))
    sn = r.scalar_one_or_none()
    if sn is None or not str(sn).strip():
        return None
    return {"synapse_number": str(sn).strip()}
