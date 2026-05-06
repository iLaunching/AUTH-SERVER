"""
Optional JWT access-token claims derived from user_profiles (shared DB with API server).
"""

from __future__ import annotations

from typing import Dict, Optional, Union
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from models.user import User, UserProfile


def synapse_claims_from_profile(profile: Optional[UserProfile]) -> Optional[Dict[str, str]]:
    # synapse_number is no longer stored on auth-api user_profiles
    return None


def synapse_claims_from_user(user: Optional[User]) -> Optional[Dict[str, str]]:
    if not user:
        return None
    return synapse_claims_from_profile(user.profile)


async def synapse_claims_for_user_id(
    db: AsyncSession, user_id: Union[str, UUID]
) -> Optional[Dict[str, str]]:
    uid = UUID(str(user_id))
    # synapse_number moved to api-server smart_hubs table; pick default hub first.
    r = await db.execute(
        text(
            """
            SELECT synapse_number
            FROM smart_hubs
            WHERE owner_id = :uid
              AND synapse_number IS NOT NULL
              AND synapse_number <> ''
            ORDER BY is_default DESC, created_at ASC
            LIMIT 1
            """
        ),
        {"uid": str(uid)},
    )
    sn = r.scalar_one_or_none()
    if sn is None or not str(sn).strip():
        return None
    return {"synapse_number": str(sn).strip()}
