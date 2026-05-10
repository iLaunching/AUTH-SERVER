"""App Attest challenge generation and consumption."""

from __future__ import annotations

import secrets

import structlog
from fastapi import HTTPException, status
from sqlalchemy import text

from config.database import async_session_maker
from .redis_helpers import delete, get_json, keys as redis_keys, set_json
from .settings import get_identity_settings

logger = structlog.get_logger()


async def generate_challenge(user_id: str) -> str:
    challenge = secrets.token_hex(32)
    s = get_identity_settings()

    await set_json(
        redis_keys().attest_challenge(challenge),
        {"user_id": user_id, "used": False},
        s.ttl_attest_challenge,
    )

    if async_session_maker:
        try:
            async with async_session_maker() as session:
                await session.execute(
                    text(
                        """
                        INSERT INTO attest_challenges (challenge, user_id)
                        VALUES (:challenge, CAST(:user_id AS uuid))
                        """
                    ),
                    {"challenge": challenge, "user_id": user_id},
                )
                await session.commit()
        except Exception as exc:
            logger.error("[Challenge] DB write failed (non-fatal)", error=str(exc))

    logger.info("[Challenge] Generated", user_id=user_id)
    return challenge


async def consume_challenge(challenge: str, user_id: str) -> None:
    cache_key = redis_keys().attest_challenge(challenge)
    cached = await get_json(cache_key)

    if not cached:
        _fail("App Attest challenge not found or expired. Please request a new one.", "CHALLENGE_INVALID")

    if cached.get("used"):
        _fail("App Attest challenge has already been used.", "CHALLENGE_ALREADY_USED")

    if cached.get("user_id") != user_id:
        logger.warning(
            "[Challenge] user_id mismatch — possible replay attempt",
            user_id=user_id,
            challenge_owner=cached.get("user_id"),
        )
        _fail("App Attest challenge is not valid for this account.", "CHALLENGE_USER_MISMATCH")

    await delete(cache_key)

    if async_session_maker:
        try:
            async with async_session_maker() as session:
                await session.execute(
                    text(
                        """
                        UPDATE attest_challenges
                        SET used = TRUE
                        WHERE challenge = :challenge AND user_id = CAST(:user_id AS uuid)
                        """
                    ),
                    {"challenge": challenge, "user_id": user_id},
                )
                await session.commit()
        except Exception as exc:
            logger.error("[Challenge] DB update failed (non-fatal)", error=str(exc))

    logger.info("[Challenge] Consumed", user_id=user_id)


def _fail(message: str, code: str) -> None:
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={"error": message, "code": code},
    )
