"""Redis-backed rate limiting for identity endpoints."""

from __future__ import annotations

import asyncio

import structlog
from fastapi import HTTPException, status

from .redis_helpers import incr_with_ttl, keys as redis_keys
from .settings import get_identity_settings

logger = structlog.get_logger()


async def check_limits(ip: str | None, phone: str | None, user_id: str | None = None) -> None:
    await asyncio.gather(
        _check_ip(ip),
        _check_phone(phone),
        _check_user(user_id),
    )


async def _check_ip(ip: str | None) -> None:
    if not ip:
        return
    s = get_identity_settings()
    try:
        count = await incr_with_ttl(redis_keys().rate_ip(ip), s.ttl_rate_limit_ip)
        if count > s.rate_limit_ip_max:
            logger.warning("[RateLimit] IP exceeded", ip=ip, count=count)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={"error": "Too many requests. Try again later.", "code": "RATE_LIMIT_IP"},
            )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("[RateLimit] Redis error on IP check — failing open", error=str(exc))


async def _check_phone(phone: str | None) -> None:
    if not phone:
        return
    s = get_identity_settings()
    try:
        count = await incr_with_ttl(redis_keys().rate_phone(phone), s.ttl_rate_limit_phone)
        if count > s.rate_limit_phone_max_per_day:
            logger.warning("[RateLimit] Phone exceeded", phone=phone, count=count)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "error": "Too many attempts for this number. Try again tomorrow.",
                    "code": "RATE_LIMIT_PHONE",
                },
            )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("[RateLimit] Redis error on phone check — failing open", error=str(exc))


async def _check_user(user_id: str | None) -> None:
    if not user_id:
        return
    s = get_identity_settings()
    try:
        count = await incr_with_ttl(redis_keys().rate_user(user_id), s.ttl_rate_limit_user)
        if count > s.rate_limit_user_max:
            logger.warning("[RateLimit] User exceeded", user_id=user_id, count=count)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={"error": "Too many requests. Try again later.", "code": "RATE_LIMIT_USER"},
            )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("[RateLimit] Redis error on user check — failing open", error=str(exc))
