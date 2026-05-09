import asyncio

import structlog
from fastapi import HTTPException, status

from .redis_helpers import incr_with_ttl, keys
from .settings import get_verification_settings

logger = structlog.get_logger()


async def check_limits(ip: str | None, phone_number: str | None) -> None:
    await asyncio.gather(
        _check_ip_limit(ip),
        _check_phone_limit(phone_number),
    )


async def _check_ip_limit(ip: str | None) -> None:
    if not ip:
        return

    s = get_verification_settings()
    key = keys().rate_limit_ip(ip)

    try:
        count = await incr_with_ttl(key, s.redis_ttl_rate_limit_ip)
        if count > s.rate_limit_ip_max:
            logger.warning("IP rate limit exceeded", ip=ip, count=count, max=s.rate_limit_ip_max)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={"error": "Too many verification requests. Try again later.", "code": "RATE_LIMIT_IP"},
            )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Redis error on IP rate limit (failing open)", error=str(exc))


async def _check_phone_limit(phone_number: str | None) -> None:
    if not phone_number:
        return

    s = get_verification_settings()
    key = keys().rate_limit_phone(phone_number)

    try:
        count = await incr_with_ttl(key, s.redis_ttl_rate_limit_phone)
        if count > s.rate_limit_phone_max_per_day:
            logger.warning(
                "Phone rate limit exceeded",
                phone_number=phone_number,
                count=count,
                max=s.rate_limit_phone_max_per_day,
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={"error": "Too many attempts for this number. Try again tomorrow.", "code": "RATE_LIMIT_PHONE"},
            )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Redis error on phone rate limit (failing open)", error=str(exc))

