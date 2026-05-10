"""Custom OTP stored hashed in Redis; SMS via configured provider."""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import asdict, dataclass

import structlog
from fastapi import HTTPException, status

from .redis_helpers import delete, keys as redis_keys
from .settings import get_identity_settings
from .sms_providers import get_sms_provider

logger = structlog.get_logger()


@dataclass
class _OTPRecord:
    phone: str
    code_hash: str
    attempts: int
    created_at: float
    request_id: str


async def send_otp(phone: str, request_id: str | None = None) -> str:
    s = get_identity_settings()
    code = _generate_code(s.otp_length)
    request_id = request_id or secrets.token_urlsafe(24)

    record = _OTPRecord(
        phone=phone,
        code_hash=_hash(code),
        attempts=0,
        created_at=time.time(),
        request_id=request_id,
    )

    from config.database import get_redis

    client = await get_redis()
    if not client:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "Service temporarily unavailable.", "code": "REDIS_UNAVAILABLE"},
        )

    await client.set(
        redis_keys().otp(request_id),
        json.dumps(asdict(record)),
        ex=s.ttl_otp,
    )

    message = s.otp_message_template.format(brand=s.brand_name, code=code)
    result = await get_sms_provider().send_sms(phone, message)

    if not result.success:
        await delete(redis_keys().otp(request_id))
        logger.error("[OTP] SMS delivery failed", phone=phone, error=result.error)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "error": "Failed to send verification code. Please try again.",
                "code": "SMS_FAILED",
                "provider_error": result.error,
            },
        )

    logger.info("[OTP] Code sent", request_id=request_id)
    return request_id


async def verify_otp(request_id: str, submitted_code: str) -> str:
    s = get_identity_settings()
    from config.database import get_redis

    client = await get_redis()
    if not client:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "Service temporarily unavailable.", "code": "REDIS_UNAVAILABLE"},
        )

    raw = await client.get(redis_keys().otp(request_id))

    if not raw:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "Code has expired or does not exist.", "code": "OTP_EXPIRED"},
        )

    record = _OTPRecord(**json.loads(raw))

    if record.attempts >= s.otp_max_attempts:
        await delete(redis_keys().otp(request_id))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"error": "Too many incorrect attempts. Please request a new code.", "code": "OTP_MAX_ATTEMPTS"},
        )

    submitted_hash = _hash(submitted_code.strip())
    correct = secrets.compare_digest(submitted_hash, record.code_hash)

    if not correct:
        record.attempts += 1
        await client.set(
            redis_keys().otp(request_id),
            json.dumps(asdict(record)),
            ex=s.ttl_otp,
        )
        remaining = s.otp_max_attempts - record.attempts
        logger.warning("[OTP] Wrong code", request_id=request_id, attempts=record.attempts)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": f"Incorrect code. {remaining} attempt(s) remaining.",
                "code": "WRONG_CODE",
                "attempts_remaining": remaining,
            },
        )

    await delete(redis_keys().otp(request_id))
    logger.info("[OTP] Verified", request_id=request_id)
    return record.phone


def _generate_code(length: int) -> str:
    return "".join(str(secrets.randbelow(10)) for _ in range(length))


def _hash(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()
