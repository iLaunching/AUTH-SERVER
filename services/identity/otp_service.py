"""Custom OTP stored hashed in Redis; SMS via configured provider."""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import time
from dataclasses import asdict, dataclass

import structlog
from fastapi import HTTPException, status

from .redis_helpers import delete, keys as redis_keys
from .settings import get_identity_settings
from .sms_providers import get_sms_provider

logger = structlog.get_logger()
# Plain line next to uvicorn access logs (structlog uses JSONRenderer in main.py).
_plain = logging.getLogger("identity_otp")


def _phone_tail(phone: str, n: int = 4) -> str:
    digits = "".join(c for c in phone if c.isdigit())
    return digits[-n:] if len(digits) >= n else "****"


async def _invalidate_previous_otp_for_user(client, user_id: str, keep_request_id: str) -> None:
    """If the user starts a new bind while an OTP is still valid, drop the old Redis OTP so only one code is live."""
    key = redis_keys().active_otp_for_user(user_id)
    raw = await client.get(key)
    if not raw:
        return
    try:
        old = raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
    except Exception:
        return
    if not old or old == keep_request_id:
        return
    await delete(redis_keys().otp(old))
    logger.info(
        "otp_superseded",
        user_id=user_id,
        superseded_request_id_prefix=old[:12],
        new_request_id_prefix=keep_request_id[:12],
    )


@dataclass
class _OTPRecord:
    phone: str
    code_hash: str
    attempts: int
    created_at: float
    request_id: str
    country_code: str | None = None
    user_id: str | None = None


async def send_otp(
    phone: str,
    request_id: str | None = None,
    *,
    country_code: str | None = None,
    user_id: str | None = None,
) -> str:
    s = get_identity_settings()
    code = _generate_code(s.otp_length)
    request_id = request_id or secrets.token_urlsafe(24)

    record = _OTPRecord(
        phone=phone,
        code_hash=_hash(code),
        attempts=0,
        created_at=time.time(),
        request_id=request_id,
        country_code=country_code,
        user_id=user_id,
    )

    from config.database import get_redis

    client = await get_redis()
    if not client:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "Service temporarily unavailable.", "code": "REDIS_UNAVAILABLE"},
        )

    if user_id:
        await _invalidate_previous_otp_for_user(client, user_id, request_id)

    await client.set(
        redis_keys().otp(request_id),
        json.dumps(asdict(record)),
        ex=s.ttl_otp,
    )

    provider_name = s.sms_provider
    message = s.otp_message_template.format(brand=s.brand_name, code=code)
    logger.info(
        "otp_sms_dispatch_start",
        request_id=request_id,
        provider=provider_name,
        phone_tail=_phone_tail(phone),
    )
    result = await get_sms_provider().send_sms(phone, message)

    if not result.success:
        await delete(redis_keys().otp(request_id))
        logger.error(
            "otp_sms_dispatch_failed",
            request_id=request_id,
            provider=provider_name,
            phone_tail=_phone_tail(phone),
            error=result.error,
        )
        _plain.warning(
            "[identity_otp] SMS_FAILED request_id=%s provider=%s to=***%s error=%s",
            request_id,
            provider_name,
            _phone_tail(phone),
            result.error,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "error": "Failed to send verification code. Please try again.",
                "code": "SMS_FAILED",
                "provider_error": result.error,
            },
        )

    if user_id:
        await client.set(
            redis_keys().active_otp_for_user(user_id),
            request_id,
            ex=s.ttl_otp,
        )

    logger.info(
        "otp_sms_dispatch_ok",
        request_id=request_id,
        provider=provider_name,
        phone_tail=_phone_tail(phone),
        message_id=result.message_id,
    )
    _plain.info(
        "[identity_otp] SMS_ACCEPTED_BY_PROVIDER request_id=%s provider=%s to=***%s message_id=%s",
        request_id,
        provider_name,
        _phone_tail(phone),
        result.message_id or "n/a",
    )
    return request_id


async def verify_otp(request_id: str, submitted_code: str) -> tuple[str, str | None]:
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

    raw_dict = json.loads(raw)
    record = _OTPRecord(
        phone=raw_dict["phone"],
        code_hash=raw_dict["code_hash"],
        attempts=int(raw_dict.get("attempts", 0)),
        created_at=float(raw_dict["created_at"]),
        request_id=raw_dict["request_id"],
        country_code=raw_dict.get("country_code"),
        user_id=raw_dict.get("user_id"),
    )

    if record.attempts >= s.otp_max_attempts:
        await delete(redis_keys().otp(request_id))
        if record.user_id:
            await delete(redis_keys().active_otp_for_user(record.user_id))
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
    if record.user_id:
        await delete(redis_keys().active_otp_for_user(record.user_id))
    logger.info("otp_verified_ok", request_id=request_id, phone_tail=_phone_tail(record.phone))
    return record.phone, record.country_code


def _generate_code(length: int) -> str:
    return "".join(str(secrets.randbelow(10)) for _ in range(length))


def _hash(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()
