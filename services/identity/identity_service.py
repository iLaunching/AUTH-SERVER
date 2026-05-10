"""Phone binding: App Attest (HIGH) or SMS OTP (MED)."""

from __future__ import annotations

import asyncio
import hashlib
import secrets
from datetime import datetime, timezone

import structlog
from fastapi import HTTPException, status
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from config.database import async_session_maker

from .challenge_service import consume_challenge
from .otp_service import send_otp, verify_otp
from .phone_validator import validate_and_normalise
from .rate_limiter import check_limits
from .redis_helpers import delete, get_json, keys as redis_keys, set_json
from .schemas import (
    BindPhoneResponse,
    BindStatus,
    ConfirmOTPResponse,
    IdentityResponse,
    TrustLevel,
    VerificationMethod,
)
from .settings import get_identity_settings

logger = structlog.get_logger()


async def start_binding(
    user_id: str,
    raw_phone: str,
    ip: str | None,
    user_agent: str | None,
    region: str = "GB",
    attest_passed: bool = False,
    attest_key_hash: str | None = None,
    attest_challenge: str | None = None,
) -> BindPhoneResponse:
    await check_limits(ip, raw_phone, user_id)

    e164, _ = validate_and_normalise(raw_phone, region)

    existing = await _get_identity_from_db(user_id)
    if existing:
        logger.info("[Identity] Already bound", user_id=user_id)
        return BindPhoneResponse(
            status=BindStatus.ALREADY_BOUND,
            trust_level=TrustLevel(existing["trust_level"]),
            real_phone_e164=existing["real_phone"],
        )

    await _assert_phone_is_free(e164, user_id)

    if attest_passed:
        if not attest_challenge:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "attest_challenge is required when attest_passed=true.",
                    "code": "CHALLENGE_REQUIRED",
                },
            )
        await consume_challenge(attest_challenge, user_id)

        bound_at = await _persist_binding(
            user_id=user_id,
            real_phone=e164,
            method=VerificationMethod.APP_ATTEST,
            trust_level=TrustLevel.HIGH,
            hardware_id=attest_key_hash,
            ip=ip,
            user_agent=user_agent,
        )
        logger.info("[Identity] Bound via App Attest — no SMS sent", user_id=user_id)
        return BindPhoneResponse(
            status=BindStatus.BOUND,
            trust_level=TrustLevel.HIGH,
            method=VerificationMethod.APP_ATTEST,
            real_phone_e164=e164,
        )

    request_id = secrets.token_urlsafe(24)
    # Strict tracking: persist pending attempt BEFORE sending SMS.
    await _upsert_attempt(
        user_id=user_id,
        phone=e164,
        method=VerificationMethod.SMS,
        request_id=request_id,
        attempt_status="pending",
        ip=ip,
        ua=user_agent,
        failure_reason=None,
    )
    try:
        request_id = await send_otp(e164, request_id=request_id)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_502_BAD_GATEWAY:
            provider_err = None
            if isinstance(exc.detail, dict):
                provider_err = exc.detail.get("provider_error")
            await _upsert_attempt(
                user_id=user_id,
                phone=e164,
                method=VerificationMethod.SMS,
                request_id=request_id,
                attempt_status="failed",
                ip=ip,
                ua=user_agent,
                failure_reason=str(provider_err or "SMS_FAILED"),
            )
        raise

    return BindPhoneResponse(
        status=BindStatus.PENDING_OTP,
        method=VerificationMethod.SMS,
        request_id=request_id,
    )


async def confirm_binding(
    user_id: str,
    request_id: str,
    code: str,
    ip: str | None,
) -> ConfirmOTPResponse:
    await check_limits(ip, None, user_id)

    real_phone = await verify_otp(request_id, code)

    await _assert_phone_is_free(real_phone, user_id)

    await _persist_binding(
        user_id=user_id,
        real_phone=real_phone,
        method=VerificationMethod.SMS,
        trust_level=TrustLevel.MED,
        ip=ip,
    )

    # Strict tracking: mark the same attempt as completed before returning.
    await _upsert_attempt(
        user_id=user_id,
        phone=real_phone,
        method=VerificationMethod.SMS,
        request_id=request_id,
        attempt_status="completed",
        ip=ip,
        ua=None,
        failure_reason=None,
    )

    return ConfirmOTPResponse(
        trust_level=TrustLevel.MED,
        real_phone_e164=real_phone,
    )


async def get_identity(user_id: str) -> IdentityResponse | None:
    raw = await _get_identity_cached(user_id)
    if not raw:
        return None
    bound_at = raw["bound_at"]
    if isinstance(bound_at, datetime):
        bound_at = bound_at.isoformat()
    return IdentityResponse(
        user_id=str(raw["user_id"]),
        real_phone=raw["real_phone"],
        trust_level=TrustLevel(raw["trust_level"]),
        method=VerificationMethod(raw["verification_method"]),
        bound_at=bound_at,
    )


async def resend_otp(
    user_id: str,
    raw_phone: str,
    ip: str | None,
    region: str = "GB",
) -> str:
    await check_limits(ip, raw_phone, user_id)
    e164, _ = validate_and_normalise(raw_phone, region)
    request_id = secrets.token_urlsafe(24)
    await _upsert_attempt(
        user_id=user_id,
        phone=e164,
        method=VerificationMethod.SMS,
        request_id=request_id,
        attempt_status="pending",
        ip=ip,
        ua=None,
        failure_reason=None,
    )
    try:
        return await send_otp(e164, request_id=request_id)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_502_BAD_GATEWAY:
            provider_err = None
            if isinstance(exc.detail, dict):
                provider_err = exc.detail.get("provider_error")
            await _upsert_attempt(
                user_id=user_id,
                phone=e164,
                method=VerificationMethod.SMS,
                request_id=request_id,
                attempt_status="failed",
                ip=ip,
                ua=None,
                failure_reason=str(provider_err or "SMS_FAILED"),
            )
        raise


async def revoke_identity(user_id: str) -> None:
    if not async_session_maker:
        return
    async with async_session_maker() as session:
        await session.execute(
            text(
                """
                UPDATE phone_identities SET revoked_at = NOW()
                WHERE user_id = CAST(:uid AS uuid) AND revoked_at IS NULL
                """
            ),
            {"uid": user_id},
        )
        await session.execute(
            text(
                """
                UPDATE user_profiles SET phone_identity_id = NULL, updated_at = NOW()
                WHERE user_id = CAST(:uid AS uuid)
                """
            ),
            {"uid": user_id},
        )
        await session.commit()

    await delete(redis_keys().identity(user_id))
    logger.info("[Identity] Revoked", user_id=user_id)


async def _get_identity_cached(user_id: str) -> dict | None:
    cached: dict | None = None
    try:
        cached = await get_json(redis_keys().identity(user_id))
    except Exception:
        cached = None
    if cached:
        return cached
    data = await _get_identity_from_db(user_id)
    if data:
        s = get_identity_settings()
        try:
            await set_json(redis_keys().identity(user_id), data, s.ttl_identity_cache)
        except Exception:
            pass
    return data


async def _get_identity_from_db(user_id: str) -> dict | None:
    if not async_session_maker:
        return None
    async with async_session_maker() as session:
        result = await session.execute(
            text(
                """
                SELECT user_id::text AS user_id, real_phone, trust_level, verification_method, bound_at
                FROM phone_identities
                WHERE user_id = CAST(:uid AS uuid) AND revoked_at IS NULL
                LIMIT 1
                """
            ),
            {"uid": user_id},
        )
        row = result.mappings().first()
    return dict(row) if row else None


async def _assert_phone_is_free(real_phone: str, requesting_user_id: str) -> None:
    try:
        cached = await get_json(redis_keys().phone_owner(real_phone))
    except Exception:
        cached = None
    owner_id = cached.get("user_id") if cached else None

    if not owner_id and async_session_maker:
        async with async_session_maker() as session:
            result = await session.execute(
                text(
                    """
                    SELECT user_id::text AS user_id FROM phone_identities
                    WHERE real_phone = :p AND revoked_at IS NULL LIMIT 1
                    """
                ),
                {"p": real_phone},
            )
            row = result.mappings().first()
            owner_id = str(row["user_id"]) if row else None

    if owner_id and owner_id != requesting_user_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "This phone number is already linked to another account.",
                "code": "PHONE_ALREADY_BOUND",
            },
        )


async def _persist_binding(
    user_id: str,
    real_phone: str,
    method: VerificationMethod,
    trust_level: TrustLevel,
    ip: str | None = None,
    user_agent: str | None = None,
    hardware_id: str | None = None,
) -> datetime | None:
    phone_hash = hashlib.sha256(real_phone.encode()).hexdigest()
    bound_at: datetime | None = None

    if not async_session_maker:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "Database unavailable.", "code": "DB_UNAVAILABLE"},
        )

    async with async_session_maker() as session:
        result = await session.execute(
            text(
                """
                INSERT INTO phone_identities
                    (user_id, real_phone, real_phone_hash, trust_level,
                     verification_method, hardware_id)
                VALUES
                    (CAST(:user_id AS uuid), :real_phone, :phone_hash, :trust_level,
                     :method, :hardware_id)
                ON CONFLICT (user_id) DO NOTHING
                RETURNING bound_at
                """
            ),
            {
                "user_id": user_id,
                "real_phone": real_phone,
                "phone_hash": phone_hash,
                "trust_level": trust_level.value,
                "method": method.value,
                "hardware_id": hardware_id,
            },
        )
        row = result.mappings().first()
        if row:
            bound_at = row["bound_at"]

        if bound_at is None:
            r2 = await session.execute(
                text(
                    """
                    SELECT bound_at FROM phone_identities
                    WHERE user_id = CAST(:uid AS uuid) AND revoked_at IS NULL LIMIT 1
                    """
                ),
                {"uid": user_id},
            )
            row2 = r2.mappings().first()
            if row2:
                bound_at = row2["bound_at"]

        await session.execute(
            text(
                """
                UPDATE user_profiles up
                SET
                    phone = :phone,
                    phone_identity_id = pi.id,
                    updated_at = NOW()
                FROM phone_identities pi
                WHERE up.user_id = CAST(:uid AS uuid)
                  AND pi.user_id = up.user_id
                  AND pi.revoked_at IS NULL
                """
            ),
            {"phone": real_phone, "uid": user_id},
        )
        await session.commit()

    s = get_identity_settings()
    data = {
        "user_id": user_id,
        "real_phone": real_phone,
        "trust_level": trust_level.value,
        "verification_method": method.value,
        "bound_at": bound_at.isoformat() if bound_at else datetime.now(timezone.utc).isoformat(),
    }
    try:
        await set_json(redis_keys().identity(user_id), data, s.ttl_identity_cache)
        await set_json(redis_keys().phone_owner(real_phone), {"user_id": user_id}, s.ttl_identity_cache)
    except Exception as exc:
        logger.error("[Identity] Cache update failed", error=str(exc))

    # App Attest has no OTP request_id row in phone_verification_attempts.
    # SMS completion is recorded in confirm_binding via _upsert_attempt (same request_id).
    if method == VerificationMethod.APP_ATTEST:
        await _log_attempt(user_id, real_phone, method, "completed", ip, user_agent)
    return bound_at


async def _log_attempt(
    user_id: str,
    phone: str,
    method: VerificationMethod,
    attempt_status: str,
    ip: str | None,
    ua: str | None,
) -> None:
    if not async_session_maker:
        return
    try:
        completed_at = None if attempt_status == "pending" else datetime.now(timezone.utc)
        async with async_session_maker() as session:
            if ip:
                await session.execute(
                    text(
                        """
                        INSERT INTO phone_verification_attempts
                            (user_id, real_phone, channel, status, ip_address, user_agent,
                             completed_at)
                        VALUES
                            (CAST(:uid AS uuid), :phone, :channel, :status, CAST(:ip AS inet), :ua,
                             :completed_at)
                        """
                    ),
                    {
                        "uid": user_id,
                        "phone": phone,
                        "channel": method.value,
                        "status": attempt_status,
                        "ip": ip,
                        "ua": ua,
                        "completed_at": completed_at,
                    },
                )
            else:
                await session.execute(
                    text(
                        """
                        INSERT INTO phone_verification_attempts
                            (user_id, real_phone, channel, status, ip_address, user_agent,
                             completed_at)
                        VALUES
                            (CAST(:uid AS uuid), :phone, :channel, :status, NULL, :ua,
                             :completed_at)
                        """
                    ),
                    {
                        "uid": user_id,
                        "phone": phone,
                        "channel": method.value,
                        "status": attempt_status,
                        "ua": ua,
                        "completed_at": completed_at,
                    },
                )
            await session.commit()
    except Exception as exc:
        logger.error("[Identity] Failed to log attempt", error=str(exc))


async def _upsert_attempt(
    user_id: str,
    phone: str,
    method: VerificationMethod,
    request_id: str,
    attempt_status: str,
    ip: str | None,
    ua: str | None,
    failure_reason: str | None,
) -> None:
    """
    One row per OTP request_id:
      - bind/resend inserts pending
      - confirm updates to completed
    """
    if not async_session_maker:
        return
    try:
        completed_at = None if attempt_status == "pending" else datetime.now(timezone.utc)
        params = {
            "uid": user_id,
            "phone": phone,
            "channel": method.value,
            "status": attempt_status,
            "ip": ip,
            "ua": ua,
            "completed_at": completed_at,
            "request_id": request_id,
            "failure_reason": failure_reason,
        }
        async with async_session_maker() as session:
            # Partial unique index on request_id cannot back ON CONFLICT (request_id).
            result = await session.execute(
                text(
                    """
                    UPDATE phone_verification_attempts
                    SET
                        user_id = CAST(:uid AS uuid),
                        real_phone = :phone,
                        channel = :channel,
                        status = :status,
                        ip_address = CAST(:ip AS inet),
                        user_agent = :ua,
                        completed_at = :completed_at,
                        failure_reason = :failure_reason
                    WHERE request_id = :request_id
                    """
                ),
                params,
            )
            if result.rowcount == 0:
                try:
                    await session.execute(
                        text(
                            """
                            INSERT INTO phone_verification_attempts
                                (user_id, real_phone, channel, status, ip_address, user_agent,
                                 completed_at, request_id, failure_reason)
                            VALUES
                                (CAST(:uid AS uuid), :phone, :channel, :status,
                                 CAST(:ip AS inet), :ua, :completed_at, :request_id, :failure_reason)
                            """
                        ),
                        params,
                    )
                except IntegrityError:
                    await session.rollback()
                    await session.execute(
                        text(
                            """
                            UPDATE phone_verification_attempts
                            SET
                                user_id = CAST(:uid AS uuid),
                                real_phone = :phone,
                                channel = :channel,
                                status = :status,
                                ip_address = CAST(:ip AS inet),
                                user_agent = :ua,
                                completed_at = :completed_at,
                                failure_reason = :failure_reason
                            WHERE request_id = :request_id
                            """
                        ),
                        params,
                    )
            await session.commit()
    except Exception as exc:
        logger.error("[Identity] Failed to upsert attempt", error=str(exc))
