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
from .phone_validator import region_code_for_e164, validate_and_normalise
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

    e164, iso_region = validate_and_normalise(raw_phone, region)

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
            country_code=iso_region,
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
        country_code=iso_region,
    )
    try:
        request_id = await send_otp(
            e164, request_id=request_id, country_code=iso_region, user_id=user_id
        )
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
                country_code=iso_region,
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

    real_phone, otp_country_code = await verify_otp(request_id, code)
    iso_cc = otp_country_code or region_code_for_e164(real_phone)

    await _assert_phone_is_free(real_phone, user_id)

    await _persist_binding(
        user_id=user_id,
        real_phone=real_phone,
        method=VerificationMethod.SMS,
        trust_level=TrustLevel.MED,
        ip=ip,
        country_code=iso_cc,
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
        country_code=iso_cc,
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
    e164, iso_region = validate_and_normalise(raw_phone, region)
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
        country_code=iso_region,
    )
    try:
        return await send_otp(
            e164, request_id=request_id, country_code=iso_region, user_id=user_id
        )
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
                country_code=iso_region,
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
                UPDATE user_profiles
                SET phone_identity_id = NULL,
                    phone_varified = FALSE,
                    updated_at = NOW()
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


async def lookup_phones(
    requester_user_id: str,
    phones: list[str],
    region: str = "GB",
    ip: str | None = None,
) -> dict:
    """Resolve E.164 phones to user_id for registered (non-revoked) identities only."""
    from .phone_validator import validate_and_normalise
    from .rate_limiter import check_limits

    await check_limits(ip=ip, phone=None, user_id=requester_user_id)

    matches: list[dict] = []
    misses: list[dict] = []
    seen_e164: set[str] = set()

    for raw in phones:
        try:
            e164, _ = validate_and_normalise(raw, region)
        except HTTPException:
            misses.append(
                {"phone": raw.strip(), "registered": False, "reason": "invalid_phone"}
            )
            continue

        if e164 in seen_e164:
            continue
        seen_e164.add(e164)

        owner_id = await _owner_user_id_for_phone(e164)
        if owner_id:
            matches.append({"phone": e164, "user_id": owner_id, "registered": True})
        else:
            misses.append({"phone": e164, "registered": False, "reason": "not_bound"})

    return {"matches": matches, "misses": misses}


async def _owner_user_id_for_phone(real_phone: str) -> str | None:
    try:
        cached = await get_json(redis_keys().phone_owner(real_phone))
    except Exception:
        cached = None
    if cached and cached.get("user_id"):
        return str(cached["user_id"])

    if not async_session_maker:
        return None
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
    return str(row["user_id"]) if row else None


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
    country_code: str | None = None,
) -> datetime | None:
    phone_hash = hashlib.sha256(real_phone.encode()).hexdigest()
    iso_cc = country_code or region_code_for_e164(real_phone)
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
                     verification_method, hardware_id, country_code)
                VALUES
                    (CAST(:user_id AS uuid), :real_phone, :phone_hash, :trust_level,
                     :method, :hardware_id, CAST(:country_code AS VARCHAR(5)))
                ON CONFLICT (user_id) DO NOTHING
                RETURNING id, bound_at
                """
            ),
            {
                "user_id": user_id,
                "real_phone": real_phone,
                "phone_hash": phone_hash,
                "trust_level": trust_level.value,
                "method": method.value,
                "hardware_id": hardware_id,
                "country_code": iso_cc,
            },
        )
        row = result.mappings().first()
        identity_id = None
        if row:
            identity_id = row["id"]
            bound_at = row["bound_at"]

        if identity_id is None:
            r2 = await session.execute(
                text(
                    """
                    SELECT id, bound_at FROM phone_identities
                    WHERE user_id = CAST(:uid AS uuid) AND revoked_at IS NULL LIMIT 1
                    """
                ),
                {"uid": user_id},
            )
            row2 = r2.mappings().first()
            if row2:
                identity_id = row2["id"]
                bound_at = row2["bound_at"]

        if identity_id is None:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "error": "Phone identity row missing after bind.",
                    "code": "PHONE_IDENTITY_PERSIST_FAILED",
                },
            )

        await session.execute(
            text(
                """
                UPDATE phone_identities
                SET country_code = COALESCE(country_code, CAST(:cc AS VARCHAR(5)))
                WHERE id = CAST(:pid AS uuid)
                """
            ),
            {"cc": iso_cc, "pid": str(identity_id)},
        )

        await session.execute(
            text(
                """
                UPDATE user_profiles up
                SET
                    phone = pi.real_phone,
                    phone_identity_id = pi.id,
                    phone_varified = TRUE,
                    "activeChat_onBoarding_complete" = TRUE,
                    country_code = COALESCE(CAST(:cc AS VARCHAR(5)), up.country_code),
                    updated_at = NOW()
                FROM phone_identities pi
                WHERE up.user_id = CAST(:uid AS uuid)
                  AND pi.id = CAST(:pid AS uuid)
                  AND pi.user_id = up.user_id
                """
            ),
            {"pid": str(identity_id), "uid": user_id, "cc": iso_cc},
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
        await _log_attempt(
            user_id,
            real_phone,
            method,
            "completed",
            ip,
            user_agent,
            country_code=iso_cc,
        )
    return bound_at


async def _log_attempt(
    user_id: str,
    phone: str,
    method: VerificationMethod,
    attempt_status: str,
    ip: str | None,
    ua: str | None,
    country_code: str | None = None,
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
                             completed_at, country_code)
                        VALUES
                            (CAST(:uid AS uuid), :phone, :channel, :status, CAST(:ip AS inet), :ua,
                             :completed_at, CAST(:country_code AS VARCHAR(5)))
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
                        "country_code": country_code,
                    },
                )
            else:
                await session.execute(
                    text(
                        """
                        INSERT INTO phone_verification_attempts
                            (user_id, real_phone, channel, status, ip_address, user_agent,
                             completed_at, country_code)
                        VALUES
                            (CAST(:uid AS uuid), :phone, :channel, :status, NULL, :ua,
                             :completed_at, CAST(:country_code AS VARCHAR(5)))
                        """
                    ),
                    {
                        "uid": user_id,
                        "phone": phone,
                        "channel": method.value,
                        "status": attempt_status,
                        "ua": ua,
                        "completed_at": completed_at,
                        "country_code": country_code,
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
    country_code: str | None = None,
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
            "country_code": country_code,
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
                        failure_reason = :failure_reason,
                        country_code = COALESCE(CAST(:country_code AS VARCHAR(5)),
                            phone_verification_attempts.country_code)
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
                                 completed_at, request_id, failure_reason, country_code)
                            VALUES
                                (CAST(:uid AS uuid), :phone, :channel, :status,
                                 CAST(:ip AS inet), :ua, :completed_at, :request_id, :failure_reason,
                                 CAST(:country_code AS VARCHAR(5)))
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
                                failure_reason = :failure_reason,
                                country_code = COALESCE(CAST(:country_code AS VARCHAR(5)),
                                    phone_verification_attempts.country_code)
                            WHERE request_id = :request_id
                            """
                        ),
                        params,
                    )
            await session.commit()
    except Exception as exc:
        logger.error("[Identity] Failed to upsert attempt", error=str(exc))
