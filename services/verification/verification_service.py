import asyncio
import time

import structlog
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from . import vonage_service, rate_limiter, db_queries
from .phone_validator import validate_and_normalise
from .redis_helpers import delete, get_json, keys, set_json
from .schemas import (
    CheckSmsCodeResponse,
    PendingVerificationState,
    StartVerificationResponse,
    TrustLevel,
    VerificationChannel,
    VerificationStatus,
    VerificationStatusResponse,
)
from .settings import get_verification_settings

logger = structlog.get_logger()


async def start_verification(
    db: AsyncSession,
    raw_phone: str,
    user_id: str,
    ip: str | None,
    user_agent: str | None,
    region: str = "GB",
) -> StartVerificationResponse:
    s = get_verification_settings()

    await rate_limiter.check_limits(ip, raw_phone)
    e164, _ = validate_and_normalise(raw_phone, region)

    existing = await db_queries.get_active_verification(db, user_id)
    if existing:
        return StartVerificationResponse(
            status=VerificationStatus.ALREADY_VERIFIED,
            trust_level=TrustLevel(existing["trust_level"]),
        )

    result = await vonage_service.start_verification(e164)

    state = PendingVerificationState(
        request_id=result.request_id,
        user_id=user_id,
        phone_number=e164,
        started_at=time.time(),
    )
    await set_json(
        keys().verify_request(result.request_id),
        state.model_dump(),
        s.redis_ttl_verify_request,
    )

    # Fire-and-forget audit logging (do not block response)
    asyncio.create_task(_safe_create_attempt(
        user_id=user_id,
        phone_number=e164,
        vonage_request_id=result.request_id,
        ip_address=ip,
        user_agent=user_agent,
    ))

    return StartVerificationResponse(
        status=VerificationStatus.PENDING,
        request_id=result.request_id,
        check_url=result.check_url,
        channel=VerificationChannel.SILENT_AUTH,
    )


async def fallback_to_sms_verification(
    _db: AsyncSession,
    user_id: str,
    request_id: str,
    ip: str | None,
    user_agent: str | None,
) -> StartVerificationResponse:
    """
    Cancel the silent_auth Vonage session (best effort) and start a new SMS-only verification.
    Redis state moves to the new request_id so `/verify/check` and webhooks stay consistent.
    """
    s = get_verification_settings()

    await rate_limiter.check_limits(ip, None)

    state_data = await get_json(keys().verify_request(request_id))
    if not state_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "Verification session not found or expired.", "code": "REQUEST_NOT_FOUND"},
        )

    state = PendingVerificationState(**state_data)
    if state.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "Not allowed for this verification session.", "code": "FORBIDDEN"},
        )

    await vonage_service.cancel_verification(request_id)

    result = await vonage_service.start_sms_verification(state.phone_number)

    await delete(keys().verify_request(request_id))

    new_state = PendingVerificationState(
        request_id=result.request_id,
        user_id=user_id,
        phone_number=state.phone_number,
        started_at=time.time(),
    )
    await set_json(
        keys().verify_request(result.request_id),
        new_state.model_dump(),
        s.redis_ttl_verify_request,
    )

    asyncio.create_task(_safe_create_attempt(
        user_id=user_id,
        phone_number=state.phone_number,
        vonage_request_id=result.request_id,
        ip_address=ip,
        user_agent=user_agent,
    ))

    return StartVerificationResponse(
        status=VerificationStatus.PENDING,
        request_id=result.request_id,
        check_url=result.check_url,
        channel=VerificationChannel.SMS,
    )


async def check_sms_code(
    db: AsyncSession,
    request_id: str,
    code: str,
    user_id: str,
    ip: str | None,
) -> CheckSmsCodeResponse:
    await rate_limiter.check_limits(ip, None)

    await vonage_service.check_verification_code(request_id, code)

    state_data = await get_json(keys().verify_request(request_id))
    if not state_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "Verification request not found or expired.", "code": "REQUEST_NOT_FOUND"},
        )

    state = PendingVerificationState(**state_data)

    await _persist_verified_identity(
        db=db,
        user_id=state.user_id,
        phone_number=state.phone_number,
        method="sms",
        trust_level=TrustLevel.MED,
        request_id=request_id,
    )
    await delete(keys().verify_request(request_id))

    return CheckSmsCodeResponse(status="verified", trust_level=TrustLevel.MED)


async def handle_webhook(db: AsyncSession, payload: dict) -> None:
    request_id = payload.get("request_id")
    wh_status = payload.get("status")
    channel = payload.get("channel", "sms")

    if not request_id:
        logger.warning("Webhook missing request_id", payload=str(payload)[:200])
        return

    state_data = await get_json(keys().verify_request(request_id))
    if not state_data:
        return

    state = PendingVerificationState(**state_data)

    if wh_status == "completed":
        trust_level = TrustLevel.HIGH if channel == "silent_auth" else TrustLevel.MED
        await _persist_verified_identity(
            db=db,
            user_id=state.user_id,
            phone_number=state.phone_number,
            method=channel,
            trust_level=trust_level,
            request_id=request_id,
        )
        await delete(keys().verify_request(request_id))
        return

    if wh_status in ("failed", "expired", "user_rejected"):
        await db_queries.update_attempt_status(db, request_id, "failed", wh_status)
        await delete(keys().verify_request(request_id))


async def get_verification_status(db: AsyncSession, user_id: str) -> VerificationStatusResponse:
    record = await db_queries.get_active_verification(db, user_id)
    if not record:
        return VerificationStatusResponse(verified=False)
    return VerificationStatusResponse(
        verified=True,
        trust_level=TrustLevel(record["trust_level"]),
        method=VerificationChannel(record["verification_method"]),
        verified_at=record["verified_at"],
        expires_at=record["expires_at"],
    )


async def revoke_verification(db: AsyncSession, user_id: str) -> None:
    await db_queries.revoke_verification(db, user_id)


async def _persist_verified_identity(
    db: AsyncSession,
    user_id: str,
    phone_number: str,
    method: str,
    trust_level: TrustLevel,
    request_id: str,
) -> None:
    await asyncio.gather(
        db_queries.upsert_verified_identity(
            db,
            user_id=user_id,
            phone_number=phone_number,
            verification_method=method,
            trust_level=trust_level.value,
        ),
        db_queries.update_attempt_status(db, request_id, "completed"),
    )
    await db.commit()


async def _safe_create_attempt(**kwargs) -> None:
    from config.database import async_session_maker
    if not async_session_maker:
        return
    try:
        async with async_session_maker() as session:
            await db_queries.create_attempt(session, **kwargs)
            await session.commit()
    except Exception as exc:
        logger.error("Failed to write verification attempt", error=str(exc))

