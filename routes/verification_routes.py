import hashlib
import hmac
import json

import jwt
import structlog
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from config.database import get_db
from models.user import User
from routes.auth_routes import get_current_user

from services.verification.schemas import (
    CheckSmsCodeRequest,
    CheckSmsCodeResponse,
    StartVerificationRequest,
    StartVerificationResponse,
    VerificationStatusResponse,
)
from services.verification.settings import get_verification_settings
from services.verification import verification_service

logger = structlog.get_logger()

router = APIRouter(prefix="/verify", tags=["verification"])


def _client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def _require_enabled():
    if not get_verification_settings().enabled:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "Not found", "code": "NOT_FOUND"},
        )


@router.get("/status", response_model=VerificationStatusResponse)
async def verify_status(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    _require_enabled()
    return await verification_service.get_verification_status(db, str(current_user.id))


@router.post("/start", response_model=StartVerificationResponse, status_code=status.HTTP_202_ACCEPTED)
async def verify_start(
    body: StartVerificationRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    _require_enabled()
    return await verification_service.start_verification(
        db=db,
        raw_phone=body.phone_number,
        user_id=str(current_user.id),
        ip=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        region=body.region,
    )


@router.post("/check", response_model=CheckSmsCodeResponse)
async def verify_check(
    body: CheckSmsCodeRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    _require_enabled()
    return await verification_service.check_sms_code(
        db=db,
        request_id=body.request_id,
        code=body.code,
        user_id=str(current_user.id),
        ip=_client_ip(request),
    )


# ---------------------------------------------------------------------
# Webhook: Vonage Verify V2
# Validate signature before any processing, then process in background.
# ---------------------------------------------------------------------
webhook_router = APIRouter(prefix="/webhooks/vonage", tags=["verification-webhook"])


@webhook_router.post("/verify", include_in_schema=False)
async def vonage_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    _require_enabled()
    raw_body = await request.body()

    secret = (get_verification_settings().vonage_webhook_secret or "").strip()
    if not secret:
        logger.error("VONAGE_WEBHOOK_SECRET is not set — cannot validate Vonage webhooks")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "Webhook verification not configured.", "code": "WEBHOOK_SECRET_MISSING"},
        )

    sig_header = (
        request.headers.get("x-vonage-signature")
        or request.headers.get("X-Vonage-Signature-SHA256")
        or ""
    )
    auth_header = request.headers.get("authorization") or ""

    if not _is_valid_webhook_signature(raw_body, sig_header, secret, auth_header):
        logger.warning(
            "Vonage webhook signature check failed",
            has_signature_header=bool(sig_header.strip()),
            has_bearer_jwt=auth_header.strip().lower().startswith("bearer "),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Invalid signature", "code": "INVALID_SIGNATURE"},
        )

    try:
        payload = json.loads(raw_body)
    except (json.JSONDecodeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "Invalid JSON", "code": "INVALID_BODY"},
        )

    # Use a background task but keep DB work safe:
    # We'll re-open a fresh session inside the service call.
    background_tasks.add_task(_process_webhook, payload)
    return {"received": True}


async def _process_webhook(payload: dict) -> None:
    from config.database import async_session_maker

    if not async_session_maker:
        return

    try:
        async with async_session_maker() as session:
            await verification_service.handle_webhook(session, payload)
            await session.commit()
    except Exception as exc:
        logger.error("Webhook processing failed", error=str(exc), request_id=payload.get("request_id"))


def _is_valid_webhook_signature(
    raw_body: bytes,
    signature_header: str,
    secret: str,
    authorization: str,
) -> bool:
    """
    Verify Vonage callbacks using either:
    - `x-vonage-signature`: hex(SHA256-HMAC(secret, raw_body)), or
    - `Authorization: Bearer <jwt>` with HS256 signed using the same webhook signing secret
      (Verify V2 commonly uses JWT; `vonage_jwt.verify_signature` pattern).
    Secret = Vonage dashboard webhook / signing secret for this application.
    """
    sec_b = secret.encode("utf-8")

    if signature_header.strip():
        sig = signature_header.strip()
        if sig.lower().startswith("sha256="):
            sig = sig.split("=", 1)[1].strip()
        expected = hmac.new(sec_b, raw_body, hashlib.sha256).hexdigest()
        try:
            if hmac.compare_digest(sig.lower(), expected.lower()):
                return True
        except (TypeError, ValueError):
            pass

    if authorization.strip().lower().startswith("bearer "):
        token = authorization.split(None, 1)[1].strip()
        try:
            claims = jwt.decode(token, secret, algorithms=["HS256"])
            try:
                body = json.loads(raw_body)
                rid = body.get("request_id")
                jwt_rid = claims.get("request_id")
                pl = claims.get("payload")
                if jwt_rid is None and isinstance(pl, dict):
                    jwt_rid = pl.get("request_id")
                if rid and jwt_rid is not None and str(jwt_rid) != str(rid):
                    return False
            except (json.JSONDecodeError, TypeError):
                pass
            return True
        except jwt.InvalidTokenError:
            pass

    return False

