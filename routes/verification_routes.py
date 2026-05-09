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
from services.verification.settings import get_verification_settings, get_vonage_webhook_signing_secrets
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

    secrets = get_vonage_webhook_signing_secrets()
    if not secrets:
        logger.error(
            "Vonage signing secret not set — set VONAGE_SIGNATURE_SECRET "
            "(API Settings → Signature secret), VONAGE_WEBHOOK_SECRET, or VONAGE_API_SECRET",
        )
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

    ok, reject_meta = _is_valid_webhook_signature(raw_body, sig_header, secrets, auth_header)
    if not ok:
        logger.warning(
            "Vonage webhook rejected",
            has_signature_header=bool(sig_header.strip()),
            has_bearer_jwt=auth_header.strip().lower().startswith("bearer "),
            **reject_meta,
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


_JWT_DECODE_OPTIONS = {
    "verify_aud": False,
    "verify_iss": False,
    "verify_nbf": False,
    # Vonage issues `iat` slightly ahead of wall clock; PyJWT treats future iat as ImmatureSignatureError.
    "verify_iat": False,
}


def _payload_hash_matches(raw_body: bytes, claims: dict) -> bool:
    ph = claims.get("payload_hash")
    if not ph:
        return True
    ph_norm = str(ph).strip().lower()
    candidates = [hashlib.sha256(raw_body).hexdigest().lower()]
    try:
        obj = json.loads(raw_body)
        candidates.append(
            hashlib.sha256(
                json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            ).hexdigest().lower()
        )
    except (json.JSONDecodeError, TypeError):
        pass
    return ph_norm in candidates


def _is_valid_webhook_signature(
    raw_body: bytes,
    signature_header: str,
    secrets: list[str],
    authorization: str,
) -> tuple[bool, dict[str, object]]:
    """
    Verify Vonage callbacks using either:
    - `x-vonage-signature`: hex(SHA256-HMAC(secret, raw_body)), or
    - `Authorization: Bearer <jwt>` HS256 — try each configured secret (signature, webhook, API).

    Optionally validate `payload_hash` vs SHA256(raw_body) when present in claims.
    """
    if signature_header.strip():
        sig = signature_header.strip()
        if sig.lower().startswith("sha256="):
            sig = sig.split("=", 1)[1].strip()
        for secret in secrets:
            sec_b = secret.encode("utf-8")
            expected = hmac.new(sec_b, raw_body, hashlib.sha256).hexdigest()
            try:
                if hmac.compare_digest(sig.lower(), expected.lower()):
                    return True, {}
            except (TypeError, ValueError):
                continue

    if authorization.strip().lower().startswith("bearer "):
        token = authorization.split(None, 1)[1].strip()
        last_err: str | None = None
        for secret in secrets:
            try:
                claims = jwt.decode(
                    token,
                    secret,
                    algorithms=["HS256"],
                    leeway=600,
                    options=_JWT_DECODE_OPTIONS,
                )
                if not _payload_hash_matches(raw_body, claims):
                    last_err = "payload_hash_mismatch"
                    continue
                return True, {}
            except jwt.InvalidTokenError as exc:
                last_err = type(exc).__name__
                continue

        meta: dict[str, object] = {"last_error": last_err or "unknown", "secrets_tried": len(secrets)}
        try:
            hdr = jwt.get_unverified_header(token)
            meta["jwt_alg"] = hdr.get("alg")
            meta["jwt_typ"] = hdr.get("typ")
        except Exception:
            pass
        return False, meta

    return False, {}

