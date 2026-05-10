"""Phone identity: App Attest + SMS OTP binding."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status

from models.user import User
from routes.auth_routes import get_current_user
from services.identity import get_identity_settings
from services.identity import identity_service
from services.identity.challenge_service import generate_challenge
from services.identity.rate_limiter import check_limits
from services.identity.schemas import (
    BindPhoneRequest,
    BindPhoneResponse,
    ConfirmOTPRequest,
    ConfirmOTPResponse,
    IdentityResponse,
    ResendOTPRequest,
    ResendOTPResponse,
)

router = APIRouter(prefix="/identity", tags=["identity"])


async def require_email_verified_user(
    current_user: User = Depends(get_current_user),
) -> User:
    if not current_user.email_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "Verify your email before adding a phone number.",
                "code": "EMAIL_NOT_VERIFIED",
            },
        )
    return current_user


def _ensure_identity_enabled() -> None:
    if not get_identity_settings().enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "Phone identity is disabled.", "code": "IDENTITY_DISABLED"},
        )


def _ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


@router.get("/challenge", summary="One-time App Attest challenge nonce")
async def get_attest_challenge(
    request: Request,
    user: User = Depends(require_email_verified_user),
):
    _ensure_identity_enabled()
    await check_limits(_ip(request), None, str(user.id))
    challenge = await generate_challenge(str(user.id))
    return {"challenge": challenge}


@router.post(
    "/bind",
    response_model=BindPhoneResponse,
    status_code=status.HTTP_200_OK,
    summary="Start phone binding (App Attest or SMS OTP)",
)
async def bind_phone(
    body: BindPhoneRequest,
    request: Request,
    user: User = Depends(require_email_verified_user),
):
    _ensure_identity_enabled()
    return await identity_service.start_binding(
        user_id=str(user.id),
        raw_phone=body.phone_number,
        ip=_ip(request),
        user_agent=request.headers.get("user-agent"),
        region=body.region,
        attest_passed=body.attest_passed,
        attest_key_hash=body.attest_key_hash,
        attest_challenge=body.attest_challenge,
    )


@router.post("/confirm", response_model=ConfirmOTPResponse, summary="Submit SMS OTP")
async def confirm_otp(
    body: ConfirmOTPRequest,
    request: Request,
    user: User = Depends(require_email_verified_user),
):
    _ensure_identity_enabled()
    return await identity_service.confirm_binding(
        user_id=str(user.id),
        request_id=body.request_id,
        code=body.code,
        ip=_ip(request),
    )


@router.post("/resend", response_model=ResendOTPResponse, summary="Resend SMS OTP")
async def resend_otp(
    body: ResendOTPRequest,
    request: Request,
    user: User = Depends(require_email_verified_user),
):
    _ensure_identity_enabled()
    request_id = await identity_service.resend_otp(
        user_id=str(user.id),
        raw_phone=body.phone_number,
        ip=_ip(request),
        region=body.region,
    )
    return ResendOTPResponse(request_id=request_id)


@router.get("/me", response_model=IdentityResponse, summary="Current user's phone identity")
async def get_identity_me(user: User = Depends(require_email_verified_user)):
    _ensure_identity_enabled()
    identity = await identity_service.get_identity(str(user.id))
    if not identity:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "No phone identity found for this account.", "code": "NOT_BOUND"},
        )
    return identity
