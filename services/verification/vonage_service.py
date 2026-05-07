from dataclasses import dataclass

import httpx
import structlog
from fastapi import HTTPException, status

from .settings import get_verification_settings

logger = structlog.get_logger()

VONAGE_API_BASE = "https://api.vonage.com/v2/verify"


@dataclass
class VerifyStartResult:
    request_id: str
    check_url: str | None


def _get_client() -> httpx.AsyncClient:
    s = get_verification_settings()
    return httpx.AsyncClient(
        auth=(s.vonage_api_key, s.vonage_api_secret),
        headers={"Content-Type": "application/json"},
        timeout=httpx.Timeout(10.0, connect=5.0),
    )


def _raise_for_status(response: httpx.Response) -> None:
    if response.is_success:
        return

    code = response.status_code
    body = response.json() if response.content else {}
    detail = body.get("detail", "")

    logger.warning("Vonage API error", status_code=code, detail=detail)

    if code == 402:
        raise HTTPException(502, {"error": "Verification quota exceeded.", "code": "VONAGE_QUOTA"})
    if code == 429:
        raise HTTPException(429, {"error": "Verification service rate limited.", "code": "VONAGE_RATE_LIMIT"})
    if code == 422:
        raise HTTPException(422, {"error": "This number cannot be verified.", "code": "VONAGE_UNVERIFIABLE"})
    if code == 404:
        raise HTTPException(404, {"error": "Verification request not found.", "code": "REQUEST_NOT_FOUND"})
    if code == 410:
        raise HTTPException(422, {"error": "Incorrect or expired code.", "code": "WRONG_CODE"})

    raise HTTPException(502, {"error": "Verification service error.", "code": "VONAGE_ERROR"})


async def start_verification(phone_number: str) -> VerifyStartResult:
    s = get_verification_settings()

    if not s.vonage_api_key or not s.vonage_api_secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "Verification not configured.", "code": "VERIFICATION_NOT_CONFIGURED"},
        )

    payload = {
        "brand": s.vonage_brand_name,
        "workflow": [
            {"channel": "silent_auth", "to": phone_number},
            {"channel": "sms", "to": phone_number},
        ],
    }

    logger.info("Starting verification", phone_number=phone_number)

    async with _get_client() as client:
        try:
            response = await client.post(VONAGE_API_BASE, json=payload)
            _raise_for_status(response)
            data = response.json()
            return VerifyStartResult(
                request_id=data["request_id"],
                check_url=data.get("check_url"),
            )
        except HTTPException:
            raise
        except httpx.RequestError as exc:
            logger.error("Vonage network error", error=str(exc))
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail={"error": "Verification service unreachable.", "code": "VONAGE_NETWORK"},
            )


async def check_verification_code(request_id: str, code: str) -> None:
    async with _get_client() as client:
        try:
            response = await client.post(f"{VONAGE_API_BASE}/{request_id}", json={"code": code})
            _raise_for_status(response)
            logger.info("OTP check success", request_id=request_id)
        except HTTPException:
            raise
        except httpx.RequestError as exc:
            logger.error("Vonage network error on check", error=str(exc))
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail={"error": "Verification service unreachable.", "code": "VONAGE_NETWORK"},
            )

