import base64
import re
from dataclasses import dataclass

import httpx
import jwt
import structlog
from cryptography.hazmat.primitives import serialization
from fastapi import HTTPException, status

from .settings import get_verification_settings

logger = structlog.get_logger()

VONAGE_API_BASE = "https://api.vonage.com/v2/verify"


@dataclass
class VerifyStartResult:
    request_id: str
    check_url: str | None


def _get_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
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


def _pem_header_hint(pem: str) -> str | None:
    """First PEM banner line only (safe to log). Helps debug wrong paste (cert vs key)."""
    for line in pem.splitlines():
        line = line.strip()
        if line.startswith("-----BEGIN"):
            return line[:120]
    return None


def _looks_like_private_key_filename_only(value: str) -> bool:
    """Users sometimes paste the download filename instead of file contents."""
    t = value.strip()
    if len(t) > 400:
        return False
    if "BEGIN" in t.upper():
        return False
    return bool(re.match(r"^private[_a-zA-Z0-9.-]+\s*$", t))


def _load_rsa_private_key(material: str):
    """
    RS256 signing key: PEM text, or raw PKCS#8 / PKCS#1 DER encoded as base64
    (common Vonage download without BEGIN/END lines).
    """
    material_bytes = material.encode("utf-8")
    try:
        return serialization.load_pem_private_key(material_bytes, password=None)
    except Exception:
        pass
    body = "".join(material.split())
    if len(body) >= 64 and re.fullmatch(r"[A-Za-z0-9+/=]+", body):
        der = base64.b64decode(body)
        return serialization.load_der_private_key(der, password=None)
    raise ValueError("could not deserialize private key")


def _build_jwt() -> str:
    """
    Vonage Application JWT (RS256).
    Uses `VONAGE_APPLICATION_ID` + `VONAGE_PRIVATE_KEY` (PEM or raw base64 DER).
    """
    import time
    import uuid

    s = get_verification_settings()
    if not s.vonage_application_id or not s.vonage_private_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "Verification not configured (JWT).", "code": "VERIFICATION_NOT_CONFIGURED"},
        )

    pem_u = s.vonage_private_key.upper()
    if "BEGIN PUBLIC KEY" in pem_u:
        logger.error(
            "VONAGE_PRIVATE_KEY is a public key; JWT signing requires the application private key",
            pem_header=_pem_header_hint(s.vonage_private_key),
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "VONAGE_PRIVATE_KEY must be the private key (BEGIN PRIVATE KEY), not the public key.",
                "code": "VONAGE_PUBLIC_KEY_NOT_ALLOWED",
            },
        )
    if "BEGIN CERTIFICATE" in pem_u:
        logger.error(
            "VONAGE_PRIVATE_KEY looks like a certificate; use the Vonage application private key PEM",
            pem_header=_pem_header_hint(s.vonage_private_key),
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "VONAGE_PRIVATE_KEY must be the application private key PEM, not a certificate.",
                "code": "VONAGE_WRONG_PEM_KIND",
            },
        )
    if _looks_like_private_key_filename_only(s.vonage_private_key):
        logger.error("VONAGE_PRIVATE_KEY looks like a filename; paste the file contents, not the name")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "VONAGE_PRIVATE_KEY must be the key file contents (PEM or base64), not the filename.",
                "code": "VONAGE_KEY_FILENAME_NOT_CONTENT",
            },
        )

    now = int(time.time())
    payload = {
        "application_id": s.vonage_application_id,
        "iat": now,
        "exp": now + 60,
        "jti": str(uuid.uuid4()),
    }
    try:
        signing_key = _load_rsa_private_key(s.vonage_private_key)
        return jwt.encode(payload, signing_key, algorithm="RS256")
    except Exception as exc:
        # Log type + PEM banner only — never log str(exc); library messages could change over time.
        logger.error(
            "Vonage JWT signing failed",
            exc_type=type(exc).__name__,
            pem_header=_pem_header_hint(s.vonage_private_key),
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "Verification JWT signing failed.", "code": "JWT_SIGN_FAILED"},
        ) from exc


async def start_verification(phone_number: str) -> VerifyStartResult:
    s = get_verification_settings()

    token = _build_jwt()

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
            response = await client.post(
                VONAGE_API_BASE,
                json=payload,
                headers={"Authorization": f"Bearer {token}"},
            )
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
            token = _build_jwt()
            response = await client.post(
                f"{VONAGE_API_BASE}/{request_id}",
                json={"code": code},
                headers={"Authorization": f"Bearer {token}"},
            )
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

