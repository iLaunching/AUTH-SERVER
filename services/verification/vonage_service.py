import base64
import json
import re
from dataclasses import dataclass

import httpx
import jwt
import structlog
from cryptography.hazmat.primitives import serialization
from fastapi import HTTPException, status

from .settings import get_verification_settings

logger = structlog.get_logger()

# Official Vonage Python SDK uses api.nexmo.com + POST /v2/verify (see vonage_verify.Verify).
VONAGE_API_BASE = "https://api.nexmo.com/v2/verify"


def _e164_to_vonage_phone(e164: str) -> str:
    """
    Verify v2 expects E.164 digits without '+' or '00' (vonage_utils PhoneNumber pattern).
    Sending '+447...' can yield 403 HTML from the edge.
    """
    s = e164.strip()
    if s.startswith("+"):
        s = s[1:]
    elif s.startswith("00"):
        s = s[2:]
    if not re.fullmatch(r"[1-9]\d{6,14}", s):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "Phone number must be valid E.164 for Vonage.", "code": "INVALID_PHONE_VONAGE"},
        )
    return s


def _vonage_http_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "ilaunching-auth-api (httpx; Vonage Verify v2)",
    }


@dataclass
class VerifyStartResult:
    request_id: str
    check_url: str | None


def _get_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=5.0))


def _parse_vonage_json(response: httpx.Response) -> dict:
    """Vonage may return HTML or empty body on proxy/gateway errors — avoid JSONDecodeError."""
    if not response.content or not response.content.strip():
        return {}
    try:
        return response.json()
    except json.JSONDecodeError:
        return {}


def _raise_for_status(response: httpx.Response) -> None:
    if response.is_success:
        return

    code = response.status_code
    body = _parse_vonage_json(response)
    detail = body.get("detail", "") if isinstance(body, dict) else ""

    ct = response.headers.get("content-type", "")
    snippet = ""
    if response.text and "json" not in ct.lower():
        snippet = (response.text[:280]).replace("\n", " ").strip()

    logger.warning(
        "Vonage API error",
        status_code=code,
        detail=detail,
        content_type=ct or None,
        body_prefix=snippet or None,
    )

    # HTML 403/401 from Vonage edge = JWT rejected or wrong app/key pairing (not JSON API body).
    if code == 401:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "Verification provider rejected authentication (401). Check Vonage application id and private key pair.",
                "code": "VONAGE_AUTH_REJECTED",
            },
        )
    if code == 403:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "Verification provider denied access (403). Confirm JWT keypair matches this Vonage Application and Verify is enabled.",
                "code": "VONAGE_FORBIDDEN",
            },
        )

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
    # Match vonage_jwt.JwtClient.generate_application_jwt defaults (no nbf/acl — extra claims can break Verify).
    ttl_sec = 15 * 60
    payload = {
        "application_id": s.vonage_application_id,
        "iat": now,
        "jti": str(uuid.uuid4()),
        "exp": now + ttl_sec,
    }
    try:
        signing_key = _load_rsa_private_key(s.vonage_private_key)
        return jwt.encode(
            payload,
            signing_key,
            algorithm="RS256",
            headers={"alg": "RS256", "typ": "JWT"},
        )
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

    to_digits = _e164_to_vonage_phone(phone_number)

    token = _build_jwt()

    payload = {
        "brand": s.vonage_brand_name[:16],
        "workflow": [
            {"channel": "silent_auth", "to": to_digits},
            {"channel": "sms", "to": to_digits},
        ],
    }

    logger.info("Starting verification", phone_e164=phone_number, vonage_to=to_digits)

    async with _get_client() as client:
        try:
            response = await client.post(
                VONAGE_API_BASE,
                json=payload,
                headers=_vonage_http_headers(token),
            )
            _raise_for_status(response)
            data = _parse_vonage_json(response)
            request_id = data.get("request_id") if isinstance(data, dict) else None
            if not request_id:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail={"error": "Invalid response from verification provider.", "code": "VONAGE_BAD_RESPONSE"},
                )
            return VerifyStartResult(
                request_id=request_id,
                check_url=data.get("check_url") if isinstance(data, dict) else None,
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
                headers=_vonage_http_headers(token),
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

