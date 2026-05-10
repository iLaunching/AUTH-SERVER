"""E.164 validation — copied from legacy verification module."""

import phonenumbers
from phonenumbers import NumberParseException, PhoneNumberFormat

from fastapi import HTTPException, status


def validate_and_normalise(raw: str, region: str = "GB") -> tuple[str, str]:
    if not raw or not raw.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "Phone number is required.", "code": "INVALID_PHONE"},
        )

    try:
        parsed = phonenumbers.parse(raw.strip(), region.upper())
    except NumberParseException:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "Invalid phone number format.", "code": "INVALID_PHONE"},
        )

    if not phonenumbers.is_valid_number(parsed):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "Phone number is not valid for its region.", "code": "INVALID_PHONE"},
        )

    e164 = phonenumbers.format_number(parsed, PhoneNumberFormat.E164)
    detected_region = phonenumbers.region_code_for_number(parsed)
    return e164, detected_region or region.upper()


def region_code_for_e164(e164: str) -> str | None:
    """
    ISO 3166-1 alpha-2 region code (e.g. GB, US) from a full E.164 number.
    Used when persisting profile country_code after OTP verify (number-only path).
    """
    if not e164 or not str(e164).strip():
        return None
    try:
        parsed = phonenumbers.parse(str(e164).strip(), None)
    except NumberParseException:
        return None
    if not phonenumbers.is_valid_number(parsed):
        return None
    return phonenumbers.region_code_for_number(parsed)
