from datetime import datetime
from enum import Enum

from pydantic import BaseModel, field_validator


class TrustLevel(str, Enum):
    HIGH = "HIGH"
    MED = "MED"


class VerificationMethod(str, Enum):
    APP_ATTEST = "app_attest"
    SMS = "sms"


class BindStatus(str, Enum):
    BOUND = "bound"
    PENDING_OTP = "pending_otp"
    ALREADY_BOUND = "already_bound"


class BindPhoneRequest(BaseModel):
    phone_number: str
    region: str = "GB"
    attest_passed: bool = False
    attest_key_hash: str | None = None
    attest_challenge: str | None = None

    @field_validator("phone_number")
    @classmethod
    def phone_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("phone_number is required")
        return v

    @field_validator("region")
    @classmethod
    def region_upper(cls, v: str) -> str:
        return v.upper()


class ConfirmOTPRequest(BaseModel):
    request_id: str
    code: str

    @field_validator("code")
    @classmethod
    def code_is_digits(cls, v: str) -> str:
        v = v.strip()
        if not v.isdigit() or not (4 <= len(v) <= 8):
            raise ValueError("code must be 4–8 digits")
        return v


class ResendOTPRequest(BaseModel):
    phone_number: str
    region: str = "GB"


class BindPhoneResponse(BaseModel):
    status: BindStatus
    trust_level: TrustLevel | None = None
    method: VerificationMethod | None = None
    request_id: str | None = None
    real_phone_e164: str | None = None


class ConfirmOTPResponse(BaseModel):
    status: str = "bound"
    trust_level: TrustLevel
    real_phone_e164: str


class ResendOTPResponse(BaseModel):
    request_id: str
    message: str = "A new code has been sent."


class IdentityResponse(BaseModel):
    user_id: str
    real_phone: str
    trust_level: TrustLevel
    method: VerificationMethod
    bound_at: str | datetime


class IdentityLookupRequest(BaseModel):
    """Batch phone → user_id lookup for room invites (registered users only)."""

    phones: list[str]
    region: str = "GB"

    @field_validator("phones")
    @classmethod
    def phones_nonempty(cls, v: list[str]) -> list[str]:
        cleaned = [p.strip() for p in v if p and p.strip()]
        if not cleaned:
            raise ValueError("phones must contain at least one number")
        if len(cleaned) > 50:
            raise ValueError("phones limited to 50 per request")
        return cleaned

    @field_validator("region")
    @classmethod
    def lookup_region_upper(cls, v: str) -> str:
        return v.upper()


class IdentityLookupMatch(BaseModel):
    phone: str
    user_id: str
    registered: bool = True


class IdentityLookupMiss(BaseModel):
    phone: str
    registered: bool = False
    reason: str = "not_bound"


class IdentityLookupResponse(BaseModel):
    matches: list[IdentityLookupMatch]
    misses: list[IdentityLookupMiss]
