from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, field_validator


class TrustLevel(str, Enum):
    HIGH = "HIGH"
    MED = "MED"


class VerificationChannel(str, Enum):
    SILENT_AUTH = "silent_auth"
    SMS = "sms"


class VerificationStatus(str, Enum):
    PENDING = "pending"
    ALREADY_VERIFIED = "already_verified"
    VERIFIED = "verified"
    FAILED = "failed"


class StartVerificationRequest(BaseModel):
    phone_number: str
    region: str = "GB"

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


class StartVerificationResponse(BaseModel):
    status: VerificationStatus
    request_id: str | None = None
    check_url: str | None = None
    channel: VerificationChannel | None = None
    trust_level: TrustLevel | None = None


class CheckSmsCodeRequest(BaseModel):
    request_id: str
    code: str

    @field_validator("code")
    @classmethod
    def code_is_numeric(cls, v: str) -> str:
        v = v.strip()
        if not v.isdigit() or not (4 <= len(v) <= 8):
            raise ValueError("code must be 4–8 digits")
        return v


class CheckSmsCodeResponse(BaseModel):
    status: Literal["verified"]
    trust_level: TrustLevel


class VerificationStatusResponse(BaseModel):
    verified: bool
    trust_level: TrustLevel | None = None
    method: VerificationChannel | None = None
    verified_at: datetime | None = None
    expires_at: datetime | None = None


class PendingVerificationState(BaseModel):
    request_id: str
    user_id: str
    phone_number: str
    started_at: float

