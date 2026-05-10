"""
Environment-backed settings for phone identity (OTP + App Attest + SMS providers).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        return int(str(raw).strip())
    except ValueError:
        return default


def _str_env(name: str, default: str = "") -> str:
    raw = os.getenv(name)
    if raw is None:
        return default
    return str(raw).strip()


@dataclass(frozen=True)
class IdentitySettings:
    enabled: bool
    redis_key_prefix: str
    brand_name: str
    sms_provider: str
    # Telnyx
    telnyx_api_key: str
    telnyx_messaging_profile_id: str
    telnyx_from_number: str
    # Twilio
    twilio_account_sid: str
    twilio_auth_token: str
    twilio_from_number: str
    # Plivo
    plivo_auth_id: str
    plivo_auth_token: str
    plivo_from_number: str
    # AWS SNS
    aws_access_key_id: str
    aws_secret_access_key: str
    aws_region: str
    # OTP
    otp_length: int
    ttl_otp: int
    otp_max_attempts: int
    otp_message_template: str
    ttl_attest_challenge: int
    ttl_identity_cache: int
    # Rate limits
    ttl_rate_limit_ip: int
    rate_limit_ip_max: int
    ttl_rate_limit_phone: int
    rate_limit_phone_max_per_day: int
    ttl_rate_limit_user: int
    rate_limit_user_max: int


@lru_cache
def get_identity_settings() -> IdentitySettings:
    return IdentitySettings(
        enabled=_bool_env("IDENTITY_ENABLED", True),
        redis_key_prefix=_str_env("IDENTITY_REDIS_PREFIX", "iden:"),
        brand_name=_str_env("BRAND_NAME", "iLaunching"),
        sms_provider=_str_env("SMS_PROVIDER", "telnyx").lower(),
        telnyx_api_key=_str_env("TELNYX_API_KEY"),
        telnyx_messaging_profile_id=_str_env("TELNYX_MESSAGING_PROFILE_ID"),
        telnyx_from_number=_str_env("TELNYX_FROM_NUMBER"),
        twilio_account_sid=_str_env("TWILIO_ACCOUNT_SID"),
        twilio_auth_token=_str_env("TWILIO_AUTH_TOKEN"),
        twilio_from_number=_str_env("TWILIO_FROM_NUMBER"),
        plivo_auth_id=_str_env("PLIVO_AUTH_ID"),
        plivo_auth_token=_str_env("PLIVO_AUTH_TOKEN"),
        plivo_from_number=_str_env("PLIVO_FROM_NUMBER"),
        aws_access_key_id=_str_env("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=_str_env("AWS_SECRET_ACCESS_KEY"),
        aws_region=_str_env("AWS_REGION", "us-east-1"),
        otp_length=max(4, min(8, _int_env("OTP_LENGTH", 6))),
        ttl_otp=_int_env("OTP_TTL_SECONDS", 600),
        otp_max_attempts=_int_env("OTP_MAX_ATTEMPTS", 5),
        otp_message_template=_str_env(
            "OTP_MESSAGE_TEMPLATE",
            "Your {brand} code is {code}. Valid for 10 minutes. Never share this.",
        ),
        ttl_attest_challenge=_int_env("ATTEST_CHALLENGE_TTL_SECONDS", 600),
        ttl_identity_cache=_int_env("IDENTITY_CACHE_TTL_SECONDS", 3600),
        ttl_rate_limit_ip=_int_env("RATE_LIMIT_IP_WINDOW_SECONDS", 3600),
        rate_limit_ip_max=_int_env("RATE_LIMIT_IP_MAX", 30),
        ttl_rate_limit_phone=_int_env("RATE_LIMIT_PHONE_WINDOW_SECONDS", 86400),
        rate_limit_phone_max_per_day=_int_env("RATE_LIMIT_PHONE_MAX_PER_DAY", 10),
        ttl_rate_limit_user=_int_env("RATE_LIMIT_USER_WINDOW_SECONDS", 3600),
        rate_limit_user_max=_int_env("RATE_LIMIT_USER_MAX", 20),
    )
