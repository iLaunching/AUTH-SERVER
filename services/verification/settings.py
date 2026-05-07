import os
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class VerificationSettings:
    enabled: bool

    # Vonage
    vonage_api_key: str
    vonage_api_secret: str
    vonage_brand_name: str
    vonage_webhook_secret: str

    # Redis
    redis_key_prefix: str

    # Rate limits
    rate_limit_ip_max: int
    rate_limit_phone_max_per_day: int
    redis_ttl_rate_limit_ip: int
    redis_ttl_rate_limit_phone: int

    # Verification behaviour
    verification_expiry_days: int
    redis_ttl_verify_request: int


def _bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "y", "on")


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw.strip())
    except ValueError:
        return default


@lru_cache
def get_verification_settings() -> VerificationSettings:
    """
    Keep this module low-friction to integrate: uses plain env vars
    (no new settings library required).
    """
    enabled = _bool_env("VERIFICATION_ENABLED", False)

    return VerificationSettings(
        enabled=enabled,

        vonage_api_key=os.getenv("VONAGE_API_KEY", ""),
        vonage_api_secret=os.getenv("VONAGE_API_SECRET", ""),
        vonage_brand_name=os.getenv("VONAGE_BRAND_NAME", "iLaunching"),
        vonage_webhook_secret=os.getenv("VONAGE_WEBHOOK_SECRET", ""),

        redis_key_prefix=os.getenv("VERIFICATION_REDIS_PREFIX", "verif:"),

        rate_limit_ip_max=_int_env("VERIFICATION_RATE_LIMIT_IP_MAX", 10),
        rate_limit_phone_max_per_day=_int_env("VERIFICATION_RATE_LIMIT_PHONE_MAX_PER_DAY", 5),
        redis_ttl_rate_limit_ip=_int_env("VERIFICATION_REDIS_TTL_RATE_LIMIT_IP", 3600),
        redis_ttl_rate_limit_phone=_int_env("VERIFICATION_REDIS_TTL_RATE_LIMIT_PHONE", 86400),

        verification_expiry_days=_int_env("VERIFICATION_EXPIRY_DAYS", 90),
        redis_ttl_verify_request=_int_env("VERIFICATION_REDIS_TTL_VERIFY_REQUEST", 300),
    )

