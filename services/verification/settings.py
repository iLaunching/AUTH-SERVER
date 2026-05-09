import os
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class VerificationSettings:
    enabled: bool

    # Vonage
    vonage_application_id: str
    vonage_private_key: str
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


def _normalize_vonage_private_key(raw: str) -> str:
    """
    Normalize Vonage application private key from env (PEM or raw base64 DER).

    Does not accept weaker credentials: you still must supply the real private key
    material; this only fixes formatting (BOM, quotes, newlines, literal \\n).

    Raw PKCS#8 / PKCS#1 DER as base64 (no BEGIN/END lines) is loaded in
    vonage_service via load_der_private_key.
    """
    if not raw:
        return ""
    key = raw.strip()
    if key.startswith("\ufeff"):
        key = key.lstrip("\ufeff").strip()
    # Whole value wrapped in quotes (JSON / copy-paste)
    if len(key) >= 2 and ((key[0] == key[-1] == '"') or (key[0] == key[-1] == "'")):
        key = key[1:-1].strip()
    key = key.replace("\\r\\n", "\n").replace("\\r", "\n").replace("\\n", "\n")
    key = key.replace("\r\n", "\n").replace("\r", "\n")
    return key


@lru_cache
def get_verification_settings() -> VerificationSettings:
    """
    Keep this module low-friction to integrate: uses plain env vars
    (no new settings library required).
    """
    enabled = _bool_env("VERIFICATION_ENABLED", False)

    return VerificationSettings(
        enabled=enabled,

        vonage_application_id=(os.getenv("VONAGE_APPLICATION_ID") or "").strip(),
        vonage_private_key=_normalize_vonage_private_key(os.getenv("VONAGE_PRIVATE_KEY") or ""),
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

