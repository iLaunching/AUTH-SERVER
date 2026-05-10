from functools import lru_cache

from ..settings import get_identity_settings
from .base import BaseSMSProvider


@lru_cache
def get_sms_provider() -> BaseSMSProvider:
    provider = get_identity_settings().sms_provider

    if provider == "telnyx":
        from .telnyx import TelnyxProvider

        return TelnyxProvider()
    if provider == "plivo":
        from .plivo import PlivoProvider

        return PlivoProvider()
    if provider == "aws_sns":
        from .aws_sns import AWSSNSProvider

        return AWSSNSProvider()
    if provider == "twilio":
        from .twilio import TwilioProvider

        return TwilioProvider()

    raise ValueError(
        f"Unknown SMS_PROVIDER='{provider}'. Valid options: telnyx, plivo, aws_sns, twilio"
    )
