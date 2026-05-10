import httpx
import structlog

from ..settings import get_identity_settings
from .base import BaseSMSProvider, SMSResult

logger = structlog.get_logger()


class TwilioProvider(BaseSMSProvider):
    async def send_sms(self, to: str, message: str) -> SMSResult:
        s = get_identity_settings()
        url = f"https://api.twilio.com/2010-04-01/Accounts/{s.twilio_account_sid}/Messages.json"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    url,
                    data={"From": s.twilio_from_number, "To": to, "Body": message},
                    auth=(s.twilio_account_sid, s.twilio_auth_token),
                )

            if response.is_success:
                msg_id = response.json().get("sid")
                logger.info("[Twilio] SMS sent", to=to, message_id=msg_id)
                return SMSResult(success=True, message_id=msg_id)

            logger.error("[Twilio] Send failed", status=response.status_code, body=response.text[:200])
            return SMSResult(success=False, error=f"HTTP {response.status_code}")

        except httpx.RequestError as exc:
            logger.error("[Twilio] Network error", error=str(exc))
            return SMSResult(success=False, error=str(exc))
