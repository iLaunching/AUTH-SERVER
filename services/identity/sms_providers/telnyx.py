import httpx
import structlog

from ..settings import get_identity_settings
from .base import BaseSMSProvider, SMSResult

logger = structlog.get_logger()


class TelnyxProvider(BaseSMSProvider):
    async def send_sms(self, to: str, message: str) -> SMSResult:
        s = get_identity_settings()
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    "https://api.telnyx.com/v2/messages",
                    json={
                        "from": s.telnyx_from_number,
                        "to": to,
                        "text": message,
                        "messaging_profile_id": s.telnyx_messaging_profile_id,
                        "type": "SMS",
                    },
                    headers={"Authorization": f"Bearer {s.telnyx_api_key}"},
                )

            if response.is_success:
                msg_id = response.json().get("data", {}).get("id")
                logger.info("[Telnyx] SMS sent", to=to, message_id=msg_id)
                return SMSResult(success=True, message_id=msg_id)

            logger.error("[Telnyx] Send failed", status=response.status_code, body=response.text[:200])
            return SMSResult(success=False, error=f"HTTP {response.status_code}")

        except httpx.RequestError as exc:
            logger.error("[Telnyx] Network error", error=str(exc))
            return SMSResult(success=False, error=str(exc))
