import httpx
import structlog

from ..settings import get_identity_settings
from .base import BaseSMSProvider, SMSResult

logger = structlog.get_logger()


class TelnyxProvider(BaseSMSProvider):
    async def send_sms(self, to: str, message: str) -> SMSResult:
        s = get_identity_settings()
        if not s.telnyx_api_key or not s.telnyx_api_key.strip():
            return SMSResult(success=False, error="TELNYX_API_KEY is missing")
        if not s.telnyx_messaging_profile_id or not s.telnyx_messaging_profile_id.strip():
            return SMSResult(success=False, error="TELNYX_MESSAGING_PROFILE_ID is missing")

        from_number = (s.telnyx_from_number or "").strip()
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    "https://api.telnyx.com/v2/messages",
                    json={
                        # Some Telnyx setups rely on Messaging Profile + sender configuration.
                        # If TELNYX_FROM_NUMBER is unset, omit it so Telnyx can select a configured sender.
                        **({"from": from_number} if from_number else {}),
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
            return SMSResult(success=False, error=f"HTTP {response.status_code}: {response.text[:200]}")

        except httpx.RequestError as exc:
            logger.error("[Telnyx] Network error", error=str(exc))
            return SMSResult(success=False, error=str(exc))
