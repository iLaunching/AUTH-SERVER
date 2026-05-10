import httpx
import structlog

from ..settings import get_identity_settings
from .base import BaseSMSProvider, SMSResult

logger = structlog.get_logger()


class PlivoProvider(BaseSMSProvider):
    async def send_sms(self, to: str, message: str) -> SMSResult:
        s = get_identity_settings()
        url = f"https://api.plivo.com/v1/Account/{s.plivo_auth_id}/Message/"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    url,
                    json={
                        "src": s.plivo_from_number.lstrip("+"),
                        "dst": to.lstrip("+"),
                        "text": message,
                    },
                    auth=(s.plivo_auth_id, s.plivo_auth_token),
                )

            if response.is_success:
                msg_id = response.json().get("message_uuid", [None])[0]
                logger.info("[Plivo] SMS sent", to=to, message_id=msg_id)
                return SMSResult(success=True, message_id=msg_id)

            logger.error("[Plivo] Send failed", status=response.status_code, body=response.text[:200])
            return SMSResult(success=False, error=f"HTTP {response.status_code}")

        except httpx.RequestError as exc:
            logger.error("[Plivo] Network error", error=str(exc))
            return SMSResult(success=False, error=str(exc))
