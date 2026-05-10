import asyncio

import boto3
import structlog

from ..settings import get_identity_settings
from .base import BaseSMSProvider, SMSResult

logger = structlog.get_logger()


class AWSSNSProvider(BaseSMSProvider):
    async def send_sms(self, to: str, message: str) -> SMSResult:
        s = get_identity_settings()

        def _publish():
            client = boto3.client(
                "sns",
                aws_access_key_id=s.aws_access_key_id or None,
                aws_secret_access_key=s.aws_secret_access_key or None,
                region_name=s.aws_region,
            )
            return client.publish(
                PhoneNumber=to,
                Message=message,
                MessageAttributes={
                    "AWS.SNS.SMS.SMSType": {
                        "DataType": "String",
                        "StringValue": "Transactional",
                    },
                    "AWS.SNS.SMS.SenderID": {
                        "DataType": "String",
                        "StringValue": (s.brand_name[:11] if s.brand_name else "SMS"),
                    },
                },
            )

        try:
            response = await asyncio.to_thread(_publish)
            msg_id = response.get("MessageId")
            logger.info("[AWS SNS] SMS sent", to=to, message_id=msg_id)
            return SMSResult(success=True, message_id=msg_id)
        except Exception as exc:
            logger.error("[AWS SNS] Send failed", error=str(exc))
            return SMSResult(success=False, error=str(exc))
