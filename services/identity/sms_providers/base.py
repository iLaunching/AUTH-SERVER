from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class SMSResult:
    success: bool
    message_id: str | None = None
    error: str | None = None


class BaseSMSProvider(ABC):
    @abstractmethod
    async def send_sms(self, to: str, message: str) -> SMSResult:
        ...
