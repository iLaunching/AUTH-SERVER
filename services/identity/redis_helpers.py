"""Redis keys and helpers for phone identity (OTP, cache, rate limits)."""

from __future__ import annotations

import json
from typing import Any

import structlog

from config.database import get_redis
from .settings import get_identity_settings

logger = structlog.get_logger()


class IdentityKeys:
    def __init__(self, prefix: str):
        self._p = prefix

    def otp(self, request_id: str) -> str:
        return f"{self._p}otp:{request_id}"

    def identity(self, user_id: str) -> str:
        return f"{self._p}id:{user_id}"

    def phone_owner(self, e164: str) -> str:
        return f"{self._p}phone:{e164}"

    def attest_challenge(self, challenge: str) -> str:
        return f"{self._p}attest:{challenge}"

    def rate_ip(self, ip: str) -> str:
        return f"{self._p}rl:ip:{ip}"

    def rate_phone(self, phone: str) -> str:
        return f"{self._p}rl:phone:{phone}"

    def rate_user(self, user_id: str) -> str:
        return f"{self._p}rl:user:{user_id}"


def keys() -> IdentityKeys:
    return IdentityKeys(get_identity_settings().redis_key_prefix)


async def set_json(key: str, value: Any, ttl_seconds: int) -> None:
    client = await get_redis()
    if not client:
        raise RuntimeError("Redis unavailable")
    await client.set(key, json.dumps(value), ex=ttl_seconds)


async def get_json(key: str) -> Any | None:
    client = await get_redis()
    if not client:
        raise RuntimeError("Redis unavailable")
    raw = await client.get(key)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None


async def delete(key: str) -> None:
    client = await get_redis()
    if not client:
        raise RuntimeError("Redis unavailable")
    await client.delete(key)


async def incr_with_ttl(key: str, ttl_seconds: int) -> int:
    client = await get_redis()
    if not client:
        raise RuntimeError("Redis unavailable")

    pipe = client.pipeline()
    pipe.incr(key)
    try:
        pipe.expire(key, ttl_seconds, nx=True)
    except TypeError:
        pipe.expire(key, ttl_seconds)
    results = await pipe.execute()
    return int(results[0])
