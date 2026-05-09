import json
from typing import Any

import structlog

from config.database import get_redis
from .settings import get_verification_settings

logger = structlog.get_logger()


class _Keys:
    def __init__(self, prefix: str):
        self._p = prefix

    def verify_request(self, request_id: str) -> str:
        return f"{self._p}vreq:{request_id}"

    def rate_limit_ip(self, ip: str) -> str:
        return f"{self._p}rl:ip:{ip}"

    def rate_limit_phone(self, phone: str) -> str:
        return f"{self._p}rl:phone:{phone}"


def keys() -> _Keys:
    return _Keys(get_verification_settings().redis_key_prefix)


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
    # Redis-py supports "nx" on expire in newer versions; guard with try.
    try:
        pipe.expire(key, ttl_seconds, nx=True)
    except TypeError:
        # Fallback: expire unconditionally (acceptable for rate limit keys)
        pipe.expire(key, ttl_seconds)
    results = await pipe.execute()
    return int(results[0])

