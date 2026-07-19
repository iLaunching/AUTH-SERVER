"""Room membership ACL + pending invites (Phase 7b).

Writes Redis keys consumed by sma-router:
  sma:acl:members:{room_id}  — SET of user UUID strings

Pending invites (server-assisted discovery until account-stream fan-out is complete):
  sma:room:invites:{user_id} — HASH field room_id → JSON payload
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import structlog
from fastapi import HTTPException, status

from config.database import get_redis

logger = structlog.get_logger()

INVITE_TTL_SECS = 86_400 * 30  # 30 days


def _acl_key(room_id: str) -> str:
    return f"sma:acl:members:{room_id}"


def _invites_key(user_id: str) -> str:
    return f"sma:room:invites:{user_id}"


def _parse_uuid(value: str, label: str) -> str:
    try:
        return str(UUID(value.strip()))
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": f"Invalid {label}.", "code": "INVALID_UUID"},
        ) from exc


async def register_room_membership(
    *,
    room_id: str,
    creator_user_id: str,
    member_user_ids: list[str],
    room_name: str,
    room_key_b64: str,
    member_can_send_messages: bool = True,
    member_can_add_members: bool = False,
    room_context: str = "MultiParty",
    invited_by_display_name: str = "",
) -> dict[str, Any]:
    """Replace ACL set for room and enqueue invites for non-creator members."""
    room_id = _parse_uuid(room_id, "room_id")
    creator_user_id = _parse_uuid(creator_user_id, "creator_user_id")
    members = {_parse_uuid(uid, "member_user_id") for uid in member_user_ids}
    members.add(creator_user_id)

    if not room_key_b64 or not room_key_b64.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "room_key_b64 is required.", "code": "MISSING_ROOM_KEY"},
        )

    client = await get_redis()
    if not client:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "Redis unavailable.", "code": "REDIS_UNAVAILABLE"},
        )

    acl = _acl_key(room_id)
    # Replace membership set atomically-ish: delete then sadd.
    await client.delete(acl)
    if members:
        await client.sadd(acl, *members)

    invited_by_phone: str | None = None
    try:
        from services.identity import identity_service

        identity = await identity_service.get_identity(creator_user_id)
        if identity and identity.get("real_phone"):
            invited_by_phone = str(identity["real_phone"])
    except Exception:
        invited_by_phone = None

    display = (invited_by_display_name or "").strip()
    context = (room_context or "MultiParty").strip() or "MultiParty"

    now = datetime.now(timezone.utc).isoformat()
    invite_payload = {
        "room_id": room_id,
        "room_name": room_name or "Room",
        "room_key_b64": room_key_b64.strip(),
        "invited_by": creator_user_id,
        "invited_by_display_name": display,
        "invited_by_phone": invited_by_phone,
        "room_context": context,
        "member_can_send_messages": member_can_send_messages,
        "member_can_add_members": member_can_add_members,
        "created_at": now,
    }
    body = json.dumps(invite_payload)

    invited: list[str] = []
    for uid in members:
        if uid == creator_user_id:
            continue
        key = _invites_key(uid)
        await client.hset(key, room_id, body)
        await client.expire(key, INVITE_TTL_SECS)
        invited.append(uid)

    logger.info(
        "room membership registered",
        room_id=room_id,
        member_count=len(members),
        invited_count=len(invited),
    )
    return {
        "room_id": room_id,
        "member_user_ids": sorted(members),
        "invited_user_ids": invited,
    }


async def list_pending_invites(user_id: str) -> list[dict[str, Any]]:
    user_id = _parse_uuid(user_id, "user_id")
    client = await get_redis()
    if not client:
        return []
    raw = await client.hgetall(_invites_key(user_id))
    out: list[dict[str, Any]] = []
    for _room_id, payload in (raw or {}).items():
        try:
            out.append(json.loads(payload))
        except (TypeError, json.JSONDecodeError):
            continue
    return out


async def ack_invite(user_id: str, room_id: str) -> None:
    user_id = _parse_uuid(user_id, "user_id")
    room_id = _parse_uuid(room_id, "room_id")
    client = await get_redis()
    if not client:
        return
    await client.hdel(_invites_key(user_id), room_id)


async def is_member(room_id: str, user_id: str) -> bool:
    room_id = _parse_uuid(room_id, "room_id")
    user_id = _parse_uuid(user_id, "user_id")
    client = await get_redis()
    if not client:
        return False
    return bool(await client.sismember(_acl_key(room_id), user_id))
