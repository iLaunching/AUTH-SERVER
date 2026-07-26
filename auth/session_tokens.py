"""
Refresh-token hashing for device sessions.

Uses SHA-256 over the full JWT (bcrypt silently truncates at 72 bytes).
Legacy bcrypt hashes are still accepted until the next successful refresh rotates them.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Tuple

from auth.password_handler import PasswordHandler


SHA256_PREFIX = "sha256:"
# How long the previous refresh hash stays valid after rotation (concurrent client race).
PREVIOUS_REFRESH_GRACE_SECS = 90
PREV_HASH_KEY = "_prev_rt_hash"
PREV_UNTIL_KEY = "_prev_rt_until"


def hash_refresh_token(token: str) -> str:
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return f"{SHA256_PREFIX}{digest}"


def verify_refresh_token_hash(token: str, stored_hash: Optional[str]) -> bool:
    if not stored_hash:
        return False
    if stored_hash.startswith(SHA256_PREFIX):
        return hmac.compare_digest(hash_refresh_token(token), stored_hash)
    # Legacy bcrypt (truncated JWT) — migrate away on next rotation.
    try:
        return PasswordHandler.verify_password(token, stored_hash)
    except Exception:
        return False


def refresh_token_accepted(
    token: str,
    current_hash: Optional[str],
    device_info: Optional[dict],
) -> Tuple[bool, bool]:
    """
    Returns (accepted, used_previous_grace).
    Accepts the current hash, or the previous hash within the grace window.
    """
    if verify_refresh_token_hash(token, current_hash):
        return True, False
    info = device_info or {}
    prev_hash = info.get(PREV_HASH_KEY)
    prev_until_raw = info.get(PREV_UNTIL_KEY)
    if not prev_hash or not prev_until_raw:
        return False, False
    try:
        prev_until = datetime.fromisoformat(str(prev_until_raw))
        if prev_until.tzinfo is None:
            prev_until = prev_until.replace(tzinfo=timezone.utc)
    except Exception:
        return False, False
    if datetime.now(timezone.utc) > prev_until:
        return False, False
    if verify_refresh_token_hash(token, prev_hash):
        return True, True
    return False, False


def store_previous_refresh_hash(device_info: Optional[dict], previous_hash: str) -> dict:
    info: dict[str, Any] = dict(device_info or {})
    info[PREV_HASH_KEY] = previous_hash
    info[PREV_UNTIL_KEY] = (
        datetime.now(timezone.utc) + timedelta(seconds=PREVIOUS_REFRESH_GRACE_SECS)
    ).isoformat()
    return info
