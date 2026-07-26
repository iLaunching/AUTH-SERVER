"""
Refresh-token hashing for device sessions.

Uses SHA-256 over the full JWT (bcrypt silently truncates at 72 bytes).
Legacy bcrypt hashes are still accepted until the next successful refresh rotates them.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Optional

from auth.password_handler import PasswordHandler


SHA256_PREFIX = "sha256:"


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
