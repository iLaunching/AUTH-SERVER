from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .settings import get_verification_settings


async def get_active_verification(db: AsyncSession, user_id: str) -> dict | None:
    result = await db.execute(
        text(
            """
            SELECT id, trust_level, verification_method, verified_at, expires_at
            FROM verified_identities
            WHERE user_id = :user_id
              AND revoked_at IS NULL
              AND expires_at > NOW()
            LIMIT 1
            """
        ),
        {"user_id": user_id},
    )
    row = result.mappings().first()
    return dict(row) if row else None


async def upsert_verified_identity(
    db: AsyncSession,
    user_id: str,
    phone_number: str,
    verification_method: str,
    trust_level: str,
    hardware_id: str | None = None,
) -> None:
    s = get_verification_settings()

    await db.execute(
        text(
            """
            INSERT INTO verified_identities
                (user_id, phone_number, trust_level, verification_method, hardware_id, expires_at)
            VALUES
                (:user_id, :phone_number, :trust_level, :verification_method, :hardware_id,
                 NOW() + (:expiry_days || ' days')::interval)
            ON CONFLICT (user_id)
            WHERE revoked_at IS NULL
            DO UPDATE SET
                phone_number        = EXCLUDED.phone_number,
                trust_level         = CASE
                    WHEN (CASE verified_identities.trust_level WHEN 'HIGH' THEN 3 ELSE 2 END)
                       < (CASE EXCLUDED.trust_level WHEN 'HIGH' THEN 3 ELSE 2 END)
                    THEN EXCLUDED.trust_level
                    ELSE verified_identities.trust_level
                END,
                verification_method = EXCLUDED.verification_method,
                hardware_id         = COALESCE(EXCLUDED.hardware_id, verified_identities.hardware_id),
                verified_at         = NOW(),
                expires_at          = EXCLUDED.expires_at,
                revoked_at          = NULL,
                updated_at          = NOW()
            """
        ),
        {
            "user_id": user_id,
            "phone_number": phone_number,
            "trust_level": trust_level,
            "verification_method": verification_method,
            "hardware_id": hardware_id,
            "expiry_days": int(s.verification_expiry_days),
        },
    )


async def revoke_verification(db: AsyncSession, user_id: str) -> None:
    await db.execute(
        text(
            """
            UPDATE verified_identities
            SET revoked_at = NOW(), updated_at = NOW()
            WHERE user_id = :user_id AND revoked_at IS NULL
            """
        ),
        {"user_id": user_id},
    )


async def create_attempt(
    db: AsyncSession,
    phone_number: str,
    vonage_request_id: str,
    user_id: str | None = None,
    channel: str = "silent_auth",
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> None:
    await db.execute(
        text(
            """
            INSERT INTO verification_attempts
                (user_id, phone_number, vonage_request_id, channel, status, ip_address, user_agent)
            VALUES
                (:user_id, :phone_number, :vonage_request_id, :channel,
                 'pending', :ip_address::inet, :user_agent)
            """
        ),
        {
            "user_id": user_id,
            "phone_number": phone_number,
            "vonage_request_id": vonage_request_id,
            "channel": channel,
            "ip_address": ip_address,
            "user_agent": user_agent,
        },
    )


async def update_attempt_status(
    db: AsyncSession,
    vonage_request_id: str,
    new_status: str,
    failure_reason: str | None = None,
) -> None:
    await db.execute(
        text(
            """
            UPDATE verification_attempts
            SET status         = :status,
                failure_reason = :failure_reason,
                completed_at   = CASE
                    WHEN :status IN ('completed','failed','expired')
                    THEN NOW() ELSE NULL
                END
            WHERE vonage_request_id = :request_id
            """
        ),
        {"status": new_status, "failure_reason": failure_reason, "request_id": vonage_request_id},
    )

