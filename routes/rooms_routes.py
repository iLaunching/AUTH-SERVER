"""Phase 7b — room membership ACL registration + pending invite pull."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from fastapi import APIRouter, Depends, status

from models.user import User
from routes.auth_routes import get_current_user
from services import room_membership

router = APIRouter(prefix="/rooms", tags=["rooms"])


class RegisterRoomMembersRequest(BaseModel):
    room_id: str
    member_user_ids: list[str] = Field(default_factory=list)
    room_name: str = "Room"
    room_key_b64: str
    member_can_send_messages: bool = True
    member_can_add_members: bool = False

    @field_validator("room_id", "room_key_b64")
    @classmethod
    def nonempty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("must not be empty")
        return v


class RegisterRoomMembersResponse(BaseModel):
    room_id: str
    member_user_ids: list[str]
    invited_user_ids: list[str]


class RoomInviteItem(BaseModel):
    room_id: str
    room_name: str
    room_key_b64: str
    invited_by: str
    member_can_send_messages: bool = True
    member_can_add_members: bool = False
    created_at: str | None = None


class RoomInvitesResponse(BaseModel):
    invites: list[RoomInviteItem]


class AckInviteRequest(BaseModel):
    room_id: str


@router.post(
    "/members",
    response_model=RegisterRoomMembersResponse,
    status_code=status.HTTP_200_OK,
    summary="Register room ACL members + enqueue invites",
)
async def register_members(
    body: RegisterRoomMembersRequest,
    user: User = Depends(get_current_user),
):
    result = await room_membership.register_room_membership(
        room_id=body.room_id,
        creator_user_id=str(user.id),
        member_user_ids=body.member_user_ids,
        room_name=body.room_name,
        room_key_b64=body.room_key_b64,
        member_can_send_messages=body.member_can_send_messages,
        member_can_add_members=body.member_can_add_members,
    )
    return RegisterRoomMembersResponse(**result)


@router.get(
    "/invites",
    response_model=RoomInvitesResponse,
    summary="Pending room invites for the current user",
)
async def list_invites(user: User = Depends(get_current_user)):
    raw = await room_membership.list_pending_invites(str(user.id))
    invites = [RoomInviteItem(**item) for item in raw if "room_id" in item and "room_key_b64" in item]
    return RoomInvitesResponse(invites=invites)


@router.post("/invites/ack", summary="Acknowledge (clear) a pending room invite")
async def ack_invite(body: AckInviteRequest, user: User = Depends(get_current_user)):
    await room_membership.ack_invite(str(user.id), body.room_id)
    return {"status": "ok"}
