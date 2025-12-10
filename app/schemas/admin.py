from pydantic import BaseModel, EmailStr
from datetime import datetime


class AdminUser(BaseModel):
    id: int
    email: EmailStr
    name: str | None
    role: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class UpdateRoleRequest(BaseModel):
    role: str


class AdminStatsResponse(BaseModel):
    total_users: int
    pending_users: int
    active_users: int
    total_admins: int
    today_signups: int
