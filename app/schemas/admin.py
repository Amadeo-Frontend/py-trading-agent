# app/schemas/admin.py
from datetime import date, datetime
from typing import List, Optional

from pydantic import BaseModel, EmailStr


class AdminUser(BaseModel):
    id: int
    email: EmailStr
    name: Optional[str]
    role: str
    is_active: bool
    created_at: datetime
    last_login_at: Optional[datetime]

    class Config:
        from_attributes = True


class AdminDailyLogin(BaseModel):
    day: date
    count: int


class AdminStats(BaseModel):
    total_users: int
    active_users: int
    admins: int
    pending_users: int
    logins_last_24h: int
    logins_per_day: List[AdminDailyLogin]
    last_users: List[AdminUser]
