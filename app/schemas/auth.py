# app/schemas/auth.py

from datetime import datetime, date
from typing import List, Optional

from pydantic import BaseModel, EmailStr, Field


# ---------------------------------------------------------
# Schemas de usuário base / criação / leitura
# ---------------------------------------------------------

class UserBase(BaseModel):
    email: EmailStr
    name: Optional[str] = None


class UserCreate(UserBase):
    # campo de entrada de senha (não vai para o banco diretamente)
    password: str = Field(min_length=6)


class UserRead(UserBase):
    id: int
    role: str
    is_active: bool

    class Config:
        from_attributes = True  # pydantic v2: converte a partir de ORM


# ---------------------------------------------------------
# Token JWT
# ---------------------------------------------------------

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    user_id: int
    role: str


# ---------------------------------------------------------
# Schemas usados no painel admin (/admin)
# ---------------------------------------------------------

class AdminUser(BaseModel):
    id: int
    email: EmailStr
    name: Optional[str] = None
    role: str
    is_active: bool
    created_at: datetime
    # campos agregados que o endpoint pode preencher:
    last_login_at: Optional[datetime] = None
    logins_count: int = 0

    class Config:
        from_attributes = True


class DailyLoginCount(BaseModel):
    day: date
    count: int


class AdminStats(BaseModel):
    total_users: int
    total_active_users: int
    total_pending_users: int
    total_admins: int

    # últimos usuários criados
    last_users: List[AdminUser] = []

    # agregados de logins por dia
    logins_per_day: List[DailyLoginCount] = []
