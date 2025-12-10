# app/schemas/auth.py
from typing import Optional

from pydantic import BaseModel, EmailStr, Field


class UserBase(BaseModel):
    email: EmailStr
    name: Optional[str] = None


class UserCreate(UserBase):
    password: str = Field(min_length=6)


class UserRead(UserBase):
    id: int
    role: str
    is_active: bool

    class Config:
        from_attributes = True  # pydantic v2


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    user_id: int
    role: str
