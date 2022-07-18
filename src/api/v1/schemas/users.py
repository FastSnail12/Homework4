from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr

__all__ = (
    "UserSignup",
    "UserLogin",
    "UserModel",
    "UserJwtToken",
    "UserUpdateModel",
)


class UserBase(BaseModel):
    username: str


class UserLogin(UserBase):
    password: str


class UserSignup(UserBase):
    email: EmailStr
    password: str


class UserModel(UserBase):
    email: EmailStr
    id: Optional[int]
    is_superuser: bool
    created_at: datetime
    updated_at: datetime


class UserUpdateModel(BaseModel):
    user: dict
    access_token: str


class UserJwtToken(BaseModel):
    access_token: str
    refresh_token: str
