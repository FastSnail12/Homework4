from datetime import datetime
from typing import Optional

from sqlmodel import Field, SQLModel
from sqlalchemy import Column, String

__all__ = ("User",)


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(nullable=False, sa_column=Column("username", String, unique=True))
    email: str = Field(nullable=False)
    hashed_password: str = Field(nullable=False)
    is_superuser: bool = Field(default=False)
    created_at: datetime = Field(default=datetime.utcnow(), nullable=False)
    updated_at: datetime = Field(default=datetime.utcnow(), nullable=False)
