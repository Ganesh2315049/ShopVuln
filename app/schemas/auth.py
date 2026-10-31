"""Authentication and user schemas."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class LoginRequest(BaseModel):
    username: str = Field(..., description="Username or email")
    password: str = Field(..., description="User password")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str
    user_id: int


class TokenPayload(BaseModel):
    sub: str  # user id as string
    username: str
    role: str
    exp: Optional[int] = None


class UserBase(BaseModel):
    username: str
    email: str
    role: str = "customer"


class UserCreate(UserBase):
    password: str


class UserResponse(UserBase):
    id: int
    balance: float
    is_active: bool
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)
