import re

from pydantic import BaseModel, EmailStr, field_validator


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    full_name: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value):
        if len(value) < 8:
            raise ValueError("Mật khẩu phải có tối thiểu 8 ký tự")
        if not re.search(r"[A-Z]", value):
            raise ValueError("Mật khẩu phải có ít nhất một chữ hoa")
        if not re.search(r"[a-z]", value):
            raise ValueError("Mật khẩu phải có ít nhất một chữ thường")
        if not re.search(r"[0-9]", value):
            raise ValueError("Mật khẩu phải có ít nhất một chữ số")
        return value


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: int
    email: EmailStr
    full_name: str
    role: str
    is_active: bool

    class Config:
        from_attributes = True


class RegisterResponse(BaseModel):
    message: str
    data: UserResponse


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
