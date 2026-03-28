from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from ..db import execute, fetch_one
from ..models.schemas import AuthResponse, LoginRequest, RegisterRequest, UserOut
from ..security import create_session, get_current_user, hash_password, utc_now, verify_password

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/register", response_model=AuthResponse)
def register(payload: RegisterRequest) -> AuthResponse:
    existing = fetch_one("SELECT id FROM users WHERE username = ?", (payload.username,))
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")
    user_id = execute(
        "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
        (payload.username, hash_password(payload.password), payload.role, utc_now()),
    )
    token = create_session(user_id)
    return AuthResponse(token=token, username=payload.username, role=payload.role)


@router.post("/login", response_model=AuthResponse)
def login(payload: LoginRequest) -> AuthResponse:
    user = fetch_one("SELECT * FROM users WHERE username = ?", (payload.username,))
    if not user or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = create_session(user["id"])
    return AuthResponse(token=token, username=user["username"], role=user["role"])


@router.get("/me", response_model=UserOut)
def me(user: dict = Depends(get_current_user)) -> UserOut:
    return UserOut(**user)
