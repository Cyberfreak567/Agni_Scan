from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status

from ..db import execute, fetch_one
from ..models.schemas import AuthResponse, LoginRequest, RegisterRequest, UserOut
from ..security import (
    clear_failed_login,
    create_session,
    ensure_login_allowed,
    get_client_ip,
    get_current_user,
    hash_password,
    needs_rehash,
    record_failed_login,
    utc_now,
    verify_password,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/register", response_model=AuthResponse)
def register(payload: RegisterRequest) -> AuthResponse:
    existing = fetch_one("SELECT id FROM users WHERE username = ?", (payload.username,))
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")
    if payload.role == "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin registration is disabled. Contact an administrator to grant admin access.",
        )
    user_id = execute(
        "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
        (payload.username, hash_password(payload.password), "user", utc_now()),
    )
    token = create_session(user_id)
    return AuthResponse(token=token, username=payload.username, role="user")


@router.post("/login", response_model=AuthResponse)
def login(payload: LoginRequest, request: Request) -> AuthResponse:
    ip = get_client_ip(request)
    ensure_login_allowed(payload.username, ip)
    user = fetch_one("SELECT * FROM users WHERE username = ?", (payload.username,))
    if not user or not verify_password(payload.password, user["password_hash"]):
        record_failed_login(payload.username, ip)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    clear_failed_login(payload.username, ip)
    if needs_rehash(user["password_hash"]):
        execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (hash_password(payload.password), user["id"]),
        )
    token = create_session(user["id"])
    return AuthResponse(token=token, username=user["username"], role=user["role"])


@router.get("/me", response_model=UserOut)
def me(user: dict = Depends(get_current_user)) -> UserOut:
    return UserOut(**user)
