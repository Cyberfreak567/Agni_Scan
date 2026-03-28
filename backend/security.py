from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timezone

from fastapi import Depends, Header, HTTPException, status

from .db import execute, fetch_one


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return f"{salt.hex()}:{digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    salt_hex, _digest_hex = stored_hash.split(":", 1)
    expected = hash_password(password, bytes.fromhex(salt_hex))
    return hmac.compare_digest(expected, stored_hash)


def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    execute(
        "INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
        (token, user_id, utc_now()),
    )
    return token


def _extract_bearer_token(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Authorization header")
    prefix = "Bearer "
    if not authorization.startswith(prefix):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Authorization header")
    return authorization[len(prefix) :].strip()


def get_current_user(authorization: str | None = Header(default=None)) -> dict:
    token = _extract_bearer_token(authorization)
    user = fetch_one(
        """
        SELECT users.id, users.username, users.role
        FROM sessions
        JOIN users ON users.id = sessions.user_id
        WHERE sessions.token = ?
        """,
        (token,),
    )
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session")
    return user


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return user
