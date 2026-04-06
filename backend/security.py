from __future__ import annotations

import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Depends, Header, HTTPException, Request, status
from passlib.context import CryptContext

from .db import execute, fetch_one

PASSWORD_CONTEXT = CryptContext(
    schemes=["argon2", "pbkdf2_sha256"],
    deprecated=["pbkdf2_sha256"],
)
SESSION_TTL = timedelta(days=7)
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_WINDOW = timedelta(minutes=15)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def utc_now_dt() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def hash_password(password: str, salt: bytes | None = None) -> str:
    if salt is not None:
        return _legacy_hash(password, salt)
    return PASSWORD_CONTEXT.hash(password)


def _legacy_hash(password: str, salt: bytes) -> str:
    import hashlib

    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return f"{salt.hex()}:{digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    if ":" in stored_hash and len(stored_hash.split(":", 1)[0]) == 32:
        salt_hex, _digest_hex = stored_hash.split(":", 1)
        expected = _legacy_hash(password, bytes.fromhex(salt_hex))
        return hmac.compare_digest(expected, stored_hash)
    return PASSWORD_CONTEXT.verify(password, stored_hash)


def needs_rehash(stored_hash: str) -> bool:
    if ":" in stored_hash and len(stored_hash.split(":", 1)[0]) == 32:
        return True
    return PASSWORD_CONTEXT.needs_update(stored_hash)


def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = (utc_now_dt() + SESSION_TTL).isoformat()
    execute(
        "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (token, user_id, utc_now(), expires_at),
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
        SELECT users.id, users.username, users.role, sessions.expires_at
        FROM sessions
        JOIN users ON users.id = sessions.user_id
        WHERE sessions.token = ?
        """,
        (token,),
    )
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session")
    expires_at = _parse_iso(user.get("expires_at"))
    if expires_at and expires_at < utc_now_dt():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired")
    return user


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return user


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def record_failed_login(username: str, ip: str) -> None:
    now = utc_now_dt()
    row = fetch_one(
        "SELECT failed_count, last_failed_at, locked_until FROM login_attempts WHERE username = ? AND ip_address = ?",
        (username, ip),
    )
    if not row:
        execute(
            "INSERT INTO login_attempts (username, ip_address, failed_count, last_failed_at, locked_until) VALUES (?, ?, ?, ?, ?)",
            (username, ip, 1, now.isoformat(), None),
        )
        return
    last_failed = _parse_iso(row["last_failed_at"]) or now
    locked_until = _parse_iso(row.get("locked_until"))
    if locked_until and locked_until > now:
        return
    window_start = now - LOCKOUT_WINDOW
    failed_count = row["failed_count"] + (0 if last_failed < window_start else 1)
    locked_until_value = None
    if failed_count >= MAX_FAILED_ATTEMPTS:
        locked_until_value = (now + LOCKOUT_WINDOW).isoformat()
    execute(
        "UPDATE login_attempts SET failed_count = ?, last_failed_at = ?, locked_until = ? WHERE username = ? AND ip_address = ?",
        (failed_count, now.isoformat(), locked_until_value, username, ip),
    )


def clear_failed_login(username: str, ip: str) -> None:
    execute("DELETE FROM login_attempts WHERE username = ? AND ip_address = ?", (username, ip))


def ensure_login_allowed(username: str, ip: str) -> None:
    row = fetch_one(
        "SELECT locked_until FROM login_attempts WHERE username = ? AND ip_address = ?",
        (username, ip),
    )
    if not row:
        return
    locked_until = _parse_iso(row.get("locked_until"))
    if locked_until and locked_until > utc_now_dt():
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Try again later.",
        )
