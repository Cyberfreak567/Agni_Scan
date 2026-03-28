from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, HttpUrl, field_validator


def normalize_url_text(value: str) -> str:
    return value.strip().split()[0]


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=128)
    role: Literal["admin", "user"] = "user"

    @field_validator("username")
    @classmethod
    def username_is_safe(cls, value: str) -> str:
        value = value.strip()
        if not value.replace("_", "").replace("-", "").isalnum():
            raise ValueError("Username must be alphanumeric, dash, or underscore")
        return value


class LoginRequest(BaseModel):
    username: str
    password: str


class AuthResponse(BaseModel):
    token: str
    username: str
    role: str


class UserOut(BaseModel):
    id: int
    username: str
    role: str


class SASTScanRequest(BaseModel):
    repo_url: HttpUrl | None = None

    @field_validator("repo_url", mode="before")
    @classmethod
    def normalize_repo_url(cls, value: str | None) -> str | None:
        if value is None:
            return value
        return normalize_url_text(value)

    @field_validator("repo_url")
    @classmethod
    def github_only(cls, value: HttpUrl | None) -> HttpUrl | None:
        if value is None:
            return value
        if value.host != "github.com":
            raise ValueError("Only GitHub repository URLs are allowed for remote SAST scans")
        return value


class DASTScanRequest(BaseModel):
    target_url: HttpUrl
    mode: Literal["quick", "full"] = "full"

    @field_validator("target_url", mode="before")
    @classmethod
    def normalize_target_url(cls, value: str) -> str:
        return normalize_url_text(value)


class VulnerabilityOut(BaseModel):
    id: int
    title: str
    severity: str
    score: float | None = None
    finding_kind: str = "vulnerability"
    owasp_category: str | None = None
    confidence: str | None = None
    file: str | None = None
    line_number: int | None = None
    description: str
    evidence: str | None = None
    tool: str
    raw_json: dict | None = None


class ScanOut(BaseModel):
    id: int
    scan_type: str
    target: str
    source_type: str | None = None
    scan_mode: str | None = None
    current_stage: str | None = None
    status: str
    progress: int
    tool_status: dict
    summary: dict
    stdout_log: str
    stderr_log: str
    error_message: str | None = None
    created_at: str
    updated_at: str
    vulnerabilities: list[VulnerabilityOut] = []
