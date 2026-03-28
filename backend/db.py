from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "scanner.db"


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(
            """
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                scan_type TEXT NOT NULL CHECK (scan_type IN ('sast', 'dast')),
                target TEXT NOT NULL,
                source_type TEXT,
                scan_mode TEXT,
                current_stage TEXT,
                status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed')),
                progress INTEGER NOT NULL DEFAULT 0,
                tool_status TEXT NOT NULL DEFAULT '{}',
                summary_json TEXT NOT NULL DEFAULT '{}',
                stdout_log TEXT NOT NULL DEFAULT '',
                stderr_log TEXT NOT NULL DEFAULT '',
                error_message TEXT,
                report_html_path TEXT,
                report_pdf_path TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                score REAL,
                finding_kind TEXT NOT NULL DEFAULT 'vulnerability',
                owasp_category TEXT,
                confidence TEXT,
                file TEXT,
                line_number INTEGER,
                description TEXT NOT NULL,
                evidence TEXT,
                tool TEXT NOT NULL,
                raw_json TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
            """
        )
        _ensure_column(conn, "scans", "scan_mode", "TEXT")
        _ensure_column(conn, "scans", "current_stage", "TEXT")
        _ensure_column(conn, "vulnerabilities", "finding_kind", "TEXT NOT NULL DEFAULT 'vulnerability'")
        _ensure_column(conn, "vulnerabilities", "score", "REAL")
        _ensure_column(conn, "vulnerabilities", "owasp_category", "TEXT")
        _ensure_column(conn, "vulnerabilities", "confidence", "TEXT")
        _ensure_column(conn, "vulnerabilities", "evidence", "TEXT")


@contextmanager
def get_conn() -> Iterable[sqlite3.Connection]:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def fetch_all(query: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]


def fetch_one(query: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
    with get_conn() as conn:
        row = conn.execute(query, params).fetchone()
        return dict(row) if row else None


def execute(query: str, params: tuple[Any, ...] = ()) -> int:
    with get_conn() as conn:
        cur = conn.execute(query, params)
        return int(cur.lastrowid)


def execute_many(query: str, items: list[tuple[Any, ...]]) -> None:
    with get_conn() as conn:
        conn.executemany(query, items)


def dumps_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True)
