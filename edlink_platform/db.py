"""SQLite store untuk platform multi-user EdLink MCP.

Satu koneksi per thread, WAL, foreign key aktif. Semua query parameterized.
Tidak ada query lintas-user tanpa filter user_id eksplisit.
"""

from __future__ import annotations

import os
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

DB_PATH = Path(os.environ.get("EDLINK_PLATFORM_DB", "platform.db")).expanduser()

_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    display_name  TEXT NOT NULL DEFAULT '',
    created_at    REAL NOT NULL,
    status        TEXT NOT NULL DEFAULT 'active',
    is_admin      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS user_sessions (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0,
    ip         TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id);

CREATE TABLE IF NOT EXISTS edlink_connections (
    user_id       TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    mode          TEXT NOT NULL,
    token_enc     TEXT NOT NULL DEFAULT '',
    email_enc     TEXT NOT NULL DEFAULT '',
    password_enc  TEXT NOT NULL DEFAULT '',
    device_json   TEXT NOT NULL DEFAULT '',
    saved_at      REAL NOT NULL DEFAULT 0,
    updated_at    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS mcp_tokens (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    client_id  TEXT NOT NULL DEFAULT '',
    name       TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_mcp_tokens_user ON mcp_tokens(user_id);

CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id     TEXT PRIMARY KEY,
    client_secret TEXT NOT NULL DEFAULT '',
    redirect_uris TEXT NOT NULL,
    client_name   TEXT NOT NULL DEFAULT '',
    created_at    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
    code            TEXT PRIMARY KEY,
    client_id       TEXT NOT NULL,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri    TEXT NOT NULL,
    code_challenge  TEXT NOT NULL,
    resource        TEXT NOT NULL DEFAULT '',
    scope           TEXT NOT NULL DEFAULT '',
    created_at      REAL NOT NULL,
    expires_at      REAL NOT NULL,
    used            INTEGER NOT NULL DEFAULT 0
);

-- Refresh token OAuth. Disimpan sebagai hash, diputar pada setiap pemakaian
-- (rotasi): token lama ditandai rotated=1 dan tidak bisa dipakai dua kali.
CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    client_id  TEXT NOT NULL DEFAULT '',
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope      TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    rotated    INTEGER NOT NULL DEFAULT 0,
    revoked    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_refresh_user ON oauth_refresh_tokens(user_id);

CREATE TABLE IF NOT EXISTS audit_events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      REAL NOT NULL,
    user_id TEXT,
    action  TEXT NOT NULL,
    detail  TEXT NOT NULL DEFAULT '',
    ip      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_events(user_id);

CREATE TABLE IF NOT EXISTS rate_limits (
    key          TEXT NOT NULL,
    window_start REAL NOT NULL,
    count        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (key, window_start)
);
"""


def connect() -> sqlite3.Connection:
    """Koneksi thread-local. WAL + foreign key + busy timeout."""
    conn = getattr(_local, "conn", None)
    path = str(DB_PATH)
    if conn is not None and getattr(_local, "path", None) == path:
        return conn
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=15.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=15000")
    _local.conn = conn
    _local.path = path
    return conn


def init_db() -> None:
    conn = connect()
    conn.executescript(SCHEMA)
    # audit_events dipakai untuk forensik, bukan arsip permanen. Simpan 90 hari.
    conn.execute("DELETE FROM audit_events WHERE ts < ?", (now() - 90 * 86400,))


@contextmanager
def tx() -> Iterator[sqlite3.Connection]:
    """Transaksi tulis eksplisit."""
    conn = connect()
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except Exception:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def q(sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
    return list(connect().execute(sql, params).fetchall())


def q1(sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
    return connect().execute(sql, params).fetchone()


def new_id(prefix: str = "") -> str:
    return prefix + secrets.token_urlsafe(18)


def now() -> float:
    return time.time()


def audit(user_id: str | None, action: str, detail: str = "", ip: str = "") -> None:
    """Catat peristiwa. Detail tidak boleh memuat kredensial."""
    with tx() as conn:
        conn.execute(
            "INSERT INTO audit_events (ts, user_id, action, detail, ip) VALUES (?,?,?,?,?)",
            (now(), user_id, action[:80], detail[:500], ip[:64]),
        )


def rate_limit(key: str, limit: int, window_seconds: int) -> bool:
    """True kalau masih diizinkan. Sliding window per detik kasar."""
    bucket = int(now() // window_seconds) * window_seconds
    with tx() as conn:
        row = conn.execute(
            "SELECT count FROM rate_limits WHERE key=? AND window_start=?",
            (key[:200], bucket),
        ).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO rate_limits (key, window_start, count) VALUES (?,?,1)",
                (key[:200], bucket),
            )
            allowed = True
        else:
            count = row["count"] + 1
            conn.execute(
                "UPDATE rate_limits SET count=? WHERE key=? AND window_start=?",
                (count, key[:200], bucket),
            )
            allowed = count <= limit
        if bucket % 3600 == 0:
            conn.execute("DELETE FROM rate_limits WHERE window_start < ?", (bucket - 86400,))
    return allowed
