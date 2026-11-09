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

-- Rate limit per identitas: satu baris per (bucket, key). Bucket memisahkan
-- jenis aksi (login, signup, link, token, mcp) supaya kuota satu aksi tidak
-- memakan kuota aksi lain. Key berisi identitas yang relevan untuk bucket itu:
-- email|ip untuk login, user_id untuk aksi yang butuh sesi, client_id untuk
-- OAuth. Admin tidak pernah dicatat oleh pemanggil, jadi tidak pernah kena.
CREATE TABLE IF NOT EXISTS rate_limits (
    bucket   TEXT NOT NULL,
    key      TEXT NOT NULL,
    count    INTEGER NOT NULL DEFAULT 0,
    reset_at REAL NOT NULL,
    PRIMARY KEY (bucket, key)
);

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
    # Baris rate limit yang window-nya lewat tidak berguna lagi.
    conn.execute("DELETE FROM rate_limits WHERE reset_at < ?", (now(),))


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


def rate_limit(bucket: str, key: str, limit: int, window: int) -> tuple[bool, int]:
    """Catat satu percobaan untuk (bucket, key).

    Window tetap: hitungan kembali ke nol saat reset_at lewat. Percobaan yang
    sudah diblokir tetap menambah count, tapi tidak menggeser reset_at, jadi
    penyerang tidak bisa memperpanjang cooldown dirinya sendiri-sendiri.

    :return: (boleh_lanjut, sisa_detik_cooldown)
    """
    if limit <= 0:
        return True, 0
    ts = now()
    ident = str(key)[:120]
    with tx() as conn:
        row = conn.execute(
            "SELECT count, reset_at FROM rate_limits WHERE bucket=? AND key=?",
            (bucket, ident),
        ).fetchone()
        if row is None or row["reset_at"] <= ts:
            conn.execute(
                "INSERT INTO rate_limits (bucket, key, count, reset_at) VALUES (?,?,1,?) "
                "ON CONFLICT(bucket, key) DO UPDATE SET count=1, reset_at=excluded.reset_at",
                (bucket, ident, ts + window),
            )
            return True, 0
        count = int(row["count"]) + 1
        conn.execute(
            "UPDATE rate_limits SET count=? WHERE bucket=? AND key=?",
            (count, bucket, ident),
        )
        if count <= limit:
            return True, 0
        return False, max(1, int(row["reset_at"] - ts))


def rate_limit_state(bucket: str, key: str) -> tuple[int, int]:
    """(count, sisa_detik) untuk ditampilkan di admin. Tanpa efek samping."""
    row = q1(
        "SELECT count, reset_at FROM rate_limits WHERE bucket=? AND key=?",
        (bucket, str(key)[:120]),
    )
    if row is None:
        return 0, 0
    return int(row["count"]), max(0, int(row["reset_at"] - now()))


def rate_limit_clear(bucket: str = "", key: str = "") -> int:
    """Hapus hitungan. Tanpa argumen = bersihkan semua bucket."""
    with tx() as conn:
        if bucket and key:
            cur = conn.execute(
                "DELETE FROM rate_limits WHERE bucket=? AND key=?", (bucket, str(key)[:120])
            )
        elif bucket:
            cur = conn.execute("DELETE FROM rate_limits WHERE bucket=?", (bucket,))
        else:
            cur = conn.execute("DELETE FROM rate_limits")
        return cur.rowcount


def rate_limit_prune() -> int:
    """Buang baris yang window-nya sudah lewat. Dipanggil saat startup."""
    with tx() as conn:
        cur = conn.execute("DELETE FROM rate_limits WHERE reset_at < ?", (now(),))
        return cur.rowcount
