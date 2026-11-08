"""Password hashing, sesi web, token MCP, PKCE.

Password: Argon2id (argon2-cffi). Sesi web dan token MCP disimpan sebagai
hash SHA-256 — token asli hanya dikirim sekali ke klien.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError, VerificationError

from . import db

SESSION_COOKIE = "edlink_session"
SESSION_TTL = int(60 * 60 * 24 * 14)  # 14 hari
MCP_TOKEN_TTL = int(60 * 60 * 24 * 30)  # 30 hari
CODE_TTL = 300

_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32)


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except Exception:
        return False


def password_problem(password: str) -> str | None:
    if len(password) < 10:
        return "Password minimal 10 karakter."
    if len(password) > 200:
        return "Password maksimal 200 karakter."
    if password.lower() in {"password12", "1234567890", "qwertyuiop"}:
        return "Password terlalu mudah ditebak."
    return None


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------ users ---

def create_user(email: str, password: str, display_name: str = "", is_admin: bool = False) -> str:
    user_id = db.new_id("usr_")
    with db.tx() as conn:
        conn.execute(
            "INSERT INTO users (id, email, password_hash, display_name, created_at, status, is_admin)"
            " VALUES (?,?,?,?,?,'active',?)",
            (user_id, email.strip().lower(), hash_password(password), display_name[:80], db.now(), 1 if is_admin else 0),
        )
    return user_id


def find_user_by_email(email: str) -> Any:
    return db.q1("SELECT * FROM users WHERE email = ? COLLATE NOCASE", (email.strip().lower(),))


def get_user(user_id: str) -> Any:
    return db.q1("SELECT * FROM users WHERE id = ?", (user_id,))


def authenticate(email: str, password: str) -> tuple[Any | None, str]:
    """Kembalikan (user_row, reason). reason kosong kalau sukses."""
    row = find_user_by_email(email)
    if row is None:
        # Tetap jalankan hash dummy supaya waktu respons mirip.
        hash_password(password)
        return None, "email atau password salah"
    if row["status"] != "active":
        return None, "akun tidak aktif"
    if not verify_password(row["password_hash"], password):
        return None, "email atau password salah"
    if needs_rehash(row["password_hash"]):
        with db.tx() as conn:
            conn.execute(
                "UPDATE users SET password_hash=? WHERE id=?",
                (hash_password(password), row["id"]),
            )
    return row, ""


# --------------------------------------------------------------- sessions ---

def create_session(user_id: str, ip: str = "", user_agent: str = "") -> str:
    sid = secrets.token_urlsafe(32)
    with db.tx() as conn:
        conn.execute(
            "INSERT INTO user_sessions (id, user_id, created_at, expires_at, revoked, ip, user_agent)"
            " VALUES (?,?,?,?,0,?,?)",
            (sha256_hex(sid), user_id, db.now(), db.now() + SESSION_TTL, ip[:64], user_agent[:300]),
        )
    return sid


def session_user(sid: str) -> Any | None:
    if not sid:
        return None
    row = db.q1(
        "SELECT s.user_id, s.expires_at, s.revoked, u.email, u.is_admin, u.status"
        " FROM user_sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ?",
        (sha256_hex(sid),),
    )
    if row is None or row["revoked"] or row["expires_at"] < db.now():
        return None
    if row["status"] != "active":
        return None
    return row


def revoke_session(sid: str) -> None:
    with db.tx() as conn:
        conn.execute("UPDATE user_sessions SET revoked=1 WHERE id=?", (sha256_hex(sid),))


def revoke_all_sessions(user_id: str) -> int:
    with db.tx() as conn:
        cur = conn.execute("UPDATE user_sessions SET revoked=1 WHERE user_id=? AND revoked=0", (user_id,))
        return cur.rowcount


# ------------------------------------------------------------- mcp tokens ---

def create_mcp_token(user_id: str, client_id: str = "", name: str = "", ttl: int = MCP_TOKEN_TTL) -> str:
    raw = "edm_" + secrets.token_urlsafe(32)
    with db.tx() as conn:
        conn.execute(
            "INSERT INTO mcp_tokens (id, user_id, token_hash, client_id, name, created_at, expires_at, revoked)"
            " VALUES (?,?,?,?,?,?,?,0)",
            (db.new_id("tok_"), user_id, sha256_hex(raw), client_id[:120], name[:80], db.now(), db.now() + ttl),
        )
    return raw


def token_user(raw_token: str) -> Any | None:
    if not raw_token:
        return None
    row = db.q1(
        "SELECT t.id AS token_id, t.user_id, t.expires_at, t.revoked, u.email, u.is_admin, u.status"
        " FROM mcp_tokens t JOIN users u ON u.id = t.user_id WHERE t.token_hash = ?",
        (sha256_hex(raw_token),),
    )
    if row is None or row["revoked"] or row["expires_at"] < db.now():
        return None
    if row["status"] != "active":
        return None
    return row


def revoke_mcp_tokens(user_id: str) -> int:
    with db.tx() as conn:
        cur = conn.execute("UPDATE mcp_tokens SET revoked=1 WHERE user_id=? AND revoked=0", (user_id,))
        return cur.rowcount


def list_mcp_tokens(user_id: str) -> list[Any]:
    return db.q(
        "SELECT id, client_id, name, created_at, expires_at, revoked FROM mcp_tokens"
        " WHERE user_id=? ORDER BY created_at DESC",
        (user_id,),
    )


# -------------------------------------------------------------------- pkce ---

def verify_pkce(verifier: str, challenge: str, method: str = "S256") -> bool:
    if not verifier or not challenge:
        return False
    if method != "S256":
        return False
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return hmac.compare_digest(computed, challenge)


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def expires_in(seconds: int) -> int:
    return int(time.time()) + seconds
