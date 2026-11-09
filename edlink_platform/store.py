"""Penyimpanan kredensial EdLink per user (multi-tenant).

Semua nilai sensitif dienkripsi dengan edlink_platform.crypto sebelum masuk DB.
Tidak ada plaintext token/password di database maupun log.
"""

from __future__ import annotations

import json
from typing import Any

from . import crypto, db

TOKEN_MAX_AGE = 60 * 60 * 8
DEFAULT_DEVICE = {
    "name": "Chrome",
    "manufacture": "Google",
    "model": "Chrome",
    "product": "Chrome",
    "hardware": "Windows 10",
    "version": "126.0.0.0",
    "regId": None,
}


class NoConnection(RuntimeError):
    pass


def _row(user_id: str) -> Any:
    return db.q1("SELECT * FROM edlink_connections WHERE user_id = ?", (user_id,))


def has_connection(user_id: str) -> bool:
    row = _row(user_id)
    return bool(row and (row["token_enc"] or (row["email_enc"] and row["password_enc"])))


def save_connection(
    user_id: str,
    mode: str,
    token: str = "",
    email: str = "",
    password: str = "",
    device: dict[str, Any] | None = None,
) -> None:
    """Simpan koneksi EdLink user. mode: 'token' atau 'password'."""
    if mode not in ("token", "password"):
        raise ValueError("mode koneksi harus 'token' atau 'password'")
    if mode == "token" and not token:
        raise ValueError("mode token butuh token")
    if mode == "password" and not (email and password):
        raise ValueError("mode password butuh email dan password")
    device_json = json.dumps(device or {}, ensure_ascii=False)
    with db.tx() as conn:
        conn.execute(
            "INSERT INTO edlink_connections"
            " (user_id, mode, token_enc, email_enc, password_enc, device_json, saved_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?)"
            " ON CONFLICT(user_id) DO UPDATE SET"
            "  mode=excluded.mode, token_enc=excluded.token_enc, email_enc=excluded.email_enc,"
            "  password_enc=excluded.password_enc, device_json=excluded.device_json,"
            "  saved_at=excluded.saved_at, updated_at=excluded.updated_at",
            (
                user_id,
                mode,
                crypto.encrypt(token),
                crypto.encrypt(email),
                crypto.encrypt(password),
                device_json,
                db.now(),
                db.now(),
            ),
        )


def update_token(user_id: str, token: str) -> None:
    """Simpan token hasil login/refresh, pertahankan kredensial lain."""
    with db.tx() as conn:
        conn.execute(
            "UPDATE edlink_connections SET token_enc=?, saved_at=?, updated_at=?"
            " WHERE user_id=?",
            (crypto.encrypt(token), db.now(), db.now(), user_id),
        )


def load_credentials(user_id: str) -> dict[str, str]:
    """Bentuk yang sama dengan _load_credentials() lama.

    `token_enc` dipakai dua hal: kredensial token yang ditempel user (mode
    "token"), dan cache token hasil login password. Di mode "password" token
    itu hanya cache — kredensial sebenarnya email+password, kalau tidak maka
    token yang sudah mati akan terus dipakai dan tool berhenti bisa login ulang.
    """
    row = _row(user_id)
    if row is None:
        raise NoConnection("user belum menghubungkan akun EdLink")
    mode = (row["mode"] or "").strip()
    email = crypto.decrypt(row["email_enc"])
    password = crypto.decrypt(row["password_enc"])
    token = crypto.decrypt(row["token_enc"])
    if mode == "password" and email and password:
        return {"email": email, "password": password}
    if token:
        return {"token": token}
    if email and password:
        return {"email": email, "password": password}
    raise NoConnection("koneksi EdLink user kosong")


def read_token_cache(user_id: str) -> dict[str, Any] | None:
    row = _row(user_id)
    if row is None:
        return None
    token = crypto.decrypt(row["token_enc"])
    if not token:
        return None
    if (db.now() - float(row["saved_at"] or 0)) > TOKEN_MAX_AGE:
        return None
    cache: dict[str, Any] = {"token": token, "saved_at": row["saved_at"], "mode": row["mode"]}
    try:
        device = json.loads(row["device_json"] or "{}")
    except json.JSONDecodeError:
        device = {}
    if device:
        cache["device"] = device
    return cache


def write_token_cache(
    user_id: str, token: str, extra: dict[str, Any] | None = None, device: dict[str, Any] | None = None
) -> None:
    extra = extra or {}
    row = _row(user_id)
    if row is None:
        raise NoConnection("user belum menghubungkan akun EdLink")
    device_json = json.dumps(device or json.loads(row["device_json"] or "{}"), ensure_ascii=False)
    with db.tx() as conn:
        conn.execute(
            "UPDATE edlink_connections SET token_enc=?, saved_at=?, updated_at=?, device_json=?"
            " WHERE user_id=?",
            (crypto.encrypt(token), db.now(), db.now(), device_json, user_id),
        )


def load_device(user_id: str) -> dict[str, Any]:
    row = _row(user_id)
    if row is not None:
        try:
            device = json.loads(row["device_json"] or "{}")
        except json.JSONDecodeError:
            device = {}
        if device.get("secureId"):
            return device
    import uuid

    device = dict(DEFAULT_DEVICE)
    device["secureId"] = str(uuid.uuid4())
    with db.tx() as conn:
        conn.execute(
            "UPDATE edlink_connections SET device_json=? WHERE user_id=?",
            (json.dumps(device, ensure_ascii=False), user_id),
        )
    return device


def disconnect(user_id: str) -> bool:
    """Hapus kredensial EdLink user. Token EdLink di sisi EdLink tidak bisa
    dicabut dari sini karena EdLink tidak menyediakan endpoint revoke."""
    with db.tx() as conn:
        cur = conn.execute("DELETE FROM edlink_connections WHERE user_id = ?", (user_id,))
        return cur.rowcount > 0


def summary(user_id: str) -> dict[str, Any]:
    """Status koneksi tanpa membocorkan nilai rahasia."""
    row = _row(user_id)
    if row is None:
        return {"connected": False, "mode": None, "updated_at": None}
    return {
        "connected": bool(row["token_enc"] or (row["email_enc"] and row["password_enc"])),
        "mode": row["mode"],
        "updated_at": row["updated_at"],
        "has_password": bool(row["password_enc"]),
    }
