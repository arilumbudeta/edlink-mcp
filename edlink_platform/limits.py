"""Kebijakan rate limit, dikumpulkan di satu tempat.

Semua pemanggil (web, OAuth, MCP) memakai konstanta yang sama supaya angka di
dokumentasi tidak melenceng dari perilaku. Bentuk tiap kebijakan:

    (bucket, limit, window_detik)

Bucket memisahkan jenis aksi, jadi kuota login tidak memakan kuota OAuth.
Key berisi identitas paling sempit yang tersedia untuk aksi itu:

    signup  -> IP
    login   -> "email|ip"
    link    -> user_id
    dcr     -> IP
    token   -> client_id (fallback IP)
    mcp     -> user_id

Admin tidak pernah dihitung. Alasannya praktis: pemilik server memegang akun
admin, dan akun yang dipakai mengurus server tidak boleh terkunci oleh kuota
yang dibuat untuk menahan penyalahgunaan dari luar.
"""

from __future__ import annotations

from typing import Any

from . import db

# (bucket, limit, window_detik)
SIGNUP: tuple[str, int, int] = ("signup", 5, 3600)  # 5 akun / jam / IP
LOGIN: tuple[str, int, int] = ("login", 10, 900)  # 10 gagal / 15 menit / email+IP
LINK: tuple[str, int, int] = ("link", 10, 600)  # 10 hubungkan EdLink / 10 menit / user
DCR: tuple[str, int, int] = ("dcr", 20, 3600)  # 20 registrasi klien / jam / IP
TOKEN: tuple[str, int, int] = ("token", 120, 300)  # 120 permintaan token / 5 menit / klien
MCP: tuple[str, int, int] = ("mcp", 600, 60)  # 600 request MCP / menit / user


def check(
    policy: tuple[str, int, int], key: str, *, is_admin: bool = False
) -> tuple[bool, int]:
    """(boleh_lanjut, sisa_detik_cooldown). Admin selalu boleh."""
    if is_admin:
        return True, 0
    bucket, limit, window = policy
    return db.rate_limit(bucket, key, limit, window)


def message(retry_after: int) -> str:
    seconds = max(1, int(retry_after))
    if seconds >= 60:
        return f"Terlalu banyak percobaan. Coba lagi dalam {seconds // 60 + 1} menit."
    return f"Terlalu banyak percobaan. Coba lagi dalam {seconds} detik."


def summary() -> list[dict[str, Any]]:
    """Daftar kebijakan untuk ditampilkan di panel admin."""
    rows = []
    for name, (bucket, limit, window) in (
        ("signup", SIGNUP),
        ("login", LOGIN),
        ("link", LINK),
        ("dcr", DCR),
        ("token", TOKEN),
        ("mcp", MCP),
    ):
        rows.append({"aksi": name, "bucket": bucket, "limit": limit, "window_detik": window})
    return rows
