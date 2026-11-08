"""Identitas request yang sedang berjalan.

Diisi oleh middleware HTTP dari bearer token MCP atau sesi web.
Di mode stdio tidak ada user — semua helper mengembalikan None dan
edlink_mcp.py memakai kredensial file lokal seperti sebelumnya.
"""

from __future__ import annotations

import contextvars
from dataclasses import dataclass

_current: contextvars.ContextVar["Identity | None"] = contextvars.ContextVar(
    "edlink_identity", default=None
)


@dataclass(frozen=True)
class Identity:
    user_id: str
    email: str
    is_admin: bool = False
    via: str = ""  # "mcp" | "web"


def set_identity(identity: "Identity | None"):
    """Set identitas, kembalikan token untuk reset."""
    return _current.set(identity)


def reset_identity(token) -> None:
    _current.reset(token)


def current() -> "Identity | None":
    return _current.get()


def current_user_id() -> str | None:
    ident = _current.get()
    return ident.user_id if ident else None


def require_user_id() -> str:
    ident = _current.get()
    if ident is None:
        raise RuntimeError(
            "Permintaan ini tidak membawa identitas user. Hubungkan EdLink lewat "
            "akun platform dulu, atau jalankan server dalam mode stdio dengan "
            "config.json lokal."
        )
    return ident.user_id
