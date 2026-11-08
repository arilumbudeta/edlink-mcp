"""Entry point platform multi-user.

Jalankan:  python platform_main.py
Env wajib: EDLINK_PLATFORM_BASE_URL, EDLINK_PLATFORM_DB, EDLINK_PLATFORM_KEY_FILE

Server menyalakan MCP Streamable HTTP (lewat edlink_mcp.py yang sudah ada)
plus halaman web, OAuth, dan admin. Mode stdio di edlink_mcp.py tidak berubah.
"""

from __future__ import annotations

import os
import sys

# Nilai default khusus mode platform. Harus diset SEBELUM import edlink_mcp.
os.environ.setdefault("EDLINK_MCP_TRANSPORT", "http")
os.environ.setdefault("EDLINK_MCP_HOST", "0.0.0.0")
os.environ.setdefault("EDLINK_MCP_PORT", "8765")
# Autentikasi ditangani IdentityMiddleware platform, bukan bearer statis FastMCP.
os.environ.setdefault("EDLINK_MCP_TRUST_PROXY_AUTH", "1")
os.environ.setdefault("EDLINK_MCP_ISSUER_URL", os.environ.get("EDLINK_PLATFORM_BASE_URL", "http://localhost:8765"))

import uvicorn  # noqa: E402

import edlink_mcp  # noqa: E402
from edlink_platform import db, security, store  # noqa: E402
from edlink_platform.app import build_app  # noqa: E402


def bootstrap_admin() -> None:
    """Buat admin pertama dari env, sekali saja. Tidak ada password default."""
    email = os.environ.get("EDLINK_PLATFORM_ADMIN_EMAIL", "").strip().lower()
    password = os.environ.get("EDLINK_PLATFORM_ADMIN_PASSWORD", "")
    if not email or not password:
        return
    existing = security.find_user_by_email(email)
    if existing is not None:
        if not existing["is_admin"]:
            with db.tx() as conn:
                conn.execute("UPDATE users SET is_admin=1 WHERE id=?", (existing["id"],))
            print(f"[bootstrap] {email} dipromosikan jadi admin", file=sys.stderr)
        return
    problem = security.password_problem(password)
    if problem:
        print(f"[bootstrap] password admin ditolak: {problem}", file=sys.stderr)
        return
    uid = security.create_user(email, password, display_name="admin", is_admin=True)
    db.audit(uid, "admin.bootstrap", email[:80], "")
    print(f"[bootstrap] admin dibuat: {email}", file=sys.stderr)


def main() -> int:
    base = os.environ.get("EDLINK_PLATFORM_BASE_URL", "").strip()
    if not base.startswith("https://") and os.environ.get("EDLINK_PLATFORM_ALLOW_HTTP") != "1":
        print(
            "EDLINK_PLATFORM_BASE_URL harus https:// (set EDLINK_PLATFORM_ALLOW_HTTP=1 "
            "hanya untuk uji lokal).",
            file=sys.stderr,
        )
        return 2

    db.init_db()
    bootstrap_admin()

    host = os.environ.get("EDLINK_MCP_HOST", "0.0.0.0")
    port = int(os.environ.get("EDLINK_MCP_PORT", "8765"))

    mcp_app = edlink_mcp.mcp.streamable_http_app()
    app = build_app(mcp_app)

    print(f"[platform] base={base} port={port} db={db.DB_PATH}", file=sys.stderr)
    print(f"[platform] MCP endpoint: {base}/mcp", file=sys.stderr)
    uvicorn.run(app, host=host, port=port, log_level=os.environ.get("EDLINK_PLATFORM_LOG_LEVEL", "info"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
