"""Halaman web platform: daftar, login, dashboard, hubungkan EdLink, admin.

HTML dibuat inline (tanpa template engine) supaya dependensi tetap minimal.
Semua nilai yang dicetak lewat _esc(); tidak ada data rahasia di halaman.
"""

from __future__ import annotations

import json
import time
from typing import Any

from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from . import db, security, store

STYLE = """
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:#0f1115;color:#e7e9ee;font:15px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{max-width:760px;margin:0 auto;padding:40px 20px}
.card{background:#171a21;border:1px solid #262b36;border-radius:16px;padding:26px;margin-bottom:18px}
h1{font-size:22px;margin:0 0 6px}
h2{font-size:15px;margin:0 0 12px;color:#a9b0bf;text-transform:uppercase;letter-spacing:.08em}
p{color:#a9b0bf;margin:8px 0}
a{color:#7fb4ff}
label{display:block;font-size:13px;color:#a9b0bf;margin:14px 0 6px}
input,textarea,select{width:100%;padding:11px 12px;border-radius:9px;border:1px solid #2b3140;
 background:#0f1115;color:#e7e9ee;font-size:14px}
input:focus,textarea:focus{outline:none;border-color:#2f7cf6}
button{margin-top:18px;padding:12px 18px;border-radius:10px;border:1px solid #2f7cf6;background:#2f7cf6;
 color:#fff;font-size:14px;font-weight:600;cursor:pointer}
button.ghost{background:transparent;border-color:#3a4150;color:#c3c9d6;margin-left:8px}
code,.mono{font-family:ui-monospace,Consolas,monospace;font-size:13px}
.mono{background:#0f1115;border:1px solid #262b36;border-radius:8px;padding:10px;display:block;
 overflow-x:auto;color:#9ad0ff;word-break:break-all}
.err{color:#ff8f8f;background:#2a1618;border:1px solid #4a2226;padding:10px 12px;border-radius:9px;margin:14px 0}
.ok{color:#7fe0a8;background:#132119;border:1px solid #1f3d2b;padding:10px 12px;border-radius:9px;margin:14px 0}
.pill{display:inline-block;padding:3px 9px;border-radius:999px;font-size:12px;background:#1f2632;color:#a9b0bf}
.pill.on{background:#15352a;color:#7fe0a8}
.pill.off{background:#2a1618;color:#ff8f8f}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 6px;border-bottom:1px solid #232833}
th{color:#8d95a6;font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.06em}
"""


def _esc(value: Any) -> str:
    import html as html_lib

    return html_lib.escape(str(value if value is not None else ""), quote=True)


def page(title: str, body: str, status: int = 200) -> HTMLResponse:
    html = f"""<!doctype html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(title)}</title><style>{STYLE}</style></head>
<body><div class="wrap">{body}</div></body></html>"""
    return HTMLResponse(html, status_code=status)


def _ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return request.client.host if request.client else ""


def _cookie(request: Request) -> str:
    return request.cookies.get(security.SESSION_COOKIE, "")


def set_session_cookie(response: Response, sid: str) -> None:
    import os

    secure = os.environ.get("EDLINK_PLATFORM_BASE_URL", "https://").startswith("https://")
    if os.environ.get("EDLINK_PLATFORM_ALLOW_HTTP") == "1":
        secure = False
    response.set_cookie(
        security.SESSION_COOKIE,
        sid,
        max_age=security.SESSION_TTL,
        httponly=True,
        secure=secure,
        samesite="lax",
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(security.SESSION_COOKIE, path="/")


def _safe_next(value: str) -> str:
    if value.startswith("/") and not value.startswith("//"):
        return value
    return "/"


# ------------------------------------------------------------------ routes ---

def signup_get(request: Request) -> Response:
    return page(
        "Daftar — EdLink MCP",
        """<div class="card">
<h1>Buat akun EdLink MCP</h1>
<p>Akun ini milikmu sendiri. Setelah daftar, hubungkan akun EdLink-mu di dashboard.</p>
<form method="post" action="/signup">
 <label>Email</label><input name="email" type="email" required autocomplete="email">
 <label>Password (minimal 10 karakter)</label><input name="password" type="password" required minlength="10" autocomplete="new-password">
 <button type="submit">Daftar</button>
</form>
<p>Sudah punya akun? <a href="/login">Masuk</a></p>
</div>""",
    )


async def signup_post(request: Request) -> Response:
    ip = _ip(request)
    if not db.rate_limit(f"signup:{ip}", limit=10, window_seconds=3600):
        return page("Terlalu banyak", '<div class="card"><h1>Terlalu banyak pendaftaran</h1><p>Coba lagi nanti.</p></div>', status=429)

    form = await request.form()
    email = str(form.get("email") or "").strip().lower()
    password = str(form.get("password") or "")

    problem = None
    if "@" not in email or len(email) < 5 or len(email) > 200:
        problem = "Email tidak valid."
    if not problem:
        problem = security.password_problem(password)
    if not problem and security.find_user_by_email(email) is not None:
        # Pesan sama seperti sukses palsu tidak dipakai; pendaftaran memang publik.
        problem = "Email sudah terdaftar. Coba masuk."

    if problem:
        return page(
            "Daftar — EdLink MCP",
            f'<div class="card"><h1>Buat akun EdLink MCP</h1><div class="err">{_esc(problem)}</div>'
            '<p><a href="/signup">Kembali</a></p></div>',
            status=400,
        )

    user_id = security.create_user(email, password)
    db.audit(user_id, "user.signup", email[:80], ip)
    sid = security.create_session(user_id, ip, request.headers.get("user-agent", ""))
    response = RedirectResponse("/dashboard?welcome=1", status_code=302)
    set_session_cookie(response, sid)
    return response


def login_get(request: Request) -> Response:
    nxt = _safe_next(str(request.query_params.get("next") or "/dashboard"))
    return page(
        "Masuk — EdLink MCP",
        f"""<div class="card">
<h1>Masuk</h1>
<form method="post" action="/login">
 <input type="hidden" name="next" value="{_esc(nxt)}">
 <label>Email</label><input name="email" type="email" required autocomplete="email">
 <label>Password</label><input name="password" type="password" required autocomplete="current-password">
 <button type="submit">Masuk</button>
</form>
<p>Belum punya akun? <a href="/signup">Daftar</a></p>
</div>""",
    )


async def login_post(request: Request) -> Response:
    ip = _ip(request)
    form = await request.form()
    email = str(form.get("email") or "").strip()
    password = str(form.get("password") or "")
    nxt = _safe_next(str(form.get("next") or "/dashboard"))

    if not db.rate_limit(f"login:{ip}", limit=10, window_seconds=900) or not db.rate_limit(
        f"login:{email.lower()}", limit=10, window_seconds=900
    ):
        return page("Terlalu banyak", '<div class="card"><h1>Terlalu banyak percobaan</h1><p>Tunggu 15 menit.</p></div>', status=429)

    user, reason = security.authenticate(email, password)
    if user is None:
        db.audit(None, "user.login_fail", email.lower()[:80], ip)
        return page(
            "Masuk — EdLink MCP",
            f'<div class="card"><h1>Masuk</h1><div class="err">{_esc(reason)}</div>'
            f'<p><a href="/login?next={_esc(nxt)}">Coba lagi</a></p></div>',
            status=401,
        )

    sid = security.create_session(user["id"], ip, request.headers.get("user-agent", ""))
    db.audit(user["id"], "user.login", "", ip)
    response = RedirectResponse(nxt, status_code=302)
    set_session_cookie(response, sid)
    return response


def logout(request: Request) -> Response:
    security.revoke_session(_cookie(request))
    response = RedirectResponse("/", status_code=302)
    clear_session_cookie(response)
    return response


def index(request: Request) -> Response:
    body = """<div class="card">
<h1>EdLink MCP</h1>
<p>Hubungkan akun EdLink-mu ke ChatGPT lewat MCP. Satu akun platform, satu akun EdLink,
data terpisah dari pengguna lain.</p>
<p><a href="/signup">Daftar</a> · <a href="/login">Masuk</a> · <a href="/docs">Dokumentasi</a></p>
</div>"""
    return page("EdLink MCP", body)


def dashboard(request: Request, user: Any) -> Response:
    uid = user["user_id"]
    conn = store.summary(uid)
    tokens = security.list_mcp_tokens(uid)
    formerr = str(request.query_params.get("error") or "")
    okmsg = str(request.query_params.get("ok") or "")
    welcome = request.query_params.get("welcome")

    status_pill = (
        '<span class="pill on">terhubung</span>' if conn["connected"] else '<span class="pill off">belum terhubung</span>'
    )

    notice = ""
    if formerr:
        notice += f'<div class="err">{_esc(formerr)}</div>'
    if okmsg:
        notice += f'<div class="ok">{_esc(okmsg)}</div>'
    if welcome:
        notice += '<div class="ok">Akun dibuat. Sekarang hubungkan akun EdLink-mu.</div>'

    token_rows = "".join(
        f"<tr><td class='mono'>{_esc(t['id'])}</td><td>{_esc(t['name'] or '-')}</td>"
        f"<td>{time.strftime('%Y-%m-%d', time.gmtime(t['created_at']))}</td>"
        f"<td>{'revoked' if t['revoked'] else 'active'}</td></tr>"
        for t in tokens
    ) or "<tr><td colspan=4>-</td></tr>"

    base_url = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    mcp_url = f"{proto}://{base_url}/mcp"

    body = f"""<div class="card">
<h1>Dashboard</h1>
<p>{_esc(user['email'])} {status_pill}</p>
{notice}
</div>

<div class="card">
<h2>Akun EdLink</h2>
<p>Mode koneksi: <code>{_esc(conn['mode'] or '-')}</code></p>
<form method="post" action="/link">
 <label>Token EdLink (129 karakter, dari DevTools edlink.id)</label>
 <textarea name="token" rows="3" placeholder="tempel token di sini" spellcheck="false"></textarea>
 <button type="submit">Simpan token</button>
</form>
<details style="margin-top:18px">
 <summary style="cursor:pointer;color:#a9b0bf">Atau pakai email + password</summary>
 <form method="post" action="/link">
  <label>Email EdLink</label><input name="email" type="email" autocomplete="username">
  <label>Password EdLink</label><input name="password" type="password" autocomplete="current-password">
  <button type="submit">Simpan &amp; login</button>
 </form>
</details>
<form method="post" action="/unlink" style="margin-top:16px">
 <button type="submit" class="ghost">Putuskan EdLink</button>
</form>
</div>

<div class="card">
<h2>Endpoint MCP</h2>
<span class="mono">{_esc(mcp_url)}</span>
<p>Tambahkan sebagai custom MCP server di ChatGPT. Autentikasi lewat OAuth saat pertama dipakai.</p>
<h2 style="margin-top:22px">Token akses</h2>
<table><tr><th>ID</th><th>Nama</th><th>Dibuat</th><th>Status</th></tr>{token_rows}</table>
<form method="post" action="/tokens/revoke" style="margin-top:14px">
 <button type="submit" class="ghost">Cabut semua token</button>
</form>
</div>

<div class="card">
<h2>Akun</h2>
<p><a href="/upload">Upload file untuk dikirim ke EdLink</a></p>
<form method="post" action="/logout"><button type="submit" class="ghost" style="margin:0">Keluar</button></form>
</div>"""
    return page("Dashboard — EdLink MCP", body)


async def link_post(request: Request, user: Any) -> Response:
    uid = user["user_id"]
    form = await request.form()
    token = str(form.get("token") or "").strip()
    email = str(form.get("email") or "").strip()
    password = str(form.get("password") or "")

    if token:
        if len(token) < 20 or len(token) > 400:
            return RedirectResponse("/dashboard?error=" + _q("Format token tidak wajar."), status_code=302)
        store.save_connection(uid, "token", token=token)
        db.audit(uid, "edlink.link", "mode=token", _ip(request))
        return RedirectResponse("/dashboard?ok=" + _q("Token EdLink disimpan."), status_code=302)

    if email and password:
        store.save_connection(uid, "password", email=email, password=password)
        db.audit(uid, "edlink.link", "mode=password", _ip(request))
        return RedirectResponse(
            "/dashboard?ok=" + _q("Kredensial disimpan. Token akan diambil saat tool pertama dipanggil."),
            status_code=302,
        )

    return RedirectResponse("/dashboard?error=" + _q("Isi token, atau email + password."), status_code=302)


async def unlink_post(request: Request, user: Any) -> Response:
    uid = user["user_id"]
    store.disconnect(uid)
    security.revoke_mcp_tokens(uid)
    security.revoke_refresh_tokens(uid)
    db.audit(uid, "edlink.unlink", "", _ip(request))
    return RedirectResponse("/dashboard?ok=" + _q("Koneksi EdLink dihapus, token MCP dicabut."), status_code=302)


async def revoke_tokens_post(request: Request, user: Any) -> Response:
    uid = user["user_id"]
    count = security.revoke_mcp_tokens(uid) + security.revoke_refresh_tokens(uid)
    db.audit(uid, "mcp.tokens_revoked", str(count), _ip(request))
    return RedirectResponse("/dashboard?ok=" + _q(f"{count} token dicabut."), status_code=302)


def _q(text: str) -> str:
    from urllib.parse import quote

    return quote(text, safe="")


# ------------------------------------------------------------------ upload ---

MAX_UPLOAD_BYTES = 25 * 1024 * 1024


def _upload_root(user_id: str):
    import os
    from pathlib import Path

    root = (Path(os.environ.get("EDLINK_PLATFORM_UPLOAD_DIR", "data/uploads")) / user_id).resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def upload_page(request: Request, user: Any) -> Response:
    root = _upload_root(user["user_id"])
    files = sorted(p.name for p in root.iterdir() if p.is_file())[:200]
    rows = "".join(f"<tr><td class='mono'>{_esc(n)}</td></tr>" for n in files) or "<tr><td>-</td></tr>"
    err = request.query_params.get("error")
    ok = request.query_params.get("ok")
    notice = f'<div class="err">{_esc(err)}</div>' if err else (f'<div class="ok">{_esc(ok)}</div>' if ok else "")
    body = f"""<div class="card">
<h1>Upload file</h1>
<p>File yang diunggah ke sini bisa dikirim ke EdLink lewat tool
<code>edlink_upload_file(path="&lt;nama file&gt;")</code>.</p>
{notice}
<form method="post" action="/upload" enctype="multipart/form-data">
 <label>File (maksimal 25 MB)</label><input type="file" name="file" required>
 <button type="submit">Unggah</button>
</form>
</div>
<div class="card">
<h2>File kamu</h2>
<table><tr><th>Nama</th></tr>{rows}</table>
<p><a href="/dashboard">Kembali ke dashboard</a></p>
</div>"""
    return page("Upload — EdLink MCP", body)


async def upload_post(request: Request, user: Any) -> Response:
    root = _upload_root(user["user_id"])
    form = await request.form()
    upload = form.get("file")
    if upload is None or not getattr(upload, "filename", ""):
        return RedirectResponse("/upload?error=" + _q("Tidak ada file."), status_code=302)

    name = str(upload.filename).replace("\\", "/").split("/")[-1]
    safe = "".join(ch for ch in name if ch.isalnum() or ch in " ._-()").strip().rstrip(".")
    if not safe or safe.startswith("."):
        return RedirectResponse("/upload?error=" + _q("Nama file tidak valid."), status_code=302)

    data = await upload.read()
    if len(data) > MAX_UPLOAD_BYTES:
        return RedirectResponse("/upload?error=" + _q("File lebih dari 25 MB."), status_code=302)
    if not data:
        return RedirectResponse("/upload?error=" + _q("File kosong."), status_code=302)

    (root / safe).write_bytes(data)
    db.audit(user["user_id"], "upload.file", f"{safe} ({len(data)} byte)", _ip(request))
    return RedirectResponse("/upload?ok=" + _q(f"{safe} diunggah."), status_code=302)


# ------------------------------------------------------------------- admin ---

def admin_page(request: Request, viewer: Any) -> Response:
    rows = db.q(
        "SELECT u.id, u.email, u.status, u.is_admin, u.created_at,"
        " (SELECT COUNT(*) FROM edlink_connections c WHERE c.user_id = u.id) AS connected"
        " FROM users u ORDER BY u.created_at DESC LIMIT 200"
    )
    events = db.q("SELECT ts, user_id, action, detail, ip FROM audit_events ORDER BY id DESC LIMIT 40")

    user_rows = "".join(
        f"<tr><td class='mono'>{_esc(r['id'])}</td><td>{_esc(r['email'])}</td>"
        f"<td>{'admin' if r['is_admin'] else 'user'}</td>"
        f"<td>{'<span class=pill on>edlink</span>' if r['connected'] else '<span class=pill off>-</span>'}</td>"
        f"<td>{_esc(r['status'])}</td>"
        f"<td><form method='post' action='/admin/user'>"
        f"<input type='hidden' name='user_id' value='{_esc(r['id'])}'>"
        f"<select name='action'><option value='suspend'>suspend</option><option value='activate'>activate</option>"
        f"<option value='revoke_sessions'>revoke sessions</option><option value='revoke_tokens'>revoke tokens</option>"
        f"<option value='unlink'>unlink edlink</option></select>"
        f"<button type='submit' class='ghost'>jalankan</button></form></td></tr>"
        for r in rows
    )
    event_rows = "".join(
        f"<tr><td>{time.strftime('%H:%M:%S', time.gmtime(e['ts']))}</td>"
        f"<td class='mono'>{_esc((e['user_id'] or '-')[:14])}</td><td>{_esc(e['action'])}</td>"
        f"<td>{_esc(e['detail'][:60])}</td><td class='mono'>{_esc(e['ip'])}</td></tr>"
        for e in events
    )
    body = f"""<div class="card">
<h1>Admin</h1><p>{_esc(viewer['email'])} · <a href="/dashboard">dashboard</a></p>
<h2 style="margin-top:20px">Pengguna ({len(rows)})</h2>
<table><tr><th>ID</th><th>Email</th><th>Role</th><th>EdLink</th><th>Status</th><th>Aksi</th></tr>{user_rows}</table>
</div>
<div class="card">
<h2>Audit terakhir</h2>
<table><tr><th>Waktu</th><th>User</th><th>Aksi</th><th>Detail</th><th>IP</th></tr>{event_rows}</table>
<p>Token dan password tidak pernah dicatat di sini.</p>
</div>"""
    return page("Admin — EdLink MCP", body)


async def admin_action(request: Request, viewer: Any) -> Response:
    form = await request.form()
    target = str(form.get("user_id") or "")
    action = str(form.get("action") or "")
    if not target:
        return RedirectResponse("/admin", status_code=302)

    if action == "suspend":
        with db.tx() as conn:
            conn.execute("UPDATE users SET status='suspended' WHERE id=?", (target,))
        security.revoke_all_sessions(target)
        security.revoke_mcp_tokens(target)
        security.revoke_refresh_tokens(target)
    elif action == "activate":
        with db.tx() as conn:
            conn.execute("UPDATE users SET status='active' WHERE id=?", (target,))
    elif action == "revoke_sessions":
        security.revoke_all_sessions(target)
    elif action == "revoke_tokens":
        security.revoke_mcp_tokens(target)
        security.revoke_refresh_tokens(target)
    elif action == "unlink":
        store.disconnect(target)
        security.revoke_mcp_tokens(target)
        security.revoke_refresh_tokens(target)
    db.audit(viewer["user_id"], "admin." + action, target, _ip(request))
    return RedirectResponse("/admin", status_code=302)


def docs_page(request: Request) -> Response:
    base = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    body = f"""<div class="card">
<h1>Dokumentasi singkat</h1>
<h2>Endpoint MCP</h2>
<span class="mono">{_esc(proto)}://{_esc(base)}/mcp</span>
<h2 style="margin-top:20px">ChatGPT</h2>
<p>Buka <code>chatgpt.com/plugins</code> → tombol plus → <strong>Add custom MCP server</strong>.
Isi nama, lalu di bagian <strong>Connection</strong> tempel URL di atas (termasuk <code>/mcp</code>).
Setujui halaman izin OAuth sekali, lalu <strong>Create as a plugin</strong>.</p>
<h2 style="margin-top:20px">Klien lain</h2>
<p>Kirim header <code>Authorization: Bearer &lt;token&gt;</code>. Token dibuat lewat alur OAuth
dan diperpanjang dengan refresh token (grant <code>refresh_token</code>).</p>
<h2 style="margin-top:20px">Privasi</h2>
<p>Kredensial EdLink disimpan terenkripsi per akun. Token EdLink tidak pernah dikirim ke
model AI, tidak dicatat di log, dan tidak dibagikan ke pengguna lain.</p>
</div>"""
    return page("Dokumentasi — EdLink MCP", body)
