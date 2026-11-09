"""OAuth 2.1 authorization server minimal untuk MCP (ChatGPT-compatible).

Yang disediakan:
- GET  /.well-known/oauth-protected-resource   (RFC 9728)
- GET  /.well-known/oauth-authorization-server (RFC 8414)
- POST /oauth/register                        (Dynamic Client Registration)
- GET  /oauth/authorize                       (consent, butuh sesi web)
- POST /oauth/authorize                       (approve/deny)
- POST /oauth/token                           (authorization_code + PKCE S256)

Token yang diterbitkan adalah token opaque milik platform (bukan JWT), disimpan
sebagai hash. Verifikasi dilakukan oleh verifier MCP di app.py.
"""

from __future__ import annotations

import json
import secrets
import time
from typing import Any
from urllib.parse import quote, urlencode, urlparse

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from . import db, security, store

SCOPES = ["edlink.read", "edlink.write"]


def _base(request: Request) -> str:
    """URL publik server, dari env kalau ada, kalau tidak dari header proxy."""
    import os

    configured = os.environ.get("EDLINK_PLATFORM_BASE_URL", "").strip().rstrip("/")
    if configured:
        return configured
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    return f"{proto}://{host}"


def protected_resource_metadata(request: Request) -> JSONResponse:
    base = _base(request)
    return JSONResponse(
        {
            "resource": f"{base}/mcp",
            "authorization_servers": [base],
            "scopes_supported": SCOPES,
            "bearer_methods_supported": ["header"],
            "resource_documentation": f"{base}/docs",
        }
    )


def authorization_server_metadata(request: Request) -> JSONResponse:
    base = _base(request)
    return JSONResponse(
        {
            "issuer": base,
            "authorization_endpoint": f"{base}/oauth/authorize",
            "token_endpoint": f"{base}/oauth/token",
            "registration_endpoint": f"{base}/oauth/register",
            "scopes_supported": SCOPES,
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
            "authorization_response_iss_parameter_supported": True,
            "service_documentation": f"{base}/docs",
        }
    )


def _ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return request.client.host if request.client else ""


async def register_client(request: Request) -> Response:
    """Dynamic Client Registration (RFC 7591) sederhana."""
    if not db.rate_limit(f"oauth_register:{_ip(request)}", limit=30, window_seconds=3600):
        return JSONResponse({"error": "too_many_requests"}, status_code=429)
    try:
        body: Any = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid_client_metadata"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "invalid_client_metadata"}, status_code=400)

    redirect_uris = body.get("redirect_uris")
    if not isinstance(redirect_uris, list) or not redirect_uris:
        return JSONResponse({"error": "invalid_redirect_uri"}, status_code=400)
    for uri in redirect_uris:
        if not isinstance(uri, str):
            return JSONResponse({"error": "invalid_redirect_uri"}, status_code=400)
        parsed = urlparse(uri)
        if parsed.scheme not in ("https", "http"):
            return JSONResponse({"error": "invalid_redirect_uri"}, status_code=400)

    client_id = "edc_" + secrets.token_urlsafe(16)
    token_auth = body.get("token_endpoint_auth_method", "none")
    client_secret = secrets.token_urlsafe(32) if token_auth == "client_secret_post" else ""

    with db.tx() as conn:
        conn.execute(
            "INSERT INTO oauth_clients (client_id, client_secret, redirect_uris, client_name, created_at)"
            " VALUES (?,?,?,?,?)",
            (
                client_id,
                client_secret,
                json.dumps(redirect_uris),
                str(body.get("client_name", ""))[:120],
                db.now(),
            ),
        )

    payload = {
        "client_id": client_id,
        "client_id_issued_at": int(time.time()),
        "redirect_uris": redirect_uris,
        "client_name": str(body.get("client_name", ""))[:120],
        "token_endpoint_auth_method": token_auth,
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
    }
    if client_secret:
        payload["client_secret"] = client_secret
        payload["client_secret_expires_at"] = 0
    return JSONResponse(payload, status_code=201)


def _client(client_id: str) -> Any:
    return db.q1("SELECT * FROM oauth_clients WHERE client_id = ?", (client_id,))


def _consent_page(
    request: Request,
    client: Any,
    redirect_uri: str,
    state: str,
    code_challenge: str,
    scope: str,
    resource: str,
    user: Any,
    error: str = "",
) -> HTMLResponse:
    params = {
        "client_id": client["client_id"],
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "scope": scope,
        "resource": resource,
    }
    hidden = "".join(
        f'<input type="hidden" name="{k}" value="{_esc(v)}">' for k, v in params.items() if v
    )
    err = f'<p class="err">{_esc(error)}</p>' if error else ""
    client_label = _esc(client["client_name"] or client["client_id"])

    # "ganti akun" harus kembali ke halaman izin yang sama, bukan ke dashboard,
    # supaya alur OAuth klien tidak putus.
    back_raw = request.url.path + (("?" + request.url.query) if request.url.query else "")
    switch_href = _esc("/logout?next=" + quote(back_raw, safe=""))

    if store.has_connection(user["user_id"]):
        mode = (store.summary(user["user_id"]).get("mode") or "").strip()
        mode_note = f" (mode <code>{_esc(mode)}</code>)" if mode and mode != "-" else ""
        edlink_status = (
            f'<p class="ok">Akun EdLink terhubung{mode_note}. Tool akan memakai akun itu.</p>'
        )
    else:
        edlink_status = (
            '<p class="warn">Akun EdLink belum terhubung. Kamu tetap bisa menyetujui, tetapi'
            ' tool akan menolak sampai akun EdLink dihubungkan di <a href="/dashboard">dashboard</a>'
            " — setelah itu ulangi langkah tambah server di " + client_label + ".</p>"
        )

    html = f"""<!doctype html>
<html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Izinkan {client_label} memakai EdLink MCP</title>
<style>
 body{{font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:#0f1115;color:#e7e9ee;
      display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0;padding:24px}}
 .card{{max-width:560px;width:100%;background:#171a21;border:1px solid #262b36;border-radius:16px;padding:28px}}
 h1{{font-size:20px;margin:0 0 8px}} p{{color:#a9b0bf;line-height:1.55;margin:8px 0}}
 a{{color:#9ad0ff}}
 .scope{{font-family:ui-monospace,Consolas,monospace;background:#0f1115;border:1px solid #262b36;
        border-radius:8px;padding:10px;color:#9ad0ff;font-size:13px}}
 .caps{{color:#a9b0bf;font-size:13px;line-height:1.6;padding-left:18px;margin:8px 0 0}}
 .caps strong{{color:#e7e9ee}}
 .row{{display:flex;gap:10px;margin-top:20px}}
 button{{flex:1;padding:12px;border-radius:10px;border:1px solid #2f7cf6;background:#2f7cf6;color:#fff;
        font-size:14px;font-weight:600;cursor:pointer}}
 button.deny{{background:transparent;border-color:#3a4150;color:#c3c9d6}}
 .err{{color:#ff8f8f}} .ok{{color:#7fe0a8}} .warn{{color:#ffd479}}
 .who{{color:#7fe0a8;font-family:ui-monospace,Consolas,monospace;font-size:13px}}
 .meta{{font-size:12px;color:#6f7786;margin-top:18px;line-height:1.5}}
 hr{{border:0;border-top:1px solid #262b36;margin:16px 0}}
</style></head><body><div class="card">
<h1>Izinkan {client_label} memakai EdLink MCP</h1>
<p><strong>Ini bukan login EdLink.</strong> Kamu sedang memberi izin ke
<strong>{client_label}</strong> untuk memanggil MCP server ini atas nama akun platformmu.
Akun EdLink yang dipakai tetap akun yang sudah kamu hubungkan sendiri di dashboard.</p>
<p class="who">login sebagai {_esc(user["email"])} · <a href="{switch_href}">ganti akun</a></p>
{err}
<hr>
{edlink_status}
<p>Yang bisa dilakukan {client_label} setelah ini:</p>
<ul class="caps">
 <li>membaca tugas, jadwal, kelas, notifikasi, dan profil EdLink</li>
 <li>mengunggah file dari folder upload akunmu</li>
 <li><strong>mengirim jawaban tugas</strong> lewat <code>edlink_send_tugas</code> — aksi tulis</li>
</ul>
<div class="scope">{_esc(scope or "edlink.read")}</div>
<form method="post" action="/oauth/authorize">
 {hidden}
 <div class="row">
  <button type="submit" name="decision" value="approve">Izinkan</button>
  <button type="submit" name="decision" value="deny" class="deny">Tolak</button>
 </div>
</form>
<p class="meta">Token bisa dicabut kapan saja dari dashboard. Server hanya menyimpan hash
token MCP, dan tidak pernah mengirim token/password EdLink ke klien.</p>
</div></body></html>"""
    return HTMLResponse(html)


def _esc(value: Any) -> str:
    import html as html_lib

    return html_lib.escape(str(value or ""), quote=True)


def _redirect_error(
    redirect_uri: str, state: str, error: str, description: str, iss: str = ""
) -> RedirectResponse:
    # RFC 9207: iss wajib ikut di SETIAP authorization response, termasuk error.
    # Metadata kita mengiklankan authorization_response_iss_parameter_supported,
    # jadi klien akan menolak respons tanpa iss.
    params = {"error": error, "error_description": description, "state": state}
    if iss:
        params["iss"] = iss
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{sep}{urlencode(params)}", status_code=302)


async def authorize(request: Request, session_user: Any) -> Response:
    if request.method == "GET":
        params = request.query_params
    else:
        form = await request.form()
        params = form

    client_id = str(params.get("client_id") or "")
    redirect_uri = str(params.get("redirect_uri") or "")
    state = str(params.get("state") or "")
    code_challenge = str(params.get("code_challenge") or "")
    challenge_method = str(params.get("code_challenge_method") or "S256")
    scope = str(params.get("scope") or "edlink.read")
    resource = str(params.get("resource") or "")

    client = _client(client_id)
    if client is None:
        return JSONResponse({"error": "invalid_client"}, status_code=400)

    allowed = json.loads(client["redirect_uris"] or "[]")
    if redirect_uri not in allowed:
        return JSONResponse({"error": "invalid_redirect_uri"}, status_code=400)

    if not _resource_matches(resource, _base(request)):
        return _redirect_error(
            redirect_uri, state, "invalid_target", "resource bukan server ini", _base(request)
        )

    if not code_challenge or challenge_method != "S256":
        return _redirect_error(redirect_uri, state, "invalid_request", "PKCE S256 wajib", _base(request))

    if not session_user:
        return RedirectResponse("/login?next=" + _esc(request.url.path + "?" + request.url.query), status_code=302)

    if request.method == "GET":
        return _consent_page(
            request, client, redirect_uri, state, code_challenge, scope, resource, session_user
        )

    decision = str(params.get("decision") or "")
    if decision != "approve":
        return _redirect_error(redirect_uri, state, "access_denied", "user menolak", _base(request))

    code = secrets.token_urlsafe(32)
    with db.tx() as conn:
        conn.execute(
            "INSERT INTO oauth_authorization_codes"
            " (code, client_id, user_id, redirect_uri, code_challenge, resource, scope, created_at, expires_at, used)"
            " VALUES (?,?,?,?,?,?,?,?,?,0)",
            (
                security.sha256_hex(code),
                client_id,
                session_user["user_id"],
                redirect_uri,
                code_challenge,
                resource,
                scope,
                db.now(),
                db.now() + security.CODE_TTL,
            ),
        )
        conn.execute(
            "INSERT INTO audit_events (ts, user_id, action, detail, ip) VALUES (?,?,?,?,?)",
            (db.now(), session_user["user_id"], "oauth.authorize", client_id[:80], request.client.host if request.client else ""),
        )

    params_out = {"code": code, "state": state, "iss": _base(request)}
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{sep}{urlencode(params_out)}", status_code=302)


async def token(request: Request) -> Response:
    if not db.rate_limit(f"oauth_token:{_ip(request)}", limit=120, window_seconds=900):
        return JSONResponse({"error": "too_many_requests"}, status_code=429)
    try:
        form = await request.form()
    except Exception:
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    grant = str(form.get("grant_type") or "")
    base = _base(request)
    if grant == "authorization_code":
        return _authorization_code_grant(form, base)
    if grant == "refresh_token":
        return _refresh_token_grant(form, base)
    return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)


def _resource_matches(resource: str, base: str) -> bool:
    """RFC 8707: nilai resource yang diminta harus menunjuk ke server ini.

    Metadata kita memakai `base/mcp`; sebagian klien memakai `base` saja.
    Keduanya diterima, selain itu ditolak supaya token tidak bisa diterbitkan
    untuk resource lain.
    """
    if not resource:
        return True
    normalized = resource.rstrip("/")
    return normalized in {base.rstrip("/"), base.rstrip("/") + "/mcp"}


def _issue_tokens(user_id: str, client_id: str, scope: str) -> JSONResponse:
    """Terbitkan pasangan access + refresh token. Token asli hanya dikirim di sini."""
    access = security.create_mcp_token(
        user_id, client_id=client_id, name="oauth:" + (client_id or "")[:40]
    )
    refresh = security.create_refresh_token(user_id, client_id=client_id, scope=scope)
    return JSONResponse(
        {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": security.MCP_TOKEN_TTL,
            "refresh_token": refresh,
            "refresh_token_expires_in": security.REFRESH_TOKEN_TTL,
            "scope": scope or "edlink.read",
        }
    )


def _authorization_code_grant(form, base: str) -> Response:
    code = str(form.get("code") or "")
    verifier = str(form.get("code_verifier") or "")
    client_id = str(form.get("client_id") or "")
    redirect_uri = str(form.get("redirect_uri") or "")
    resource = str(form.get("resource") or "")

    if not _resource_matches(resource, base):
        return JSONResponse({"error": "invalid_target"}, status_code=400)

    row = db.q1(
        "SELECT * FROM oauth_authorization_codes WHERE code = ?",
        (security.sha256_hex(code),),
    )
    if row is None or row["used"] or row["expires_at"] < db.now():
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    if client_id and row["client_id"] != client_id:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    if redirect_uri and row["redirect_uri"] != redirect_uri:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    if not security.verify_pkce(verifier, row["code_challenge"]):
        return JSONResponse({"error": "invalid_grant", "error_description": "PKCE gagal"}, status_code=400)

    with db.tx() as conn:
        conn.execute("UPDATE oauth_authorization_codes SET used=1 WHERE code=?", (row["code"],))

    return _issue_tokens(row["user_id"], row["client_id"], row["scope"] or "edlink.read")


def _refresh_token_grant(form, base: str) -> Response:
    raw = str(form.get("refresh_token") or "")
    client_id = str(form.get("client_id") or "")
    resource = str(form.get("resource") or "")

    if not _resource_matches(resource, base):
        return JSONResponse({"error": "invalid_target"}, status_code=400)

    row = security.refresh_token_row(raw)
    if row is None:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    if client_id and row["client_id"] and row["client_id"] != client_id:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)

    # Rotasi: token lama mati. Replay token lama ditolak, bukan diterbitkan ulang.
    if not security.rotate_refresh_token(raw):
        security.revoke_refresh_tokens(row["user_id"])
        db.audit(row["user_id"], "oauth.refresh_replay", row["client_id"][:80], "")
        return JSONResponse({"error": "invalid_grant"}, status_code=400)

    db.audit(row["user_id"], "oauth.refresh", row["client_id"][:80], "")
    return _issue_tokens(row["user_id"], row["client_id"], row["scope"] or "edlink.read")
