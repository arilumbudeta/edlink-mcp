"""Aplikasi Starlette: MCP + OAuth + web, dengan identitas per request.

Alur:
  request  ->  IdentityMiddleware  ->  routes web  |  Mount("/") -> MCP app
                      |
                      +-- bearer token MCP  -> identity(user)
                      +-- cookie sesi web   -> identity(user)

Setiap tool EdLink membaca identitas dari edlink_platform.identity, jadi tidak
ada tool yang menerima user_id dari argumen dan tidak ada state global user.
"""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from typing import Any

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Mount, Route

from . import db, identity, oauth, security, store, web


class _McpRootAlias:
    """Layani MCP di "/" juga, bukan hanya "/mcp".

    Klien MCP (ChatGPT, Claude) sering memakai base URL tanpa "/mcp". Tanpa
    alias ini POST "/" jatuh ke router web lalu dijawab 404, dan klien
    melaporkan "no MCP server was found at the provided URL" walau OAuth-nya
    sudah sukses. GET "/" dari browser tetap halaman landing karena middleware
    hanya menganggapnya MCP kalau Accept minta text/event-stream.
    """

    def __init__(self, app, target: str = "/mcp") -> None:
        self.app = app
        self.target = target

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") == "http":
            path = scope.get("path") or "/"
            if path in ("", "/"):
                scope = dict(scope)
                scope["path"] = self.target
                scope["raw_path"] = self.target.encode()
        await self.app(scope, receive, send)


class IdentityMiddleware:
    """Resolve identitas dari bearer MCP atau cookie sesi web."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        ident: identity.Identity | None = None
        auth_error: str = ""

        path = request.url.path
        is_mcp = path == "/mcp" or path.startswith("/mcp/")
        if not is_mcp and path in ("", "/"):
            # Base URL tanpa /mcp: hitung sebagai MCP kalau bukan browser yang
            # minta HTML. GET "/" dengan Accept text/html tetap landing page.
            accept = request.headers.get("accept", "").lower()
            is_mcp = request.method != "GET" or "text/event-stream" in accept

        if is_mcp:
            header = request.headers.get("authorization", "")
            if header.lower().startswith("bearer "):
                raw = header[7:].strip()
                row = security.token_user(raw)
                if row is not None:
                    ident = identity.Identity(
                        user_id=row["user_id"], email=row["email"], is_admin=bool(row["is_admin"]), via="mcp"
                    )
                else:
                    auth_error = "invalid_token"
            else:
                auth_error = "missing_token"

            if ident is None:
                base = oauth._base(request)
                payload = json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32001, "message": "Authentication required"},
                    }
                )
                response = Response(payload, status_code=401, media_type="application/json")
                response.headers["WWW-Authenticate"] = (
                    f'Bearer resource_metadata="{base}/.well-known/oauth-protected-resource", '
                    'scope="edlink.read edlink.write"'
                )
                await response(scope, receive, send)
                return
        else:
            sid = web._cookie(request)
            row = security.session_user(sid)
            if row is not None:
                ident = identity.Identity(
                    user_id=row["user_id"], email=row["email"], is_admin=bool(row["is_admin"]), via="web"
                )

        token = identity.set_identity(ident)
        scope.setdefault("state", {})
        scope["state"]["identity"] = ident
        try:
            await self.app(scope, receive, send)
        finally:
            identity.reset_identity(token)


# --------------------------------------------------------------- handlers ---

def _user(request: Request) -> Any | None:
    ident = request.scope.get("state", {}).get("identity")
    if ident is None or ident.via != "web":
        return None
    row = security.get_user(ident.user_id)
    if row is None:
        return None
    return {"user_id": row["id"], "email": row["email"], "is_admin": bool(row["is_admin"])}


async def dashboard_route(request: Request) -> Response:
    user = _user(request)
    if user is None:
        return RedirectResponse("/login?next=/dashboard", status_code=302)
    return web.dashboard(request, user)


async def admin_route(request: Request) -> Response:
    user = _user(request)
    if user is None:
        return RedirectResponse("/login?next=/admin", status_code=302)
    if not user["is_admin"]:
        return web.page("Akses ditolak", '<div class="card"><h1>403</h1><p>Bukan admin.</p></div>', status=403)
    return web.admin_page(request, user)


async def admin_action_route(request: Request) -> Response:
    user = _user(request)
    if user is None:
        return RedirectResponse("/login?next=/admin", status_code=302)
    if not user["is_admin"]:
        return web.page("Akses ditolak", '<div class="card"><h1>403</h1><p>Bukan admin.</p></div>', status=403)
    return await web.admin_action(request, user)


async def link_route(request: Request) -> Response:
    user = _user(request)
    if user is None:
        return RedirectResponse("/login?next=/dashboard", status_code=302)
    return await web.link_post(request, user)


async def unlink_route(request: Request) -> Response:
    user = _user(request)
    if user is None:
        return RedirectResponse("/login?next=/dashboard", status_code=302)
    return await web.unlink_post(request, user)


async def revoke_tokens_route(request: Request) -> Response:
    user = _user(request)
    if user is None:
        return RedirectResponse("/login?next=/dashboard", status_code=302)
    return await web.revoke_tokens_post(request, user)


async def upload_page_route(request: Request) -> Response:
    user = _user(request)
    if user is None:
        return RedirectResponse("/login?next=/upload", status_code=302)
    return web.upload_page(request, user)


async def upload_post_route(request: Request) -> Response:
    user = _user(request)
    if user is None:
        return RedirectResponse("/login?next=/upload", status_code=302)
    return await web.upload_post(request, user)


async def authorize_route(request: Request) -> Response:
    sess = security.session_user(web._cookie(request))
    session_user = None
    if sess is not None:
        session_user = {"user_id": sess["user_id"], "email": sess["email"]}
    return await oauth.authorize(request, session_user)


async def health_route(request: Request) -> Response:
    try:
        db.q1("SELECT 1 AS ok")
        database = "ok"
    except Exception:
        database = "error"
    return JSONResponse({"status": "ok" if database == "ok" else "degraded", "database": database})


# ------------------------------------------------------------------- build ---

def build_app(mcp_app) -> Starlette:
    """:param mcp_app: Starlette app dari FastMCP.streamable_http_app()."""

    @asynccontextmanager
    async def lifespan(app):
        db.init_db()
        store.has_connection  # pastikan modul store ter-import
        async with mcp_app.router.lifespan_context(mcp_app):
            yield

    routes = [
        Route("/", web.index, methods=["GET"]),
        Route("/health", health_route, methods=["GET"]),
        Route("/docs", web.docs_page, methods=["GET"]),
        Route("/signup", web.signup_get, methods=["GET"]),
        Route("/signup", web.signup_post, methods=["POST"]),
        Route("/login", web.login_get, methods=["GET"]),
        Route("/login", web.login_post, methods=["POST"]),
        Route("/logout", web.logout, methods=["POST", "GET"]),
        Route("/dashboard", dashboard_route, methods=["GET"]),
        Route("/link", link_route, methods=["POST"]),
        Route("/unlink", unlink_route, methods=["POST"]),
        Route("/tokens/revoke", revoke_tokens_route, methods=["POST"]),
        Route("/upload", upload_page_route, methods=["GET"]),
        Route("/upload", upload_post_route, methods=["POST"]),
        Route("/admin", admin_route, methods=["GET"]),
        Route("/admin/user", admin_action_route, methods=["POST"]),
        Route("/.well-known/oauth-protected-resource", oauth.protected_resource_metadata, methods=["GET"]),
        Route("/.well-known/oauth-authorization-server", oauth.authorization_server_metadata, methods=["GET"]),
        Route("/oauth/register", oauth.register_client, methods=["POST"]),
        Route("/oauth/authorize", authorize_route, methods=["GET", "POST"]),
        Route("/oauth/token", oauth.token, methods=["POST"]),
        Mount("/", app=_McpRootAlias(mcp_app)),
    ]
    return Starlette(routes=routes, middleware=[Middleware(IdentityMiddleware)], lifespan=lifespan)
