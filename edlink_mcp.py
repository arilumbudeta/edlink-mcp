"""
EdLink MCP Server — tools untuk akses tugas/jadwal/kelas/notifikasi dari EdLink (edlink.id, SEVIMA).

Endpoint dipetakan dari web app edlink.id & pwa.edlink.id (api.edlink.id/api/v1.4).

Auth flow:
  POST /site/login {username, app_id, email, password, web_reg_id, device}
  -> token dipakai sebagai header Authorization: Bearer <token>

Kredensial dibaca dari (urutan prioritas):
  1. Environment variables  EDLINK_EMAIL / EDLINK_PASSWORD
  2. File config.json       di folder yang sama dengan script ini

Jalankan lokal:  python edlink_mcp.py                       (stdio MCP)
Jalankan HTTP :  EDLINK_MCP_TRANSPORT=http python edlink_mcp.py
                 endpoint /mcp, bind 0.0.0.0, port dari EDLINK_MCP_PORT (default 8765).
                 Wajib: EDLINK_MCP_AUTH_TOKEN (bearer), EDLINK_MCP_ISSUER_URL.
                 Opsional: EDLINK_MCP_HOST, EDLINK_MCP_ALLOWED_HOSTS, EDLINK_MCP_ALLOWED_ORIGINS.

"""

import html as html_lib
import json
import mimetypes
import os
import re
import secrets
import time
import uuid
import webbrowser
from functools import wraps
from pathlib import Path
from typing import Any

import httpx

try:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _MCPServer
except ImportError:  # mcp 2.x
    from mcp.server.mcpserver import MCPServer as _MCPServer

SCRIPT_DIR = Path(__file__).resolve().parent
CONFIG_PATH = SCRIPT_DIR / "config.json"
TOKEN_CACHE_PATH = SCRIPT_DIR / "token_cache.json"

API_BASE = "https://api.edlink.id/api/v1.4"
REFERER = "https://edlink.id/login"
OAUTH_URL = f"{API_BASE}/auth/google"  # 302 -> accounts.google.com, callback -> JSON token
REQUEST_TIMEOUT = 30.0
TOKEN_MAX_AGE = 60 * 60 * 8  # cache token maksimal 8 jam sebelum dipakai ulang

# Transport Streamable HTTP (buat deploy publik / ChatGPT custom MCP app)
DEFAULT_HTTP_PORT = 8765
MOUNT_PATH = "/mcp"

_TOKEN_EXPIRED_MSG = (
    "Token EdLink expired. Login ulang di edlink.id (via Google), lalu ambil token "
    "baru: di halaman edlink.id/classes jalankan di console browser: "
    "copy(helpers.getToken(document.cookie.match(/(?:^|; )token=([^;]+)/)[1]).token) "
    "— atau ikuti langkah 'Ambil token baru' di README.md"
)


def _env_list(name: str) -> list[str]:
    return [item.strip() for item in os.environ.get(name, "").split(",") if item.strip()]


def _platform_user_id() -> str | None:
    """User yang sedang memanggil, kalau server jalan di mode platform.

    Mode stdio mengembalikan None → kredensial dibaca dari config.json lokal
    seperti sebelumnya. Mode HTTP multi-user mengembalikan id user dari token
    MCP yang sudah diverifikasi middleware.
    """
    try:
        from edlink_platform import identity
    except ImportError:
        return None
    return identity.current_user_id()


class StaticBearerVerifier:
    """Verifikasi Bearer token statis dengan perbandingan constant-time."""

    def __init__(self, expected_token: str) -> None:
        self._expected = expected_token.encode("utf-8")

    async def verify_token(self, token: str) -> Any:
        from mcp.server.auth.provider import AccessToken

        candidate = token.encode("utf-8")
        if not secrets.compare_digest(candidate, self._expected):
            return None
        return AccessToken(
            token="***", client_id="static-token", scopes=[], subject="edlink-mcp"
        )


def _build_http_server():
    """FastMCP + Streamable HTTP.

    Dua mode autentikasi:

    1. Bearer statis (default) — `EDLINK_MCP_AUTH_TOKEN` wajib, dibandingkan
       constant-time. Cocok untuk klien yang bisa mengirim header Authorization
       (MCP Inspector, Codex, skrip).

    2. Proxy-trust — `EDLINK_MCP_TRUST_PROXY_AUTH=1`. Server tidak memeriksa
       Authorization karena gerbang auth ada di reverse proxy / port publisher
       (mis. instabox-port --private, yang hanya melayani URL ber-`_token`).
       Hanya aman bila satu-satunya jalur masuk memang proxy tersebut.

    ChatGPT tidak bisa mengirim API key statis, jadi mode 2 yang dipakai untuk
    integrasi ChatGPT.
    """
    trust_proxy = os.environ.get("EDLINK_MCP_TRUST_PROXY_AUTH", "").strip().lower() in (
        "1",
        "true",
        "yes",
    )
    issuer_url = os.environ.get("EDLINK_MCP_ISSUER_URL", "").strip()
    if not issuer_url:
        raise RuntimeError(
            "EDLINK_MCP_ISSUER_URL belum diset (contoh https://host.example)."
        )
    auth_token = os.environ.get("EDLINK_MCP_AUTH_TOKEN", "").strip()
    if not trust_proxy and not auth_token:
        raise RuntimeError(
            "EDLINK_MCP_AUTH_TOKEN belum diset — server HTTP tidak akan start "
            "tanpa autentikasi (atau set EDLINK_MCP_TRUST_PROXY_AUTH=1 kalau "
            "gerbang auth ada di reverse proxy)."
        )

    host = os.environ.get("EDLINK_MCP_HOST", "0.0.0.0")
    port = int(os.environ.get("EDLINK_MCP_PORT", str(DEFAULT_HTTP_PORT)))
    allowed_hosts = _env_list("EDLINK_MCP_ALLOWED_HOSTS") or [
        f"localhost:{port}",
        f"127.0.0.1:{port}",
    ]
    allowed_origins = _env_list("EDLINK_MCP_ALLOWED_ORIGINS")

    from mcp.server.transport_security import TransportSecuritySettings

    kwargs: dict[str, Any] = {
        "host": host,
        "port": port,
        "streamable_http_path": MOUNT_PATH,
        "stateless_http": True,
        "json_response": True,
        "max_request_body_size": 2 * 1024 * 1024,
        "transport_security": TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed_hosts,
            allowed_origins=allowed_origins,
        ),
    }
    if not trust_proxy:
        from mcp.server.auth.settings import AuthSettings

        kwargs["auth"] = AuthSettings(
            issuer_url=issuer_url,
            resource_server_url=issuer_url.rstrip("/") + MOUNT_PATH,
            required_scopes=None,
            validate_token_resource=False,  # verifier ini yang pegang validasi
        )
        kwargs["token_verifier"] = StaticBearerVerifier(auth_token)
    return _MCPServer("edlink", **kwargs)


def _make_server():
    transport = os.environ.get("EDLINK_MCP_TRANSPORT", "stdio").lower()
    if transport in ("http", "streamable-http"):
        return _build_http_server(), transport
    return _MCPServer("edlink"), "stdio"


mcp, _TRANSPORT = _make_server()


def tool():
    """Daftarkan tool. Kalau kredensial belum ada, balikin prompt setup (manual/oauth),
    bukan exception mentah — supaya install pertama langsung ditanya metode login."""

    def decorator(fn):
        @wraps(fn)
        async def wrapper(*args, **kwargs):
            try:
                return await fn(*args, **kwargs)
            except RuntimeError as exc:
                if "Kredensial EdLink belum ada" in str(exc):
                    return json.dumps(_setup_prompt(), ensure_ascii=False)
                raise

        return mcp.tool()(wrapper)

    return decorator


# ---------------------------------------------------------------- config ---

def _load_credentials() -> dict[str, str]:
    user_id = _platform_user_id()
    if user_id:
        from edlink_platform import store

        return store.load_credentials(user_id)
    email = os.environ.get("EDLINK_EMAIL", "").strip()
    password = os.environ.get("EDLINK_PASSWORD", "").strip()
    token = os.environ.get("EDLINK_TOKEN", "").strip()
    if token:
        return {"token": token}
    if CONFIG_PATH.exists():
        try:
            cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            token = str(cfg.get("token", "")).strip()
            if token:
                return {"token": token}
            email = str(cfg.get("email", "")).strip()
            password = str(cfg.get("password", "")).strip()
            if email and password:
                return {"email": email, "password": password}
        except (json.JSONDecodeError, OSError):
            pass
    if email and password:
        return {"email": email, "password": password}
    raise RuntimeError(
        "Kredensial EdLink belum ada. Panggil tool 'edlink_setup_status' untuk "
        "memilih login manual (email+password) atau OAuth Google (link)."
    )


def _load_device() -> dict[str, Any]:
    """Device fingerprint stabil — disimpan supaya tiap login konsisten."""
    user_id = _platform_user_id()
    if user_id:
        from edlink_platform import store

        return store.load_device(user_id)
    if TOKEN_CACHE_PATH.exists():
        try:
            cache = json.loads(TOKEN_CACHE_PATH.read_text(encoding="utf-8"))
            dev = cache.get("device")
            if isinstance(dev, dict) and dev.get("secureId"):
                return dev
        except (json.JSONDecodeError, OSError):
            pass
    return {
        "secureId": str(uuid.uuid4()),
        "name": "Chrome",
        "manufacture": "Google",
        "model": "Chrome",
        "product": "Chrome",
        "hardware": "Windows 10",
        "version": "126.0.0.0",
        "regId": None,
    }


def _read_token_cache() -> dict[str, Any] | None:
    user_id = _platform_user_id()
    if user_id:
        from edlink_platform import store

        return store.read_token_cache(user_id)
    if not TOKEN_CACHE_PATH.exists():
        return None
    try:
        cache = json.loads(TOKEN_CACHE_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    token = cache.get("token")
    saved_at = cache.get("saved_at", 0)
    if not token or (time.time() - saved_at) > TOKEN_MAX_AGE:
        return None
    return cache


def _write_token_cache(token: str, extra: dict[str, Any] | None = None) -> None:
    user_id = _platform_user_id()
    if user_id:
        from edlink_platform import store

        store.write_token_cache(user_id, token, extra=extra, device=_load_device())
        return
    payload: dict[str, Any] = {
        "token": token,
        "saved_at": time.time(),
        "device": _load_device(),
    }
    if extra:
        payload.update(extra)
    TOKEN_CACHE_PATH.write_text(json.dumps(payload), encoding="utf-8")


# ------------------------------------------------------------------- api ---

_TOKEN_KEYS = ("token", "access_token", "accessToken", "authorization", "userToken")


def _find_token(obj: Any, depth: int = 0) -> str | None:
    """Cari token di struktur response sedalam mungkin.

    Per Nov 2026 login web mengembalikan token di `data.userToken.token`,
    bukan `data.token`, jadi pencarian harus rekursif.
    """
    if depth > 6:
        return None
    if isinstance(obj, dict):
        for key in _TOKEN_KEYS:
            val = obj.get(key)
            if isinstance(val, str) and len(val) >= 16:
                return val
            if isinstance(val, dict):
                inner = val.get("token")
                if isinstance(inner, str) and len(inner) >= 16:
                    return inner
        for key, val in obj.items():
            found = _find_token(val, depth + 1)
            if found:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = _find_token(item, depth + 1)
            if found:
                return found
    return None


def _extract_token(login_payload: Any) -> str:
    """Token bisa di beberapa field tergantung versi API."""
    found = _find_token(login_payload)
    if found:
        return found
    # Jangan pernah dump payload: isinya profil user dan bisa memuat token.
    top = list(login_payload)[:12] if isinstance(login_payload, dict) else type(login_payload).__name__
    raise RuntimeError(
        "Login sukses tapi token tidak ditemukan di response. "
        f"Kunci yang ada: {', '.join(map(str, top))}"
    )


def _normalize(body: Any, path: str) -> Any:
    """Response EdLink: {"data": ..., "applicationSystem": {message, code}}.

    Aturan:
    - "data" ada dan bukan null  -> sukses, kembalikan data.
    - applicationSystem.code 2 / pesan "login kembali" -> PermissionError (token expired).
    - applicationSystem.code != 0 -> RuntimeError dengan pesan API.
    - payload tanpa "data" tapi ada "message" (Laravel 404/405) -> RuntimeError,
      supaya fallback method (POST -> GET) di _authed_request benar-benar jalan.
    """
    if not isinstance(body, dict):
        return body
    app = body.get("applicationSystem") or {}
    message = app.get("message") or body.get("message")
    code = app.get("code")

    if "data" not in body and message and not app:
        raise RuntimeError(f"EdLink API {path}: {message}")

    data = body.get("data", body)
    if data is None and message:
        if code == 2 or "login kembali" in str(message).lower():
            raise PermissionError(f"Token EdLink expired/invalid: {message}")
        if code not in (None, 0):
            raise RuntimeError(f"EdLink API {path}: {message} (code={code})")
    return data


async def _edlink_request_payload(
    path: str,
    method: str = "POST",
    body: dict[str, Any] | None = None,
    token: str | None = None,
) -> dict[str, Any]:
    """Kirim request mentah dan kembalikan payload JSON utuh (tanpa normalisasi)."""
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-App-Locale": "id",
        "X-Referer": REFERER,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = f"{API_BASE}/{path.lstrip('/')}"
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        resp = await client.request(
            method.upper(), url, headers=headers, json=(body if body is not None else {})
        )
    if resp.status_code in (401, 403):
        raise PermissionError(f"HTTP {resp.status_code}: token invalid/expired")
    try:
        return resp.json()
    except ValueError:
        raise RuntimeError(f"HTTP {resp.status_code} bukan JSON: {resp.text[:300]}")


async def _edlink_request(
    path: str,
    method: str = "POST",
    body: dict[str, Any] | None = None,
    token: str | None = None,
) -> Any:
    payload = await _edlink_request_payload(path, method, body, token=token)
    return _normalize(payload, path)


async def _login() -> str:
    """Dapatkan token: mode 'token' (Google/manual) langsung pakai; mode
    email/password login ke site/login."""
    creds = _load_credentials()
    if "token" in creds:
        _write_token_cache(creds["token"], extra={"mode": "token"})
        return creds["token"]
    # `device` sengaja TIDAK dikirim: per Nov 2026 EdLink menjawab HTTP 500
    # untuk semua bentuk device dict (secureId saja pun gagal), sedangkan tanpa
    # field ini login web berjalan normal. Device fingerprint hanya dipakai
    # alur mobile.
    payload = {
        "username": "",
        "app_id": "",
        "email": creds["email"],
        "password": creds["password"],
        "web_reg_id": None,
    }
    # Payload mentah, bukan _normalize(): token berada di data.userToken.token
    # dan normalisasi hanya mengembalikan `data` tanpa jaminan bentuk.
    result = await _edlink_request_payload("site/login", method="POST", body=payload)
    token = _extract_token(result)
    _write_token_cache(token, extra={"mode": "password"})
    return token


async def _current_token() -> str:
    cached = _read_token_cache()
    token = cached.get("token") if cached else None
    if token:
        return token
    return await _login()


async def _edlink_upload(
    path: str,
    file_path: Path,
    fields: dict[str, str] | None,
    token: str,
) -> dict[str, Any]:
    """Upload multipart (media/upload, drive/upload). Field file wajib."""
    headers = {
        "Accept": "application/json",
        "X-App-Locale": "id",
        "X-Referer": REFERER,
        "Authorization": f"Bearer {token}",
    }
    content = file_path.read_bytes()
    mime = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
    url = f"{API_BASE}/{path.lstrip('/')}"
    async with httpx.AsyncClient(timeout=180.0) as client:
        resp = await client.post(
            url,
            headers=headers,
            data=fields or {},
            files={"file": (file_path.name, content, mime)},
        )
    if resp.status_code in (401, 403):
        raise PermissionError(f"HTTP {resp.status_code}: token invalid/expired")
    try:
        return resp.json()
    except ValueError:
        raise RuntimeError(f"HTTP {resp.status_code} bukan JSON: {resp.text[:300]}")


async def _authed_request(
    path: str,
    method: str | None = None,
    body: dict[str, Any] | None = None,
    raw: bool = False,
) -> Any:
    """Request dengan token.

    - method=None  -> coba POST dulu (default API EdLink), fallback GET kalau route menolak.
    - method eksplisit -> langsung method itu (dipakai untuk GET-only dan submit).
    - token expired di mode password -> login ulang sekali lalu retry.
    - token expired di mode Google  -> RuntimeError dengan instruksi ambil token baru.
    - raw=True -> kembalikan payload JSON utuh (untuk baca applicationSystem.message).
    """
    creds_hint = None
    try:
        creds_hint = _load_credentials()
    except RuntimeError:
        pass
    cached = _read_token_cache()
    token = cached.get("token") if cached else None
    mode = (cached or {}).get("mode") or ("token" if creds_hint and "token" in creds_hint else "password")

    async def call(m: str) -> Any:
        nonlocal token
        if not token:
            token = await _login()
        payload = await _edlink_request_payload(path, m, body, token=token)
        return payload if raw else _normalize(payload, path)

    async def attempt(m: str) -> Any:
        nonlocal token
        try:
            return await call(m)
        except PermissionError:
            if mode == "token":
                raise RuntimeError(_TOKEN_EXPIRED_MSG)
            token = None
            return await call(m)

    if method:
        return await attempt(method.upper())

    last_exc: Exception | None = None
    for candidate in ("POST", "GET"):
        try:
            return await attempt(candidate)
        except RuntimeError as exc:
            if "Supported methods" in str(exc):
                last_exc = exc
                continue
            raise
    raise last_exc or RuntimeError(f"EdLink API {path}: tidak ada method yang didukung")


# ------------------------------------------------------------- formatting ---

_TAG_RE = re.compile(r"<[^>]+>")
_HTML_MARK_RE = re.compile(r"<(p|br|div|ul|ol|li|strong|em|h[1-6])\b", re.IGNORECASE)


def _strip_html(value: Any) -> str:
    """HTML tugas -> teks polos buat dibaca agent."""
    if not isinstance(value, str):
        return ""
    text = re.sub(r"<br\s*/?>", "\n", value, flags=re.IGNORECASE)
    text = re.sub(r"</p\s*>", "\n", text, flags=re.IGNORECASE)
    text = _TAG_RE.sub("", text)
    text = text.replace("\xa0", " ")  # EdLink kadang kirim non-breaking space
    return html_lib.unescape(text).strip()


def _html_jawaban(value: str) -> str:
    """Jawaban agent -> HTML yang sama formatnya dengan editor EdLink."""
    text = (value or "").strip()
    if not text:
        return ""
    if _HTML_MARK_RE.search(text):
        return text
    escaped = html_lib.escape(text)
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", escaped) if p.strip()]
    if not paragraphs:
        paragraphs = [escaped]
    return "".join(f"<p>{p.replace(chr(10), '<br>')}</p>" for p in paragraphs)


def _assignment_items(data: Any) -> list[dict[str, Any]]:
    """Ambil array tugas dari home/openassignmentsandquizes."""
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        inner = data.get("data")
        if isinstance(inner, list):
            return [item for item in inner if isinstance(item, dict)]
        if isinstance(inner, dict):
            nested = inner.get("data")
            if isinstance(nested, list):
                return [item for item in nested if isinstance(item, dict)]
    return []


def _assignment_summary(data: dict[str, Any]) -> dict[str, Any]:
    """Ringkas detail learning-material (type Q) jadi bentuk yang enak dibaca agent."""
    tq = data.get("teacherQuestion") or {}
    gate = data.get("submissionGate") or {}
    my = data.get("mySubmission") or {}
    group = data.get("group") or {}
    section = data.get("section") or {}
    attachments = []
    for media in data.get("medias") or []:
        if not isinstance(media, dict):
            continue
        attachments.append(
            {
                "id": media.get("id"),
                "nama": media.get("name"),
                "ekstensi": media.get("extension"),
                "ukuran": media.get("size"),
                "link": (media.get("file") or {}).get("link"),
            }
        )
    return {
        "id": data.get("id"),
        "judul": data.get("title"),
        "kelas": group.get("name"),
        "kelas_paralel": group.get("className"),
        "tipe": data.get("type"),
        "meet": section.get("meet"),
        "topik": section.get("topic"),
        "deadline": tq.get("dueDate"),
        "deadline_timestamp": tq.get("dueDateTimestamp"),
        "allow_late_submission": tq.get("allowLateSubmission", data.get("allowLateSubmission")),
        "batas_ukuran_file": tq.get("filesizeLimit"),
        "instruksi_html": data.get("description") or "",
        "instruksi_teks": _strip_html(data.get("description") or ""),
        "lampiran_tugas": attachments,
        "sudah_submit": bool(my.get("hasSubmittedAnswer") or gate.get("hasSubmittedAnswer")),
        "bisa_submit": gate.get("canSubmit"),
        "bisa_edit": bool(gate.get("canEditSubmission") or my.get("canEditSubmission")),
        "perlu_konfirmasi_terlambat": bool(gate.get("requiresLateConfirmation")),
        "alasan_gate": gate.get("reason"),
        "gate": gate,
    }


def _extract_media_id(payload: Any, depth: int = 0) -> Any:
    """Cari id media di response upload yang bentuknya bisa beda-beda."""
    if depth > 5:
        return None
    if isinstance(payload, dict):
        if "id" in payload and any(k in payload for k in ("name", "extension", "mime", "file")):
            return payload.get("id")
        for key in ("data", "media", "file", "files"):
            if key in payload:
                found = _extract_media_id(payload[key], depth + 1)
                if found is not None:
                    return found
        for value in payload.values():
            if isinstance(value, (dict, list)):
                found = _extract_media_id(value, depth + 1)
                if found is not None:
                    return found
    elif isinstance(payload, list):
        for item in payload:
            found = _extract_media_id(item, depth + 1)
            if found is not None:
                return found
    return None


def _media_items(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict):
        data = data.get("data") or data.get("items") or []
    if not isinstance(data, list):
        return []
    result = []
    for media in data:
        if not isinstance(media, dict):
            continue
        result.append(
            {
                "id": media.get("id"),
                "nama": media.get("name"),
                "ekstensi": media.get("extension"),
                "mime": media.get("mime"),
                "ukuran": media.get("size"),
                "storage_type": media.get("storageType") or media.get("storage_type"),
                "link": (media.get("file") or {}).get("link") if isinstance(media.get("file"), dict) else None,
            }
        )
    return result


def _setup_prompt() -> dict[str, Any]:
    """Payload pertama-install: tanya manual vs OAuth, plus link OAuth."""
    platform_user = _platform_user_id()
    if platform_user:
        # Mode platform: kredensial tidak boleh masuk chat, dan tidak ada
        # config.json bersama. Satu-satunya jalur adalah dashboard per akun.
        base = os.environ.get("EDLINK_PLATFORM_BASE_URL", "").rstrip("/")
        dashboard = f"{base}/dashboard" if base else "dashboard platform"
        return {
            "perlu_setup": True,
            "metode": "platform",
            "pesan": "Akun platform ini belum terhubung ke akun EdLink.",
            "langkah": [
                f"Buka {dashboard} di browser dan login.",
                "Tempel token EdLink (129 karakter dari DevTools edlink.id), "
                "atau isi email + password EdLink.",
                "Kembali ke sini, lalu panggil edlink_setup_status() lagi.",
            ],
            "catatan": (
                "Jangan menempel token atau password EdLink di chat. Halaman dashboard "
                "menyimpannya terenkripsi untuk akun ini saja."
            ),
        }
    return {
        "perlu_setup": True,
        "pesan": "Kredensial EdLink belum ada. Pilih metode login dulu.",
        "pilih_salah_satu": [
            {
                "metode": "manual",
                "deskripsi": "Login pakai email + password akun EdLink.",
                "tool": "edlink_setup_manual",
                "parameter": {"email": "email-kamu@example.com", "password": "password-kamu"},
            },
            {
                "metode": "oauth",
                "deskripsi": "Login Google lewat link OAuth resmi EdLink, lalu copy token.",
                "link": OAUTH_URL,
                "tool": "edlink_setup_oauth",
                "langkah": [
                    "Panggil edlink_setup_oauth() — browser terbuka ke link OAuth EdLink.",
                    f"Atau buka manual: {OAUTH_URL}",
                    "Login dengan akun Google yang terdaftar di EdLink.",
                    "Setelah callback, browser menampilkan JSON berisi token; copy nilainya.",
                    "Panggil edlink_setup_token(token='...') — token langsung disimpan ke config.json.",
                ],
            },
        ],
        "catatan": (
            "Kalau browser tidak menampilkan token mentah, buka edlink.id/classes lalu "
            "jalankan di console: "
            "copy(helpers.getToken(document.cookie.match(/(?:^|; )token=([^;]+)/)[1]).token)"
        ),
    }


# ----------------------------------------------------------------- tools ---

@tool()
async def edlink_tugas() -> str:
    """Daftar tugas & kuis yang masih terbuka/belum dikerjakan di EdLink, beserta deadline dan kelasnya.

    Pakai tool ini setiap kali user bertanya 'ada tugas apa saja?', 'ada tugas gak?',
    'tugas yang belum dikerjakan', 'assignment pending', dan sejenisnya.
    """
    data = await _authed_request("home/openassignmentsandquizes")
    if data is None:
        return json.dumps({"ada_tugas": False, "ringkasan": "Tidak ada tugas/kuis terbuka."}, ensure_ascii=False)
    return json.dumps({"ada_tugas": True, "data": data}, ensure_ascii=False, default=str)


@tool()
async def edlink_tugas_terbaru(urut: str = "deadline") -> str:
    """Ambil satu tugas paling relevan + detailnya, siap dikerjakan agent.

    urut="deadline" (default) -> deadline paling dekat lebih dulu.
    urut="baru"               -> id terbesar (paling baru dibuat) lebih dulu.

    Ini pintu masuk untuk perintah user: "kerjakan tugas terbaru dan send".
    Alur agent: panggil tool ini -> baca detail.instruksi_teks -> susun jawaban
    -> panggil edlink_send_tugas(tugas_id, jawaban, media_ids, konfirmasi_terlambat).
    """
    data = await _authed_request("home/openassignmentsandquizes")
    items = _assignment_items(data)
    if not items:
        return json.dumps(
            {"ada_tugas": False, "ringkasan": "Tidak ada tugas/kuis terbuka."},
            ensure_ascii=False,
        )

    if urut.lower() in ("baru", "created", "id"):
        ordered = sorted(items, key=lambda item: int(item.get("id") or 0), reverse=True)
    else:
        ordered = sorted(items, key=lambda item: str(item.get("dueAt") or "9999-12-31"))

    chosen = ordered[0]
    detail_data = await _authed_request(f"learningmaterials/detail/{chosen.get('id')}")
    detail = _assignment_summary(detail_data) if isinstance(detail_data, dict) else None

    kandidat = []
    for item in ordered:
        group = item.get("group") or {}
        kandidat.append(
            {
                "id": item.get("id"),
                "judul": item.get("title"),
                "kelas": group.get("name"),
                "deadline": item.get("dueAt"),
                "tipe": item.get("type"),
            }
        )

    return json.dumps(
        {
            "ada_tugas": True,
            "urut": urut,
            "terpilih": kandidat[0],
            "detail": detail,
            "kandidat": kandidat,
            "langkah_berikut": [
                "Baca detail.instruksi_teks dan detail.lampiran_tugas.",
                "Susun jawaban lengkap sesuai instruksi.",
                "Kalau perlu lampiran: edlink_upload_file(path) lalu pakai media_id-nya.",
                "Kirim: edlink_send_tugas(tugas_id, jawaban, media_ids=[...]).",
                "Kalau detail.perlu_konfirmasi_terlambat=true dan user sudah bilang 'send', "
                "panggil ulang edlink_send_tugas(..., konfirmasi_terlambat=True).",
            ],
        },
        ensure_ascii=False,
        default=str,
    )


@tool()
async def edlink_tugas_detail(tugas_id: int) -> str:
    """Detail satu tugas/kuis: instruksi, deadline, lampiran, status submission gate,
    dan status jawabanmu. Pakai sebelum mengerjakan atau mengirim tugas.

    tugas_id didapat dari edlink_tugas() atau edlink_tugas_terbaru().
    """
    data = await _authed_request(f"learningmaterials/detail/{tugas_id}")
    if not isinstance(data, dict):
        return json.dumps(
            {"ok": False, "error": f"Detail tugas {tugas_id} tidak ditemukan."},
            ensure_ascii=False,
        )
    return json.dumps({"ok": True, "tugas": _assignment_summary(data)}, ensure_ascii=False, default=str)


@tool()
async def edlink_tugas_jawaban_saya(tugas_id: int) -> str:
    """Cek jawaban yang sudah kamu kirim untuk satu tugas (kalau ada)."""
    try:
        data = await _authed_request(f"lecturer-question/detail-answer/{tugas_id}")
    except RuntimeError as exc:
        if "Data tidak ditemukan" in str(exc):
            return json.dumps(
                {"ada_jawaban": False, "tugas_id": tugas_id},
                ensure_ascii=False,
            )
        raise
    if not data:
        return json.dumps({"ada_jawaban": False, "tugas_id": tugas_id}, ensure_ascii=False)
    return json.dumps({"ada_jawaban": True, "tugas_id": tugas_id, "jawaban": data}, ensure_ascii=False, default=str)


@tool()
async def edlink_send_tugas(
    tugas_id: int,
    jawaban: str,
    media_ids: list[int] | None = None,
    konfirmasi_terlambat: bool = False,
    timpa_jawaban_lama: bool = True,
) -> str:
    """KIRIM tugas ke EdLink. Ini aksi tulis — dipakai setelah jawaban disusun.

    tugas_id: id dari edlink_tugas()/edlink_tugas_terbaru().
    jawaban: teks atau HTML jawaban. Teks polos otomatis dibungkus <p>...</p>.
    media_ids: opsional, id media dari edlink_upload_file()/edlink_media().
    konfirmasi_terlambat: wajib True kalau submission gate minta konfirmasi
        keterlambatan (tugas sudah lewat deadline tapi masih allowLateSubmission).
    timpa_jawaban_lama: kalau sudah pernah submit dan masih bisa edit, kirim ulang
        menimpa jawaban lama (default True). Set False untuk menolak.

    Hasil: {"ok": true, "aksi": "kirim"|"edit", "pesan": "...", ...}.
    """
    answer_html = _html_jawaban(jawaban)
    if not answer_html:
        return json.dumps({"ok": False, "error": "Jawaban kosong — tidak ada yang dikirim."}, ensure_ascii=False)

    media_list: list[int] = []
    for media in media_ids or []:
        try:
            media_list.append(int(media))
        except (TypeError, ValueError):
            return json.dumps(
                {"ok": False, "error": f"media_ids tidak valid: {media!r} (harus angka)."},
                ensure_ascii=False,
            )

    detail_data = await _authed_request(f"learningmaterials/detail/{tugas_id}")
    if not isinstance(detail_data, dict):
        return json.dumps(
            {"ok": False, "error": f"Tugas {tugas_id} tidak ditemukan."},
            ensure_ascii=False,
        )

    gate = detail_data.get("submissionGate") or {}
    my = detail_data.get("mySubmission") or {}
    sudah_submit = bool(my.get("hasSubmittedAnswer") or gate.get("hasSubmittedAnswer"))
    bisa_edit = bool(gate.get("canEditSubmission") or my.get("canEditSubmission"))

    if not sudah_submit and gate.get("canSubmit") is False:
        return json.dumps(
            {
                "ok": False,
                "error": gate.get("reason") or "Submission ditutup oleh dosen.",
                "gate": gate,
            },
            ensure_ascii=False,
        )

    if gate.get("requiresLateConfirmation") and not konfirmasi_terlambat:
        return json.dumps(
            {
                "ok": False,
                "perlu_konfirmasi_terlambat": True,
                "deadline": (detail_data.get("teacherQuestion") or {}).get("dueDate"),
                "pesan": (
                    "Tugas sudah lewat deadline. Kalau user sudah menyuruh kirim, "
                    "panggil ulang dengan konfirmasi_terlambat=True."
                ),
                "gate": gate,
            },
            ensure_ascii=False,
        )

    if sudah_submit:
        if not bisa_edit:
            return json.dumps(
                {
                    "ok": False,
                    "error": "Sudah submit dan submission dikunci — tidak bisa diedit.",
                    "gate": gate,
                },
                ensure_ascii=False,
            )
        if not timpa_jawaban_lama:
            return json.dumps(
                {"ok": False, "error": "Sudah pernah submit; timpa_jawaban_lama=False."},
                ensure_ascii=False,
            )
        try:
            existing = await _authed_request(f"lecturer-question/detail-answer/{tugas_id}")
        except RuntimeError as exc:
            if "Data tidak ditemukan" in str(exc):
                existing = None
            else:
                raise
        answer_id = existing.get("id") if isinstance(existing, dict) else None
        if not answer_id:
            return json.dumps(
                {"ok": False, "error": "Jawaban lama tidak ditemukan; tidak bisa edit."},
                ensure_ascii=False,
            )
        raw = await _authed_request(
            f"lecturer-question/edit-answer/{answer_id}",
            "POST",
            {"id": answer_id, "media_ids": media_list, "answer": answer_html},
            raw=True,
        )
        app = (raw or {}).get("applicationSystem") or {}
        return json.dumps(
            {
                "ok": app.get("code") == 0,
                "aksi": "edit",
                "tugas_id": tugas_id,
                "jawaban_id": answer_id,
                "pesan": app.get("message") or (raw or {}).get("message"),
                "media_ids": media_list,
            },
            ensure_ascii=False,
            default=str,
        )

    raw = await _authed_request(
        f"lecturer-question/set-answer/{tugas_id}",
        "POST",
        {"id": None, "media_ids": media_list, "answer": answer_html},
        raw=True,
    )
    app = (raw or {}).get("applicationSystem") or {}
    return json.dumps(
        {
            "ok": app.get("code") == 0,
            "aksi": "kirim",
            "tugas_id": tugas_id,
            "pesan": app.get("message") or (raw or {}).get("message"),
            "media_ids": media_list,
        },
        ensure_ascii=False,
        default=str,
    )


@tool()
async def edlink_media(cari: str = "", batas: int = 10) -> str:
    """Daftar berkas yang sudah kamu upload ke EdLink (sumber media_ids untuk lampiran tugas).

    cari: filter nama (opsional). batas: maksimal hasil (1-50, default 10).
    """
    limit = max(1, min(int(batas), 50))
    provider = json.dumps(
        {"criterion": [], "page": {"current": 1, "limit": limit}, "sort": []}
    )
    data = await _authed_request("media/all", "POST", {"dataProvider": provider})
    items = _media_items(data)
    if cari.strip():
        needle = cari.strip().lower()
        items = [item for item in items if needle in str(item.get("nama") or "").lower()]
    return json.dumps({"jumlah": len(items), "media": items[:limit]}, ensure_ascii=False, default=str)


@tool()
async def edlink_upload_file(path: str, ke_drive: bool = False, parent_id: str | None = None) -> str:
    """Upload berkas untuk lampiran tugas. Kembalikan media_id yang dipakai di edlink_send_tugas.

    path: path file lokal (contoh C:\\path\\ke\\tugas.pdf).
    ke_drive: True -> upload ke Google Drive EdLink (drive/upload);
              False (default) -> media pribadi EdLink (media/upload).
    parent_id: opsional, folder tujuan kalau ke_drive=True.
    """
    file_path = Path(path).expanduser()
    user_id = _platform_user_id()
    if user_id:
        # Mode platform: user tidak boleh membaca file sembarang di server.
        root = (Path(os.environ.get("EDLINK_PLATFORM_UPLOAD_DIR", "data/uploads")) / user_id).resolve()
        root.mkdir(parents=True, exist_ok=True)
        candidate = (root / Path(path).name).resolve()
        if Path(path).is_absolute() or ".." in Path(path).parts:
            candidate = (Path(path).expanduser().resolve())
        try:
            candidate.relative_to(root)
        except ValueError:
            return json.dumps(
                {
                    "ok": False,
                    "error": (
                        "Mode platform hanya menerima nama file di folder upload akun "
                        "ini. Unggah lewat dashboard, atau kirim nama file tanpa path."
                    ),
                },
                ensure_ascii=False,
            )
        file_path = candidate
    if not file_path.is_file():
        return json.dumps(
            {"ok": False, "error": f"File tidak ditemukan: {file_path}"},
            ensure_ascii=False,
        )

    token = await _current_token()
    if ke_drive:
        endpoint = "drive/upload"
        fields = {"parent_id": parent_id} if parent_id else None
    else:
        endpoint = "media/upload"
        fields = None

    raw = await _edlink_upload(endpoint, file_path, fields, token)
    app = (raw or {}).get("applicationSystem") or {}
    media_id = _extract_media_id(raw)
    return json.dumps(
        {
            "ok": app.get("code", 0) == 0,
            "endpoint": endpoint,
            "nama_file": file_path.name,
            "ukuran_byte": file_path.stat().st_size,
            "media_id": media_id,
            "pesan": app.get("message") or (raw or {}).get("message"),
            "catatan": (
                "Kalau media_id null, panggil edlink_media(cari=nama_file) untuk ambil id-nya."
            ),
        },
        ensure_ascii=False,
        default=str,
    )


@tool()
async def edlink_jadwal_hari_ini() -> str:
    """Jadwal kuliah/kelas hari ini dari EdLink (today-schedule)."""
    data = await _authed_request("home/today-schedule")
    return json.dumps({"data": data}, ensure_ascii=False, default=str)


@tool()
async def edlink_jadwal_bulanan(bulan: int | None = None, tahun: int | None = None) -> str:
    """Jadwal bulanan dari EdLink (monthly-schedule). Bulan & tahun opsional (1-12, mis. 2026).

    Kalau user menanyakan 'ada kelas/pertemuan gak minggu ini', 'jadwal bulan depan', pakai ini.
    """
    params: dict[str, Any] = {}
    if bulan is not None:
        params["month"] = bulan
    if tahun is not None:
        params["year"] = tahun
    qs = "&".join(f"{k}={v}" for k, v in params.items())
    path = "home/monthly-schedule" + (f"?{qs}" if qs else "")
    data = await _authed_request(path)
    return json.dumps({"data": data}, ensure_ascii=False, default=str)


@tool()
async def edlink_kelas() -> str:
    """Daftar kelas/group yang diikuti di EdLink.

    Sumber: group/academic-lists (terverifikasi mengembalikan semua kelas dengan
    nama, kelas paralel, prodi, fakultas, dan jumlah sesi). Fallback ke group/me
    kalau academic-lists kosong — group/me sendiri terbukti sering balikin array
    kosong walau akun punya kelas aktif.
    """
    data = await _authed_request("group/academic-lists")
    classes = data if isinstance(data, list) else []
    if not classes:
        data = await _authed_request("group/me")
        classes = data.get("data") if isinstance(data, dict) else data
        if not isinstance(classes, list):
            classes = []
    ringkas = []
    for g in classes:
        if not isinstance(g, dict):
            continue
        ringkas.append(
            {
                "groupId": g.get("id"),
                "nama": g.get("name"),
                "kelasParalel": g.get("className"),
                "prodi": (g.get("department") or {}).get("name") if isinstance(g.get("department"), dict) else g.get("departmentId"),
                "jumlahSesi": g.get("sectionsCount"),
            }
        )
    return json.dumps({"jumlah": len(ringkas), "kelas": ringkas}, ensure_ascii=False, default=str)


@tool()
async def edlink_notifikasi(hanya_belum_dibaca: bool = False) -> str:
    """Notifikasi EdLink (notification/all). Set hanya_belum_dibaca=True untuk yang belum dibaca saja."""
    path = "notification/all"
    data = await _authed_request(path)
    if hanya_belum_dibaca and isinstance(data, list):
        data = [n for n in data if isinstance(n, dict) and not n.get("is_read", True)]
    elif hanya_belum_dibaca and isinstance(data, dict):
        items = data.get("data") or data.get("items") or []
        if isinstance(items, list):
            data = [n for n in items if isinstance(n, dict) and not n.get("is_read", True)]
    return json.dumps({"data": data}, ensure_ascii=False, default=str)


@tool()
async def edlink_api(path: str, method: str = "AUTO", body: dict[str, Any] | None = None) -> str:
    """Panggil endpoint EdLink API apa pun secara langsung (advanced).

    path: path di bawah https://api.edlink.id/api/v1.4/ tanpa leading slash,
          contoh 'post/group/123?comment=true', 'user/profile', 'notification/all'.
    method: AUTO (default — coba POST lalu GET), atau paksa POST/GET/PUT/DELETE.
    body: dict JSON untuk POST/PUT.

    Endpoint terpeta dari reverse engineering (contoh yang umum dipakai):
      home/openassignmentsandquizes, home/today-schedule, home/monthly-schedule,
      group/me, group/detail/{id}, post/group/{id}?comment=true, notification/all,
      user/profile, sections/all/{groupId}, learningmaterials/all/{groupId},
      learningmaterials/detail/{id}, lecturer-question/detail-answer/{id},
      lecturer-question/set-answer/{id}, quiz/start/{id}, university/krs/{period}
    """
    if path.startswith("/"):
        path = path.lstrip("/")
    if not path:
        raise ValueError("path tidak boleh kosong")
    if method and method.upper() != "AUTO":
        data = await _authed_request(path, method.upper(), body)
    else:
        data = await _authed_request(path, None, body)
    return json.dumps({"data": data}, ensure_ascii=False, default=str)


@tool()
async def edlink_setup_status() -> str:
    """Cek apakah MCP sudah punya kredensial. Kalau belum, tampilkan pilihan login.

    Panggil ini PERTAMA KALI setelah install. Hasilnya:
    - perlu_setup=false -> sudah siap dipakai.
    - perlu_setup=true  -> ada dua metode: manual (email+password) atau oauth (link Google).
    """
    try:
        creds = _load_credentials()
    except RuntimeError:
        return json.dumps(_setup_prompt(), ensure_ascii=False)
    metode = "token" if "token" in creds else "password"
    return json.dumps(
        {
            "perlu_setup": False,
            "metode": metode,
            "pesan": "Kredensial sudah ada. Panggil edlink_login_status untuk validasi.",
        },
        ensure_ascii=False,
    )


@tool()
async def edlink_login_oauth_link() -> str:
    """Ambil link OAuth Google EdLink (link-based, redirect ke accounts.google.com).

    Setelah login di browser, copy token dari JSON callback lalu simpan dengan
    edlink_setup_token(token).
    """
    return json.dumps(
        {
            "metode": "oauth",
            "link": OAUTH_URL,
            "sifat": "link-based (HTTP 302 ke Google OAuth)",
            "langkah": [
                f"Buka {OAUTH_URL} di browser.",
                "Login dengan akun Google yang terdaftar di EdLink.",
                "Selesai login, browser menampilkan JSON berisi token.",
                "Copy token, lalu panggil edlink_setup_token(token='...').",
            ],
            "fallback": (
                "Kalau yang terbuka halaman EdLink (bukan JSON), buka edlink.id/classes dan "
                "jalankan: copy(helpers.getToken(document.cookie.match(/(?:^|; )token=([^;]+)/)[1]).token)"
            ),
        },
        ensure_ascii=False,
    )


@tool()
async def edlink_setup_oauth() -> str:
    """Buka link OAuth Google EdLink di browser default (link-based).

    Setelah login, copy token dari JSON callback lalu panggil edlink_setup_token(token).
    """
    try:
        opened = bool(webbrowser.open(OAUTH_URL, new=2))
    except Exception:  # noqa: BLE001 — headless/server bisa gagal buka browser
        opened = False
    return json.dumps(
        {
            "metode": "oauth",
            "link": OAUTH_URL,
            "browser_terbuka": opened,
            "langkah": [
                "Login Google di browser yang terbuka.",
                "Setelah callback, copy token dari JSON yang tampil.",
                "Panggil edlink_setup_token(token='...').",
            ],
            "catatan": (
                "Kalau browser tidak terbuka otomatis, buka link di atas manual."
            ),
        },
        ensure_ascii=False,
    )


@tool()
async def edlink_setup_token(token: str) -> str:
    """Simpan token OAuth/manual ke config.json + token_cache.json, setelah divalidasi.

    Pakai setelah login Google lewat edlink_login_oauth_link().
    """
    token = (token or "").strip()
    if not token:
        return json.dumps({"ok": False, "error": "Token kosong."}, ensure_ascii=False)
    try:
        profile = await _edlink_request("user/profile", method="POST", body={}, token=token)
    except Exception as exc:  # noqa: BLE001 — token dari user, lapor apa adanya
        return json.dumps({"ok": False, "error": f"Token tidak valid: {exc}"}, ensure_ascii=False)
    name = profile.get("name") if isinstance(profile, dict) else None
    platform_user = _platform_user_id()
    if platform_user:
        from edlink_platform import store

        store.save_connection(platform_user, "token", token=token)
        _write_token_cache(token, extra={"mode": "token"})
        return json.dumps(
            {"ok": True, "metode": "token", "user": name, "penyimpanan": "akun platform"},
            ensure_ascii=False,
        )
    CONFIG_PATH.write_text(
        json.dumps(
            {
                "token": token,
                "note": "Token EdLink (OAuth/manual). Kalau expired, ulangi edlink_login_oauth_link.",
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    _write_token_cache(token, extra={"mode": "token"})
    return json.dumps(
        {"ok": True, "metode": "token", "user": name, "config": str(CONFIG_PATH)},
        ensure_ascii=False,
    )


@tool()
async def edlink_setup_manual(email: str, password: str) -> str:
    """Simpan kredensial email+password EdLink, login sekali untuk verifikasi.

    Pakai kalau user memilih metode manual (bukan OAuth).
    """
    email = (email or "").strip()
    if not email or not password:
        return json.dumps(
            {"ok": False, "error": "Email dan password wajib diisi."},
            ensure_ascii=False,
        )
    payload = {
        "username": "",
        "app_id": "",
        "email": email,
        "password": password,
        "web_reg_id": None,
        "device": _load_device(),
    }
    try:
        result = await _edlink_request("site/login", method="POST", body=payload)
        token = _extract_token(result)
    except Exception as exc:  # noqa: BLE001 — kredensial dari user, lapor apa adanya
        return json.dumps({"ok": False, "error": f"Login manual gagal: {exc}"}, ensure_ascii=False)
    platform_user = _platform_user_id()
    if platform_user:
        from edlink_platform import store

        store.save_connection(
            platform_user,
            "password",
            email=email,
            password=password,
            device=_load_device(),
        )
        _write_token_cache(token, extra={"mode": "password"})
        return json.dumps(
            {"ok": True, "metode": "password", "email": email, "penyimpanan": "akun platform"},
            ensure_ascii=False,
        )
    CONFIG_PATH.write_text(
        json.dumps(
            {
                "email": email,
                "password": password,
                "note": "Kredensial EdLink mode manual (email+password).",
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    _write_token_cache(token, extra={"mode": "password"})
    return json.dumps(
        {
            "ok": True,
            "metode": "password",
            "email": email,
            "token_tersimpan": True,
            "config": str(CONFIG_PATH),
        },
        ensure_ascii=False,
    )


@tool()
async def edlink_login_status() -> str:
    """Cek status kredensial & token: validasi token dengan memanggil user/profile.

    Pakai ini kalau user mau memastikan akun EdLink terhubung, atau setelah mengganti config.json.
    Kalau belum ada kredensial, tool ini mengembalikan pilihan setup manual/oauth.
    """
    try:
        creds = _load_credentials()
    except RuntimeError as exc:
        prompt = _setup_prompt()
        prompt["ok"] = False
        prompt["error"] = str(exc)
        return json.dumps(prompt, ensure_ascii=False)
    try:
        if "token" in creds:
            profile = await _edlink_request(
                "user/profile", method="POST", body={}, token=creds["token"]
            )
            name = profile.get("name") if isinstance(profile, dict) else None
            return json.dumps(
                {"ok": True, "mode": "token (Google/manual)", "user": name},
                ensure_ascii=False,
            )
        token = await _login()
        masked = token[:8] + "..." if len(token) > 8 else token
        return json.dumps(
            {"ok": True, "mode": "password", "email": creds["email"], "token_preview": masked},
            ensure_ascii=False,
        )
    except Exception as exc:  # noqa: BLE001 — lapor apa pun dari API apa adanya
        return json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False)


# ------------------------------------------------------------------ main ---

if __name__ == "__main__":
    if _TRANSPORT in ("http", "streamable-http"):
        mcp.run(transport="streamable-http")
    else:
        mcp.run(transport="stdio")
