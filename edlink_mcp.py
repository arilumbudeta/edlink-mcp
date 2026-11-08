"""
EdLink MCP Server — tools untuk akses tugas/jadwal/kelas/notifikasi dari EdLink (edlink.id, SEVIMA).

Endpoint dipetakan dari web app edlink.id & pwa.edlink.id (api.edlink.id/api/v1.4).

Auth flow:
  POST /site/login {username, app_id, email, password, web_reg_id, device}
  -> token dipakai sebagai header Authorization: Bearer <token>

Kredensial dibaca dari (urutan prioritas):
  1. Environment variables  EDLINK_EMAIL / EDLINK_PASSWORD
  2. File config.json       di folder yang sama dengan script ini

Jalankan:  python edlink_mcp.py   (stdio MCP)
"""

import asyncio
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
from mcp.server.mcpserver import MCPServer

SCRIPT_DIR = Path(__file__).resolve().parent
CONFIG_PATH = SCRIPT_DIR / "config.json"
TOKEN_CACHE_PATH = SCRIPT_DIR / "token_cache.json"

API_BASE = "https://api.edlink.id/api/v1.4"
REFERER = "https://edlink.id/login"
REQUEST_TIMEOUT = 30.0
TOKEN_MAX_AGE = 60 * 60 * 8  # cache token maksimal 8 jam sebelum dipakai ulang

mcp = MCPServer("edlink")


# ---------------------------------------------------------------- config ---

def _load_credentials() -> dict[str, str]:
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
        "Kredensial EdLink tidak ditemukan. Isi config.json dengan 'token' "
        "(hasil login Google, lihat README) atau 'email'+'password'."
    )


def _load_device() -> dict[str, Any]:
    """Device fingerprint stabil — disimpan supaya tiap login konsisten."""
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
    payload: dict[str, Any] = {
        "token": token,
        "saved_at": time.time(),
        "device": _load_device(),
    }
    if extra:
        payload.update(extra)
    TOKEN_CACHE_PATH.write_text(json.dumps(payload), encoding="utf-8")


# ------------------------------------------------------------------- api ---

def _extract_token(login_payload: Any) -> str:
    """Token bisa di beberapa field tergantung versi API — cek kandidat umum."""
    candidates = [
        login_payload,
        login_payload.get("data") if isinstance(login_payload, dict) else None,
    ]
    for obj in candidates:
        if not isinstance(obj, dict):
            continue
        for key in ("token", "access_token", "accessToken", "authorization"):
            val = obj.get(key)
            if isinstance(val, str) and val:
                return val
            if isinstance(val, dict) and isinstance(val.get("token"), str):
                return val["token"]
    raise RuntimeError(
        f"Login sukses tapi token tidak ditemukan di response. Struktur response: "
        f"{json.dumps(login_payload)[:500]}"
    )


def _normalize(body: Any, path: str) -> Any:
    """Response EdLink: {"data": ..., "applicationSystem": {message, code}}.
    data==null + code!=0 berarti error -> raise dengan message API-nya.
    code=2 / indikasi sesi habis -> PermissionError (token expired)."""
    if not isinstance(body, dict):
        return body
    data = body.get("data", body)
    app = body.get("applicationSystem") or {}
    message = app.get("message")
    code = app.get("code")
    if data is None and message and code not in (None, 0):
        if code == 2 or "login kembali" in str(message).lower():
            raise PermissionError(f"Token EdLink expired/invalid: {message}")
        raise RuntimeError(f"EdLink API {path}: {message} (code={code})")
    return data


async def _edlink_request(
    path: str,
    method: str = "POST",
    body: dict[str, Any] | None = None,
    token: str | None = None,
) -> Any:
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
        resp = await client.request(method.upper(), url, headers=headers, json=body)
    if resp.status_code in (401, 403):
        raise PermissionError(f"HTTP {resp.status_code}: token invalid/expired")
    try:
        payload = resp.json()
    except ValueError:
        raise RuntimeError(f"HTTP {resp.status_code} bukan JSON: {resp.text[:300]}")
    return _normalize(payload, path)


async def _login() -> str:
    """Dapatkan token: mode 'token' (Google/manual) langsung pakai; mode
    email/password login ke site/login."""
    creds = _load_credentials()
    if "token" in creds:
        _write_token_cache(creds["token"], extra={"mode": "token"})
        return creds["token"]
    device = _load_device()
    payload = {
        "username": "",
        "app_id": "",
        "email": creds["email"],
        "password": creds["password"],
        "web_reg_id": None,
        "device": device,
    }
    result = await _edlink_request("site/login", method="POST", body=payload)
    token = _extract_token(result)
    _write_token_cache(token, extra={"mode": "password"})
    return token


async def _authed_request(path: str, method: str | None = None, body: dict[str, Any] | None = None) -> Any:
    """Request dengan token. Endpoint EdLink kebanyakan POST; kalau route gak
    support method-nya (Laravel: 'Supported methods: ...'), coba method satunya.
    Token invalid/expired di mode password -> login ulang sekali lalu retry."""
    creds_hint = None
    try:
        creds_hint = _load_credentials()
    except RuntimeError:
        pass
    cached = _read_token_cache()
    token = cached.get("token") if cached else None
    mode = (cached or {}).get("mode") or ("token" if creds_hint and "token" in creds_hint else "password")

    async def call(m: str) -> Any:
        if token:
            return await _edlink_request(path, m, body, token=token)
        raise PermissionError("no cached token")

    if method:
        return await call(method.upper())

    # auto-fallback method: POST dulu (default API EdLink), GET kalau route nolak
    try:
        if token:
            return await call("POST")
        token = await _login()
        return await call("POST")
    except RuntimeError as exc:
        if "Supported methods" in str(exc) and "POST" in str(exc):
            return await call("GET")
        raise
    except PermissionError:
        if mode == "token":
            raise RuntimeError(
                "Token EdLink expired. Login ulang di edlink.id (via Google), lalu ambil token "
                "baru: di halaman edlink.id/classes jalankan di console browser: "
                "copy(JSON.parse(atob(document.cookie.split('token=')[1].split(';')[0]) || '{}')) "
                "— atau lebih mudah: jalankan ulang langkah 'Ambil token' di README.md"
            )
        token = await _login()
        return await call("POST")


# ----------------------------------------------------------------- tools ---

@mcp.tool()
async def edlink_tugas() -> str:
    """Daftar tugas & kuis yang masih terbuka/belum dikerjakan di EdLink, beserta deadline dan kelasnya.

    Pakai tool ini setiap kali user bertanya 'ada tugas apa saja?', 'ada tugas gak?',
    'tugas yang belum dikerjakan', 'assignment pending', dan sejenisnya.
    """
    data = await _authed_request("home/openassignmentsandquizes")
    if data is None:
        return json.dumps({"ada_tugas": False, "ringkasan": "Tidak ada tugas/kuis terbuka."}, ensure_ascii=False)
    return json.dumps({"ada_tugas": True, "data": data}, ensure_ascii=False, default=str)


@mcp.tool()
async def edlink_jadwal_hari_ini() -> str:
    """Jadwal kuliah/kelas hari ini dari EdLink (today-schedule)."""
    data = await _authed_request("home/today-schedule")
    return json.dumps({"data": data}, ensure_ascii=False, default=str)


@mcp.tool()
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


@mcp.tool()
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


@mcp.tool()
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


@mcp.tool()
async def edlink_api(path: str, method: str = "GET", body: dict[str, Any] | None = None) -> str:
    """Panggil endpoint EdLink API apa pun secara langsung (advanced).

    path: path di bawah https://api.edlink.id/api/v1.4/ tanpa leading slash,
          contoh 'post/group/123?comment=true', 'user/profile', 'notification/all'.
    method: GET (default), POST, PUT, DELETE.
    body: dict JSON untuk POST/PUT.

    Endpoint terpeta dari reverse engineering (contoh yang umum dipakai):
      home/openassignmentsandquizes, home/today-schedule, home/monthly-schedule,
      group/me, group/detail/{id}, post/group/{id}?comment=true, notification/all,
      user/profile, sections/all/{groupId}, learningmaterials/all/{groupId},
      quiz/start/{id}, university/krs/{period}
    """
    if path.startswith("/"):
        path = path.lstrip("/")
    if not path:
        raise ValueError("path tidak boleh kosong")
    data = await _authed_request(path, method.upper(), body)
    return json.dumps({"data": data}, ensure_ascii=False, default=str)


@mcp.tool()
async def edlink_login_status() -> str:
    """Cek status kredensial & token: validasi token dengan memanggil user/profile.

    Pakai ini kalau user mau memastikan akun EdLink terhubung, atau setelah mengganti config.json.
    """
    try:
        creds = _load_credentials()
    except RuntimeError as exc:
        return json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False)
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
    mcp.run(transport="stdio")
