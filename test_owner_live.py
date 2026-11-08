"""Bukti end-to-end untuk akun pemilik lewat endpoint publik.

Login admin -> OAuth (PKCE) -> tools/call edlink_setup_status -> cabut token.
Tidak mencetak token atau isi kredensial.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sys

import httpx

BASE = os.environ["PLATFORM_TEST_BASE"].rstrip("/")
EMAIL = os.environ["PLATFORM_ADMIN_EMAIL"]
PASSWORD = os.environ["PLATFORM_ADMIN_PASSWORD"]
REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect"


def pkce() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return verifier, base64.urlsafe_b64encode(digest).decode().rstrip("=")


def main() -> int:
    with httpx.Client(timeout=45, follow_redirects=False) as client:
        r = client.post(f"{BASE}/login", data={"email": EMAIL, "password": PASSWORD})
        if r.status_code != 302:
            print("login admin gagal:", r.status_code)
            return 1
        print("login admin: ok")

        # Klien OAuth memakai redirect stabil (klien yang memenuhi RFC 9207).
        reg = client.post(
            f"{BASE}/oauth/register",
            json={"redirect_uris": [REDIRECT], "client_name": "owner-check"},
        )
        if reg.status_code != 201:
            print("registrasi klien gagal:", reg.status_code, reg.text[:120])
            return 1
        client_id = reg.json()["client_id"]

        verifier, challenge = pkce()
        params = {
            "client_id": client_id,
            "redirect_uri": REDIRECT,
            "response_type": "code",
            "state": secrets.token_hex(8),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "edlink.read edlink.write",
            "resource": f"{BASE}/mcp",
        }
        page = client.get(f"{BASE}/oauth/authorize", params=params)
        if page.status_code != 200:
            print("halaman izin gagal:", page.status_code)
            return 1
        approve = client.post(
            f"{BASE}/oauth/authorize", data={**params, "decision": "approve"}
        )
        loc = approve.headers.get("location", "")
        if "code=" not in loc or "iss=" not in loc:
            print("approve gagal:", approve.status_code)
            return 1
        code = loc.split("code=")[1].split("&")[0]

        tok = client.post(
            f"{BASE}/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": verifier,
                "client_id": client_id,
                "redirect_uri": REDIRECT,
                "resource": f"{BASE}/mcp",
            },
        )
        if tok.status_code != 200:
            print("tukar code gagal:", tok.status_code, tok.text[:160])
            return 1
        body = tok.json()
        access = body["access_token"]
        print("token OAuth terbit: ya, refresh_token:", "ya" if body.get("refresh_token") else "tidak")

        headers = {
            "Authorization": f"Bearer {access}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        init = client.post(
            f"{BASE}/mcp",
            headers=headers,
            content=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {"name": "owner-check", "version": "1"},
                    },
                }
            ),
        )
        print("initialize:", init.status_code)
        sid = init.headers.get("mcp-session-id")
        if sid:
            headers["mcp-session-id"] = sid
        client.post(
            f"{BASE}/mcp",
            headers=headers,
            content=json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        )

        call = client.post(
            f"{BASE}/mcp",
            headers=headers,
            content=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "edlink_setup_status", "arguments": {}},
                }
            ),
        )
        text = call.text
        if call.status_code != 200:
            print("tools/call gagal:", call.status_code, text[:160])
            return 1
        payload = json.loads(text)
        content = payload.get("result", {}).get("content") or []
        inner = content[0].get("text", "") if content else ""
        parsed = json.loads(inner) if inner.strip().startswith("{") else {}
        print("tools/call edlink_setup_status: perlu_setup =", parsed.get("perlu_setup"))
        print("metode koneksi:", parsed.get("metode"))

        call2 = client.post(
            f"{BASE}/mcp",
            headers=headers,
            content=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "edlink_login_status", "arguments": {}},
                }
            ),
        )
        if call2.status_code == 200:
            body2 = json.loads(call2.text)
            inner2 = (body2.get("result", {}).get("content") or [{}])[0].get("text", "")
            parsed2 = json.loads(inner2) if inner2.strip().startswith("{") else {}
            print("edlink_login_status: ok =", parsed2.get("ok"), "user =", parsed2.get("user") or parsed2.get("nama"))

        revoke = client.post(f"{BASE}/tokens/revoke")
        print("token dicabut:", revoke.status_code == 302)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
