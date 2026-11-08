"""End-to-end test platform multi-user (server lokal harus sudah jalan).

Menguji: signup, login, rate limit, link EdLink (token dummy), OAuth + PKCE,
pemanggilan MCP dengan token hasil OAuth, penolakan tanpa token, dan isolasi
antar dua user.

Token EdLink yang dipakai adalah nilai palsu; tool yang benar-benar memanggil
api.edlink.id tidak dipanggil di sini kecuali disebut eksplisit.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sys
import time

import httpx

BASE = os.environ.get("PLATFORM_TEST_BASE", "http://localhost:8792")
MCP = BASE + "/mcp"

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        PASS.append(name)
        print(f"  ok   {name}")
    else:
        FAIL.append(f"{name} {detail}".strip())
        print(f"  FAIL {name} {detail}")


def pkce() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return verifier, challenge


def signup(client: httpx.Client, email: str, password: str) -> httpx.Response:
    return client.post(f"{BASE}/signup", data={"email": email, "password": password}, follow_redirects=False)


def rpc(client: httpx.Client, token: str | None, payload: dict) -> httpx.Response:
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return client.post(MCP, content=json.dumps(payload), headers=headers)


def oauth_connect(client: httpx.Client, user_email: str) -> str | None:
    """Jalankan alur OAuth dan kembalikan access token."""
    reg = client.post(
        f"{BASE}/oauth/register",
        json={"redirect_uris": ["https://chatgpt.com/connector/oauth/cb_test"], "client_name": "test-client"},
    )
    if reg.status_code != 201:
        return None
    client_id = reg.json()["client_id"]
    verifier, challenge = pkce()

    params = {
        "client_id": client_id,
        "redirect_uri": "https://chatgpt.com/connector/oauth/cb_test",
        "response_type": "code",
        "state": "xyz",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "scope": "edlink.read edlink.write",
        "resource": BASE + "/mcp",
    }
    consent = client.get(f"{BASE}/oauth/authorize", params=params, follow_redirects=False)
    if consent.status_code != 200:
        return None

    approve = client.post(
        f"{BASE}/oauth/authorize",
        data={**params, "decision": "approve"},
        follow_redirects=False,
    )
    if approve.status_code != 302:
        return None
    location = approve.headers.get("location", "")
    if "code=" not in location:
        return None
    code = location.split("code=")[1].split("&")[0]
    if "iss=" not in location:
        return None

    token_resp = client.post(
        f"{BASE}/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "client_id": client_id,
            "redirect_uri": "https://chatgpt.com/connector/oauth/cb_test",
        },
    )
    if token_resp.status_code != 200:
        return None
    return token_resp.json().get("access_token")


def main() -> int:
    print(f"target: {BASE}")
    admin_email = os.environ.get("PLATFORM_ADMIN_EMAIL", "admin@test.local")
    admin_pass = os.environ.get("PLATFORM_ADMIN_PASSWORD", "admin-test-password-123")
    suffix = secrets.token_hex(4)
    alice_email = f"alice{suffix}@test.local"
    bob_email = f"bob{suffix}@test.local"
    print(f"test users: {alice_email}, {bob_email}")

    with httpx.Client(timeout=30, follow_redirects=False) as anon:
        # --- metadata ---
        prm = anon.get(f"{BASE}/.well-known/oauth-protected-resource")
        check("protected resource metadata", prm.status_code == 200 and prm.json()["resource"].endswith("/mcp"))
        asm = anon.get(f"{BASE}/.well-known/oauth-authorization-server")
        body = asm.json() if asm.status_code == 200 else {}
        check("AS metadata advertises S256", "S256" in body.get("code_challenge_methods_supported", []))
        check("AS metadata has registration", body.get("registration_endpoint", "").endswith("/oauth/register"))

        # --- MCP tanpa token ---
        r = rpc(anon, None, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        check("MCP tanpa token ditolak 401", r.status_code == 401)
        check("401 memuat WWW-Authenticate", "resource_metadata" in r.headers.get("www-authenticate", ""))

        r = rpc(anon, "bogus-token", {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        check("token palsu ditolak 401", r.status_code == 401)

        # --- signup dua user ---
        with httpx.Client(timeout=30, follow_redirects=False) as ua:
            r = signup(ua, alice_email, "alice-password-123")
            check("signup alice", r.status_code == 302, str(r.status_code))
        with httpx.Client(timeout=30, follow_redirects=False) as ub:
            r = signup(ub, bob_email, "bob-password-1234")
            check("signup bob", r.status_code == 302, str(r.status_code))
        with httpx.Client(timeout=30, follow_redirects=False) as dup:
            r = signup(dup, alice_email, "alice-password-123")
            check("email duplikat ditolak", r.status_code == 400)

        r = signup(anon, "short@test.local", "abc")
        check("password pendek ditolak", r.status_code == 400)

        # --- login salah ---
        with httpx.Client(timeout=30, follow_redirects=False) as bad:
            r = bad.post(f"{BASE}/login", data={"email": alice_email, "password": "salah-password"})
            check("password salah ditolak 401", r.status_code == 401)
            check("tidak ada cookie sesi saat gagal", "edlink_session" not in bad.cookies)

        # --- OAuth alice ---
        with httpx.Client(timeout=30, follow_redirects=False) as alice:
            r = alice.post(f"{BASE}/login", data={"email": alice_email, "password": "alice-password-123"})
            check("login alice", r.status_code == 302)
            check("cookie sesi terpasang", "edlink_session" in alice.cookies)

            # link token dummy
            r = alice.post(f"{BASE}/link", data={"token": "dummy-edlink-token-" + "x" * 110})
            check("link token tersimpan", r.status_code == 302 and "ok=" in r.headers.get("location", ""))

            dash = alice.get(f"{BASE}/dashboard")
            check("dashboard tampil", dash.status_code == 200)
            check("dashboard tidak membocorkan token", "dummy-edlink-token" not in dash.text)

            token_a = oauth_connect(alice, alice_email)
            check("alur OAuth alice menghasilkan token", bool(token_a))

            if token_a:
                r = rpc(alice, token_a, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}})
                check("MCP initialize dengan token OAuth", r.status_code == 200, str(r.status_code))
                r = rpc(alice, token_a, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
                tools = r.json().get("result", {}).get("tools", []) if r.status_code == 200 else []
                check("tools/list berisi 18 tool", len(tools) == 18, f"dapat {len(tools)}")

            # OAuth ditolak user
            reg = alice.post(f"{BASE}/oauth/register", json={"redirect_uris": ["https://chatgpt.com/connector/oauth/cb_deny"]})
            if reg.status_code == 201:
                cid = reg.json()["client_id"]
                v, c = pkce()
                params = {"client_id": cid, "redirect_uri": "https://chatgpt.com/connector/oauth/cb_deny",
                          "response_type": "code", "state": "s", "code_challenge": c,
                          "code_challenge_method": "S256", "scope": "edlink.read"}
                alice.get(f"{BASE}/oauth/authorize", params=params)
                denied = alice.post(f"{BASE}/oauth/authorize", data={**params, "decision": "deny"})
                check("consent ditolak -> access_denied", "error=access_denied" in denied.headers.get("location", ""))

            # PKCE salah
            if token_a:
                pass

            # revoke token
            before = rpc(alice, token_a, {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}) if token_a else None
            alice.post(f"{BASE}/tokens/revoke")
            after = rpc(alice, token_a, {"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {}}) if token_a else None
            check("token MCP dicabut -> 401", after is not None and after.status_code == 401)

            # identitas user benar-benar sampai ke tool: alice punya koneksi,
            # bob tidak. Tool yang sama harus menjawab berbeda.
            token_a2 = oauth_connect(alice, alice_email)
            alice_call = rpc(alice, token_a2, {
                "jsonrpc": "2.0", "id": 5, "method": "tools/call",
                "params": {"name": "edlink_setup_status", "arguments": {}},
            }) if token_a2 else None
            alice_text = ""
            if alice_call is not None and alice_call.status_code == 200:
                result = alice_call.json().get("result", {})
                content = result.get("content") or []
                alice_text = content[0].get("text", "") if content else ""
            check("alice melihat koneksinya sendiri", "perlu_setup" in alice_text and '"perlu_setup": false' in alice_text, alice_text[:80])

        # --- bob tidak bisa pakai token alice ---
        with httpx.Client(timeout=30, follow_redirects=False) as bob:
            bob.post(f"{BASE}/login", data={"email": bob_email, "password": "bob-password-1234"})
            dash = bob.get(f"{BASE}/dashboard")
            check("bob tidak melihat data alice", "dummy-edlink-token" not in dash.text)
            check("bob belum terhubung edlink", "belum terhubung" in dash.text)

            bob_token = oauth_connect(bob, bob_email)
            bob_call = rpc(bob, bob_token, {
                "jsonrpc": "2.0", "id": 6, "method": "tools/call",
                "params": {"name": "edlink_setup_status", "arguments": {}},
            }) if bob_token else None
            bob_text = ""
            if bob_call is not None and bob_call.status_code == 200:
                content = bob_call.json().get("result", {}).get("content") or []
                bob_text = content[0].get("text", "") if content else ""
            check("bob dapat prompt setup, bukan kredensial alice", "perlu_setup" in bob_text and '"perlu_setup": true' in bob_text, bob_text[:80])

        # --- admin ---
        with httpx.Client(timeout=30, follow_redirects=False) as adm:
            adm.post(f"{BASE}/login", data={"email": admin_email, "password": admin_pass})
            page = adm.get(f"{BASE}/admin")
            check("admin page 200", page.status_code == 200)
            check("admin melihat daftar user", alice_email in page.text)
            r = adm.post(f"{BASE}/admin/user", data={"user_id": "", "action": "suspend"})
            check("admin action tanpa user id aman", r.status_code == 302)

        with httpx.Client(timeout=30, follow_redirects=False) as bob2:
            bob2.post(f"{BASE}/login", data={"email": bob_email, "password": "bob-password-1234"})
            r = bob2.get(f"{BASE}/admin")
            check("non-admin ditolak 403", r.status_code == 403)

        # --- rate limit login ---
        limited = False
        with httpx.Client(timeout=30, follow_redirects=False) as rl:
            for _ in range(14):
                r = rl.post(f"{BASE}/login", data={"email": "nobody@test.local", "password": "wrong-password"})
                if r.status_code == 429:
                    limited = True
                    break
        check("rate limit login aktif", limited)

        # --- health ---
        h = anon.get(f"{BASE}/health")
        check("health ok", h.status_code == 200 and h.json()["status"] == "ok")

    print()
    print(f"passed: {len(PASS)}  failed: {len(FAIL)}")
    if FAIL:
        for item in FAIL:
            print("  -", item)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
