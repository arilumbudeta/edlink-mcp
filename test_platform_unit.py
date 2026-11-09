"""Unit test inti platform — tanpa jaringan, tanpa server.

Menguji enkripsi, hashing password, isolasi penyimpanan per user, PKCE,
pencabutan token, rate limit, dan guard path upload.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="edlink-platform-test-")
os.environ["EDLINK_PLATFORM_DB"] = str(Path(_TMP) / "test.db")
os.environ["EDLINK_PLATFORM_KEY_FILE"] = str(Path(_TMP) / "test.key")

from edlink_platform import crypto, db, identity, security, store  # noqa: E402


class CryptoAndStorageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        db.init_db()

    def setUp(self) -> None:
        suffix = db.new_id()
        self.user_a = security.create_user(f"a{suffix}@example.test", "password-aaaa-1")
        self.user_b = security.create_user(f"b{suffix}@example.test", "password-bbbb-2")
        self.email_a = f"a{suffix}@example.test"

    def test_encrypt_roundtrip(self) -> None:
        secret = "token-rahasia-123"
        blob = crypto.encrypt(secret)
        self.assertNotIn(secret, blob)
        self.assertEqual(crypto.decrypt(blob), secret)

    def test_empty_encrypt_is_empty(self) -> None:
        self.assertEqual(crypto.encrypt(""), "")
        self.assertEqual(crypto.decrypt(""), "")

    def test_password_hash_is_not_plaintext(self) -> None:
        user = security.find_user_by_email(self.email_a)
        self.assertNotIn("password-aaaa-1", user["password_hash"])
        self.assertTrue(user["password_hash"].startswith("$argon2id$"))

    def test_verify_password(self) -> None:
        user = security.find_user_by_email(self.email_a)
        self.assertTrue(security.verify_password(user["password_hash"], "password-aaaa-1"))
        self.assertFalse(security.verify_password(user["password_hash"], "salah"))

    def test_authenticate_wrong_password(self) -> None:
        user, reason = security.authenticate(self.email_a, "salah-password")
        self.assertIsNone(user)
        self.assertTrue(reason)

    def test_duplicate_email_rejected_by_db(self) -> None:
        import sqlite3

        with self.assertRaises(sqlite3.IntegrityError):
            security.create_user(self.email_a, "password-cccc-3")

    def test_token_encrypted_at_rest(self) -> None:
        store.save_connection(self.user_a, "token", token="edlink-token-aaaaaaaaaa")
        raw = db.q1("SELECT token_enc FROM edlink_connections WHERE user_id=?", (self.user_a,))
        self.assertNotIn("edlink-token-aaaaaaaaaa", raw["token_enc"])
        self.assertEqual(store.load_credentials(self.user_a)["token"], "edlink-token-aaaaaaaaaa")

    def test_password_mode_roundtrip(self) -> None:
        store.save_connection(self.user_b, "password", email="b@edlink.test", password="pw-secret-1")
        creds = store.load_credentials(self.user_b)
        self.assertEqual(creds, {"email": "b@edlink.test", "password": "pw-secret-1"})
        raw = db.q1("SELECT email_enc, password_enc FROM edlink_connections WHERE user_id=?", (self.user_b,))
        self.assertNotIn("pw-secret-1", raw["password_enc"])
        self.assertNotIn("b@edlink.test", raw["email_enc"])

    def test_user_isolation_of_connection(self) -> None:
        store.save_connection(self.user_a, "token", token="token-milik-a")
        self.assertFalse(store.has_connection(self.user_b))
        with self.assertRaises(store.NoConnection):
            store.load_credentials(self.user_b)

    def test_disconnect_removes_only_that_user(self) -> None:
        store.save_connection(self.user_a, "token", token="token-a")
        store.save_connection(self.user_b, "token", token="token-b")
        self.assertTrue(store.disconnect(self.user_a))
        self.assertFalse(store.has_connection(self.user_a))
        self.assertTrue(store.has_connection(self.user_b))

    def test_summary_never_leaks_secret(self) -> None:
        store.save_connection(self.user_a, "password", email="x@y.test", password="pwpwpwpw12")
        info = store.summary(self.user_a)
        self.assertTrue(info["connected"])
        self.assertNotIn("pwpwpwpw12", str(info))

    def test_token_cache_expires(self) -> None:
        store.save_connection(self.user_a, "token", token="cache-token-x")
        with db.tx() as conn:
            conn.execute(
                "UPDATE edlink_connections SET saved_at=? WHERE user_id=?",
                (db.now() - store.TOKEN_MAX_AGE - 10, self.user_a),
            )
        self.assertIsNone(store.read_token_cache(self.user_a))

    def test_device_is_stable_per_user(self) -> None:
        store.save_connection(self.user_a, "token", token="t")
        first = store.load_device(self.user_a)
        second = store.load_device(self.user_a)
        self.assertEqual(first["secureId"], second["secureId"])


class TokenAndSessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        db.init_db()

    def setUp(self) -> None:
        self.user = security.create_user(f"t{db.new_id()}@example.test", "password-zzzz-9")

    def test_mcp_token_lifecycle(self) -> None:
        raw = security.create_mcp_token(self.user)
        row = security.token_user(raw)
        self.assertIsNotNone(row)
        self.assertEqual(row["user_id"], self.user)
        security.revoke_mcp_tokens(self.user)
        self.assertIsNone(security.token_user(raw))

    def test_mcp_token_not_stored_plaintext(self) -> None:
        raw = security.create_mcp_token(self.user)
        row = db.q1("SELECT token_hash FROM mcp_tokens WHERE user_id=?", (self.user,))
        self.assertNotEqual(row["token_hash"], raw)
        self.assertEqual(row["token_hash"], security.sha256_hex(raw))

    def test_expired_token_rejected(self) -> None:
        raw = security.create_mcp_token(self.user, ttl=-10)
        self.assertIsNone(security.token_user(raw))

    def test_suspended_user_token_rejected(self) -> None:
        raw = security.create_mcp_token(self.user)
        with db.tx() as conn:
            conn.execute("UPDATE users SET status='suspended' WHERE id=?", (self.user,))
        self.assertIsNone(security.token_user(raw))

    def test_session_lifecycle(self) -> None:
        sid = security.create_session(self.user)
        row = security.session_user(sid)
        self.assertIsNotNone(row)
        security.revoke_session(sid)
        self.assertIsNone(security.session_user(sid))

    def test_session_stored_hashed(self) -> None:
        sid = security.create_session(self.user)
        row = db.q1("SELECT id FROM user_sessions WHERE user_id=? ORDER BY created_at DESC", (self.user,))
        self.assertNotEqual(row["id"], sid)

    def test_unknown_session_rejected(self) -> None:
        self.assertIsNone(security.session_user("tidak-ada"))


class PkceTests(unittest.TestCase):
    def test_valid_pkce(self) -> None:
        import base64
        import hashlib
        import secrets

        verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        self.assertTrue(security.verify_pkce(verifier, challenge))

    def test_wrong_verifier(self) -> None:
        self.assertFalse(security.verify_pkce("salah", "challenge-palsu"))

    def test_plain_method_rejected(self) -> None:
        self.assertFalse(security.verify_pkce("v", "v", method="plain"))


class IdentityTests(unittest.TestCase):
    def test_no_identity_by_default(self) -> None:
        self.assertIsNone(identity.current_user_id())
        with self.assertRaises(RuntimeError):
            identity.require_user_id()

    def test_identity_roundtrip(self) -> None:
        ident = identity.Identity(user_id="usr_x", email="x@y.test", via="mcp")
        token = identity.set_identity(ident)
        try:
            self.assertEqual(identity.current_user_id(), "usr_x")
            self.assertEqual(identity.require_user_id(), "usr_x")
        finally:
            identity.reset_identity(token)
        self.assertIsNone(identity.current_user_id())


class UploadGuardTests(unittest.TestCase):
    """edlink_upload_file di mode platform tidak boleh membaca file server."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="edlink-upload-")
        self._old = os.environ.get("EDLINK_PLATFORM_UPLOAD_DIR")
        os.environ["EDLINK_PLATFORM_UPLOAD_DIR"] = self.tmp

    def tearDown(self) -> None:
        if self._old is None:
            os.environ.pop("EDLINK_PLATFORM_UPLOAD_DIR", None)
        else:
            os.environ["EDLINK_PLATFORM_UPLOAD_DIR"] = self._old

    def test_absolute_path_escape_rejected(self) -> None:
        import asyncio
        import json as jsonlib

        import edlink_mcp

        ident = identity.Identity(user_id="usr_guard", email="g@y.test", via="mcp")
        token = identity.set_identity(ident)
        try:
            target = str(Path(self.tmp).parent / "secret.txt")
            Path(target).write_text("secret", encoding="utf-8")
            out = asyncio.run(edlink_mcp.edlink_upload_file(path=target))
            payload = jsonlib.loads(out)
            self.assertFalse(payload["ok"])
            self.assertIn("platform", out.lower())
        finally:
            identity.reset_identity(token)

    def test_relative_name_inside_root_allowed(self) -> None:
        # File tidak ada → pesan "tidak ditemukan", bukan penolakan path.
        import asyncio
        import json as jsonlib

        import edlink_mcp

        ident = identity.Identity(user_id="usr_guard2", email="g2@y.test", via="mcp")
        token = identity.set_identity(ident)
        try:
            out = asyncio.run(edlink_mcp.edlink_upload_file(path="materi.pdf"))
            payload = jsonlib.loads(out)
            self.assertFalse(payload["ok"])
            self.assertIn("tidak ditemukan", payload["error"].lower())
        finally:
            identity.reset_identity(token)


class RefreshTokenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        db.init_db()

    def setUp(self) -> None:
        self.user = security.create_user(f"r{db.new_id()}@example.test", "password-rrrr-4")

    def test_refresh_token_stored_hashed(self) -> None:
        raw = security.create_refresh_token(self.user, client_id="edc_x")
        row = db.q1("SELECT token_hash FROM oauth_refresh_tokens WHERE token_hash=?", (security.sha256_hex(raw),))
        self.assertIsNotNone(row)
        self.assertNotEqual(row["token_hash"], raw)
        self.assertNotIn(raw, str(dict(row)))

    def test_refresh_token_row_lookup(self) -> None:
        raw = security.create_refresh_token(self.user, client_id="edc_x", scope="edlink.read")
        row = security.refresh_token_row(raw)
        self.assertIsNotNone(row)
        self.assertEqual(row["user_id"], self.user)

    def test_rotate_marks_used_and_blocks_replay(self) -> None:
        raw = security.create_refresh_token(self.user)
        self.assertTrue(security.rotate_refresh_token(raw))
        self.assertFalse(security.rotate_refresh_token(raw))
        self.assertIsNone(security.refresh_token_row(raw))

    def test_expired_refresh_token_rejected(self) -> None:
        raw = security.create_refresh_token(self.user, ttl=-5)
        self.assertIsNone(security.refresh_token_row(raw))

    def test_suspended_user_refresh_rejected(self) -> None:
        raw = security.create_refresh_token(self.user)
        with db.tx() as conn:
            conn.execute("UPDATE users SET status='suspended' WHERE id=?", (self.user,))
        self.assertIsNone(security.refresh_token_row(raw))

    def test_revoke_all_refresh_tokens(self) -> None:
        first = security.create_refresh_token(self.user)
        second = security.create_refresh_token(self.user)
        self.assertEqual(security.revoke_refresh_tokens(self.user), 2)
        self.assertIsNone(security.refresh_token_row(first))
        self.assertIsNone(security.refresh_token_row(second))


class SetupPromptTests(unittest.TestCase):
    """Prompt setup harus berbeda di mode platform: tanpa config.json bersama."""

    def tearDown(self) -> None:
        os.environ.pop("EDLINK_PLATFORM_BASE_URL", None)

    def test_stdio_prompt_unchanged(self) -> None:
        import edlink_mcp

        prompt = edlink_mcp._setup_prompt()
        self.assertTrue(prompt["perlu_setup"])
        self.assertIn("pilih_salah_satu", prompt)
        self.assertEqual(len(prompt["pilih_salah_satu"]), 2)

    def test_platform_prompt_points_to_dashboard(self) -> None:
        import edlink_mcp

        os.environ["EDLINK_PLATFORM_BASE_URL"] = "https://example.test"
        ident = identity.Identity(user_id="usr_setup", email="s@example.test", via="mcp")
        token = identity.set_identity(ident)
        try:
            prompt = edlink_mcp._setup_prompt()
        finally:
            identity.reset_identity(token)

        self.assertEqual(prompt["metode"], "platform")
        self.assertNotIn("pilih_salah_satu", prompt)
        self.assertIn("https://example.test/dashboard", " ".join(prompt["langkah"]))
        self.assertIn("Jangan menempel", prompt["catatan"])


class CredentialModeTests(unittest.TestCase):
    """Mode password tidak boleh dilaporkan sebagai mode token gara-gara cache."""

    @classmethod
    def setUpClass(cls) -> None:
        db.init_db()

    def test_password_mode_wins_over_cached_token(self) -> None:
        uid = security.create_user(f"c{db.new_id()}@example.test", "password-cccc-1")
        store.save_connection(uid, "password", email="ed@x.test", password="ed-pass")
        store.write_token_cache(uid, "t" * 96, extra={"mode": "password"})
        creds = store.load_credentials(uid)
        self.assertEqual(creds.get("email"), "ed@x.test")
        self.assertIn("password", creds)
        self.assertNotIn("token", creds)

    def test_token_mode_returns_token(self) -> None:
        uid = security.create_user(f"d{db.new_id()}@example.test", "password-dddd-1")
        store.save_connection(uid, "token", token="pasted-token-value-1234567890")
        self.assertEqual(store.load_credentials(uid), {"token": "pasted-token-value-1234567890"})


class EdLinkLoginShapeTests(unittest.TestCase):
    """Bentuk response login EdLink (per Nov 2026: data.userToken.token)."""

    def test_token_nested_in_user_token(self) -> None:
        import edlink_mcp

        token = "7" * 96
        payload = {"data": {"id": 1, "userToken": {"token": token}}, "applicationSystem": None}
        self.assertEqual(edlink_mcp._extract_token(payload), token)

    def test_token_at_top_level_still_works(self) -> None:
        import edlink_mcp

        token = "a" * 40
        self.assertEqual(edlink_mcp._extract_token({"data": {"token": token}}), token)

    def test_missing_token_error_does_not_leak_payload(self) -> None:
        import edlink_mcp

        secret = "sup3r-s3cret-value-abcdef"
        with self.assertRaises(RuntimeError) as ctx:
            edlink_mcp._extract_token({"data": {"name": secret, "email": "x@y.test"}})
        self.assertNotIn(secret, str(ctx.exception))
        self.assertIn("Kunci yang ada", str(ctx.exception))

    def test_login_does_not_send_device(self) -> None:
        """EdLink 500 untuk device dict; _login wajib tidak mengirimkannya."""
        import asyncio

        import edlink_mcp

        seen: dict[str, object] = {}

        async def fake(path, method="POST", body=None, token=None):
            seen["path"] = path
            seen["body"] = dict(body or {})
            return {"data": {"userToken": {"token": "z" * 96}}}

        original_request = edlink_mcp._edlink_request_payload
        original_creds = edlink_mcp._load_credentials
        original_cache = edlink_mcp._write_token_cache
        edlink_mcp._edlink_request_payload = fake  # type: ignore[assignment]
        edlink_mcp._load_credentials = lambda: {"email": "e@x.test", "password": "p"}  # type: ignore[assignment]
        edlink_mcp._write_token_cache = lambda *a, **k: None  # type: ignore[assignment]
        try:
            token = asyncio.run(edlink_mcp._login())
        finally:
            edlink_mcp._edlink_request_payload = original_request  # type: ignore[assignment]
            edlink_mcp._load_credentials = original_creds  # type: ignore[assignment]
            edlink_mcp._write_token_cache = original_cache  # type: ignore[assignment]

        self.assertEqual(token, "z" * 96)
        self.assertEqual(seen["path"], "site/login")
        self.assertNotIn("device", seen["body"])


class MateriToolTests(unittest.TestCase):
    """Helper unduhan & ekstraksi teks (tanpa jaringan)."""

    def test_download_url_allowlist(self) -> None:
        import edlink_mcp

        ok = "https://storage.googleapis.com/assets-edlink/p/x.backup"
        self.assertEqual(edlink_mcp._validate_download_url(ok), ok)
        for bad in (
            "http://storage.googleapis.com/x",
            "https://evil.example/x",
            "https://storage.googleapis.com:8443/x",
            "https://user:pw@storage.googleapis.com/x",
        ):
            with self.assertRaises(ValueError):
                edlink_mcp._validate_download_url(bad)

    def test_parse_pages(self) -> None:
        import edlink_mcp

        self.assertEqual(edlink_mcp._parse_pages("1-3,5", 10), [0, 1, 2, 4])
        self.assertEqual(edlink_mcp._parse_pages("7", 5), [0, 1, 2, 3, 4])
        self.assertEqual(edlink_mcp._parse_pages("", 3), [0, 1, 2])

    def test_magic_bytes(self) -> None:
        import edlink_mcp

        self.assertTrue(edlink_mcp._magic_ok(b"%PDF-1.7\n", "pdf"))
        self.assertTrue(edlink_mcp._magic_ok(b"PK\x03\x04rest", "xlsx"))
        self.assertFalse(edlink_mcp._magic_ok(b"<html>", "pdf"))
        self.assertTrue(edlink_mcp._magic_ok(b"anything", "txt"))

    def test_media_file_urls_order(self) -> None:
        import edlink_mcp

        media = {
            "file": {"link": "https://storage.googleapis.com/a.pdf"},
            "values": {"downloadLink": "https://drive.google.com/b"},
        }
        kinds = [kind for kind, _ in edlink_mcp._media_file_urls(media)]
        self.assertEqual(kinds, ["gcs", "drive"])
        self.assertEqual(edlink_mcp._media_file_urls({}), [])

    def test_extract_xlsx(self) -> None:
        import io as _io

        from openpyxl import Workbook

        import edlink_mcp

        wb = Workbook()
        ws = wb.active
        ws["A1"] = "p"
        ws["B1"] = "p ^ q"
        ws["A2"] = "T"
        ws["B2"] = "T"
        buf = _io.BytesIO()
        wb.save(buf)

        text, info = edlink_mcp._extract_text(buf.getvalue(), "xlsx", "1-5", "t.xlsx")
        self.assertIn("p ^ q", text)
        self.assertEqual(info.get("sheet"), ["Sheet"])


if __name__ == "__main__":
    unittest.main()
