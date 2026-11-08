"""Regression tests keamanan unduhan materi EdLink.

Tidak butuh kredensial asli dan tidak menyentuh jaringan: semua response
di-mock lewat httpx.MockTransport.
"""
import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import httpx

import edlink_sync_materi as sync


def mock_client(handler) -> httpx.Client:
    return httpx.Client(
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
        headers={"Accept": "*/*", "User-Agent": "edlink-mcp-test/1.0"},
    )


def auth_headers(request: httpx.Request) -> dict[str, str]:
    return {k.lower(): v for k, v in request.headers.items()}


class DownloadSecurityTests(unittest.TestCase):
    def test_download_client_has_no_authorization(self) -> None:
        client = sync.download_client()
        try:
            self.assertNotIn("authorization", {k.lower() for k in client.headers})
        finally:
            client.close()

    def test_download_rejects_authenticated_client(self) -> None:
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(str(request.url))
            return httpx.Response(200, content=b"%PDF-1.4")

        client = mock_client(handler)
        client.headers["Authorization"] = "Bearer secret"
        try:
            with tempfile.TemporaryDirectory() as tmp:
                dest = Path(tmp) / "x.pdf"
                ok = sync.download_media(
                    {"file": {"link": "https://storage.googleapis.com/x.pdf"}, "extension": "pdf"},
                    dest,
                    client=client,
                )
                self.assertFalse(ok)
                self.assertEqual(seen, [])
                self.assertFalse(dest.exists())
        finally:
            client.close()

    def test_external_host_rejected_without_request(self) -> None:
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(str(request.url))
            return httpx.Response(200, content=b"%PDF-1.4")

        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "x.pdf"
            ok = sync.download_media(
                {"file": {"link": "https://evil.example/x.pdf"}, "extension": "pdf"},
                dest,
                client=mock_client(handler),
            )
            self.assertFalse(ok)
            self.assertEqual(seen, [])
            self.assertFalse(dest.exists())

    def test_unsupported_scheme_rejected(self) -> None:
        for url in (
            "http://storage.googleapis.com/x.pdf",
            "file:///tmp/x.pdf",
            "ftp://storage.googleapis.com/x.pdf",
        ):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    sync.validate_download_url(url)

    def test_legit_gcs_download_without_auth(self) -> None:
        headers_seen: list[dict[str, str]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            headers_seen.append(auth_headers(request))
            return httpx.Response(200, content=b"%PDF-1.4\n%mock")

        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "materi.pdf"
            ok = sync.download_media(
                {
                    "file": {"link": "https://storage.googleapis.com/assets-edlink/materi.pdf"},
                    "extension": "pdf",
                },
                dest,
                client=mock_client(handler),
            )
            self.assertTrue(ok)
            self.assertTrue(dest.exists())
            self.assertEqual(dest.read_bytes()[:4], b"%PDF")
            self.assertTrue(headers_seen)
            for headers in headers_seen:
                self.assertNotIn("authorization", headers)

    def test_redirect_to_untrusted_host_rejected(self) -> None:
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(str(request.url))
            if request.url.host == "storage.googleapis.com":
                return httpx.Response(
                    302, headers={"location": "https://evil.example/x.pdf"}
                )
            return httpx.Response(200, content=b"%PDF-1.4")

        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "x.pdf"
            ok = sync.download_media(
                {"file": {"link": "https://storage.googleapis.com/x.pdf"}, "extension": "pdf"},
                dest,
                client=mock_client(handler),
            )
            self.assertFalse(ok)
            self.assertEqual(len(seen), 1)
            self.assertNotIn("evil.example", " ".join(seen))

    def test_redirect_to_allowed_host_no_auth(self) -> None:
        headers_seen: list[dict[str, str]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            headers_seen.append(auth_headers(request))
            if request.url.host == "storage.googleapis.com":
                return httpx.Response(
                    302,
                    headers={"location": "https://drive.usercontent.google.com/download?id=x"},
                )
            return httpx.Response(200, content=b"%PDF-1.4")

        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "x.pdf"
            ok = sync.download_media(
                {"file": {"link": "https://storage.googleapis.com/x.pdf"}, "extension": "pdf"},
                dest,
                client=mock_client(handler),
            )
            self.assertTrue(ok)
            self.assertEqual(len(headers_seen), 2)
            for headers in headers_seen:
                self.assertNotIn("authorization", headers)

    def test_gcs_403_falls_back_to_drive(self) -> None:
        hosts: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            hosts.append(request.url.host)
            if request.url.host == "storage.googleapis.com":
                return httpx.Response(403)
            return httpx.Response(200, content=b"%PDF-1.4")

        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "x.pdf"
            ok = sync.download_media(
                {
                    "file": {"link": "https://storage.googleapis.com/x.pdf"},
                    "values": {"downloadLink": "https://drive.google.com/file/d/abc"},
                    "extension": "pdf",
                },
                dest,
                client=mock_client(handler),
            )
            self.assertTrue(ok)
            self.assertEqual(hosts, ["storage.googleapis.com", "drive.google.com"])

    def test_drive_interstitial_download(self) -> None:
        hosts: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            hosts.append(request.url.host)
            if request.url.host == "drive.google.com":
                html = (
                    '<html><body><form action="https://drive.usercontent.google.com/download">'
                    '<input name="id" value="abc">'
                    '<input name="export" value="download">'
                    "</form></body></html>"
                )
                return httpx.Response(200, content=html.encode())
            if request.url.host == "drive.usercontent.google.com":
                return httpx.Response(200, content=b"%PDF-1.4\n%mock")
            return httpx.Response(404)

        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "drive.pdf"
            ok = sync.download_media(
                {
                    "values": {"downloadLink": "https://drive.google.com/file/d/abc"},
                    "extension": "pdf",
                },
                dest,
                client=mock_client(handler),
            )
            self.assertTrue(ok)
            self.assertEqual(hosts, ["drive.google.com", "drive.usercontent.google.com"])
            self.assertEqual(dest.read_bytes()[:4], b"%PDF")

    def test_api_redirect_not_followed(self) -> None:
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(str(request.url))
            return httpx.Response(
                302, headers={"location": "https://evil.example/steal"}
            )

        client = httpx.Client(
            transport=httpx.MockTransport(handler),
            follow_redirects=False,
            headers={"Authorization": "Bearer test-token"},
        )
        try:
            with patch.object(sync, "get_session", return_value=client):
                with self.assertRaises(RuntimeError):
                    sync.api("test")
        finally:
            client.close()
        self.assertEqual(seen, ["https://api.edlink.id/api/v1.4/test"])


class DirectoryAndDuplicateTests(unittest.TestCase):
    def test_resolve_kuliah_dir_env_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {"EDLINK_KULIAH_DIR": tmp}):
                self.assertEqual(sync.resolve_kuliah_dir(), Path(tmp))

    def test_resolve_kuliah_dir_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {}, clear=True):
                with patch("pathlib.Path.home", return_value=Path(tmp)):
                    self.assertEqual(
                        sync.resolve_kuliah_dir(),
                        Path(tmp) / "Documents" / "Kuliah",
                    )

    def test_ensure_dir_creates_parents(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "a" / "b" / "c"
            sync.ensure_dir(target)
            self.assertTrue(target.is_dir())

    def test_same_filename_in_different_sessions_both_downloaded(self) -> None:
        sections = [
            {
                "meet": 1,
                "type": 0,
                "materials": [
                    {
                        "title": "Materi",
                        "medias": [
                            {
                                "id": 1,
                                "name": "file.pdf",
                                "file": {"link": "https://storage.googleapis.com/a.pdf"},
                            }
                        ],
                    }
                ],
            },
            {
                "meet": 2,
                "type": 0,
                "materials": [
                    {
                        "title": "Materi",
                        "medias": [
                            {
                                "id": 2,
                                "name": "file.pdf",
                                "file": {"link": "https://storage.googleapis.com/b.pdf"},
                            }
                        ],
                    }
                ],
            },
        ]
        calls = []

        def fake_download(media, dest):
            calls.append(str(dest))
            dest.write_bytes(b"%PDF-1.4")
            return True

        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(sync, "CLASSES", {1: ("Kelas", "Pertemuan {meet}")}):
                with patch.object(sync, "KULIAH", Path(tmp)):
                    with patch.object(sync, "api", return_value=sections):
                        with patch.object(sync, "download_media", side_effect=fake_download):
                            with redirect_stdout(io.StringIO()):
                                sync.main()
            self.assertTrue((Path(tmp) / "Kelas" / "Pertemuan 1" / "file.pdf").exists())
            self.assertTrue((Path(tmp) / "Kelas" / "Pertemuan 2" / "file.pdf").exists())
            self.assertEqual(len(calls), 2)

    def test_existing_exact_destination_skipped_and_not_overwritten(self) -> None:
        existing = None
        sections = [
            {
                "meet": 1,
                "type": 0,
                "materials": [
                    {
                        "title": "Materi",
                        "medias": [
                            {
                                "id": 1,
                                "name": "file.pdf",
                                "file": {"link": "https://storage.googleapis.com/a.pdf"},
                            }
                        ],
                    }
                ],
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            existing = Path(tmp) / "Kelas" / "Pertemuan 1" / "file.pdf"
            existing.parent.mkdir(parents=True)
            existing.write_bytes(b"OLD")
            with patch.object(sync, "CLASSES", {1: ("Kelas", "Pertemuan {meet}")}):
                with patch.object(sync, "KULIAH", Path(tmp)):
                    with patch.object(sync, "api", return_value=sections):
                        with patch.object(sync, "download_media") as download:
                            with redirect_stdout(io.StringIO()):
                                sync.main()
            download.assert_not_called()
            self.assertEqual(existing.read_bytes(), b"OLD")


if __name__ == "__main__":
    unittest.main()
