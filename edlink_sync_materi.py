"""Unduh semua materi EdLink ke folder Kuliah (default: ~/Documents/Kuliah,
bisa dioverride lewat env EDLINK_KULIAH_DIR), satu folder per sesi,
mengikuti konvensi lokal yang sudah ada.

Sumber token: token_cache.json (sama dengan yang dipakai edlink_mcp.py).
File materi diunduh lewat klien TANPA Authorization; token hanya dipakai untuk
request ke API EdLink. Host unduhan dibatasi allowlist.
"""
import html as html_lib
import json
import os
import re
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx

EDLINK_DIR = Path(__file__).resolve().parent
API_BASE = "https://api.edlink.id/api/v1.4"

# Host yang boleh dihubungi untuk unduhan materi. Diverifikasi dari URL yang
# dikembalikan API EdLink: storage.googleapis.com/assets-edlink/... untuk GCS,
# drive.google.com untuk downloadLink Google Drive, dan
# drive.usercontent.google.com sebagai tujuan redirect unduhan Drive.
ALLOWED_DOWNLOAD_HOSTS = {
    "storage.googleapis.com",
    "drive.google.com",
    "drive.usercontent.google.com",
}
ALLOWED_DOWNLOAD_SCHEMES = {"https"}

# kelas -> (nama folder lokal, template folder sesi)
CLASSES = {
    2247265: ("Algoritma Pemrograman", "Pertemuan {meet}"),
    2224297: ("Pengantar Informatika", "Pertemuan {meet}"),
    2224607: ("Statistika", "Pertemuan {meet}"),
    2263993: ("Aljabar Linier", "SESI {meet:02d}"),
    2326974: ("Agama", "Pertemuan {meet}"),
    2224558: ("Logika Matematika", "Pertemuan {meet}"),
    2226879: ("Bahasa Jepang", "Pertemuan {meet}"),
}

SPECIAL_TYPE = {1: "UTS", 2: "UAS"}  # tipe section selain kuliah biasa


def resolve_kuliah_dir() -> Path:
    """Folder tujuan materi: env EDLINK_KULIAH_DIR, atau ~/Documents/Kuliah."""
    raw = os.environ.get("EDLINK_KULIAH_DIR") or (Path.home() / "Documents" / "Kuliah")
    return Path(raw).expanduser()


KULIAH = resolve_kuliah_dir()

_TOKEN: str | None = None
_SESSION: httpx.Client | None = None


def load_token() -> str:
    cache = json.loads((EDLINK_DIR / "token_cache.json").read_text(encoding="utf-8"))
    token = str(cache.get("token", "")).strip()
    if not token:
        cfg = json.loads((EDLINK_DIR / "config.json").read_text(encoding="utf-8"))
        token = str(cfg.get("token", "")).strip()
    if not token:
        raise SystemExit("token tidak ditemukan di token_cache.json / config.json")
    return token


def get_token() -> str:
    global _TOKEN
    if _TOKEN is None:
        _TOKEN = load_token()
    return _TOKEN


def get_session() -> httpx.Client:
    """Klien terautentikasi, KHUSUS untuk API EdLink. Redirect tidak diikuti."""
    global _SESSION
    if _SESSION is None:
        _SESSION = httpx.Client(
            timeout=120,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "X-App-Locale": "id",
                "X-Referer": "https://edlink.id/login",
                "Authorization": f"Bearer {get_token()}",
            },
            follow_redirects=False,
        )
    return _SESSION


def download_client() -> httpx.Client:
    """Klien unduhan tanpa Authorization. Tidak ada token yang bisa bocor."""
    return httpx.Client(
        timeout=120,
        follow_redirects=False,
        headers={"Accept": "*/*", "User-Agent": "edlink-mcp/1.0"},
    )


def validate_download_url(url: str) -> str:
    """Hanya HTTPS + host allowlist. Gagal dengan pesan host/skema yang ditolak."""
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_DOWNLOAD_SCHEMES:
        raise ValueError(f"skema unduhan tidak didukung: {scheme or '(kosong)'!r}")
    if parsed.username or parsed.password:
        raise ValueError("URL unduhan tidak boleh mengandung kredensial")
    if parsed.port not in (None, 443):
        raise ValueError(f"port unduhan tidak didukung: {parsed.port}")
    host = (parsed.hostname or "").lower()
    if host not in ALLOWED_DOWNLOAD_HOSTS:
        raise ValueError(f"host unduhan tidak diizinkan: {host or '(kosong)'!r}")
    return url


def safe_get(
    client: httpx.Client,
    url: str,
    params: dict[str, str] | None = None,
    max_redirects: int = 5,
) -> httpx.Response:
    """GET tanpa Authorization, redirect divalidasi per-hop (host + skema)."""
    current = validate_download_url(url)
    for _ in range(max_redirects + 1):
        r = client.get(current, params=params)
        params = None
        if 300 <= r.status_code < 400 and r.headers.get("location"):
            current = validate_download_url(urljoin(str(r.url), r.headers["location"]))
            continue
        return r
    raise RuntimeError("terlalu banyak redirect saat mengunduh materi")


def api(path: str, body: dict | None = None):
    """POST dulu; kalau Laravel menolak method, coba GET. Redirect ditolak."""
    client = get_session()
    url = f"{API_BASE}/{path.lstrip('/')}"
    r = client.post(url, json=body or {})
    if r.status_code == 404 or "Supported methods" in r.text[:200]:
        r = client.get(url)
    if 300 <= r.status_code < 400:
        raise RuntimeError(f"API redirect tidak diikuti: {r.headers.get('location')}")
    r.raise_for_status()
    payload = r.json()
    data = payload.get("data", payload) if isinstance(payload, dict) else payload
    if data is None:
        raise RuntimeError(f"API {path} balikin data null: {str(payload)[:200]}")
    return data


def sanitize(name: str) -> str:
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name).strip().rstrip(".")
    return name[:180] or "tanpa-nama"


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def drive_confirm(html: str, base_url: str, client: httpx.Client) -> bytes | None:
    """Halaman interstitial Google Drive: kirim ulang form konfirmasinya."""
    m = re.search(r'action="([^"]+)"', html)
    if not m:
        return None
    action = html_lib.unescape(m.group(1))
    action_url = urljoin(base_url, action)
    inputs = {
        html_lib.unescape(key): html_lib.unescape(value)
        for key, value in re.findall(r'name="([^"]+)"\s+value="([^"]*)"', html)
    }
    r = safe_get(client, action_url, params=inputs)
    if r.status_code == 200 and not looks_like_html(r.content):
        return r.content
    return None


def looks_like_html(content: bytes) -> bool:
    head = content[:5].lower()
    return head in (b"<!doc", b"<html")


def download_media(media: dict, dest: Path, client: httpx.Client | None = None) -> bool:
    """Coba link GCS dulu; kalau 401/403, fallback ke downloadLink Google Drive.

    Klien unduhan tidak pernah membawa Authorization. Host/skema divalidasi
    sebelum request dan di setiap redirect.
    """
    owns_client = client is None
    client = client or download_client()
    try:
        if any(key.lower() == "authorization" for key in client.headers):
            print(f"    GAGAL {dest.name}: klien unduhan membawa Authorization")
            return False
        candidates = [("gcs", (media.get("file") or {}).get("link"))]
        drive_url = (media.get("values") or {}).get("downloadLink")
        if drive_url:
            candidates.append(("drive", drive_url))
        last_err = ""
        for kind, url in candidates:
            if not url:
                continue
            try:
                r = safe_get(client, url)
                if r.status_code in (401, 403) and kind == "gcs":
                    last_err = f"HTTP {r.status_code} ({kind})"
                    continue
                if r.status_code != 200:
                    last_err = f"HTTP {r.status_code} ({kind})"
                    continue
                content = r.content
                if kind == "drive" and looks_like_html(content):
                    content = drive_confirm(
                        content.decode("utf-8", "replace"), str(r.url), client
                    )
                    if content is None:
                        last_err = "interstitial drive tak terpecahkan"
                        continue
                dest.write_bytes(content)
                if magic_ok(dest, media.get("extension", "")):
                    return True
                dest.unlink(missing_ok=True)
                last_err = f"magic bytes salah ({kind})"
            except ValueError as exc:
                last_err = str(exc)[:120]
            except Exception as exc:
                last_err = str(exc)[:120]
                time.sleep(2)
        print(f"    GAGAL {dest.name}: {last_err}")
        return False
    finally:
        if owns_client:
            client.close()


def magic_ok(dest: Path, ext: str) -> bool:
    with dest.open("rb") as fh:
        head = fh.read(8)
    if ext == "pdf":
        return head.startswith(b"%PDF")
    if ext in ("pptx", "docx"):
        return head.startswith(b"PK")
    if ext == "ppt":
        return head.startswith(b"\xd0\xcf\x11\xe0")
    return True


def main():
    report: dict[str, list[str]] = {}
    for gid, (class_name, sesi_tpl) in CLASSES.items():
        class_dir = KULIAH / class_name
        seen_media: set[int] = set()
        lines: list[str] = []

        sections = api(f"sections/all/{gid}")
        ensure_dir(class_dir)
        print(f"\n== {class_name}: {len(sections)} sesi ==")
        for sec in sorted(sections, key=lambda s: s.get("meet") or 0):
            meet = sec.get("meet") or 0
            sec_type = sec.get("type")
            folder_name = SPECIAL_TYPE.get(sec_type) or sesi_tpl.format(meet=meet)
            materials = sec.get("materials") or []
            for mat in materials:
                for media in mat.get("medias") or []:
                    mid = media.get("id")
                    if mid in seen_media:
                        continue
                    seen_media.add(mid)
                    name = sanitize(media.get("name") or f"media-{mid}")
                    title = mat.get("title") or ""
                    # buku referensi & RPS ditaruh di folder Referensi
                    if re.search(r"\b(buku|rps)\b", title, re.IGNORECASE):
                        target_dir = class_dir / "Referensi"
                    else:
                        target_dir = class_dir / folder_name
                    dest = target_dir / name
                    rel = dest.relative_to(class_dir).as_posix()
                    if dest.exists():
                        lines.append(f"  [skip] {rel} (sudah ada)")
                        continue
                    has_link = (media.get("file") or {}).get("link") or (
                        media.get("values") or {}
                    ).get("downloadLink")
                    if not has_link:
                        lines.append(f"  [tanpa-link] {rel}")
                        continue
                    ensure_dir(target_dir)
                    if download_media(media, dest):
                        size_kb = dest.stat().st_size // 1024
                        lines.append(f"  [OK] {rel} ({size_kb} KB)")
                    else:
                        dest.unlink(missing_ok=True)
                        lines.append(f"  [GAGAL] {rel}")
        report[class_name] = lines

    print("\n========== LAPORAN ==========")
    for class_name, lines in report.items():
        print(f"\n{class_name}")
        for line in lines:
            print(line)


if __name__ == "__main__":
    sys.exit(main())
