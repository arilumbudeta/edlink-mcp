"""Unduh semua materi EdLink ke C:\\Users\\Lumi\\Documents\\Kuliah,
satu folder per sesi, mengikuti konvensi lokal yang sudah ada.

Sumber token: token_cache.json (sama dengan yang dipakai edlink_mcp.py).
Materi diunduh dari file.link (GCS assets-edlink), fallback Bearer bila 403.
"""
import json
import re
import sys
import time
from pathlib import Path

import httpx

EDLINK_DIR = Path(r"C:\Users\Lumi\Documents\EDLINK")
KULIAH = Path(r"C:\Users\Lumi\Documents\Kuliah")
API_BASE = "https://api.edlink.id/api/v1.4"

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


def load_token() -> str:
    cache = json.loads((EDLINK_DIR / "token_cache.json").read_text(encoding="utf-8"))
    token = str(cache.get("token", "")).strip()
    if not token:
        cfg = json.loads((EDLINK_DIR / "config.json").read_text(encoding="utf-8"))
        token = str(cfg.get("token", "")).strip()
    if not token:
        raise SystemExit("token tidak ditemukan di token_cache.json / config.json")
    return token


TOKEN = load_token()
SESSION = httpx.Client(
    timeout=120,
    headers={
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-App-Locale": "id",
        "X-Referer": "https://edlink.id/login",
        "Authorization": f"Bearer {TOKEN}",
    },
    follow_redirects=True,
)


def api(path: str, body: dict | None = None):
    """POST dulu; kalau Laravel menolak method, coba GET."""
    url = f"{API_BASE}/{path.lstrip('/')}"
    r = SESSION.post(url, json=body or {})
    if r.status_code == 404 or "Supported methods" in r.text[:200]:
        r = SESSION.get(url)
    r.raise_for_status()
    payload = r.json()
    data = payload.get("data", payload) if isinstance(payload, dict) else payload
    if data is None:
        raise RuntimeError(f"API {path} balikin data null: {str(payload)[:200]}")
    return data


def plain_get(url: str) -> httpx.Response:
    """GET file tanpa header Authorization (GCS publik)."""
    with httpx.Client(timeout=120, follow_redirects=True) as client:
        return client.get(url)


def sanitize(name: str) -> str:
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name).strip().rstrip(".")
    return name[:180] or "tanpa-nama"


def existing_names(class_dir: Path) -> set[str]:
    return {p.name.lower() for p in class_dir.rglob("*") if p.is_file()}


def drive_confirm(html: str) -> bytes | None:
    """Halaman interstitial Google Drive: kirim ulang form konfirmasinya."""
    m = re.search(r'action="([^"]+)"', html)
    if not m:
        return None
    action = m.group(1).replace("&amp;", "&")
    inputs = dict(re.findall(r'name="([^"]+)"\s+value="([^"]*)"', html))
    with httpx.Client(timeout=180, follow_redirects=True) as client:
        r = client.get(action, params=inputs)
    if r.status_code == 200 and r.content[:5] not in (b"<!DOC", b"<html"):
        return r.content
    return None


def download_media(media: dict, dest: Path) -> bool:
    """Coba link GCS dulu; kalau 401 (file google_drive), pakai downloadLink Drive."""
    candidates = [("gcs", (media.get("file") or {}).get("link"))]
    drive_url = (media.get("values") or {}).get("downloadLink")
    if drive_url:
        candidates.append(("drive", drive_url))
    last_err = ""
    for kind, url in candidates:
        if not url:
            continue
        try:
            r = SESSION.get(url) if kind == "gcs" else plain_get(url)
            if r.status_code in (401, 403) and kind == "gcs":
                r = plain_get(url)
            if r.status_code != 200:
                last_err = f"HTTP {r.status_code} ({kind})"
                continue
            content = r.content
            if kind == "drive" and content[:5] in (b"<!DOC", b"<html"):
                content = drive_confirm(content.decode("utf-8", "replace"))
                if content is None:
                    last_err = "interstitial drive tak terpecahkan"
                    continue
            dest.write_bytes(content)
            if magic_ok(dest, media.get("extension", "")):
                return True
            dest.unlink(missing_ok=True)
            last_err = f"magic bytes salah ({kind})"
        except Exception as exc:
            last_err = str(exc)[:120]
            time.sleep(2)
    print(f"    GAGAL {dest.name}: {last_err}")
    return False


def magic_ok(dest: Path, ext: str) -> bool:
    head = dest.open("rb").read(8)
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
        class_dir.mkdir(exist_ok=True)
        seen_media: set[int] = set()
        have = existing_names(class_dir)
        lines: list[str] = []

        sections = api(f"sections/all/{gid}")
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
                    if name.lower() in have:
                        lines.append(f"  [skip] {rel} (sudah ada)")
                        continue
                    has_link = (media.get("file") or {}).get("link") or (
                        media.get("values") or {}
                    ).get("downloadLink")
                    if not has_link:
                        lines.append(f"  [tanpa-link] {rel}")
                        continue
                    target_dir.mkdir(parents=True, exist_ok=True)
                    if download_media(media, dest):
                        have.add(name.lower())
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
