"""Enkripsi kredensial EdLink at-rest.

Kunci master TIDAK disimpan di database. Disimpan di file terpisah
(default /etc/edlink-mcp/master.key, override EDLINK_PLATFORM_KEY_FILE).
File harus mode 600 dan tidak ikut git.

Format: Fernet (AES-128-CBC + HMAC-SHA256) dari paket cryptography.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

KEY_PATH = Path(os.environ.get("EDLINK_PLATFORM_KEY_FILE", "master.key")).expanduser()


class CryptoError(RuntimeError):
    pass


def _load_key() -> bytes:
    if KEY_PATH.exists():
        key = KEY_PATH.read_bytes().strip()
        if len(key) != 44:
            raise CryptoError(
                f"key file {KEY_PATH} tidak valid (harus 44 byte base64 Fernet)"
            )
        return key
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key()
    KEY_PATH.write_bytes(key)
    try:
        os.chmod(KEY_PATH, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return key


_fernet: Fernet | None = None


def fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        _fernet = Fernet(_load_key())
    return _fernet


def encrypt(plaintext: str) -> str:
    """Teks kosong tetap kosong — jangan enkripsi nilai yang tidak ada."""
    if not plaintext:
        return ""
    return fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    try:
        return fernet().decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise CryptoError(
            "kredensial tidak bisa didekripsi — key file berbeda atau data rusak"
        ) from exc


def rotate_key(new_key_path: Path, reencrypt) -> int:
    """Ganti key lalu enkripsi ulang semua nilai. reencrypt(decrypt_fn) -> jumlah."""
    global _fernet
    old = fernet()
    new_key = Fernet.generate_key()
    new_key_path.parent.mkdir(parents=True, exist_ok=True)
    new_key_path.write_bytes(new_key)
    try:
        os.chmod(new_key_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    count = reencrypt(lambda value: old.decrypt(value.encode("ascii")).decode("utf-8"))
    _fernet = Fernet(new_key)
    return count
