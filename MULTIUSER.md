# MULTI-USER PLATFORM

EdLink MCP bisa jalan dua mode:

| Mode | Entry point | Auth | Data |
| --- | --- | --- | --- |
| Local (stdio) | `edlink_mcp.py` | tidak ada, lokal saja | `config.json` + `token_cache.json` di folder repo |
| Platform (HTTP) | `platform_main.py` | akun platform + OAuth 2.1 | SQLite per user, kredensial terenkripsi |

Mode stdio tidak berubah dan tidak membutuhkan paket `edlink_platform`.

## Arsitektur

```
ChatGPT / klien MCP
   |  Authorization: Bearer <token platform>
   v
Starlette  ── IdentityMiddleware ──┬── /mcp          -> FastMCP (18 tool)
   |                               ├── /oauth/*      -> authorization server
   |                               ├── /signup /login -> akun platform
   |                               ├── /dashboard     -> hubungkan EdLink
   |                               └── /admin         -> administrasi
   |
   +-- SQLite (users, sessions, edlink_connections, mcp_tokens,
   |           oauth_clients, oauth_authorization_codes, audit_events, rate_limits)
   +-- master.key (Fernet, di luar database, mode 600)
```

Identitas per request:

1. `IdentityMiddleware` membaca token atau cookie.
2. Token dicocokkan ke tabel `mcp_tokens` (hash SHA-256) → `user_id`.
3. `user_id` disimpan di contextvar (`edlink_platform.identity`).
4. Setiap fungsi kredensial di `edlink_mcp.py` (`_load_credentials`, `_read_token_cache`,
   `_write_token_cache`, `_load_device`) menanyakan user aktif lebih dulu.
   Kalau tidak ada user (stdio), jalur file lama dipakai.

Tool **tidak pernah** menerima `user_id` dari argumen. Skema 18 tool tidak berubah.

## Alur user baru

1. Buka `https://<host>/signup`, daftar dengan email + password (min 10 karakter).
2. Login → dashboard.
3. Hubungkan EdLink: tempel token 129 karakter, atau isi email + password EdLink.
4. Di ChatGPT: **Add custom MCP server** → `https://<host>/mcp` → autentikasi OAuth.
5. Halaman izin muncul sekali; setujui. Token platform diterbitkan dan dipakai ChatGPT.

## Autentikasi

- Password: Argon2id (`time_cost=3`, `memory_cost=64 MiB`, `parallelism=4`), rehash otomatis.
- Sesi web: cookie `HttpOnly`, `SameSite=Lax`, `Secure` di HTTPS, TTL 14 hari,
  yang disimpan hanya hash SHA-256.
- Token MCP: `edm_...`, TTL 30 hari, disimpan sebagai hash, bisa dicabut per user.
- OAuth 2.1: authorization code + PKCE `S256`, DCR di `/oauth/register`,
  metadata di `/.well-known/oauth-authorization-server` dan
  `/.well-known/oauth-protected-resource`, parameter `resource` di-echo,
  `iss` dikirim di redirect.
- Rate limit: signup 5/jam/IP, login 10/15 menit per IP dan per email.

## Penyimpanan kredensial EdLink

- Token/password dienkripsi Fernet sebelum masuk database.
- Kunci master di file terpisah (`EDLINK_PLATFORM_KEY_FILE`), mode 600.
- Password EdLink hanya disimpan kalau user memilih mode email+password;
  mode token tidak menyimpan password sama sekali.
- Admin tidak bisa melihat token terdekripsi lewat panel admin.
- `PUTUSKAN EDLINK` menghapus baris koneksi dan mencabut semua token MCP user.
- EdLink tidak menyediakan endpoint revoke, jadi token di sisi EdLink tetap
  valid sampai expired walau dihapus dari platform. Ini batasan protokol.

## Skema database

| Tabel | Isi |
| --- | --- |
| `users` | id, email unik, `password_hash`, status, `is_admin` |
| `user_sessions` | hash sesi, user, expiry, revoked, ip, user agent |
| `edlink_connections` | per user: mode, token/email/password terenkripsi, device JSON |
| `mcp_tokens` | hash token MCP, client_id OAuth, expiry, revoked |
| `oauth_clients` | hasil DCR: client_id, secret opsional, redirect_uris |
| `oauth_authorization_codes` | kode sekali pakai, PKCE challenge, resource, expiry |
| `audit_events` | aksi, user, ip, waktu. Tanpa nilai rahasia |
| `rate_limits` | counter per key + window |

Semua query memakai parameter binding. Foreign key `ON DELETE CASCADE`.

## Admin

Admin pertama dibuat dari env saat start:

```bash
EDLINK_PLATFORM_ADMIN_EMAIL=you@example.com
EDLINK_PLATFORM_ADMIN_PASSWORD=<acak>
```

Kalau password dikosongkan, tidak ada admin yang dibuat dan tidak ada
password default. Untuk membaca password yang digenerate saat deploy:

```bash
grep '^EDLINK_PLATFORM_ADMIN_PASSWORD=' /data/workspace/edlink-mcp/.env
```

Panel `/admin` bisa: lihat user, suspend/activate, cabut sesi, cabut token MCP,
putuskan koneksi EdLink, dan membaca 40 audit event terakhir. Admin tidak bisa
membaca token atau password user.

## Environment

| Variabel | Wajib | Keterangan |
| --- | --- | --- |
| `EDLINK_PLATFORM_BASE_URL` | ya | URL publik, harus `https://` |
| `EDLINK_PLATFORM_DB` | ya | path SQLite |
| `EDLINK_PLATFORM_KEY_FILE` | ya | path master key Fernet |
| `EDLINK_PLATFORM_ADMIN_EMAIL` | tidak | bootstrap admin |
| `EDLINK_PLATFORM_ADMIN_PASSWORD` | tidak | bootstrap admin |
| `EDLINK_PLATFORM_ALLOW_HTTP` | tidak | `1` hanya untuk uji lokal |
| `EDLINK_MCP_ALLOWED_HOSTS` | ya | host publik + localhost |
| `EDLINK_MCP_PORT` | tidak | default 8765 |

`EDLINK_MCP_TRUST_PROXY_AUTH=1` diset otomatis oleh `platform_main.py`: auth
FastMCP dimatikan karena `IdentityMiddleware` yang memverifikasi token.

## Backup dan restore

```bash
# backup (konsisten walau service jalan)
sqlite3 /data/workspace/edlink-mcp/data/platform.db ".backup '/data/backup/platform-$(date +%F).db'"

# tanpa sqlite3 CLI
python3 -c "import sqlite3;sqlite3.connect('/data/workspace/edlink-mcp/data/platform.db').backup(sqlite3.connect('/data/backup/platform.db'))"

# key WAJIB ikut dibackup, tanpa key data token tidak bisa dibuka
cp /data/workspace/edlink-mcp/data/master.key /data/backup/master.key
chmod 600 /data/backup/master.key
```

Restore: hentikan service, kembalikan `platform.db` dan `master.key`, start lagi.
Key yang berbeda membuat semua kredensial EdLink tidak bisa didekripsi
(pesan errornya jelas, bukan crash).

## Batasan yang diketahui

- SQLite satu file. Cukup untuk puluhan pengguna aktif; bukan untuk ribuan
  penulis bersamaan. Kalau perlu Postgres, lapisan `db.py` yang diganti.
- Email verification tidak ada karena VM tidak punya SMTP. Pendaftaran langsung aktif.
- Password reset belum ada; admin bisa suspend atau membuat akun baru.
- EdLink tidak punya OAuth resmi untuk pihak ketiga, jadi user menempel token
  atau email+password sendiri. Tidak ada refresh token resmi; mode password
  login ulang otomatis saat token expired, mode token harus tempel token baru.
- Token MCP tidak kedaluwarsa otomatis saat user ganti password (belum ada
  ganti password). Cabut manual lewat dashboard atau admin.
- Isolasi diuji lewat `test_platform_e2e.py` (32 pemeriksaan), bukan audit
  pihak ketiga.

## Uji

```bash
# lokal, butuh server jalan di :8792
python test_platform_e2e.py

# terhadap deployment publik
PLATFORM_TEST_BASE=https://<host> \
PLATFORM_ADMIN_EMAIL=... PLATFORM_ADMIN_PASSWORD=... \
python test_platform_e2e.py
```

Test membuat akun `alice@test.local` dan `bob@test.local`. Hapus setelah run
di produksi:

```bash
cd /data/workspace/edlink-mcp
./.venv/bin/python -c "import sqlite3;c=sqlite3.connect('data/platform.db');print(c.execute(\"DELETE FROM users WHERE email LIKE '%@test.local'\").rowcount);c.commit()"
```
