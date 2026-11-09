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
   |           oauth_clients, oauth_authorization_codes, audit_events)
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

Di mode platform, tool setup ikut menyesuaikan:

- `edlink_setup_status` mengembalikan instruksi dashboard, bukan pilihan
  `edlink_setup_manual` / `edlink_setup_oauth` (yang menulis `config.json`
  bersama di folder repo).
- `edlink_setup_token` dan `edlink_setup_manual` menyimpan ke
  `edlink_connections` milik user yang sedang memanggil, terenkripsi. Tidak ada
  `config.json` yang ditulis dan tidak ada path server yang dibocorkan.
- Respons setup tidak lagi memuat potongan token. Token asli tidak pernah
  kembali ke chat, log, atau model.

## Alur user baru

1. Buka `https://<host>/signup`, daftar dengan email + password (min 10 karakter).
2. Login → dashboard.
3. Hubungkan EdLink dengan **email + password EdLink** (server yang login, tanpa
   DevTools). Token disimpan terenkripsi dan diperbarui otomatis saat expired.
   Akun yang hanya punya login Google: tempel token sekali lewat bagian "tempel token".
4. Di ChatGPT: **Add custom MCP server** → `https://<host>/mcp` → autentikasi OAuth.
5. Halaman izin muncul sekali; setujui. Token platform diterbitkan dan dipakai ChatGPT.

### Dua OAuth yang berbeda

| OAuth | Alur | Status |
| --- | --- | --- |
| Platform ↔ ChatGPT/Claude | `/oauth/authorize` + PKCE + DCR milik platform ini | browser-based penuh |
| Platform ↔ EdLink | tidak ada | EdLink tidak punya AS pihak ketiga |

EdLink hanya punya `site/login` dan `auth/google` (EdLink adalah *client* Google, bukan
server OAuth). Tidak ada authorization endpoint untuk pihak ketiga, jadi token EdLink
tidak bisa didapat lewat redirect browser. Jalur resminya:

- email + password EdLink → server login sendiri, token disimpan terenkripsi;
- akun Google-only → tempel token sekali, lalu server yang mengurus pembaruan.

Validasi saat link: token dicek ke `user/profile` dan password dicek dengan login
sungguhan sebelum disimpan, jadi kredensial salah tidak pernah masuk database.

## Autentikasi

- Password: Argon2id (`time_cost=3`, `memory_cost=64 MiB`, `parallelism=4`), rehash otomatis.
- Sesi web: cookie `HttpOnly`, `SameSite=Lax`, `Secure` di HTTPS, TTL 14 hari,
  yang disimpan hanya hash SHA-256.
- Token MCP: `edm_...`, TTL 30 hari, disimpan sebagai hash, bisa dicabut per user.
- Refresh token: `edr_...`, TTL 90 hari, disimpan sebagai hash, **diputar setiap
  kali dipakai**. Token lama langsung mati; replay token lama dianggap
  kompromi dan mencabut semua refresh token user itu.
- OAuth 2.1: authorization code + PKCE `S256`, DCR di `/oauth/register`,
  metadata di `/.well-known/oauth-authorization-server` dan
  `/.well-known/oauth-protected-resource`, parameter `resource` di-echo,
  `iss` dikirim di redirect. Grant yang didukung: `authorization_code`,
  `refresh_token`.
- Rate limit: **dimatikan** di deployment ini (keputusan owner). Signup, login, DCR,
  token, dan link EdLink tidak dibatasi. Nyalakan lagi kalau server dibuka lebih luas.

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
| `oauth_refresh_tokens` | hash refresh token, client, scope, rotated/revoked, expiry |
| `audit_events` | aksi, user, ip, waktu. Tanpa nilai rahasia |

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
| `EDLINK_PLATFORM_TEST_MODE` | tidak | `1` hanya untuk suite uji: lewati validasi EdLink saat link. **Jangan di produksi.** |
| `EDLINK_MCP_ALLOWED_HOSTS` | ya | host publik + localhost |
| `EDLINK_MCP_PORT` | tidak | default 8765 |

`EDLINK_MCP_TRUST_PROXY_AUTH=1` diset otomatis oleh `platform_main.py`: auth
FastMCP dimatikan karena `IdentityMiddleware` yang memverifikasi token.

## Migrasi dari single-user

Deployment single-user menyimpan kredensial di `.env` (`EDLINK_TOKEN` atau
`EDLINK_EMAIL`/`EDLINK_PASSWORD`) atau di `token_cache.json`. Di mode platform
kredensial itu tidak lagi dibaca — semuanya harus pindah ke tabel
`edlink_connections`, terenkripsi per user.

Pemilik server tetap punya akun EdLink sendiri: ia login sebagai admin, dan
token lamanya dipindahkan ke baris koneksi milik admin. Akun itu tidak dipakai
bersama oleh user lain.

```python
# jalankan di repo, service boleh tetap hidup
import os, sys
sys.path.insert(0, "/data/workspace/edlink-mcp")
os.environ["EDLINK_PLATFORM_DB"] = "/data/workspace/edlink-mcp/data/platform.db"
os.environ["EDLINK_PLATFORM_KEY_FILE"] = "/data/workspace/edlink-mcp/data/master.key"

from edlink_platform import security, store
admin = security.find_user_by_email("kamu@example.com")
store.save_connection(admin["id"], "token", token="<token 129 karakter>")
assert store.load_credentials(admin["id"])["token"] == "<token 129 karakter>"
```

Setelah round-trip terbukti, hapus plaintext-nya: beri komentar pada
`EDLINK_TOKEN`/`EDLINK_EMAIL`/`EDLINK_PASSWORD` di `.env` dan hapus
`token_cache.json` serta `config.json`. `EDLINK_MCP_AUTH_TOKEN` juga tidak
terpakai di mode platform karena auth dipegang `IdentityMiddleware`.

## Backup dan restore

Backup otomatis harian sudah tersedia sebagai timer systemd:

```bash
sudo install -m 644 deploy/edlink-backup.service /etc/systemd/system/
sudo install -m 644 deploy/edlink-backup.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now edlink-backup.timer
systemctl list-timers edlink-backup.timer
```

Backup manual atau untuk mengecek hasilnya:

```bash
bash deploy/backup_platform.sh              # ke ./backups
bash deploy/backup_platform.sh /data/backup # folder lain
EDLINK_PLATFORM_BACKUP_KEEP=30 bash deploy/backup_platform.sh
```

Skrip memakai SQLite online backup API, jadi aman dijalankan saat service
hidup. Setiap pasangan `platform-<stamp>.db` + `master-<stamp>.key` disimpan
dengan mode 600 pada key, lalu retensi memangkas sisanya.

Setara dengan perintah manual:

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
- Isolasi diuji lewat `test_platform_e2e.py` (41 pemeriksaan), bukan audit
  pihak ketiga.

## Uji

```bash
# lokal, butuh server jalan di :8792
python test_platform_e2e.py

# terhadap deployment publik
PLATFORM_TEST_BASE=https://<host> \
PLATFORM_ADMIN_EMAIL=... PLATFORM_ADMIN_PASSWORD=... \
python test_platform_e2e.py

# bukti khusus akun pemilik: login -> OAuth -> tools/call -> cabut token
PLATFORM_TEST_BASE=https://<host> \
PLATFORM_ADMIN_EMAIL=... PLATFORM_ADMIN_PASSWORD=... \
python test_owner_live.py
```

`test_owner_live.py` membuktikan rantai lengkap untuk akun pemilik: login web,
OAuth PKCE, `initialize`, `edlink_setup_status`, `edlink_login_status`, lalu
mencabut token yang dipakai. Skrip ini tidak mencetak token atau kredensial.

Test membuat akun `alice<hex>@test.local` dan `bob<hex>@test.local` (akhiran acak
per run, jadi run berulang tidak bentrok). Hapus setelah run di produksi:

```bash
cd /data/workspace/edlink-mcp
./.venv/bin/python - <<'PY'
import sqlite3
conn = sqlite3.connect("data/platform.db")
conn.execute("PRAGMA foreign_keys=ON")   # WAJIB: cascade tidak jalan tanpanya
print("users:", conn.execute("DELETE FROM users WHERE email LIKE '%@test.local'").rowcount)
for table in ("user_sessions", "edlink_connections", "mcp_tokens", "oauth_authorization_codes"):
    cur = conn.execute(f"DELETE FROM {table} WHERE user_id NOT IN (SELECT id FROM users)")
    print(f"{table} orphans:", cur.rowcount)
print("oauth_clients:", conn.execute("DELETE FROM oauth_clients").rowcount)
conn.commit()
PY
```

`sqlite3` CLI tidak menyalakan foreign key secara default, jadi menghapus user
tanpa `PRAGMA foreign_keys=ON` meninggalkan baris yatim di tabel turunan.
Skrip di atas menghapus user lalu menyapu sisa baris yatim.

