# DEPLOYMENT — EdLink MCP on InstaBox (Debian 13)

Panduan ini mendokumentasikan deployment nyata yang berjalan di VM InstaBox.
Semua perintah VM memakai bash di Debian 13 (trixie); semua perintah dari PC
memakai PowerShell.

## 1. Arsitektur

```
ChatGPT / MCP client
        |
        | HTTPS
        v
https://<host>.instabox.tech/mcp?_token=<private-token>
        |
        |  instabox-port (reverse proxy + token gate)
        v
uvicorn 0.0.0.0:8765  (edlink_mcp.py, Streamable HTTP, /mcp)
        |
        +--> api.edlink.id        (Authorization: Bearer <EdLink token>)
        +--> storage.googleapis.com / drive.google.com  (TANPA Authorization)
```

- Aplikasi: satu proses Python, `edlink_mcp.py`, di `/data/workspace/edlink-mcp`.
- Manajer proses: systemd (`edlink-mcp.service`), auto-start saat boot,
  restart otomatis saat crash.
- Transport: MCP Streamable HTTP (stateless, JSON response) di `/mcp`.
  STDIO tetap jadi default saat `EDLINK_MCP_TRANSPORT` tidak diset.
- Ingress publik: `instabox-port`, satu-satunya jalur masuk. Tidak ada port
  lain yang diekspos; SSH hanya lewat `ssh.instabox.sh:2222` milik platform.

## 2. Prasyarat

VM (sudah terpenuhi):

- Debian 13, kernel `6.18.60-instabox`, 4 vCPU, 8 GiB RAM, 16 GiB root
  (`/data` terpisah, persisten).
- `python3` 3.13.5, `python3-venv`, `git`, `curl`.
- `sudo` tanpa password untuk user `user`.
- `instabox-port` di `/usr/local/bin/instabox-port`.

PC: PowerShell 5.1, `ssh.exe`, `scp.exe`, `curl.exe`.

## 3. Setup VM (sekali jalan)

### 3.1 Ambil kode

```bash
mkdir -p /data/workspace
cd /data/workspace
git clone https://github.com/arilumbudeta/edlink-mcp.git
cd edlink-mcp
```

### 3.2 Virtual environment

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install --upgrade pip
./.venv/bin/python -m pip install -r requirements.txt
```

`requirements.txt` memaku `mcp>=1.30.0,<2` karena transport HTTP di
`edlink_mcp.py` memakai API FastMCP 1.x (`host`, `port`, `streamable_http_path`,
`token_verifier`). SDK 2.x mengganti API itu.

### 3.3 Environment

```bash
cp .env.example .env
chmod 600 .env
```

Isi `.env`. Token acak: `openssl rand -hex 32`.

| Variabel | Isi |
| --- | --- |
| `EDLINK_MCP_TRANSPORT` | `http` |
| `EDLINK_MCP_HOST` | `0.0.0.0` |
| `EDLINK_MCP_PORT` | `8765` |
| `EDLINK_MCP_ISSUER_URL` | `https://<host>.instabox.tech` (tanpa `/mcp`) |
| `EDLINK_MCP_ALLOWED_HOSTS` | `<host>.instabox.tech,localhost:8765,127.0.0.1:8765` |
| `EDLINK_MCP_ALLOWED_ORIGINS` | kosong untuk klien non-browser |
| `EDLINK_TOKEN` | token EdLink (JANGAN yang lama kalau sudah expired) |
| `EDLINK_MCP_AUTH_TOKEN` | bearer statis, wajib kalau tidak memakai mode proxy-trust |
| `EDLINK_MCP_TRUST_PROXY_AUTH` | `1` hanya kalau gerbang auth ada di reverse proxy |

### 3.4 Dua mode autentikasi

**Mode A — bearer statis (default).** Server menolak request tanpa
`Authorization: Bearer <EDLINK_MCP_AUTH_TOKEN>`. Pakai ini untuk MCP Inspector,
Codex, atau skrip sendiri.

**Mode B — proxy-trust.** `EDLINK_MCP_TRUST_PROXY_AUTH=1` mematikan pemeriksaan
bearer di aplikasi karena gerbang auth sudah ada di `instabox-port --private`:
URL hanya bisa dibuka dengan `_token`. Ini mode yang dipakai ChatGPT, karena
ChatGPT **tidak bisa** mengirim API key/bearer kustom (lihat bagian 8).

Mode B hanya aman kalau satu-satunya jalur masuk memang proxy tersebut. Di VM
ini benar: `eth0` adalah `172.16.0.2/30` di belakang NAT, tanpa IP publik.

### 3.5 systemd

```bash
sudo install -m 644 deploy/edlink-mcp.service /etc/systemd/system/edlink-mcp.service
sudo systemctl daemon-reload
sudo systemctl enable --now edlink-mcp.service
```

Unit sudah memuat hardening: `NoNewPrivileges`, `ProtectSystem=full`,
`ProtectHome=read-only`, `ReadWritePaths=/data/workspace/edlink-mcp`,
`PrivateTmp`, `MemoryMax=512M`.

## 4. Manajemen service

```bash
sudo systemctl status edlink-mcp.service
sudo systemctl restart edlink-mcp.service
sudo systemctl stop edlink-mcp.service
sudo systemctl is-enabled edlink-mcp.service
```

## 5. Log

```bash
sudo journalctl -u edlink-mcp.service -n 50 --no-pager
sudo journalctl -u edlink-mcp.service -f
sudo journalctl -u edlink-mcp.service --since '1 hour ago'
```

## 6. Update aplikasi

```bash
cd /data/workspace/edlink-mcp
git pull --ff-only origin main
./.venv/bin/python -m pip install -r requirements.txt
sudo systemctl restart edlink-mcp.service
sudo journalctl -u edlink-mcp.service -n 20 --no-pager
```

Data yang bertahan: `.env`, `config.json`, `token_cache.json`, dan materi
Kuliah di luar repo. `git pull` tidak menyentuhnya.

## 7. Endpoint HTTPS publik

`instabox-port` memetakan port VM ke URL HTTPS. Dua pilihan:

**Publik** (siapa pun yang tahu URL bisa konek, auth murni di aplikasi):

```bash
instabox-port publish 8765 --name edlink-mcp --json
```

**Privat** (URL butuh `_token`, ini yang dipakai):

```bash
instabox-port publish 8765 --name edlink-mcp --private --json
```

Output memuat `token` dan `tokenUrl`. Token ditampilkan **sekali**; simpan di
tempat aman. Rotasi:

```bash
instabox-port publish 8765 --private --rotate-token --json
```

Cek dan cabut:

```bash
instabox-port list
instabox-port unpublish 8765
```

Endpoint yang dipakai ChatGPT:

```
https://<host>.instabox.tech/mcp?_token=<private-token>
```

URL berlaku selama sandbox berjalan. Kalau sandbox di-stop, publikasi ikut
berhenti dan perlu dipublish ulang.

## 8. Koneksi ChatGPT

Berdasarkan dokumentasi resmi OpenAI (developers.openai.com/plugins):

1. Buka [ChatGPT Plugins](https://chatgpt.com/plugins) → tombol plus →
   **Add custom MCP server**.
2. Isi nama dan deskripsi.
3. Di bagian **Connection**, pilih **public endpoint** dan tempel URL lengkap
   termasuk `/mcp` dan `?_token=...`.
4. Autentikasi: pilih tanpa auth. Gerbang auth ada di `_token`.
5. Setujui risk warning → **Create as a plugin**.
6. Tinjau tool yang terdeteksi (harus 18), lalu install dan uji di chat.

Batasan yang perlu diketahui:

- ChatGPT **tidak mendukung** API key statis, OAuth client-credentials, atau
  mTLS milik pelanggan. Karena itu bearer statis tidak bisa dipakai langsung
  oleh ChatGPT; jalurnya adalah `_token` pada URL.
- Untuk auth OAuth 2.1 penuh, server harus menyediakan
  `/.well-known/oauth-protected-resource` plus authorization server yang
  mendukung PKCE (`S256`), CIMD atau DCR, dan echo parameter `resource`.
  Belum diimplementasikan di repo ini.
- Endpoint harus HTTPS. `instabox.tech` sudah HTTPS.
- Custom MCP server memerlukan akun/workspace yang mengizinkannya. Kalau menu
  tersebut tidak muncul, batasan itu ada di plan/workspace, bukan di server.
- Write action (mis. `edlink_send_tugas`, `edlink_upload_file`) meminta
  konfirmasi manual di ChatGPT.

Integrasi dinyatakan **berhasil** hanya setelah ChatGPT benar-benar menemukan
dan memanggil minimal satu tool EdLink. Sampai itu terjadi, statusnya
"endpoint siap", bukan "terintegrasi".

## 9. Catatan keamanan

- Rahasia hanya di `.env` (mode `600`) dan `token_cache.json` (mode `600`).
  Keduanya di-`.gitignore`.
- Token EdLink hanya dikirim ke `api.edlink.id`. Unduhan materi memakai klien
  tanpa `Authorization`, dengan allowlist host (`storage.googleapis.com`,
  `drive.google.com`, `drive.usercontent.google.com`) dan validasi redirect
  per hop.
- `client_is_authenticated()` menolak klien unduhan yang membawa header
  `Authorization` **atau** objek `httpx.Client.auth`.
- Perbandingan bearer memakai `secrets.compare_digest`.
- DNS rebinding protection aktif; `Host` di luar allowlist ditolak (`421`).
- Tidak ada endpoint debug dan tidak ada CORS terbuka.
- `_token` pada URL adalah rahasia. Ia bisa muncul di log proxy, riwayat
  browser, atau tangkapan layar. Rotasi kalau bocor.

## 10. Troubleshooting

| Gejala | Penyebab | Perbaikan |
| --- | --- | --- |
| `401` tanpa `_token` | gate proxy | tambahkan `?_token=...` |
| `401` dengan `_token`, mode A | bearer aplikasi aktif | set `EDLINK_MCP_TRUST_PROXY_AUTH=1` atau kirim `Authorization` |
| `421 Invalid Host` | `Host` tidak ada di `EDLINK_MCP_ALLOWED_HOSTS` | tambahkan host publik, restart |
| `502` dari proxy | aplikasi mati / port salah | `systemctl status`, cek port di `.env` |
| service gagal start | `EDLINK_MCP_AUTH_TOKEN`/`ISSUER_URL` kosong | isi `.env`, lihat `journalctl` |
| `token tidak ditemukan` | `.env` tidak terbaca | cek `EnvironmentFile` dan permission |
| tool balas "Kredensial EdLink belum ada" | `EDLINK_TOKEN` kosong/expired | isi token baru, restart |
| URL mati setelah lama | sandbox di-stop | `instabox-port publish` ulang |
