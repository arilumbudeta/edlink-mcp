# EdLink MCP Server

MCP server untuk akses **EdLink (edlink.id / SEVIMA)** dari agent coding — jadi agent bisa
jawab "ada tugas gak?" dengan data asli dari akun kamu.

Endpoint-nya di-reverse-engineer dari web app `edlink.id` + PWA `pwa.edlink.id`
(API internal `https://api.edlink.id/api/v1.4`).

## Setup

1. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

2. Salin `config.example.json` jadi `config.json`, isi email & password EdLink kamu:

   ```json
   { "email": "email-kamu", "password": "password-kamu" }
   ```

   Alternatif: pakai environment variables `EDLINK_EMAIL` + `EDLINK_PASSWORD`
   (di-pass lewat konfigurasi MCP di bawah, gak perlu file config).

## Tools yang tersedia

| Tool | Fungsi |
|---|---|
| `edlink_tugas()` | Daftar tugas & kuis yang masih terbuka + deadline — tool utama buat "ada tugas gak?" |
| `edlink_jadwal_hari_ini()` | Jadwal kuliah hari ini |
| `edlink_jadwal_bulanan(bulan, tahun)` | Jadwal bulanan |
| `edlink_kelas()` | Daftar kelas yang diikuti |
| `edlink_notifikasi(hanya_belum_dibaca)` | Notifikasi |
| `edlink_api(path, method, body)` | Panggil endpoint API EdLink apa pun (advanced, buat ekspansi) |
| `edlink_login_status()` | Cek kredensial/token berfungsi |

Dua mode auth:
1. **Mode token (Google SSO)** — `config.json` berisi field `"token"`. Gak butuh password.
2. **Mode password** — `config.json` berisi `"email"` + `"password"` (login via `site/login`).

## Ambil token baru (mode Google SSO)

Token Google SSO diambil dari browser setelah login. Kalau token expired
(MCP bilang "Token EdLink expired"):

1. Login ke [edlink.id](https://edlink.id) via Google di browser
2. Setelah masuk ke halaman `/classes`, buka **DevTools (F12) → Console**, jalankan:

   ```js
   copy(helpers.getToken(document.cookie.match(/(?:^|; )token=([^;]+)/)[1]).token)
   ```

   (`copy()` menyalin hasil ke clipboard — fitur DevTools Chrome/Edge)
3. Paste hasilnya ke `config.json` field `"token"`, restart session

> Catatan teknis: cookie `token` di edlink.id berisi 96-hex char yang di-encode;
> `helpers.getToken()` (global di halaman EdLink) decode jadi token API asli (129 char)
> yang dipakai sebagai `Authorization: Bearer <token>`.

## Daftarkan ke ZCode

Sudah terdaftar otomatis di `~/.zcode/cli/config.json`:

```json
{
  "mcp": {
    "servers": {
      "edlink": {
        "command": "python",
        "args": ["C:\\Users\\Lumi\\Documents\\EDLINK\\edlink_mcp.py"]
      }
    }
  }
}
```

Yang tinggal kamu lakukan: isi `config.json` (langkah Setup di atas), lalu **restart
session ZCode** — MCP server auto-connect saat session baru dibuka. Kalau mau pakai env
vars daripada config.json, tambahkan blok `env` di entry server-nya:

```json
"env": { "EDLINK_EMAIL": "email-kamu", "EDLINK_PASSWORD": "password-kamu" }
```

## Daftarkan ke Claude Desktop

`%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "edlink": {
      "command": "python",
      "args": ["C:\\Users\\Lumi\\Documents\\EDLINK\\edlink_mcp.py"]
    }
  }
}
```

## Cursor / client MCP lain

Format sama: command `python`, argumen path `edlink_mcp.py`, transport stdio.

## Test cepat

```bash
python -c "import edlink_mcp; print('import ok')"
```

Setelah di-daftarkan, tanya agent: *"cek edlink, ada tugas gak?"*

## Catatan keamanan

- `config.json` & `token_cache.json` berisi kredensial/token — jangan di-commit
  (sudah dibantu oleh `.gitignore` bila repo di-init).
- Server hanya berjalan lokal (stdio), kredensial tidak dikirim ke mana pun kecuali
  langsung ke API resmi EdLink.
