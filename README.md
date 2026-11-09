# EdLink MCP Server

**MCP server untuk EdLink (edlink.id / SEVIMA)** — biar agent coding dan ChatGPT bisa lihat
tugas, jadwal, kelas, notifikasi, **mengerjakan tugas, dan mengirimnya** langsung dari akun
masing-masing.

Ada dua bentuk deployment:

| Bentuk | Untuk siapa | Kredensial |
|---|---|---|
| **Platform publik** (`platform_main.py`) | siapa pun yang mau pakai dari ChatGPT atau perangkat lain | akun platform sendiri, akun EdLink sendiri, terenkripsi per user |
| **Lokal stdio** (`edlink_mcp.py`) | satu orang, satu mesin, keamanan maksimal | `config.json` di komputermu sendiri |

Dua-duanya menjalankan 20 tool yang sama. Yang berbeda cuma di mana kredensial disimpan dan
siapa yang boleh memanggil.

> **Lokal tetap yang paling aman.** Tidak ada port terbuka, tidak ada URL yang bisa bocor,
> token EdLink tidak pernah meninggalkan komputer sendiri. Pakai platform publik kalau kamu
> memang butuh akses dari ChatGPT atau dari perangkat lain.

![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![MCP](https://img.shields.io/badge/MCP-stdio%20%2B%20streamable%20HTTP-6E56CF?style=for-the-badge)
![OAuth](https://img.shields.io/badge/OAuth-2.1%20%2B%20PKCE-2F7CF6?style=for-the-badge)
![EdLink](https://img.shields.io/badge/EdLink-reverse--engineered-0A66C2?style=for-the-badge)
![Stars](https://img.shields.io/github/stars/arilumbudeta/edlink-mcp?style=for-the-badge&logo=github&color=FFD700)

---

## Pakai server publik (multi-user)

Server contoh berjalan di:

```
https://8765-agqzr5ia5piewgnk2prlcfqhlm.instabox.tech
```

Langkahnya, tanpa install apa pun:

1. Buka `/signup` di host itu, daftar dengan email + password (minimal 10 karakter).
2. Login, lalu di `/dashboard` hubungkan akun EdLink kamu sendiri. Jalur utamanya
   **email + password EdLink** — server yang login ke EdLink, jadi tidak perlu DevTools.
   Akun yang cuma punya login Google pakai token sekali, lihat
   [Dua jalur koneksi EdLink](#dua-jalur-koneksi-edlink).
3. Salin URL MCP dari dashboard: `https://<host>/mcp`.
4. Di ChatGPT: `chatgpt.com/plugins` → tombol plus → **Add custom MCP server** →
   tempel URL MCP → setujui halaman izin OAuth → **Create as a plugin**.
5. Minta ChatGPT memanggil `edlink_setup_status`. Kalau jawabannya `perlu_setup: false`,
   akunmu sudah nyambung.

### Dua jalur koneksi EdLink

| Jalur | Untuk siapa | Yang dikerjakan |
|---|---|---|
| **Email + password EdLink** (utama) | akun EdLink dengan password | server login sendiri ke `site/login`, token disimpan terenkripsi, diperbarui otomatis saat expired |
| **Token manual** | akun EdLink yang login lewat Google (tanpa password) | kamu ambil token sekali dari DevTools, tempel di dashboard |

Bedanya dengan OAuth ChatGPT: server ini **jadi** authorization server untuk klien MCP
(`/oauth/authorize`, PKCE, DCR). Untuk EdLink peran itu tidak ada — EdLink hanya
menyediakan `site/login` dan `auth/google` (EdLink sebagai *client* Google), tanpa
authorization endpoint untuk pihak ketiga. Jadi tidak ada redirect browser yang bisa
mengembalikan token EdLink ke server ini; yang bisa dilakukan cuma login langsung atau
menyerahkan token sekali.

#### Kalau akun EdLink-mu login lewat Google

Token diambil manual, sekali saja (ulangi kalau sudah expired dan tool meminta):

1. Buka `https://edlink.id`, login lewat Google seperti biasa.
2. Buka DevTools (`F12`) → tab **Console**.
3. Jalankan:

   ```js
   copy(helpers.getToken(document.cookie.match(/(?:^|; )token=([^;]+)/)[1]).token)
   ```

4. Token 129 karakter sudah tersalin ke clipboard.
5. Di `/dashboard`, buka bagian **Akun EdLink** → sub-bagian token → tempel → **Simpan token**.

Token ini kredensial hidup: hanya tempel di dashboard, jangan pernah tempel di chat,
issue, atau commit. Mode token **tidak** auto-refresh — kalau EdLink menolak token karena
expired, tool akan menjawab dengan instruksi mengambil token baru, ulangi langkah 1–5.

Isolasi yang berlaku di server publik:

- Setiap akun punya baris koneksi EdLink sendiri, dienkripsi Fernet dengan kunci di luar
  database (mode 600).
- Token/password EdLink tidak pernah dikirim ke model, tidak masuk log, tidak dicatat di
  audit.
- Tool tidak menerima `user_id` dari argumen; identitas diambil dari bearer token di
  middleware. Satu user tidak bisa menyentuh data user lain.
- Token MCP bisa dicabut kapan saja dari dashboard, dan `Putuskan EdLink` mematikan
  koneksi sekaligus mencabut seluruh token.

Kalau kamu tidak butuh akses jarak jauh, **jangan pakai server publik** — pasang versi
lokal di bawah, itu lebih aman.

Detail arsitektur, skema database, admin, dan batasan: [MULTIUSER.md](MULTIUSER.md).

---

## ⚠️ Ini Reverse Engineering — baca dulu

Project ini **bukan API resmi EdLink** dan **tidak berafiliasi** dengan SEVIMA / EdLink.
Semua endpoint di sini dipetakan lewat **reverse engineering** dari:

- web app `edlink.id`
- PWA `pwa.edlink.id`
- bundle JavaScript `quantum` + `ruang-kelas-pwa`
- probe langsung ke API internal `https://api.edlink.id/api/v1.4`

Artinya:

- Endpoint internal bisa berubah kapan saja.
- Update frontend EdLink juga bisa menggeser nama route atau bentuk response.
- Request data selalu langsung ke `api.edlink.id`. Di mode lokal kredensial tidak pernah
  keluar dari mesinmu; di mode platform kredensial melewati server milikmu sendiri dan
  disimpan terenkripsi per akun.
- Kamu yang punya akun, kamu yang pegang kendali. `edlink_send_tugas` adalah aksi tulis.

Pemetaan dilakukan dengan membaca bundle JavaScript yang dikirim ke browser, mencocokkan
nama route dengan request jaringan, lalu memverifikasi setiap endpoint lewat probe langsung
ke API. Hasilnya bukan dokumentasi resmi, melainkan peta kerja yang cukup untuk membaca
tugas, menyusun jawaban, dan mengirim submission.

Yang berhasil dipetakan:

| Area | Endpoint |
|---|---|
| Auth manual | `site/login` |
| Auth Google (mobile) | `auth/mobile/google` |
| Auth Google (link OAuth) | `auth/google` → 302 ke `accounts.google.com` |
| Tugas terbuka | `home/openassignmentsandquizes` |
| Detail tugas / materi | `learningmaterials/detail/{id}` |
| Jawaban saya | `lecturer-question/detail-answer/{id}` |
| Kirim jawaban | `lecturer-question/set-answer/{id}` |
| Edit jawaban | `lecturer-question/edit-answer/{answerId}` |
| Info submission | `lecturer-question/{id}/lecturer-question-answers/info` |
| Media / lampiran | `media/all`, `media/upload`, `drive/upload` |
| Jadwal | `home/today-schedule`, `home/monthly-schedule` |
| Kelas | `group/academic-lists` |
| Notifikasi | `notification/all` |

---

## Fitur

- **Lihat tugas terbuka** + deadline + kelas.
- **Detail tugas** — instruksi lengkap, lampiran dosen, deadline, status submission.
- **Cek jawaban sendiri** — sudah submit atau belum, jawaban apa yang terkirim.
- **Kirim tugas** — `set-answer` untuk submission baru, `edit-answer` untuk kirim ulang.
- **Upload lampiran** — media pribadi EdLink atau Google Drive EdLink.
- **Auto-pilot** — agent mengerjakan lalu mengirim tugas dalam satu alur.
- **Login link-based** — OAuth Google lewat link, atau manual email + password.
- **Jadwal & kelas** — hari ini, bulanan, daftar kelas.
- **Notifikasi** — semua atau hanya yang belum dibaca.
- **API explorer** — `edlink_api` buat endpoint yang belum dipetakan.
- **Platform multi-user** — tiap orang daftar sendiri, koneksi EdLink terpisah dan
  terenkripsi, admin panel untuk suspend/cabut token.
- **OAuth 2.1 + PKCE** — ChatGPT dan klien lain connect tanpa menempel API key statis;
  access token 30 hari, refresh token 90 hari dengan rotasi.
- **Audit** — login, link/unlink EdLink, dan OAuth dicatat tanpa nilai rahasia.
  Rate limit dimatikan (lihat catatan keamanan).

---

## Tools

| Tool | Fungsi |
|---|---|
| `edlink_tugas()` | Daftar tugas & kuis terbuka + deadline |
| `edlink_tugas_terbaru(urut)` | Ambil satu tugas paling relevan + detail. `urut="deadline"` (dekat deadline) atau `"baru"` (id terbaru) |
| `edlink_tugas_detail(tugas_id)` | Instruksi, lampiran, deadline, submission gate, status jawaban |
| `edlink_tugas_jawaban_saya(tugas_id)` | Jawaban yang sudah kamu kirim (kalau ada) |
| `edlink_send_tugas(tugas_id, jawaban, media_ids, konfirmasi_terlambat)` | **Kirim / edit jawaban tugas** |
| `edlink_media(cari, batas)` | Daftar berkas yang sudah diupload (sumber `media_ids`) |
| `edlink_upload_file(path, ke_drive, parent_id)` | Upload lampiran, balikin `media_id` |
| `edlink_jadwal_hari_ini()` | Jadwal kuliah hari ini |
| `edlink_jadwal_bulanan(bulan, tahun)` | Jadwal bulanan |
| `edlink_kelas()` | Daftar kelas yang diikuti |
| `edlink_notifikasi(hanya_belum_dibaca)` | Notifikasi |
| `edlink_api(path, method, body)` | Panggil endpoint API apa pun (advanced, `method="AUTO"` default) |
| `edlink_setup_status()` | Cek kredensial; kalau belum ada, tampilkan pilihan login |
| `edlink_login_oauth_link()` | Ambil link OAuth Google EdLink |
| `edlink_setup_oauth()` | Buka link OAuth Google EdLink di browser |
| `edlink_setup_token(token)` | Simpan token OAuth/manual setelah divalidasi |
| `edlink_setup_manual(email, password)` | Simpan kredensial email + password |
| `edlink_login_status()` | Validasi token / kredensial yang tersimpan |

Di mode platform, `edlink_setup_token` dan `edlink_setup_manual` menyimpan ke akun platform
yang sedang memanggil (terenkripsi), bukan ke `config.json`. `edlink_setup_status` akan
mengarahkan ke halaman dashboard, bukan meminta token lewat chat.

### Contoh output `edlink_tugas_terbaru`

```json
{
  "ada_tugas": true,
  "urut": "deadline",
  "terpilih": {
    "id": 1234567,
    "judul": "Contoh Tugas Praktikum",
    "kelas": "Algoritma Pemrograman",
    "deadline": "2026-10-09 12:00:00",
    "tipe": "Q"
  },
  "detail": {
    "instruksi_teks": "Lampirkan hasil praktikum 1 sampai 4...",
    "lampiran_tugas": [],
    "sudah_submit": false,
    "bisa_submit": true,
    "perlu_konfirmasi_terlambat": true
  },
  "langkah_berikut": [
    "Baca detail.instruksi_teks dan detail.lampiran_tugas.",
    "Susun jawaban lengkap sesuai instruksi.",
    "Kalau perlu lampiran: edlink_upload_file(path) lalu pakai media_id-nya.",
    "Kirim: edlink_send_tugas(tugas_id, jawaban, media_ids=[...])."
  ]
}
```

---

## Setup lokal (stdio)

1. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

2. Daftarkan MCP server ke client kamu (contoh di bawah).

3. Buka session, lalu panggil:

   ```text
   edlink_setup_status()
   ```

   Hasilnya salah satu:

   - `"perlu_setup": false` → sudah siap, lanjut `edlink_login_status()`.
   - `"perlu_setup": true` → pilih metode login:

     **A. Manual (email + password EdLink)**

     ```text
     edlink_setup_manual(email="email-kamu", password="password-kamu")
     ```

     **B. OAuth Google (link-based)**

     ```text
     edlink_setup_oauth()
     ```

     Tool ini membuka browser default ke link OAuth. Kalau browser tidak terbuka,
     ambil link-nya lewat `edlink_login_oauth_link()` lalu buka manual:

     ```text
     https://api.edlink.id/api/v1.4/auth/google
     ```

     Link ini **302 redirect ke `accounts.google.com`** — jadi memang berbasis link,
     bukan popup lokal. Setelah login Google selesai, browser akan menampilkan JSON
     callback berisi token. Copy token-nya, lalu:

     ```text
     edlink_setup_token(token="token-hasil-login")
     ```

     Kalau yang terbuka halaman EdLink (bukan JSON), buka `edlink.id/classes` lalu
     jalankan di console browser:

     ```js
     copy(helpers.getToken(document.cookie.match(/(?:^|; )token=([^;]+)/)[1]).token)
     ```

> Catatan: kalau kamu memanggil tool lain sebelum setup, MCP otomatis membalas
> prompt pilihan `manual` / `oauth` — bukan error mentah. Tinggal jawab salah satu.

---

## Auto-pilot: "kerjakan tugas terbaru dan send"

Cukup bilang ke agent:

> kerjakan tugas terbaru dan send

Alur yang dijalankan agent:

Alur ini sengaja dibuat pendek supaya agent tidak perlu menebak: satu tool memilih tugas,
satu tool membuka detail, satu tool mengirim. Kalau tugas sudah lewat deadline, tool berhenti
di gate konfirmasi dan menunggu perintah kirim berikutnya.

1. `edlink_tugas_terbaru(urut="deadline")` — ambil tugas paling dekat deadline.
   Pakai `urut="baru"` kalau mau tugas yang paling baru dibuat.
2. `edlink_tugas_detail(tugas_id)` — baca `instruksi_teks`, `lampiran_tugas`, `deadline`.
3. Susun jawaban sesuai instruksi.
4. Kalau tugas minta lampiran:
   `edlink_upload_file(path="C:\\...\\tugas.pdf")` → dapat `media_id`.
5. Kirim:
   ```text
   edlink_send_tugas(
     tugas_id=...,
     jawaban="...",
     media_ids=[...],
     konfirmasi_terlambat=True
   )
   ```
6. Cek hasil: `{"ok": true, "aksi": "kirim", "pesan": "..."}`.

**Submission gate** yang dijaga tool:

- `canSubmit: false` → ditolak.
- `requiresLateConfirmation: true` → balikin `perlu_konfirmasi_terlambat: true`;
  kirim ulang dengan `konfirmasi_terlambat=True` setelah user menyuruh kirim.
- Sudah pernah submit & `canEditSubmission: true` → otomatis pakai `edit-answer`.
- Sudah submit & locked → ditolak.

### Tempel ke AGENTS.md (biar agent langsung paham)

```md
## EdLink auto-pilot
Saat user bilang "kerjakan tugas terbaru dan send":
1. Panggil edlink_tugas_terbaru(urut="deadline").
2. Baca edlink_tugas_detail(tugas_id) — ikuti instruksi_teks.
3. Susun jawaban lengkap; kalau perlu lampiran, edlink_upload_file lalu ambil media_id.
4. Kirim edlink_send_tugas(tugas_id, jawaban, media_ids, konfirmasi_terlambat=True).
5. Laporkan hasil {"ok", "aksi", "pesan"} apa adanya.
```

---

## Daftarkan ke client MCP

### OpenCode

Edit `~/.config/opencode/opencode.json`:

```json
{
  "mcp": {
    "servers": {
      "edlink": {
        "type": "local",
        "command": ["python", "C:\\path\\ke\\edlink-mcp\\edlink_mcp.py"]
      }
    }
  }
}
```

### ZCode

Entry di `~/.zcode/cli/config.json`:

```json
{
  "mcp": {
    "servers": {
      "edlink": {
        "command": "python",
        "args": ["C:\\path\\ke\\edlink-mcp\\edlink_mcp.py"]
      }
    }
  }
}
```

Mau pakai env vars daripada `config.json`? Tambahkan:

```json
"env": { "EDLINK_EMAIL": "email-kamu", "EDLINK_PASSWORD": "password-kamu" }
```

### Claude Desktop

`%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "edlink": {
      "command": "python",
      "args": ["C:\\path\\ke\\edlink-mcp\\edlink_mcp.py"]
    }
  }
}
```

### Cursor / client MCP lain

Format sama: command `python`, argumen path `edlink_mcp.py`, transport stdio.

---

## Mode auth

1. **Mode token** — `config.json` berisi `"token"`. Cocok untuk OAuth Google.
2. **Mode password** — `config.json` berisi `"email"` + `"password"`. Login ulang otomatis
   kalau token expired.

Urutan pembacaan kredensial:

1. Environment variables `EDLINK_TOKEN`, lalu `EDLINK_EMAIL` + `EDLINK_PASSWORD`.
2. `config.json` di folder yang sama dengan `edlink_mcp.py`.
3. `token_cache.json` (cache token maksimal 8 jam).

### Ambil token manual (fallback)

Kalau token expired dan kamu tidak mau lewat `edlink_login_oauth_link()`:

1. Login ke [edlink.id](https://edlink.id) via Google di browser.
2. Setelah masuk ke halaman `/classes`, buka **DevTools (F12) → Console**, jalankan:

   ```js
   copy(helpers.getToken(document.cookie.match(/(?:^|; )token=([^;]+)/)[1]).token)
   ```

3. Paste hasilnya ke `config.json` field `"token"`, atau panggil
   `edlink_setup_token(token="...")`, lalu restart session.

> Catatan teknis: cookie `token` di edlink.id berisi 96-hex char yang di-encode;
> `helpers.getToken()` (global di halaman EdLink) decode jadi token API asli (129 char)
> yang dipakai sebagai `Authorization: Bearer <token>`.

---

## Deploy publik (Streamable HTTP)

Ada dua cara menjalankan server di jaringan:

1. **Single-user HTTP** — `edlink_mcp.py` dengan `EDLINK_MCP_TRANSPORT=http`.
   Satu akun EdLink (punyamu), satu token. Cocok untuk akses pribadi.
2. **Platform multi-user** — `platform_main.py`. Siapa pun bisa daftar, masing-masing
   menghubungkan akun EdLink sendiri, kredensial terpisah dan terenkripsi.
   Ini yang dipakai untuk ChatGPT. Detail: [MULTIUSER.md](MULTIUSER.md).

### Lokal atau publik? Pilih salah satu

**Local MCP (stdio) — paling aman.** Server jalan di mesinmu, tidak ada port
yang terbuka, tidak ada URL yang bisa bocor. Token EdLink tidak pernah keluar
dari komputer sendiri. Ini pilihan yang dipakai kalau kamu hanya memakai satu
perangkat.

**Public URL MCP — praktis.** Server jalan di VM dan bisa diakses dari mana
saja, termasuk ChatGPT. Lebih gampang, tapi URL-nya bisa dipakai siapa pun yang
tahu alamatnya, jadi seluruh isi EdLink-mu ikut terbuka. Pakai ini kalau kamu
butuh akses jarak jauh dan sudah paham risikonya.

**Ringkas:** lokal untuk keamanan maksimal, publik untuk kemudahan. Kalau ragu,
pakai lokal.

### Menjalankan single-user HTTP

```bash
export EDLINK_MCP_TRANSPORT=http
export EDLINK_MCP_PORT=8765
export EDLINK_MCP_ISSUER_URL=https://host.example
export EDLINK_MCP_ALLOWED_HOSTS=host.example,localhost:8765
export EDLINK_MCP_AUTH_TOKEN=$(openssl rand -hex 32)
python edlink_mcp.py
```

Endpoint: `POST https://host.example/mcp`.

### Menjalankan platform multi-user

```bash
export EDLINK_PLATFORM_BASE_URL=https://host.example
export EDLINK_PLATFORM_DB=./data/platform.db
export EDLINK_PLATFORM_KEY_FILE=./data/master.key
export EDLINK_PLATFORM_ADMIN_EMAIL=kamu@example.com
export EDLINK_PLATFORM_ADMIN_PASSWORD=$(openssl rand -hex 24)
export EDLINK_MCP_ALLOWED_HOSTS=host.example
python platform_main.py
```

Endpoint MCP `POST /mcp`, halaman web `/signup`, `/login`, `/dashboard`, `/admin`.
Autentikasi memakai OAuth 2.1 dengan PKCE, jadi klien seperti ChatGPT bisa
menghubungkan akunnya sendiri.

### Menghubungkan ChatGPT ke platform

1. Buka `https://<host>/signup`, daftar akun platform, lalu login.
2. Di `/dashboard`, tempel token EdLink (129 karakter, dari DevTools `edlink.id`)
   atau pilih email + password EdLink. Data ini disimpan terenkripsi, hanya
   untuk akunmu.
3. Salin URL MCP yang tertulis di dashboard: `https://<host>/mcp`.
4. Di ChatGPT buka [chatgpt.com/plugins](https://chatgpt.com/plugins), tekan
   tombol plus, lalu **Add custom MCP server**.
5. Isi nama dan deskripsi, lalu di bagian **Connection** tempel URL MCP
   (termasuk path `/mcp`).
6. Di bagian authentication, selesaikan alur OAuth: halaman izin platform
   terbuka sekali, setujui, dan ChatGPT menerima token untuk akunmu.
   Baca peringatan risiko yang muncul, lalu **I understand and want to continue**.
7. Tekan **Create as a plugin**, lalu periksa daftar tool yang ditemukan.
8. Uji dengan meminta ChatGPT memanggil `edlink_setup_status` — hasilnya harus
   `perlu_setup: false` kalau koneksi EdLink sudah tersimpan.

Kebijakan akun/workspace bisa memblokir custom MCP server; kalau tombolnya
tidak ada, fitur itu dimatikan di workspace tersebut.

Setiap akun hanya melihat data EdLink miliknya sendiri. Tool tidak pernah
menerima `user_id` dari argumen; identitas ditentukan dari token di
`IdentityMiddleware`. Access token berlaku 30 hari dan diperpanjang otomatis
lewat refresh token (90 hari, diputar setiap pemakaian).

### Dua mode auth HTTP single-user

1. **Bearer statis** (default) — `EDLINK_MCP_AUTH_TOKEN` wajib, dibandingkan
   constant-time. Untuk MCP Inspector, Codex, atau skrip sendiri.
2. **Proxy-trust** — `EDLINK_MCP_TRUST_PROXY_AUTH=1` mematikan pemeriksaan
   bearer karena gerbang auth ada di reverse proxy. Dipakai untuk ChatGPT,
   yang tidak bisa mengirim API key statis.

Variabel lengkap ada di [.env.example](.env.example), langkah deployment dan
integrasi ChatGPT ada di [DEPLOYMENT.md](DEPLOYMENT.md).

---

## Test cepat

```bash
python -c "import edlink_mcp; print('import ok')"
python test_mcp_smoke.py      # list semua tools
python test_mcp_call.py       # panggil edlink_login_status
```

Setelah terdaftar, tanya agent:

- *"cek edlink, ada tugas gak?"*
- *"kerjakan tugas terbaru dan send"*
- *"jadwal hari ini apa?"*

---

## Peta endpoint hasil reverse engineering

```text
site/login                         -> email/password login
auth/mobile/google                 -> Google login via Firebase (mobile)
auth/google                        -> 302 ke Google OAuth (link-based)
auth/google/callback               -> callback JSON berisi token
user/profile                       -> validasi token
home/openassignmentsandquizes      -> daftar tugas/kuis terbuka
home/today-schedule                -> jadwal hari ini
home/monthly-schedule              -> jadwal bulanan
group/academic-lists               -> daftar kelas
notification/all                   -> notifikasi
learningmaterials/detail/{id}      -> detail tugas + submissionGate
lecturer-question/detail-answer/{id}      -> jawaban saya
lecturer-question/set-answer/{id}         -> kirim jawaban
lecturer-question/edit-answer/{answerId}  -> edit jawaban
lecturer-question/{id}/lecturer-question-answers/info -> info submission
media/all                          -> daftar media/berkas
media/upload                       -> upload media pribadi (multipart)
drive/upload                       -> upload ke Google Drive EdLink (multipart)
quiz/start/{id}                    -> mulai kuis
```

Semua endpoint di atas kebanyakan **POST**. `edlink_api` default `method="AUTO"`
(coba POST dulu, fallback GET kalau route menolak).

---

## Catatan keamanan

- **Lokal (stdio)**: `config.json` dan `token_cache.json` menyimpan kredensial;
  **jangan di-commit** (sudah dibantu `.gitignore`). Tidak ada port terbuka, kredensial
  hanya ke `api.edlink.id`.
- **Platform publik**: kredensial EdLink dienkripsi per akun (Fernet, kunci di file
  terpisah mode 600), password platform di-hash Argon2id, tidak ada admin default.
- **Rate limit dimatikan** di server publik ini: signup, login, DCR, token, dan link
  EdLink tidak dibatasi. Efeknya brute force password platform dan spam signup jadi
  mungkin. Nyalakan lagi kalau server dibuka untuk khalayak luas.
- **Mode token EdLink tidak auto-refresh.** Kalau token expired, tool meminta token baru;
  ambil ulang lewat DevTools seperti di README. Mode email+password yang memperbarui sendiri.
- `edlink_send_tugas` adalah aksi tulis. Tool ini menghormati `submissionGate` dan
  menolak kalau submission ditutup atau terkunci.
- `edlink_setup_manual` menyimpan password di `config.json` (file lokal, di-ignore git).
  Kalau tidak mau menyimpan password, pakai mode token/OAuth.

---

## Star Progression

[![Star History Chart](https://api.star-history.com/svg?repos=arilumbudeta/edlink-mcp&type=Date)](https://www.star-history.com/#arilumbudeta/edlink-mcp&Date)
