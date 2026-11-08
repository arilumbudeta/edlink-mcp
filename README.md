# EdLink MCP Server

**MCP server untuk EdLink (edlink.id / SEVIMA)** — biar agent coding bisa lihat tugas,
jadwal, kelas, notifikasi, **mengerjakan tugas, dan mengirimnya** langsung dari akun kamu.

Project ini menggabungkan pembacaan data akademik dengan aksi pengiriman tugas, jadi agent
tidak cuma bisa menjawab "ada tugas apa" — ia juga bisa membaca instruksi, menyusun jawaban,
mengunggah lampiran, dan mengirimkannya lewat alur yang sama dengan web EdLink. Semua tool
berjalan lewat stdio lokal dan memakai token akun kamu sendiri, sehingga tidak ada server
perantara yang menyimpan kredensial.

![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![MCP](https://img.shields.io/badge/MCP-stdio-6E56CF?style=for-the-badge)
![EdLink](https://img.shields.io/badge/EdLink-reverse--engineered-0A66C2?style=for-the-badge)
![Stars](https://img.shields.io/github/stars/arilumbudeta/edlink-mcp?style=for-the-badge&logo=github&color=FFD700)

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
- Semua request tetap langsung ke `api.edlink.id`; kredensial tidak mampir ke server pihak ketiga.
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

## Setup pertama kali (interaktif)

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

Selain stdio, server bisa jalan sebagai endpoint HTTP jarak jauh. Default tetap
stdio; HTTP hanya aktif kalau `EDLINK_MCP_TRANSPORT` diset.

```bash
export EDLINK_MCP_TRANSPORT=http
export EDLINK_MCP_PORT=8765
export EDLINK_MCP_ISSUER_URL=https://host.example
export EDLINK_MCP_ALLOWED_HOSTS=host.example,localhost:8765
export EDLINK_MCP_AUTH_TOKEN=$(openssl rand -hex 32)
python edlink_mcp.py
```

Endpoint: `POST https://host.example/mcp`.

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

Dua mode auth HTTP:

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

- Dua file lokal — `config.json` dan `token_cache.json` — menyimpan kredensial;
  **jangan di-commit** (sudah dibantu `.gitignore`).
- Server hanya berjalan lokal (stdio). Kredensial tidak dikirim ke mana pun kecuali
  langsung ke API resmi EdLink.
- `edlink_send_tugas` adalah aksi tulis. Tool ini menghormati `submissionGate` dan
  menolak kalau submission ditutup atau terkunci.
- `edlink_setup_manual` menyimpan password di `config.json` (file lokal, di-ignore git).
  Kalau tidak mau menyimpan password, pakai mode token/OAuth.

---

## Star Progression

[![Star History Chart](https://api.star-history.com/svg?repos=arilumbudeta/edlink-mcp&type=Date)](https://www.star-history.com/#arilumbudeta/edlink-mcp&Date)
