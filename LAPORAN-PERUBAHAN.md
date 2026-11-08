# LAPORAN PERUBAHAN — Sesi Sinkronisasi Materi (9 November 2026)

Laporan ini mendokumentasikan apa yang **ditambahkan** dan apa yang **tidak disentuh**
pada direktori `C:\path\ke\EDLINK` selama sesi unduh materi EdLink,
plus temuan teknis API yang relevan untuk pengembangan MCP ke depan.

---

## 1. FILE YANG DITAMBAHKAN

### `edlink_sync_materi.py` (baru)

Script unduh massal materi EdLink ke `C:\path\ke\Kuliah` (default `~/Documents/Kuliah`), satu folder
per sesi. **Bukan bagian dari MCP server** — script terpisah yang memakai pola yang
sama dengan `edlink_mcp.py`.

**Relasi dengan `edlink_mcp.py` (reused, tidak dimodifikasi):**
- Token dibaca dari `token_cache.json` yang sama (fallback `config.json`) — tanpa login ulang.
- `API_BASE = https://api.edlink.id/api/v1.4` dan header yang sama
  (`X-App-Locale: id`, `X-Referer: https://edlink.id/login`, `Authorization: Bearer`).
- Pola request POST-dulu, fallback GET kalau Laravel menolak ("Supported methods").
- HTTP client `httpx` (bukan `requests`) karena itu yang terpasang di environment ini.

**Fitur tambahan di luar MCP:**
| Fitur | Keterangan |
|---|---|
| Fallback Google Drive | Media dengan `storageType: google_drive` balikin 401 dari link GCS `assets-edlink` — script jatuh ke `values.downloadLink`, termasuk menyelesaikan halaman interstitial Drive (form confirm) |
| Verifikasi magic bytes | `%PDF`, `PK` (pptx/docx/xlsx), `\xd0\xcf\x11\xe0` (ppt lama) — file rusak/HTML terdeteksi dan dihapus |
| Dedupe | Per `media.id` (satu file ke-naruh dua sesi hanya diunduh sekali) + skip nama file yang sudah ada di mana pun di folder kelas |
| Mapping folder sesi | Konvensi lokal dipertahankan: `Pertemuan N` (umum), `SESI NN` (Aljabar Linier), `UTS`/`UAS` untuk section type 1/2 |
| Folder `Referensi` | Materi berjudul "Buku …" / "RPS …" dipisah ke subfolder `Referensi`, tidak mencampur slide pertemuan |
| Laporan per kelas | `[OK] / [skip] / [GAGAL] / [tanpa-link]` per file, aman dijalankan ulang (idempoten) |

---

## 2. FILE YANG TIDAK DIUBAH

Demi kejelasan — **tidak ada** perubahan pada:

- `edlink_mcp.py` (server MCP-nya sendiri)
- `config.json`, `token_cache.json` (token cache lama masih segar, dipakai apa adanya)
- `README.md`, `smoke.py`, `test_mcp_*.py`, `verify.ps1`, `requirements.txt`
- `tools/`, `ts/`, `__pycache__/`

---

## 3. TEMUAN TEKNIS API (berguna untuk pengembangan MCP)

1. **Semua endpoint menolak GET.** `user/profile`, `notification/all`, `sections/all/{id}`
   semuanya wajib POST (body `{}` cukup). Pesan Laravel: "The GET method is not supported…".
   MCP sudah punya fallback ini; sinkronisasi mengikuti pola yang sama.
2. **`group/me` balikin array kosong** (GET maupun POST, dengan/tanpa param limit).
   Daftar kelas tidak bisa diambil dari endpoint ini.
3. **Sumber ID kelas alternatif yang terbukti jalan:**
   - `notification/all` → munculkan `groupId` + nama kelas dari notifikasi materi/tugas.
   - Endpoint jadwal bulanan (monthly-schedule) → tiap entri perkuliahan punya
     `section.group_id`; ini yang menyelamatkan 2 kelas yang tidak muncul di notifikasi.
4. **Paginasi `notification/all?page=2` tidak berfungsi** via param query — halaman 2
   balikin isi halaman 1. (Total 11 notifikasi, hanya 10 yang bisa dibaca.)
5. **Link GCS untuk media Google Drive dilindungi (401).** Media yang dosennya upload
   via Drive (Statistika, Aljabar Linier, PTI sesi 2) tidak bisa diunduh dari
   `file.link`; harus lewat `values.downloadLink` + penanganan interstitial.
6. **Kelas yang terdata saat sesi ini (7 total):**

   | Group ID | Kelas | Kelas paralel |
   |---|---|---|
   | 2247265 | Algoritma Pemrograman | S1A |
   | 2224297 | Pengantar Teknologi Informasi | S1A |
   | 2224607 | Statistika | S1A |
   | 2263993 | Aljabar Linier | S1A |
   | 2326974 | Agama | S1BX |
   | 2224558 | Logika Matematika | S1A |
   | 2226879 | Bahasa Jepang (Huruf & Perkenalan Diri) | S1AL |

---

## 4. HASIL SINKRONISASI

**46 file baru terunduh** (semua lolos verifikasi magic bytes):

| Kelas | Folder | File baru | Catatan |
|---|---|---|---|
| Algoritma Pemrograman | Pertemuan 1–7, UTS, Referensi | 7 | 3 buku + RPS ke `Referensi`; sisanya materi 4, kuis sesi 5, materi sesi 6 |
| Pengantar Informatika | Pertemuan 2, 3, 5, 6 | 4 | Sesi 4 = duplikat file sesi 3 di EdLink → ter-dedupe |
| Statistika | Pertemuan 1–7 | 9 | Termasuk PPT-02 & PPT-03 via fallback Drive (33 MB-an) |
| Aljabar Linier | SESI 01–07 | 7 | Semua materi via fallback Drive |
| Agama | Pertemuan 1–7 | 15 | Semua presentasi kelompok |
| Logika Matematika | Pertemuan 1–3 | 4 | 3 PDF + `tabel kebenaran.xlsx` |
| Bahasa Jepang | (folder dibuat, kosong) | 0 | Terverifikasi: 0 media di seluruh 16 sesi — dosen belum upload apapun |

Verifikasi akhir: 60 file materi (pdf/pptx/docx/ppt) di seluruh folder Kuliah
discan magic bytes — **0 korup**. File kerjaan lama (tugas, drawio, cpp, py)
tidak disentuh.

---

## 5. CARA PAKAI ULANG

```powershell
python -I C:\path\ke\EDLINK\edlink_sync_materi.py
```

Idempoten: file yang sudah ada di-skip, hanya materi baru yang diunduh.
Kalau token cache expired, refresh token dulu lewat prosedur di `README.md`
(sinkronisasi tidak melakukan login sendiri).
