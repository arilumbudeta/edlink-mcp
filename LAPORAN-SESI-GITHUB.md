# LAPORAN SESI GITHUB — Setup gh CLI, MCP GitHub, dan Push Repo (9 November 2026)

Laporan ini mendokumentasikan pekerjaan sesi: install `gh` CLI, login OAuth,
registrasi MCP server `github`, pembersihan direktori, dan push project ini ke
GitHub. Tidak ada perubahan pada logika server EdLink.

---

## 1. HASIL AKHIR

| Item | Status |
|---|---|
| Repo GitHub | **https://github.com/arilumbudeta/edlink-mcp** — public, branch `main` |
| Commit pertama | `f763eac` — "Initial commit: EdLink MCP server", 15 file |
| `gh` CLI | v2.103.3 di `C:\Users\Lumi\AppData\Local\Programs\gh-cli\gh.exe`, masuk user PATH |
| Login OAuth | Device flow sukses — dua akun di keyring: **`arilumbudeta` (aktif)** dan `ilmnce` |
| MCP server `github` | Terdaftar di `~/.zcode/cli/config.json` → `mcp.servers.github`, koneksi live terverifikasi |
| File sensitif | `config.json` + `token_cache.json` **tidak ter-track** — diverifikasi via `git ls-files` |

---

## 2. YANG DIUBAH DI LUAR REPO

### `~/.zcode/cli/config.json` (MCP ZCode)

Entry baru, sejajar dengan `edlink`:

```json
"github": {
  "command": "cmd",
  "args": ["/c", "npx", "-y", "mcp-remote", "https://api.githubcopilot.com/mcp/",
           "--header", "Authorization: Bearer <token-gh>"]
}
```

### Akun & token

- Login pertama sebagai `ilmnce`; user kemudian menambah akun `arilumbudeta` dan
  `gh auth switch` ke sana.
- Token MCP **di-wire ulang** ke akun aktif (sed swap token lama→baru di config,
  tanpa token tampil di output) dan koneksi re-verified.
- Konsekuensi: tools `mcp__github__*` beroperasi sebagai `arilumbudeta`.

---

## 3. YANG DIUBAH DI DALAM REPO

| Perubahan | Detail |
|---|---|
| `.gitignore` | Diperluas: `.mcp-env/`, `node_modules/`, `.agent-skills/`, `*.log`, `.venv/`, `.DS_Store` + entri lama (`config.json`, `token_cache.json`, `__pycache__/`, `*.pyc`) |
| Dihapus | `__pycache__/` (regenerable), `install.log` (64KB log install lama) |
| Git identity | Lokal ke repo ini: `arilumbudeta <324909238+arilumbudeta@users.noreply.github.com>` (noreply agar commit ke-link ke akun GitHub) |
| Remote | `origin` = `https://github.com/arilumbudeta/edlink-mcp.git`, `main` → `origin/main` |

**Isi repo (15 file):** `README.md`, `LAPORAN-PERUBAHAN.md`, `edlink_mcp.py`,
`edlink_sync_materi.py`, `smoke.py`, `test_mcp_call.py`, `test_mcp_smoke.py`,
`verify.ps1`, `requirements.txt`, `config.example.json`, `.gitignore`,
`tools/spec-x-v2.md.TODO`, `ts/{package.json,package-lock.json,tsconfig.json}`.

**Yang sengaja tidak masuk repo:**

| Direktori/file | Ukuran | Alasan |
|---|---|---|
| `config.json`, `token_cache.json` | ~1KB | Bawa token SSO EdLink yang masih live |
| `.mcp-env/` | 211MB | venv Python, regenerable dari `requirements.txt` |
| `.agent-skills/` | 118MB | Klone skill pihak ketiga (shallow clone ulang lihat `.agent-skills/README.md`) |
| `ts/node_modules/` | 54MB | Regenerable dari `package-lock.json` |

---

## 4. TEMUAN TEKNIS (biar nggak diulang dua kali)

1. **winget corrupt** — `0x8a15000f` ("Data required by the source is missing");
   `winget source reset --force` menolak karena butuh admin. Jalur lain: zip
   langsung dari GitHub releases.
2. **Zip gh diekstrak flat** — `bin/gh.exe` langsung di root zip, tanpa folder
   versi. Git Bash `tar` tidak bisa baca zip — pakai PowerShell
   `Expand-Archive`.
3. **Git Bash memangsa `$var`** dalam command `powershell -Command "..."` pakai
   double-quote — variabel PowerShell harus lewat file `.ps1` (sesuai catatan
   di AGENTS.md).
4. **OAuth browser mcp-remote GAGAL** untuk `api.githubcopilot.com/mcp/`:
   `Incompatible auth server: does not support dynamic client registration`.
   Jalur yang jalan: token dari `gh auth login` (device flow) → header
   `Authorization: Bearer`.
5. **`gh auth token` mengikuti akun aktif** — setelah `gh auth switch`, token
   yang keluar berubah. Ambil token akun spesifik: `gh auth token -u <akun>`.
6. **PATH tidak instan** — jendela shell yang dibuka sebelum perubahan
   `HKCU:\Environment` tidak kenal `gh`; fix instan
   `$env:Path += ';C:\Users\Lumi\AppData\Local\Programs\gh-cli'` atau buka
   window baru (dari dalam ZCode: aplikasi ZCode-nya harus di-restart dulu).
7. **Sweep rahasia pra-commit** — grep token `b0ce2872…` di seluruh direktori:
   hanya ada di `config.json` + `token_cache.json` (keduanya di-ignore). Tidak
   ada Bearer/hex di kode, README, atau laporan. `config.example.json` berisi
   placeholder saja.

---

## 5. CATATAN KEAMANAN

- Token EdLink (SSO) tidak pernah keluar dari dua file lokal yang di-ignore;
  belum pernah masuk git history (repo di-init setelah `.gitignore` siap).
- Token GitHub (40-char, OAuth gh) disimpan di Windows keyring; di config MCP
  hanya sebagai header Bearer lokal (stdio, tidak dikirim ke mana pun selain
  `api.githubcopilot.com`).
- Repo **public** berdokumentasi API internal edlink.id hasil reverse
  engineering — kredensial tidak ikut, tapi endpoint & pola auth iya. Putuskan
  sendiri kalau nanti mau di-private (`gh repo edit arilumbudeta/edlink-mcp --visibility private`).

---

## 6. CARA PAKAI ULANG

```powershell
# Switch akun GitHub lalu samakan token MCP:
gh auth switch -u ilmnce
$tok = gh auth token
# ganti header Authorization di ~/.zcode/cli/config.json dengan $tok, restart sesi

# Workflow commit berikutnya:
git add -A
git commit -m "pesan"
git push
```

Restart sesi ZCode setelah config MCP berubah agar `mcp__github__*` muncul.
