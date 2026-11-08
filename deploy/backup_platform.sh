#!/usr/bin/env bash
# Backup database platform + master key, konsisten walau service jalan.
#
#   bash deploy/backup_platform.sh [folder-tujuan]
#
# Tanpa master.key, isi tabel edlink_connections tidak bisa didekripsi.
# Keduanya harus disimpan bersama. Retensi default: 14 backup terakhir.
set -eu
cd "$(dirname "$0")/.." || exit 1

REPO_DIR="$(pwd)"
DB="${EDLINK_PLATFORM_DB:-$REPO_DIR/data/platform.db}"
KEY="${EDLINK_PLATFORM_KEY_FILE:-$REPO_DIR/data/master.key}"
DEST="${1:-$REPO_DIR/backups}"
KEEP="${EDLINK_PLATFORM_BACKUP_KEEP:-14}"
STAMP="$(date +%Y%m%d-%H%M%S)"

[ -f "$DB" ] || { echo "database tidak ada: $DB" >&2; exit 1; }
[ -f "$KEY" ] || { echo "master key tidak ada: $KEY" >&2; exit 1; }

mkdir -p "$DEST"
chmod 700 "$DEST"

PY="./.venv/bin/python"
[ -x "$PY" ] || PY="python3"

# .backup memakai SQLite online backup API: aman dipanggil saat WAL aktif.
"$PY" - "$DB" "$DEST/platform-$STAMP.db" <<'PY'
import sqlite3
import sys

src, dst = sys.argv[1], sys.argv[2]
with sqlite3.connect(src) as source, sqlite3.connect(dst) as target:
    source.backup(target)
print(f"database -> {dst}")
PY

cp "$KEY" "$DEST/master-$STAMP.key"
chmod 600 "$DEST/platform-$STAMP.db"
chmod 600 "$DEST/master-$STAMP.key"
echo "key      -> $DEST/master-$STAMP.key"

# Verifikasi restore cepat: buka salinan dan baca skema.
"$PY" - "$DEST/platform-$STAMP.db" <<'PY'
import sqlite3
import sys

conn = sqlite3.connect(sys.argv[1])
tables = conn.execute(
    "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
).fetchone()[0]
users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
conn.close()
print(f"verify   -> {tables} tabel, {users} user")
PY

# Retensi: simpan $KEEP pasangan terbaru.
ls -1t "$DEST"/platform-*.db 2>/dev/null | tail -n +$((KEEP + 1)) | while read -r old; do
  stamp="$(basename "$old" | sed 's/^platform-//; s/\.db$//')"
  rm -f "$old" "$DEST/master-$stamp.key"
done

echo
echo "backup selesai di $DEST"
ls -1t "$DEST" | head -6
