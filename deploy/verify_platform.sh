#!/usr/bin/env bash
# Verifikasi cepat deployment platform multi-user.
# Jalankan di VM: bash deploy/verify_platform.sh
# Tidak pernah mencetak token, password, atau isi kredensial.
set -u
cd "$(dirname "$0")/.." || exit 1

REPO_DIR="$(pwd)"
PY="./.venv/bin/python"
BASE="${EDLINK_PLATFORM_BASE_URL:-}"
FAILED=0

pass() { echo "  ok   $1"; }
fail() { echo "  FAIL $1"; FAILED=$((FAILED + 1)); }

echo "=== service ==="
for unit in edlink-platform.service; do
  enabled=$(systemctl is-enabled "$unit" 2>/dev/null || echo unknown)
  active=$(systemctl is-active "$unit" 2>/dev/null || echo unknown)
  [ "$enabled" = "enabled" ] && pass "$unit enabled" || fail "$unit enabled ($enabled)"
  [ "$active" = "active" ] && pass "$unit active" || fail "$unit active ($active)"
done

echo
echo "=== http ==="
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8765/health)
[ "$code" = "200" ] && pass "health 200" || fail "health $code"

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8765/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
[ "$code" = "401" ] && pass "MCP tanpa token 401" || fail "MCP tanpa token $code"

www=$(curl -s -D - -o /dev/null -X POST http://127.0.0.1:8765/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | grep -i '^www-authenticate')
echo "$www" | grep -q 'resource_metadata' && pass "401 memuat resource_metadata" || fail "header WWW-Authenticate"

grants=$(curl -s http://127.0.0.1:8765/.well-known/oauth-authorization-server)
echo "$grants" | grep -q '"S256"' && pass "metadata S256" || fail "metadata S256"
echo "$grants" | grep -q 'refresh_token' && pass "metadata refresh_token" || fail "metadata refresh_token"

echo
echo "=== data ==="
if [ -f data/master.key ]; then
  mode=$(stat -c '%a' data/master.key)
  [ "$mode" = "600" ] && pass "master.key mode 600" || fail "master.key mode $mode"
else
  fail "master.key tidak ada"
fi
[ -f data/platform.db ] && pass "platform.db ada" || fail "platform.db tidak ada"

cat > /tmp/verify_platform_check.py <<'PY'
import os
import sqlite3
import sys

repo = os.getcwd()
sys.path.insert(0, repo)
os.environ.setdefault("EDLINK_PLATFORM_DB", os.path.join(repo, "data", "platform.db"))
os.environ.setdefault("EDLINK_PLATFORM_KEY_FILE", os.path.join(repo, "data", "master.key"))

from edlink_platform import db, security, store  # noqa: E402

db.init_db()
admin = db.q1("SELECT id, email FROM users WHERE is_admin=1 ORDER BY created_at LIMIT 1")
if admin is None:
    print("  FAIL tidak ada admin")
else:
    print("  ok   admin ada:", admin["email"])
    try:
        creds = store.load_credentials(admin["id"])
        kind = "token" if "token" in creds else "email+password"
        print(f"  ok   kredensial admin bisa didekripsi ({kind})")
    except store.NoConnection:
        print("  warn admin belum menghubungkan EdLink")
    except Exception as exc:
        print("  FAIL dekripsi kredensial:", type(exc).__name__)

bad = db.q1("SELECT COUNT(*) AS n FROM users WHERE email LIKE '%@test.local'")
print(f"  {'ok  ' if bad['n'] == 0 else 'warn'} baris test user: {bad['n']}")
conn = sqlite3.connect(os.environ["EDLINK_PLATFORM_DB"])
for table in ("user_sessions", "edlink_connections", "mcp_tokens", "oauth_refresh_tokens"):
    n = conn.execute(
        f"SELECT COUNT(*) FROM {table} WHERE user_id NOT IN (SELECT id FROM users)"
    ).fetchone()[0]
    print(f"  {'ok  ' if n == 0 else 'FAIL'} baris yatim {table}: {n}")
conn.close()
PY
"$PY" /tmp/verify_platform_check.py
rm -f /tmp/verify_platform_check.py

echo
echo "=== secret scan (journal) ==="
if sudo -n true 2>/dev/null; then
  if sudo journalctl -u edlink-platform.service --no-pager -o cat 2>/dev/null |
     grep -qiE 'edm_[A-Za-z0-9_-]{20,}|edr_[A-Za-z0-9_-]{20,}|ibp_|Bearer [A-Za-z0-9._-]{20,}|password=[^ ]{6,}'; then
    fail "jejak rahasia di journal"
  else
    pass "journal bersih"
  fi
else
  echo "  skip butuh sudo tanpa password"
fi

echo
if [ -n "$BASE" ]; then
  echo "=== public endpoint ($BASE) ==="
  code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/health")
  [ "$code" = "200" ] && pass "public health 200" || fail "public health $code"
  code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/.well-known/oauth-protected-resource")
  [ "$code" = "200" ] && pass "public metadata 200" || fail "public metadata $code"
fi

echo
if [ "$FAILED" -eq 0 ]; then
  echo "RESULT: OK"
  exit 0
fi
echo "RESULT: $FAILED masalah"
exit 1
