#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://127.0.0.1:5000}"
PDF="${PDF:-test.pdf}"
SERVER_CONT="${SERVER_CONT:-tatou-server-1}"

# ---------- 1) 路径处理：把 Windows 路径转为 Unix，并校验 ----------
PDF_UNIX="$(cygpath -u "$PDF" 2>/dev/null || echo "$PDF")"
[ -r "$PDF_UNIX" ] || { echo "Missing PDF: $PDF_UNIX" >&2; exit 26; }

# ---------- 2) 打印与辅助 ----------
say(){ printf "\n\033[1;36m=> %s\033[0m\n" "$*"; }
ok(){ printf "\033[1;32m✔ %s\033[0m\n" "$*"; }
fail(){ printf "\033[1;31m✘ %s\033[0m\n" "$*"; exit 1; }
js_str(){ sed -n "s/.*\\\"$1\\\"[[:space:]]*:[[:space:]]*\\\"\\([^\"]*\\)\\\".*/\\1/p"; }
js_int(){ sed -n "s/.*\\\"$1\\\"[[:space:]]*:[[:space:]]*\\([0-9]\\+\\).*/\\1/p"; }

# ---------- 3) healthz（兼容 /api/healthz 与 /healthz） ----------
say "healthz"
curl -sS -m 5 "$BASE/api/healthz" >/dev/null || \
curl -sS -m 5 "$BASE/healthz"     >/dev/null || fail "healthz failed"
ok "healthz ok"

# ---------- 4) 每次唯一的账号，避免“email already exists” ----------
TS="$(date +%s%N)"; RND="$RANDOM"
LOGIN="demo_${TS}_${RND}"
EMAIL="${LOGIN}@example.com"
PASSWORD="P@ss-${TS}"

say "create-user"
CREATE_USER=$(curl -sS --fail-with-body -m 10 -X POST "$BASE/api/create-user" \
  -H "Content-Type: application/json" \
  -d "{\"login\":\"$LOGIN\",\"password\":\"$PASSWORD\",\"email\":\"$EMAIL\"}") || {
  echo "RESP: ${CREATE_USER:-<empty>}"; fail "create-user failed"
}
echo "RESP: $CREATE_USER"
USER_ID=$(echo "$CREATE_USER" | js_int id); [ -n "${USER_ID:-}" ] || fail "parse user id failed"

say "login"
LOGIN_JSON=$(curl -sS --fail-with-body -m 10 -X POST "$BASE/api/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}") || {
  echo "RESP: ${LOGIN_JSON:-<empty>}"; fail "login failed"
}
echo "RESP: $LOGIN_JSON"
TOKEN=$(echo "$LOGIN_JSON" | js_str token); [ -n "${TOKEN:-}" ] || fail "token missing"

# ---------- 5) 上传 PDF（使用转换后的路径） ----------
say "upload-document"
UPLOAD=$(curl -sS --fail-with-body -m 20 -X POST "$BASE/api/upload-document" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@${PDF_UNIX};type=application/pdf" \
  -F "name=$(basename "$PDF_UNIX")") || {
  echo "RESP: ${UPLOAD:-<empty>}"; fail "upload failed"
}
echo "RESP: $UPLOAD"
DOC_ID=$(echo "$UPLOAD" | js_int id); [ -n "${DOC_ID:-}" ] || fail "parse doc id failed"

# ---------- 6) 写入 XMP 元数据水印 ----------
say "create-watermark metadata-xmp"
BODY=$(cat <<JSON
{"id": $DOC_ID, "method": "metadata-xmp", "position": "k1_$TS", "key": "K2", "secret": "HELLO_XMP_$TS", "intended_for": "qa"}
JSON
)
RESP=$(curl -sS --fail-with-body -m 30 -X POST "$BASE/api/create-watermark" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "$BODY") || true
echo "RESP: ${RESP:-<empty>}"

# 兼容：直接取 link；若重复则回退到 list-versions
LINK=$(echo "$RESP" | sed -n 's/.*"link"[[:space:]]*:[[:space:]]*"\([a-f0-9]\{40\}\)".*/\1/p')
if [ -z "${LINK:-}" ] && echo "$RESP" | grep -qi "Duplicate entry"; then
  LINK=$(echo "$RESP" | grep -oE '[a-f0-9]{40}' | head -n1 || true)
  [ -n "${LINK:-}" ] && ok "duplicate -> reuse link: $LINK"
fi
if [ -z "${LINK:-}" ]; then
  say "fallback list-versions"
  LV=$(curl -sS -m 10 -H "Authorization: Bearer $TOKEN" "$BASE/api/list-versions/$DOC_ID") || true
  echo "LIST: $LV"
  LINK=$(echo "$LV" | sed -n 's/.*"link"[[:space:]]*:[[:space:]]*"\([a-f0-9]\{40\}\)".*/\1/p' | tail -n1)
fi
[ -n "${LINK:-}" ] || fail "no link returned"
ok "link=$LINK"

# ---------- 7) 容器内校验（自适应 TTY） ----------
say "verify in container"
curl -sS --fail-with-body -m 20 -H "Authorization: Bearer $TOKEN" -o "wm_xmp.pdf" "$BASE/api/get-version/$LINK"
docker cp wm_xmp.pdf "$SERVER_CONT":/tmp/wm_xmp.pdf
TTY_OPTS="-i"; [ -t 1 ] && TTY_OPTS="-it"
docker exec $TTY_OPTS "$SERVER_CONT" python -c "
from server.src.metadata_watermark import MetadataWatermark
print(MetadataWatermark().read_secret(pdf_bytes=open('/tmp/wm_xmp.pdf','rb').read(), key='K2'))
"
ok "metadata flow ok"
exit 0
