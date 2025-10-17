#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://127.0.0.1:5000}"
PDF="${PDF:-test.pdf}"
SERVER_CONT="${SERVER_CONT:-tatou-server-1}"
STAMP=$(date +%s)

say(){ printf "\n\033[1;36m=> %s\033[0m\n" "$*"; }
ok(){ printf "\033[1;32m✔ %s\033[0m\n" "$*"; }
fail(){ printf "\033[1;31m✘ %s\033[0m\n" "$*"; exit 1; }
js_str(){ sed -n "s/.*\\\"$1\\\"[[:space:]]*:[[:space:]]*\\\"\\([^\"]*\\)\\\".*/\\1/p"; }
js_int(){ sed -n "s/.*\\\"$1\\\"[[:space:]]*:[[:space:]]*\\([0-9]\\+\\).*/\\1/p"; }

[ -f "$PDF" ] || fail "Missing PDF: $PDF"

say "healthz"
curl -sS -m 5 "$BASE/healthz" >/dev/null || fail "healthz failed"; ok "healthz ok"

say "create-user"
CREATE_USER=$(curl -sS -m 10 -X POST "$BASE/api/create-user" \
  -H "Content-Type: application/json" \
  -d "{\"login\":\"demo_$STAMP\",\"password\":\"p@ssw0rd\",\"email\":\"demo_${STAMP}@example.com\"}")
echo "RESP: $CREATE_USER"
USER_ID=$(echo "$CREATE_USER" | js_int id); [ -n "${USER_ID:-}" ] || fail "create-user failed"

say "login"
LOGIN=$(curl -sS -m 10 -X POST "$BASE/api/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"demo_${STAMP}@example.com\",\"password\":\"p@ssw0rd\"}")
echo "RESP: $LOGIN"
TOKEN=$(echo "$LOGIN" | js_str token); [ -n "${TOKEN:-}" ] || fail "login failed"

say "upload-document"
UPLOAD=$(curl -sS -m 20 -X POST "$BASE/api/upload-document" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@$PDF" -F "name=test.pdf")
echo "RESP: $UPLOAD"
DOC_ID=$(echo "$UPLOAD" | js_int id); [ -n "${DOC_ID:-}" ] || fail "upload failed"

say "create-watermark metadata-xmp"
BODY=$(cat <<JSON
{"id": $DOC_ID, "method": "metadata-xmp", "position": "k1_$STAMP", "key": "K2", "secret": "HELLO_XMP_$STAMP", "intended_for": "qa"}
JSON
)
RESP=$(curl -sS -m 30 --fail-with-body -X POST "$BASE/api/create-watermark" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "$BODY") || true
echo "RESP: ${RESP:-<empty>}"

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

say "verify in container"
curl -sS -m 20 -H "Authorization: Bearer $TOKEN" -o "wm_xmp.pdf" "$BASE/api/get-version/$LINK"
docker cp wm_xmp.pdf "$SERVER_CONT":/tmp/wm_xmp.pdf
# Git Bash 下建议 winpty；如果不是 Git Bash，可把 winpty 去掉
if command -v winpty >/dev/null 2>&1; then PFX="winpty "; else PFX=""; fi
${PFX}docker exec -it "$SERVER_CONT" python -c "
from server.src.metadata_watermark import MetadataWatermark;
print(MetadataWatermark().read_secret(pdf_bytes=open('/tmp/wm_xmp.pdf','rb').read(), key='K2'))
"
ok "done"
