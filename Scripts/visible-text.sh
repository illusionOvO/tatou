#!/usr/bin/env bash
set -euo pipefail

# ==============================
# 配置（可用环境变量覆盖）
# ==============================
BASE="${BASE:-http://127.0.0.1:5000}"
PDF="${PDF:-test.pdf}"                  # 本地测试 PDF
SERVER_CONT="${SERVER_CONT:-tatou-server-1}"

METHOD="visible-text-redundant"
POSITION="${POSITION:-br}"
KEY="${KEY:-K3}"
STAMP=$(date +%s)
SECRET="${SECRET:-HELLO_VTEXT_${STAMP}}"
INTENDED_FOR="${INTENDED_FOR:-qa-user-${STAMP}}"

TS=$(date +%s)
LOGIN="demo_${TS}"
EMAIL="demo_${TS}@example.com"
PASSWORD="p@ssw0rd"

# ==============================
# 小工具（无 jq 解析 JSON）
# ==============================
say()  { printf "\n\033[1;96m==> %s\033[0m\n" "$*"; }
ok()   { printf "\033[1;32m✔ %s\033[0m\n" "$*"; }
die()  { printf "\033[1;91m[ERROR]\033[0m %s\n" "$*" >&2; exit 1; }
jstr() { sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" <<<"$1"; }
jint() { sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\\([0-9]\\+\\).*/\\1/p" <<<"$1"; }

# ==============================
# 0) 预检查
# ==============================
[ -f "$PDF" ] || die "找不到 PDF: $PDF"

# ==============================
# 1) 健康检查
# ==============================
say "health check /healthz"
curl -sS -m 5 "$BASE/healthz" >/dev/null || die "后端不可用"
ok "healthz ok"

# ==============================
# 2) 创建用户（存在也不影响）
# ==============================
say "Create-user /api/create-user"
curl -sS -m 10 -X POST "$BASE/api/create-user" \
  -H "Content-Type: application/json" \
  -d "{\"login\":\"$LOGIN\",\"password\":\"$PASSWORD\",\"email\":\"$EMAIL\"}" >/dev/null || true

# ==============================
# 3) 登录换 token
# ==============================
say "Login /api/login"
LOGIN_JSON=$(curl -sS -m 10 -X POST "$BASE/api/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")
echo "RESP: $LOGIN_JSON"
TOKEN=$(jstr "$LOGIN_JSON" token)
[ -n "${TOKEN:-}" ] || die "登录失败，未拿到 token"
ok "token=${TOKEN:0:16}..."

# ==============================
# 4) 上传 PDF
# ==============================
say "Upload PDF /api/upload-document"
UP_JSON=$(curl -sS -m 30 -X POST "$BASE/api/upload-document" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@${PDF};type=application/pdf" \
  -F "name=$(basename "$PDF")")
echo "RESP: $UP_JSON"
DOC_ID=$(jint "$UP_JSON" id); [ -n "$DOC_ID" ] || DOC_ID=$(jstr "$UP_JSON" id)
[ -n "${DOC_ID:-}" ] || die "上传失败，未拿到文档 id"
ok "doc_id=$DOC_ID"

# ==============================
# 5) 创建 visible-text 水印版本
# ==============================
say "Create-watermark /api/create-watermark  method=${METHOD}"
BODY=$(cat <<JSON
{"id": $DOC_ID, "method": "$METHOD", "position": "$POSITION",
 "key": "$KEY", "secret": "$SECRET", "intended_for": "$INTENDED_FOR"}
JSON
)
CW_JSON=$(curl -sS -m 60 --fail-with-body -X POST "$BASE/api/create-watermark" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "$BODY") || true
echo "RESP: ${CW_JSON:-<empty>}"

# 解析 link（40hex），容错 Duplicate
LINK=$(sed -n 's/.*"link"[[:space:]]*:[[:space:]]*"\([a-f0-9]\{40\}\)".*/\1/p' <<<"$CW_JSON")
if [ -z "${LINK:-}" ] && grep -qi "Duplicate entry" <<<"$CW_JSON"; then
  LINK=$(grep -oE '[a-f0-9]{40}' <<<"$CW_JSON" | head -n1 || true)
fi
if [ -z "${LINK:-}" ]; then
  LV=$(curl -sS -m 10 -H "Authorization: Bearer $TOKEN" "$BASE/api/list-versions/$DOC_ID") || true
  LINK=$(sed -n 's/.*"link"[[:space:]]*:[[:space:]]*"\([a-f0-9]\{40\}\)".*/\1/p' <<<"$LV" | tail -n1)
fi
[ -n "${LINK:-}" ] || die "未能获取版本 link"
ok "link=$LINK"

# ==============================
# 6) 下载并验证（容器内调用 VisibleTextWatermark.read_secret）
# ==============================
say "Verify watermark -> 容器内 read_secret(key='$KEY')"
curl -sS -m 30 -H "Authorization: Bearer $TOKEN" \
  -o wm_vtext.pdf "$BASE/api/get-version/$LINK"

docker cp wm_vtext.pdf "$SERVER_CONT":/tmp/wm_vtext.pdf
if command -v winpty >/dev/null 2>&1; then PFX="winpty "; else PFX=""; fi
${PFX}docker exec -it "$SERVER_CONT" python -c "
from server.src.visible_text import VisibleTextWatermark;
print(VisibleTextWatermark().read_secret(open('/tmp/wm_vtext.pdf','rb').read(), key='K3'))
"

ok "Done"

# ==============================
# 7) （可选）列版本 & 删除文档
# ==============================
say "List version /api/list-versions/$DOC_ID"
curl -sS -m 10 -H "Authorization: Bearer $TOKEN" "$BASE/api/list-versions/$DOC_ID" | head -c 600; echo

# 如不想删除，请注释掉下面两行
say "Delete document /api/delete-document/$DOC_ID"
curl -sS -m 10 -X DELETE -H "Authorization: Bearer $TOKEN" "$BASE/api/delete-document/$DOC_ID" || true
ok "All done"
