#!/usr/bin/env bash
set -euo pipefail

# ==============================
# 配置（可用环境变量覆盖）
# ==============================
BASE="${BASE:-http://127.0.0.1:5000}"
PDF="${PDF:-test.pdf}"          # 本机测试 PDF：Windows 用 E:/...；Linux 用 /home/...
SERVER_CONT="${SERVER_CONT:-tatou-server-1}"

METHOD="${METHOD:-visible-text-redundant}"
POSITION="${POSITION:-br}"
KEY="${KEY:-K3}"

STAMP="$(date +%s)"
SECRET="${SECRET:-HELLO_VTEXT_${STAMP}}"
INTENDED_FOR="${INTENDED_FOR:-qa-user-${STAMP}}"

# 动态唯一账号，避免 email/login 已存在
TS="$(date +%s%N)"; RND="$RANDOM"
LOGIN="demo_${TS}_${RND}"
EMAIL="${LOGIN}@example.com"
PASSWORD="P@ss-${TS}"

# ==============================
# 路径统一（关键：避免 curl (26)）
# ==============================
if command -v cygpath >/dev/null 2>&1; then
  PDF_UNIX="$(cygpath -u "$PDF")"
elif command -v wslpath >/dev/null 2>&1; then
  PDF_UNIX="$(wslpath -a "$PDF")"
else
  PDF_UNIX="$PDF"
fi
: "${PDF_UNIX:=$PDF}"          # 防御：确保在 set -u 下已定义
[ -r "$PDF_UNIX" ] || { echo "Missing PDF: $PDF_UNIX" >&2; exit 26; }

# ==============================
# 小工具（无 jq 解析 JSON）
# ==============================
say()  { printf "\n\033[1;36m=> %s\033[0m\n" "$*"; }
ok()   { printf "\033[1;32m✔ %s\033[0m\n" "$*"; }
fail() { printf "\033[1;31m✘ %s\033[0m\n" "$*"; exit 1; }
jstr(){ sed -n "s/.*\\\"$1\\\"[[:space:]]*:[[:space:]]*\\\"\\([^\"]*\\)\\\".*/\\1/p"; }
jint(){ sed -n "s/.*\\\"$1\\\"[[:space:]]*:[[:space:]]*\\([0-9]\\+\\).*/\\1/p"; }

# ==============================
# 1) 健康检查（两种路径都试）
# ==============================
say "health check"
curl -sS -m 5 "$BASE/api/healthz" >/dev/null || \
curl -sS -m 5 "$BASE/healthz"     >/dev/null || fail "healthz failed"
ok "healthz ok"

# ==============================
# 2) 创建用户 & 登录
# ==============================
say "create-user"
CREATE_JSON="$(curl -sS --fail-with-body -m 10 -X POST "$BASE/api/create-user" \
  -H 'Content-Type: application/json' \
  -d "{\"login\":\"$LOGIN\",\"password\":\"$PASSWORD\",\"email\":\"$EMAIL\"}")" || {
  echo "RESP: ${CREATE_JSON:-<empty>}"; fail "create-user failed"
}
echo "RESP: $CREATE_JSON"

say "login -> token"
LOGIN_JSON="$(curl -sS --fail-with-body -m 10 -X POST "$BASE/api/login" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")" || {
  echo "RESP: ${LOGIN_JSON:-<empty>}"; fail "login failed"
}
echo "RESP: $LOGIN_JSON"
TOKEN="$(echo "$LOGIN_JSON" | jstr token)"; [ -n "${TOKEN:-}" ] || fail "token missing"
echo "token=_${TOKEN:0:12}..."

# ==============================
# 3) 上传 PDF（使用 $PDF_UNIX）
# ==============================
say "upload-document"
UP_JSON="$(curl -sS --fail-with-body -m 30 -X POST "$BASE/api/upload-document" \
  -H "Authorization: Bearer $TOKEN" \
  -F "name=$(basename "$PDF_UNIX")" \
  -F "file=@${PDF_UNIX};type=application/pdf")" || {
  echo "RESP: ${UP_JSON:-<empty>}"; fail "upload failed"
}
echo "RESP: $UP_JSON"
DOC_ID="$(echo "$UP_JSON" | jint id)"; [ -n "${DOC_ID:-}" ] || DOC_ID="$(echo "$UP_JSON" | jstr id)"
[ -n "${DOC_ID:-}" ] || fail "parse doc id failed"
ok "doc_id=$DOC_ID"

# ==============================
# 4) 创建 visible-text 版本
# ==============================
say "create-watermark method=${METHOD}"
BODY=$(cat <<JSON
{"id": $DOC_ID, "method": "$METHOD", "position": "$POSITION",
 "key": "$KEY", "secret": "$SECRET", "intended_for": "$INTENDED_FOR"}
JSON
)
CW_JSON="$(curl -sS --fail-with-body -m 60 -X POST "$BASE/api/create-watermark" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "$BODY")" || true
echo "RESP: ${CW_JSON:-<empty>}"

# 解析 link（容错 Duplicate）
LINK="$(echo "$CW_JSON" | sed -n 's/.*"link"[[:space:]]*:[[:space:]]*"\([a-f0-9]\{40\}\)".*/\1/p')"
if [ -z "${LINK:-}" ] && echo "$CW_JSON" | grep -qi "Duplicate entry"; then
  LINK="$(echo "$CW_JSON" | grep -oE '[a-f0-9]{40}' | head -n1 || true)"
fi
if [ -z "${LINK:-}" ]; then
  LV="$(curl -sS -m 10 -H "Authorization: Bearer $TOKEN" "$BASE/api/list-versions/$DOC_ID")" || true
  LINK="$(echo "$LV" | sed -n 's/.*"link"[[:space:]]*:[[:space:]]*"\([a-f0-9]\{40\}\)".*/\1/p' | tail -n1)"
fi
[ -n "${LINK:-}" ] || fail "no link returned"
ok "link=$LINK"

# ==============================
# 5) 下载并在容器内验证（自适应 TTY，避免 stdin is not a tty）
# ==============================
say "verify watermark -> container VisibleTextWatermark.read_secret"
curl -sS --fail-with-body -m 30 -H "Authorization: Bearer $TOKEN" \
     -o wm_vtext.pdf "$BASE/api/get-version/$LINK"

docker cp wm_vtext.pdf "$SERVER_CONT":/tmp/wm_vtext.pdf

# 非交互环境不加 -t；且只有在有 TTY 且存在 winpty 时才用 winpty
PFX=""
if [ -t 1 ] && command -v winpty >/dev/null 2>&1; then
  PFX="winpty "
fi
TTY_OPTS="-i"; [ -t 1 ] && TTY_OPTS="-it"

${PFX}docker exec $TTY_OPTS "$SERVER_CONT" python -c "
from server.src.visible_text import VisibleTextWatermark
print(VisibleTextWatermark().read_secret(open('/tmp/wm_vtext.pdf','rb').read(), key='$KEY'))
"

ok "visible-text flow ok"
exit 0
