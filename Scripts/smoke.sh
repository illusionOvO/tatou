#!/usr/bin/env bash
set -euo pipefail

# ==============================
# 基础配置（可用环境变量覆盖）
# ==============================
BASE="${BASE:-http://127.0.0.1:5000}"
PDF="${PDF:-test.pdf}"     # 本机测试 PDF；Windows 可用 E:/...，Linux 用 /home/...
METHOD="trailer-hmac"
POSITION="eof"
KEY="K1"

# 把 Windows 路径转成 Unix 路径（Git Bash / WSL 兼容）；纯 Linux 原样使用
if command -v cygpath >/dev/null 2>&1; then
  PDF_UNIX="$(cygpath -u "$PDF")"
elif command -v wslpath >/dev/null 2>&1; then
  PDF_UNIX="$(wslpath -a "$PDF")"
else
  PDF_UNIX="$PDF"
fi
: "${PDF_UNIX:=$PDF}"                        # 防御：确保 set -u 下变量已定义
[ -r "$PDF_UNIX" ] || { echo "Missing PDF: $PDF_UNIX" >&2; exit 26; }

# ==============================
# 小工具函数（与 text_metadata.sh 保持一致风格）
# ==============================
say(){ printf "\n\033[1;36m=> %s\033[0m\n" "$*"; }
ok(){  printf "\033[1;32m✔ %s\033[0m\n" "$*"; }
fail(){ printf "\033[1;31m✘ %s\033[0m\n" "$*"; exit 1; }
js_str(){ sed -n "s/.*\\\"$1\\\"[[:space:]]*:[[:space:]]*\\\"\\([^\"]*\\)\\\".*/\\1/p"; }
js_int(){ sed -n "s/.*\\\"$1\\\"[[:space:]]*:[[:space:]]*\\([0-9]\\+\\).*/\\1/p"; }

# ==============================
# 1) healthz
# ==============================
say "health check /healthz"
curl -sS -m 5 "$BASE/api/healthz" >/dev/null || \
curl -sS -m 5 "$BASE/healthz"     >/dev/null || fail "healthz failed"
ok "healthz ok"

# ==============================
# 2) 动态创建用户 & 登录（避免重复账号）
# ==============================
TS="$(date +%s%N)"; RND="$RANDOM"
LOGIN="demo_${TS}_${RND}"
EMAIL="${LOGIN}@example.com"
PASSWORD="P@ss-${TS}"

say "create-user  /api/create-user"
CREATE_JSON="$(curl -sS --fail-with-body -m 10 -X POST "$BASE/api/create-user" \
  -H 'Content-Type: application/json' \
  -d "{\"login\":\"$LOGIN\",\"password\":\"$PASSWORD\",\"email\":\"$EMAIL\"}")" || {
  echo "RESP: ${CREATE_JSON:-<empty>}"; fail "create-user failed"
}
echo "RESP: $CREATE_JSON"

say "login  /api/login -> token"
LOGIN_JSON="$(curl -sS --fail-with-body -m 10 -X POST "$BASE/api/login" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")" || {
  echo "RESP: ${LOGIN_JSON:-<empty>}"; fail "login failed"
}
echo "RESP: $LOGIN_JSON"
TOKEN="$(echo "$LOGIN_JSON" | js_str token)"; [ -n "${TOKEN:-}" ] || fail "token missing"
echo "token=_${TOKEN:0:12}..."

# ==============================
# 3) 上传 PDF （关键：使用 $PDF_UNIX）
# ==============================
say "upload-document  /api/upload-document"
UP_JSON="$(curl -sS --fail-with-body -m 20 -X POST "$BASE/api/upload-document" \
  -H "Authorization: Bearer $TOKEN" \
  -F "name=$(basename "$PDF_UNIX")" \
  -F "file=@${PDF_UNIX};type=application/pdf")" || {
  echo "RESP: ${UP_JSON:-<empty>}"; fail "upload failed"
}
echo "RESP: $UP_JSON"
DOC_ID="$(echo "$UP_JSON" | js_int id)"; [ -n "${DOC_ID:-}" ] || DOC_ID="$(echo "$UP_JSON" | js_str id)"
[ -n "${DOC_ID:-}" ] || fail "parse doc id failed"
ok "doc_id=$DOC_ID"

# ==============================
# 4) 创建水印版本（trailer-hmac）
# ==============================
SECRET="HELLO_TATOU_${TS}"
INTENDED_FOR="qa-user-${TS}"
say "create-watermark  /api/create-watermark  method=${METHOD}"
BODY=$(cat <<JSON
{"id": $DOC_ID, "method": "$METHOD", "position": "$POSITION", "key": "$KEY", "secret": "$SECRET", "intended_for": "$INTENDED_FOR"}
JSON
)
CW_JSON="$(curl -sS --fail-with-body -m 30 -X POST "$BASE/api/create-watermark" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "$BODY")" || true
echo "RESP: ${CW_JSON:-<empty>}"

# 优先从返回中抓 link；若遇 Duplicate 则兜底
VER_LINK="$(echo "$CW_JSON" | sed -n 's/.*"link"[[:space:]]*:[[:space:]]*"\([a-f0-9]\{40\}\)".*/\1/p')"
if [ -z "${VER_LINK:-}" ] && echo "$CW_JSON" | grep -qi "Duplicate entry"; then
  VER_LINK="$(echo "$CW_JSON" | grep -oE '[a-f0-9]{40}' | head -n1 || true)"
  [ -n "${VER_LINK:-}" ] && ok "duplicate -> reuse link: $VER_LINK"
fi
if [ -z "${VER_LINK:-}" ]; then
  say "fallback list-versions"
  LV="$(curl -sS -m 10 -H "Authorization: Bearer $TOKEN" "$BASE/api/list-versions/$DOC_ID")" || true
  echo "LIST: $LV"
  VER_LINK="$(echo "$LV" | sed -n 's/.*"link"[[:space:]]*:[[:space:]]*"\([a-f0-9]\{40\}\)".*/\1/p' | tail -n1)"
fi
[ -n "${VER_LINK:-}" ] || fail "no link returned"
ok "link=$VER_LINK"

# ==============================
# 5) 下载并在容器内验证水印（不分配 TTY）
# ==============================
say "verify watermark (container)"
curl -sS --fail-with-body -m 20 -H "Authorization: Bearer $TOKEN" \
     -o wm.pdf "$BASE/api/get-version/$VER_LINK"

# 直接通过 stdin 喂入容器内 Python，不用 -t
docker exec -i tatou-server-1 python -c \
"from server.src.add_after_eof import AddAfterEOF; import sys; \
print(AddAfterEOF().read_secret(pdf_bytes=sys.stdin.buffer.read(), key='$KEY'))" \
< wm.pdf

ok "smoke flow ok"
exit 0
