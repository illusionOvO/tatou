#!/usr/bin/env bash
set -euo pipefail

# ==============================
# 配置区（按需修改）
# ==============================
BASE="http://127.0.0.1:5000"            # 后端基址
PDF="/mnt/e/SOFTSEC VT 2025 Group project/tatou/test.pdf"         # 测试 PDF 路径
STAMP=$(date +%s)               #时间戳，保证唯一
METHOD="trailer-hmac"           # 水印方法
POSITION="eof"
KEY="K1"
SECRET="HELLO_TATOU_${STAMP}"
INTENDED_FOR="qa-user-${STAMP}"

TS=$(date +%s)
LOGIN="demo_${TS}"
EMAIL="demo_${TS}@example.com"
PASSWORD="Passw0rd!"

# ==============================
# 小工具函数（无 jq 解析 JSON）
# ==============================
say() { printf "\n\033[1;96m==> %s\033[0m\n" "$*"; }
die() { printf "\n\033[1;91m[ERROR]\033[0m %s\n" "$*" >&2; exit 1; }

# 从一行 JSON 提取 "key":"value" 的字符串值
json_get_string () {
  local json="$1" key="$2"
  echo "$json" | tr -d '\n' | sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p"
}

# 从一行 JSON 提取数字值  "key": 123
json_get_number () {
  local json="$1" key="$2"
  echo "$json" | tr -d '\n' | sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\\([0-9]\\+\\).*/\\1/p"
}

# ==============================
# 1) 健康检查
# ==============================
say "1) Health check：/healthz"
curl -s -i "$BASE/healthz" | sed -n '1,6p' || true

# ==============================
# 2) 创建用户（已存在报 4xx 也不影响）
# ==============================
say "2) Create user：/api/create-user"
CREATE_JSON=$(curl -s -X POST "$BASE/api/create-user" \
  -H "Content-Type: application/json" \
  -d "{\"login\":\"$LOGIN\",\"password\":\"$PASSWORD\",\"email\":\"$EMAIL\"}" || true)
echo "RESP: $CREATE_JSON"

# ==============================
# 3) 登录，获取 token
# ==============================
say "3) Login：/api/login -> token"
LOGIN_JSON=$(curl -s -X POST "$BASE/api/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")
echo "RESP: $LOGIN_JSON"
TOKEN=$(json_get_string "$LOGIN_JSON" "token")
[ -n "${TOKEN:-}" ] || die "登录失败，未拿到 token"
echo "TOKEN: ${TOKEN:0:16}..."

# ==============================
# 4) 上传 PDF，得到文档 id
# ==============================
say "4) Upload PDF：/api/upload-document"
UP_JSON=$(curl -s -X POST "$BASE/api/upload-document" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@${PDF};type=application/pdf" \
  -F "name=$(basename "$PDF")")
echo "RESP: $UP_JSON"
DOC_ID=$(json_get_number "$UP_JSON" "id")
# 如果 id 是字符串（有些实现返回字符串 id），换成字符串提取
if [ -z "$DOC_ID" ]; then DOC_ID=$(json_get_string "$UP_JSON" "id"); fi
[ -n "$DOC_ID" ] || die "upload fail cannot get document id"
echo "DOC_ID: $DOC_ID"

# ==============================
# 5) 列出文档
# ==============================
say "5) List document：/api/list-documents"
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/api/list-documents" | head -c 600; echo

# ==============================
# 6) 创建水印版本
# ==============================
say "6) Create watermark：/api/create-watermark"
CW_JSON=$(
  curl -s -X POST "$BASE/api/create-watermark" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
          \"id\": ${DOC_ID},
          \"method\": \"${METHOD}\",
          \"position\": \"${POSITION}\",
          \"key\": \"${KEY}\",
          \"secret\": \"${SECRET}\",
          \"intended_for\": \"${INTENDED_FOR}\"
        }"
)
echo "RESP: $CW_JSON"

# 先尝试从正常返回里抓 link（40位hex）
VER_LINK=$(echo "$CW_JSON" | sed -n 's/.*"link"[[:space:]]*:[[:space:]]*"\([a-f0-9]\{40\}\)".*/\1/p')

# 如果没拿到 link，但报了 Duplicate，则兜底取“已存在”的那个 link
if [ -z "$VER_LINK" ] && echo "$CW_JSON" | grep -q "Duplicate entry"; then
  # 1) 先尝试从错误文本里直接提取 40位hex（常见返回里就带着）
  VER_LINK=$(echo "$CW_JSON" | grep -oE '[a-f0-9]{40}' | head -n1)
fi

# 再兜底：去查该文档的版本列表，拿“最新”的 link
if [ -z "$VER_LINK" ]; then
  LV=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/api/list-versions/$DOC_ID")
  VER_LINK=$(echo "$LV" | sed -n 's/.*"link"[[:space:]]*:[[:space:]]*"\([a-f0-9]\{40\}\)".*/\1/p' | tail -n1)
fi

if [ -n "$VER_LINK" ]; then
  echo "VERSION LINK: $VER_LINK"
else
  echo "❌ Can't get link（创建失败或实现未返回 link）。"
  # 也可以在这里 exit 1
fi

# ==============================
# 7) 列出该文档所有版本
# ==============================
say "7) List-version：/api/list-versions/${DOC_ID}"
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/api/list-versions/${DOC_ID}" | head -c 600; echo

# ==============================
# 8) 验证水印
# ==============================
say "8) Read=watermark：/api/read-watermark"
if [ -n "$VER_LINK" ]; then
  echo "⇒ Download the version and verify the watermark locally"
  curl -s -H "Authorization: Bearer $TOKEN" \
       -o wm.pdf "$BASE/api/get-version/$VER_LINK"

  docker exec -i tatou-server-1 python -c \
  "from server.src.add_after_eof import AddAfterEOF; import sys; \
print(AddAfterEOF().read_secret(pdf_bytes=sys.stdin.buffer.read(), key='K1'))" \
  < wm.pdf
else
  echo "❌ Can't get link，unable verify"
fi

# ==============================
# 9) 删除文档
# ==============================
say "9) Delete document：/api/delete-document/${DOC_ID}"
DEL_JSON=$(curl -s -X DELETE -H "Authorization: Bearer $TOKEN" \
  "$BASE/api/delete-document/${DOC_ID}")
echo "RESP: $DEL_JSON"

say "✅ Complete the entire process "
