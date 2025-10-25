#!/usr/bin/env bash
set -euo pipefail

# 结果文件：带时间戳，避免覆盖
TS=$(date +"%Y%m%d_%H%M%S")
LOG="test_results_${TS}.log"

# 你可以在这里统一设置环境变量（供支持覆盖的脚本使用）
# 可按需改动，例如：BASE、PDF、SERVER_CONT...
export BASE="${BASE:-http://127.0.0.1:5000}"
export PDF="${PDF:-E:/project/tatou/test.pdf}"
export SERVER_CONT="${SERVER_CONT:-tatou-server-1}"

# 彩色输出（终端），同时写入日志（无颜色）
say(){ printf "\n\033[1;96m==> %s\033[0m\n" "$*"; }
rule(){ printf -- "-----------------------------------------------------------------\n"; }

# 记录器：将命令的 stdout+stderr 同时输出到屏幕并追加到日志
run_and_log() {
  local name="$1"; shift
  say "开始执行：$name"
  {
    rule
    echo "[$(date '+%F %T')] START $name"
    echo "CMD: $*"
    echo
  } >>"$LOG"

  # 运行并将输出同时 tee 到日志
  {
    "$@" 2>&1 | tee -a "$LOG"
  } || {
    code=$?
    echo "[ERROR] $name 退出码：$code" | tee -a "$LOG"
    return "$code"
  }

  {
    echo
    echo "[$(date '+%F %T')] END   $name"
    rule
    echo
  } >>"$LOG"
}

main() {
  echo "# Tatou 集成测试日志  $(date '+%F %T')" >"$LOG"
  echo "# BASE=$BASE" >>"$LOG"
  echo "# PDF=$PDF" >>"$LOG"
  echo >>"$LOG"

  # 1) visible-text（支持用环境变量覆盖 BASE/PDF/KEY/SECRET 等）  :contentReference[oaicite:3]{index=3}
  run_and_log "visible-text.sh" bash ./visible-text.sh || true

  # 2) smoke（注意：脚本里 PDF 是写死的绝对路径，如需用自己的 PDF，建议改脚本为 PDF=\"${PDF:-...}\"）  :contentReference[oaicite:4]{index=4}
  run_and_log "smoke.sh"        bash ./smoke.sh        || true

  # 3) text_metadata（支持环境变量覆盖 BASE/PDF）  :contentReference[oaicite:5]{index=5}
  run_and_log "text_metadata.sh" bash ./text_metadata.sh || true

  say "All execution completed. Summarize logs in：$LOG"
  echo "Resulf file：$LOG"
}

main "$@"
