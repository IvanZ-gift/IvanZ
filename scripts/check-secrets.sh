#!/usr/bin/env bash
# 密钥扫描：提交/推送前把明显是密钥的东西拦下来。
#   scripts/check-secrets.sh            # 扫描工作区所有（未被忽略的）文件
#   scripts/check-secrets.sh --staged   # 只扫描已 git add 的内容（pre-commit 用）
#   scripts/check-secrets.sh --range A..B  # 扫描一段提交历史（pre-push 用）
# 误报时：SKIP_SECRET_SCAN=1 git commit ... 可以强行通过。
set -uo pipefail

MODE="all"
RANGE=""
case "${1:-}" in
  --staged) MODE="staged" ;;
  --range)  MODE="range"; RANGE="${2:?need A..B}" ;;
esac

if [ "${SKIP_SECRET_SCAN:-0}" = "1" ]; then
  echo "[secret-scan] SKIP_SECRET_SCAN=1 -> 跳过检查" >&2
  exit 0
fi

# 明显是密钥的模式（够用就好，不追求全）
PATTERNS=(
  'gh[pousr]_[A-Za-z0-9]{30,}'                 # GitHub token
  'github_pat_[A-Za-z0-9_]{50,}'               # GitHub fine-grained PAT
  'sk-[A-Za-z0-9_-]{20,}'                      # OpenAI / Anthropic style
  'AKIA[0-9A-Z]{16}'                           # AWS access key id
  'ASIA[0-9A-Z]{16}'                           # AWS temp key
  'AIza[0-9A-Za-z_-]{35}'                      # Google API key
  'xox[baprs]-[0-9A-Za-z-]{10,}'               # Slack token
  '-----BEGIN [A-Z ]*PRIVATE KEY-----'         # 任何私钥
  'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.'  # JWT
  'ssh-(rsa|ed25519) AAAA[A-Za-z0-9+/=]{40,}'  # 私钥串
  'mongodb(\+srv)?://[^:@/ ]+:[^@/ ]+@'        # 带密码的 mongo 连接串
  'mysql://[^:@/ ]+:[^@/ ]+@'
  'postgres(ql)?://[^:@/ ]+:[^@/ ]+@'
  'redis://[^:@/ ]+:[^@/ ]+@'
  '(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)[\"'"'"']?[[:space:]]*[:=][[:space:]]*[\"'"'"'][A-Za-z0-9_\-]{16,}[\"'"'"']'
  'AccountKey=[A-Za-z0-9+/=]{40,}'             # Azure
)

# 收集要检查的 “文件名:行号:内容”
scan_blob() { # $1=可能为空的标签
  local label="$1"
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    local re
    for re in "${PATTERNS[@]}"; do
      if printf '%s' "$line" | grep -Eq -- "$re"; then
        printf '%s\n' "$line"
        break
      fi
    done
  done
}

hits=""
case "$MODE" in
  all)
    while IFS= read -r f; do
      # 跳过二进制
      if grep -Iq . "$f" 2>/dev/null; then
        out=$(grep -nE -- "$(IFS='|'; printf '%s' "${PATTERNS[*]}")" "$f" 2>/dev/null || true)
        [ -n "$out" ] && hits+=$(printf '%s\n' "$out" | sed "s|^|$f:|")$'\n'
      fi
    done < <(git ls-files -co --exclude-standard)
    ;;
  staged)
    while IFS= read -r f; do
      out=$(git show ":$f" 2>/dev/null | grep -nE -- "$(IFS='|'; printf '%s' "${PATTERNS[*]}")" || true)
      [ -n "$out" ] && hits+=$(printf '%s\n' "$out" | sed "s|^|$f:|")$'\n'
    done < <(git diff --cached --name-only --diff-filter=ACMR)
    ;;
  range)
    hits=$(git log -p --no-color "$RANGE" 2>/dev/null \
      | grep -nE -- "$(IFS='|'; printf '%s' "${PATTERNS[*]}")" || true)
    ;;
esac

if [ -n "${hits//[$'\n' ]/}" ]; then
  echo ""
  echo "=================================================================="
  echo " [secret-scan] 发现疑似密钥，已阻止："
  echo "=================================================================="
  printf '%s' "$hits" | grep -v '^+' | awk '{print "  " substr($0,1,200)}' | sort -u | head -40
  echo "------------------------------------------------------------------"
  echo " 如果是误报：先在聊天里让 Hermes 确认，再 SKIP_SECRET_SCAN=1 重试。"
  echo " 如果是真密钥：删掉它，并立刻去对应平台作废/轮换这把钥匙。"
  echo "=================================================================="
  exit 1
fi

echo "[secret-scan] OK：没有发现疑似密钥 ($MODE)" >&2
exit 0
