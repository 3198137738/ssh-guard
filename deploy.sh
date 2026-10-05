#!/usr/bin/env bash
# 批量在多台服务器上并发执行 ssh-guard.sh
#   脚本内容通过 SSH 的 stdin 传过去，服务器本身不需要能访问 GitHub
#
# 用法: ./deploy.sh -f hosts.txt [-P 并发数] [-i 私钥] [-u 默认用户] [--] [ssh-guard 命令和参数]
# 示例:
#   ./deploy.sh -f hosts.txt                          # 所有服务器执行 install
#   ./deploy.sh -f hosts.txt -- report --top 10       # 所有服务器出爆破报告
#   ./deploy.sh -f hosts.txt -- install --disable-password
set -uo pipefail

RAW_URL="https://raw.githubusercontent.com/3198137738/ssh-guard/main/ssh-guard.sh"
HOSTS_FILE=""
PARALLEL=10
IDENTITY=""
DEF_USER=root
SHOW=0

usage() {
  cat <<'EOF'
用法: ./deploy.sh -f hosts.txt [选项] [--] [ssh-guard 命令和参数]

选项:
  -f FILE    服务器列表，每行一个: [user@]host[:port]，# 开头为注释
  -P N       并发数（默认 10）
  -i KEY     SSH 私钥
  -u USER    未写用户名时使用的默认用户（默认 root）
  -s         执行完后把每台服务器的输出打印出来（report 时常用）
  -h         帮助

非 root 用户需要有免密 sudo（sudo -n）。
EOF
}

while getopts "f:P:i:u:sh" opt; do
  case "$opt" in
    f) HOSTS_FILE=$OPTARG ;;
    P) PARALLEL=$OPTARG ;;
    i) IDENTITY=$OPTARG ;;
    u) DEF_USER=$OPTARG ;;
    s) SHOW=1 ;;
    h) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done
shift $((OPTIND - 1))
[ "${1:-}" = "--" ] && shift
[ -n "$HOSTS_FILE" ] && [ -f "$HOSTS_FILE" ] || { usage; exit 1; }
[ $# -gt 0 ] || set -- install

# 优先用同目录下的 ssh-guard.sh，没有就从 GitHub 下载
SCRIPT="$(cd "$(dirname "$0")" && pwd)/ssh-guard.sh"
if [ ! -f "$SCRIPT" ]; then
  SCRIPT=$(mktemp)
  curl -fsSL "$RAW_URL" -o "$SCRIPT" || { echo "下载 ssh-guard.sh 失败: $RAW_URL" >&2; exit 1; }
fi

LOG_DIR="logs/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$LOG_DIR"

REMOTE_ARGS=$(printf '%q ' "$@")
REMOTE_CMD="if [ \"\$(id -u)\" -eq 0 ]; then bash -s -- $REMOTE_ARGS; else sudo -n bash -s -- $REMOTE_ARGS; fi"

run_one() {
  local spec=$1 user host port name rc
  spec=${spec%%#*}
  spec=$(echo "$spec" | tr -d '[:space:]')
  [ -n "$spec" ] || return 0
  case "$spec" in *@*) user=${spec%%@*}; host=${spec#*@} ;; *) user=$DEF_USER; host=$spec ;; esac
  case "$host" in *:*) port=${host##*:}; host=${host%:*} ;; *) port=22 ;; esac
  name="$host"
  [ "$port" != 22 ] && name="$host-$port"

  local opts=(-p "$port" -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new)
  [ -n "$IDENTITY" ] && opts+=(-i "$IDENTITY")
  ssh "${opts[@]}" "$user@$host" "$REMOTE_CMD" <"$SCRIPT" >"$LOG_DIR/$name.log" 2>&1
  rc=$?
  echo "$rc" >"$LOG_DIR/$name.rc"
  if [ "$rc" -eq 0 ]; then echo "[成功] $user@$host:$port"; else echo "[失败] $user@$host:$port (退出码 $rc)  → $LOG_DIR/$name.log"; fi
}
export -f run_one
export SCRIPT LOG_DIR REMOTE_CMD IDENTITY DEF_USER

echo "执行: ssh-guard.sh $*    并发: $PARALLEL    日志: $LOG_DIR/"
grep -vE '^[[:space:]]*(#|$)' "$HOSTS_FILE" | xargs -P "$PARALLEL" -I{} bash -c 'run_one "$1"' _ {}

total=$(ls "$LOG_DIR"/*.rc 2>/dev/null | wc -l)
failed=$(grep -lv '^0$' "$LOG_DIR"/*.rc 2>/dev/null | wc -l)
echo
echo "完成: 共 $total 台，成功 $((total - failed)) 台，失败 $failed 台"

if [ "$SHOW" = 1 ]; then
  for f in "$LOG_DIR"/*.log; do
    echo
    echo "################ $(basename "$f" .log) ################"
    cat "$f"
  done
fi
[ "$failed" -eq 0 ]
