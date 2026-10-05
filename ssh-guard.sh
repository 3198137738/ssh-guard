#!/usr/bin/env bash
# ssh-guard —— SSH 爆破防护一键脚本
#   - fail2ban sshd jail：aggressive 模式（关掉密码登录后也能识别 preauth 断开）、永久封禁、封全部端口
#   - 检测到 Docker 时额外在 DOCKER-USER 链封禁（容器映射端口不走 INPUT 链）
#   - 爆破分析报告：失败次数 Top IP、首/末次时间、是否已封、/24 网段汇总
#   - 可选关闭 SSH 密码登录（带密钥检查与自动回滚）
#   - 批量并发部署到多台服务器（脚本经 SSH 传过去，服务器无需访问 GitHub）
#
# 一键运行（不带参数进入交互菜单）：
#   curl -fsSL https://raw.githubusercontent.com/3198137738/ssh-guard/main/ssh-guard.sh | sudo bash
# 非交互：
#   curl -fsSL https://raw.githubusercontent.com/3198137738/ssh-guard/main/ssh-guard.sh | sudo bash -s -- install
set -uo pipefail

VERSION="1.3.1"
RAW_URL="https://raw.githubusercontent.com/3198137738/ssh-guard/main/ssh-guard.sh"
JAIL_FILE=/etc/fail2ban/jail.d/ssh-guard.local
F2B_CONF_FILE=/etc/fail2ban/fail2ban.d/ssh-guard.local
FILTER_NAME=ssh-guard-sshd
FILTER_FILE=/etc/fail2ban/filter.d/${FILTER_NAME}.conf
SYSTEMD_DROPIN=/etc/systemd/system/fail2ban.service.d/ssh-guard.conf
SSHD_CONFIG=/etc/ssh/sshd_config
SSHD_DROPIN=/etc/ssh/sshd_config.d/00-ssh-guard.conf
SSHD_PUBKEY_DROPIN=/etc/ssh/sshd_config.d/00-ssh-guard-pubkey.conf
KEYS_DIR=/root/ssh-guard-keys
MARK="# managed by ssh-guard"
NETS_FILE=/etc/ssh-guard/blocked-nets.txt
NET_SET=ssh-guard-net
NETS_UNIT=/etc/systemd/system/ssh-guard-nets.service
NETS_RESTORE=/usr/local/sbin/ssh-guard-nets-restore

# 默认参数
MAXRETRY=3
FINDTIME=1h
BANTIME=-1
IGNOREIP=""
DOCKER=auto
DISABLE_PW=0
FORCE=0
SINCE=""
TOP=0
LOGFILE=""
BAN_MIN=1
SUBNET_MIN=3
NO_SUBNET=0
DRY_RUN=0
KEY_USER=""
KEY_TEXT=""
KEY_FILE=""
KEY_GITHUB=""
KEY_GEN=0

if [ -t 1 ]; then R=$'\e[31m' G=$'\e[32m' Y=$'\e[33m' B=$'\e[36m' N=$'\e[0m'; else R='' G='' Y='' B='' N=''; fi
info() { printf '%s[*]%s %s\n' "$B" "$N" "$*"; }
ok()   { printf '%s[✓]%s %s\n' "$G" "$N" "$*"; }
warn() { printf '%s[!]%s %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '%s[✗]%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
用法: ssh-guard.sh [命令] [选项]
不带任何参数且有终端时进入交互菜单；没有终端时（如 cron、批量部署）默认执行 install。

命令:
  menu                 交互菜单
  install              安装/更新 fail2ban 防护（可重复执行）
  report               分析 SSH 爆破日志：Top IP、首/末次时间、是否已封、/24 网段汇总
  addkey               启用 SSH 密钥登录：给用户添加公钥（粘贴 / GitHub 导入 / 服务器上生成）
  harden               关闭 SSH 密码登录，只允许密钥（会先检查是否已配置公钥）
  unharden             撤销 harden，恢复原来的密码登录设置
  status               查看当前封禁情况
  banlog               一键封禁日志中所有爆破 IP 及爆破集中的 /24 网段（需先 install）
  unban <IP|网段>...   解封 IP 或网段（如 1.2.3.0/24）
  apply-nets           按 /etc/ssh-guard/blocked-nets.txt 重建网段封禁规则（手动编辑列表后执行）
  uninstall            移除 ssh-guard 写入的 fail2ban 配置和网段封禁（不卸载 fail2ban）
  deploy               在多台服务器上并发执行本脚本的某个命令（本机无需 root）
  help                 显示本帮助

install 选项:
  --maxretry N         findtime 内失败 N 次即封禁（默认 3）
  --findtime T         统计窗口，如 10m / 1h / 1d（默认 1h）
  --bantime T          封禁时长，-1 为永久（默认 -1）
  --ignoreip "IP ..."  白名单，空格或逗号分隔；当前登录会话的 IP 会自动加入
  --no-docker          不在 DOCKER-USER 链封禁
  --disable-password   安装完成后顺便执行 harden

addkey 选项（公钥来源至少选一种，可组合）:
  --user USER          给哪个用户添加（默认: 通过 sudo 调用时为原用户，否则 root）
  --key "ssh-ed25519 AAAA..."  直接给出公钥，可重复
  --key-file FILE      从文件读取公钥（可多行）
  --github NAME        导入 https://github.com/NAME.keys 中的全部公钥
  --generate           在服务器上生成 ed25519 密钥对，并打印私钥供保存
  --disable-password   添加完成后顺便关闭密码登录（确认密钥可用时再用）

harden 选项:
  --force              未检测到任何 authorized_keys 也强制关闭密码登录（可能把自己锁在外面）

report 选项:
  --since T            只分析该时间之后的日志（仅 journal 有效），如 "2026-10-01" / "24 hours ago"
  --top N              只显示前 N 个 IP（默认 0 = 全部）
  --log FILE           指定日志文件（支持 .gz）

banlog 选项（也支持 --since / --log 限定分析范围）:
  --min N              失败 ≥ N 次的 IP 才封（默认 1，即日志中所有爆破 IP）
  --subnet-min N       同一 /24 中有 ≥ N 个 IP 参与爆破时封整个网段（默认 3）
  --no-subnet          只封单个 IP，不封网段
  --dry-run            只预览要封禁的 IP 和网段，不做修改
  白名单 IP、日志中成功登录过的 IP 不会被封，它们所在的网段以及内网/保留网段也不会被封

deploy 用法: ssh-guard.sh deploy -f hosts.txt [选项] [-- 远程命令和参数]（远程命令默认 install）
  -f, --hosts FILE     服务器列表，每行 [user@]host[:port]，# 开头为注释
  -P, --parallel N     并发数（默认 10）
  -i, --identity KEY   SSH 私钥
  -u, --user USER      未写用户名时的默认用户（默认 root）
  -s, --show           结束后打印每台服务器的输出
  -p, --password       目标服务器还没有密钥时用密码登录（逐台执行，按提示输入密码）
  要求本机能用密钥免密登录；非 root 用户需要免密 sudo。输出保存在 ./ssh-guard-logs/

示例:
  curl -fsSL <RAW_URL> | sudo bash
  curl -fsSL <RAW_URL> | sudo bash -s -- install --maxretry 5 --ignoreip "1.2.3.4" --disable-password
  curl -fsSL <RAW_URL> | sudo bash -s -- report --since "24 hours ago"
  curl -fsSL <RAW_URL> | sudo bash -s -- banlog --dry-run
  curl -fsSL <RAW_URL> | sudo bash -s -- addkey --github your-github-name
  curl -fsSL <RAW_URL> | bash -s -- deploy -f hosts.txt -p -- addkey --key "$(cat ~/.ssh/id_ed25519.pub)"
  curl -fsSL <RAW_URL> | bash -s -- deploy -f hosts.txt -s -- report --top 10
EOF
}

need_root() { [ "$(id -u)" -eq 0 ] || die "请用 root 运行（sudo bash ...）"; }

# ver_ge A B：A >= B
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

pkg_install() {
  if command -v apt-get >/dev/null 2>&1; then
    if [ -z "${APT_UPDATED:-}" ]; then apt-get update -qq >/dev/null; APT_UPDATED=1; fi
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null
  elif command -v dnf >/dev/null 2>&1; then
    # RHEL 系的 fail2ban 在 EPEL 里
    rpm -q epel-release >/dev/null 2>&1 || dnf install -y -q epel-release >/dev/null 2>&1 || true
    dnf install -y -q "$@" >/dev/null
  elif command -v yum >/dev/null 2>&1; then
    rpm -q epel-release >/dev/null 2>&1 || yum install -y -q epel-release >/dev/null 2>&1 || true
    yum install -y -q "$@" >/dev/null
  elif command -v zypper >/dev/null 2>&1; then
    zypper -nq install "$@" >/dev/null
  elif command -v apk >/dev/null 2>&1; then
    apk add -q "$@"
  elif command -v pacman >/dev/null 2>&1; then
    pacman -S --noconfirm --needed "$@" >/dev/null
  else
    return 1
  fi
}

svc() { # svc <action> <name...>：依次尝试多个服务名
  local act=$1; shift
  local s
  for s in "$@"; do
    if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files "$s.service" >/dev/null 2>&1 \
       && systemctl "$act" "$s" >/dev/null 2>&1; then return 0; fi
    if command -v service >/dev/null 2>&1 && service "$s" "$act" >/dev/null 2>&1; then return 0; fi
    if command -v rc-service >/dev/null 2>&1 && rc-service "$s" "$act" >/dev/null 2>&1; then return 0; fi
  done
  return 1
}

sshd_bin() { command -v sshd 2>/dev/null || { [ -x /usr/sbin/sshd ] && echo /usr/sbin/sshd; }; }

sshd_opt() { # 读取 sshd 生效配置
  local bin; bin=$(sshd_bin) || return 1
  "$bin" -T 2>/dev/null | awk -v k="$1" '$1==k{$1=""; sub(/^ /,""); print}'
}

# ---------------------------------------------------------------- 日志 ---

# 日志后端：有近期的 auth.log/secure 就读文件，否则读 journal
detect_backend() {
  SSH_LOG="" BACKEND=""
  local f
  for f in /var/log/auth.log /var/log/secure; do
    if [ -s "$f" ] && [ -n "$(find "$f" -mtime -7 2>/dev/null)" ]; then SSH_LOG=$f; break; fi
  done
  if [ -n "$SSH_LOG" ]; then
    BACKEND=auto
  elif command -v journalctl >/dev/null 2>&1; then
    BACKEND=systemd
  else
    for f in /var/log/auth.log /var/log/secure /var/log/messages; do
      [ -f "$f" ] && { SSH_LOG=$f; BACKEND=auto; return; }
    done
    die "找不到 SSH 日志（无 /var/log/auth.log、/var/log/secure，也没有 journalctl）"
  fi
}

# 输出 SSH 相关日志到 stdout
collect_logs() {
  if [ -n "$LOGFILE" ]; then
    zcat -f "$LOGFILE"
    return
  fi
  detect_backend
  if [ "$BACKEND" = systemd ]; then
    journalctl _COMM=sshd + _COMM=sshd-session -o short-iso --no-pager ${SINCE:+--since "$SINCE"} 2>/dev/null
  else
    [ -n "$SINCE" ] && warn "--since 只对 journal 有效，读取日志文件时会分析全部轮转日志"
    # 按时间从旧到新拼接轮转日志
    local f
    for f in $(ls -tr "$SSH_LOG"* 2>/dev/null); do zcat -f "$f" 2>/dev/null; done | grep -E 'sshd(-session)?\['
  fi
}

# 失败/异常连接的日志特征（关掉密码登录后主要是 preauth 阶段断开）
FAIL_RE='Failed (password|publickey|none|keyboard-interactive)|Invalid user|Did not receive identification|(Connection closed|Connection reset) by .*\[preauth\]|maximum authentication attempts|Unable to negotiate|banner exchange|Bad protocol version|not allowed because'

# ------------------------------------------------------------- install ---

install_fail2ban() {
  if ! command -v fail2ban-client >/dev/null 2>&1; then
    info "安装 fail2ban ..."
    pkg_install fail2ban || die "fail2ban 安装失败，请手动安装后重试"
  fi
  F2B_VER=$(fail2ban-client --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n1)
  [ -n "$F2B_VER" ] || die "无法获取 fail2ban 版本"
  ver_ge "$F2B_VER" 0.10 || die "fail2ban $F2B_VER 太旧，需要 ≥ 0.10 才支持 aggressive 模式"
  ok "fail2ban $F2B_VER"
}

ensure_journal_support() {
  # systemd 后端需要 python 的 systemd 模块
  local py
  py=$(head -n1 "$(command -v fail2ban-server)" 2>/dev/null | sed -n 's/^#! *//p' | awk '{print $NF}')
  case "$py" in *python*) ;; *) py=python3 ;; esac
  if ! "$py" -c 'import systemd.journal' >/dev/null 2>&1; then
    info "安装 python systemd 模块 ..."
    pkg_install python3-systemd || pkg_install python-systemd || pkg_install fail2ban-systemd \
      || warn "python systemd 模块安装失败，fail2ban 可能无法读取 journal"
  fi
}

# 封禁动作：封全部端口；优先 ipset（大量 IP 时性能好）
choose_actions() {
  local ad=/etc/fail2ban/action.d
  ACTIONS=()
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null \
     && [ -f "$ad/firewallcmd-ipset.conf" ]; then
    command -v ipset >/dev/null 2>&1 || pkg_install ipset || true
    ACTIONS+=("firewallcmd-ipset[name=sshd, port=\"$PORTS\", actiontype=<allports>]")
  elif command -v iptables >/dev/null 2>&1; then
    command -v ipset >/dev/null 2>&1 || pkg_install ipset || true
    if command -v ipset >/dev/null 2>&1 && [ -f "$ad/iptables-ipset-proto6-allports.conf" ]; then
      ACTIONS+=("iptables-ipset-proto6-allports[name=sshd]")
    elif command -v ipset >/dev/null 2>&1 && [ -f "$ad/iptables-ipset.conf" ]; then
      ACTIONS+=("iptables-ipset[name=sshd, type=allports]")
    else
      ACTIONS+=("iptables-allports[name=sshd, protocol=all]")
    fi
  elif command -v nft >/dev/null 2>&1; then
    if [ -f "$ad/nftables-allports.conf" ]; then
      ACTIONS+=("nftables-allports[name=sshd]")
    else
      ACTIONS+=("nftables[name=sshd, type=allports]")
    fi
  else
    die "未找到 firewalld / iptables / nftables，无法封禁"
  fi

  # Docker 映射的端口走 FORWARD 链，INPUT 里的封禁拦不住，需要在 DOCKER-USER 里再封一次
  USE_DOCKER=0
  if [ "$DOCKER" != no ] && command -v iptables >/dev/null 2>&1 \
     && iptables -nL DOCKER-USER >/dev/null 2>&1 && [ -f "$ad/iptables-allports.conf" ]; then
    ACTIONS+=("iptables-allports[name=sshd-docker, chain=DOCKER-USER, protocol=all]")
    USE_DOCKER=1
  fi
}

collect_ignoreip() {
  local ips="127.0.0.1/8 ::1"
  [ -n "${SSH_CLIENT:-}" ] && ips+=" ${SSH_CLIENT%% *}"
  # 当前已登录会话的来源 IP，避免把自己封掉（sudo 会清掉 SSH_CLIENT，所以还要看 who）
  ips+=" $(who 2>/dev/null | sed -nE 's/.*\(([^)]*)\).*/\1/p' \
           | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-fA-F]*:[0-9a-fA-F:]*:[0-9a-fA-F]*$' | tr '\n' ' ')"
  ips+=" ${IGNOREIP//,/ }"
  # 保留上次安装时的白名单
  [ -f "$JAIL_FILE" ] && ips+=" $(sed -nE 's/^ignoreip *= *//p' "$JAIL_FILE")"
  # shellcheck disable=SC2086
  IGNORE_LIST=$(printf '%s\n' $ips | awk 'NF && !s[$0]++' | tr '\n' ' ' | sed 's/ $//')
}

# OpenSSH 9.8+ 把认证拆到 sshd-session 进程，fail2ban < 1.1 的 sshd 过滤器认不出来
need_session_fix() {
  ver_ge "$F2B_VER" 1.1 && return 1
  local p
  for p in /usr/lib/openssh/sshd-session /usr/libexec/openssh/sshd-session /usr/libexec/sshd-session /usr/sbin/sshd-session; do
    [ -e "$p" ] && return 0
  done
  return 1
}

write_filter() {
  if need_session_fix; then
    cat >"$FILTER_FILE" <<EOF
$MARK
# 兼容 OpenSSH 9.8+ 的 sshd-session 进程名（fail2ban 1.1 起已内置）
[INCLUDES]
before = sshd.conf

[DEFAULT]
_daemon = sshd(?:-session)?

[Definition]
journalmatch = _SYSTEMD_UNIT=sshd.service + _SYSTEMD_UNIT=ssh.service + _COMM=sshd + _COMM=sshd-session
EOF
    FILTER=$FILTER_NAME
    info "检测到 sshd-session，已启用兼容过滤器 $FILTER_NAME"
  else
    rm -f "$FILTER_FILE"
    FILTER=sshd
  fi
}

write_jail() {
  local action_lines="" a
  for a in "${ACTIONS[@]}"; do action_lines+="${action_lines:+$'\n'           }$a"; done
  {
    echo "$MARK  ($(date '+%F %T'))"
    echo "# 手动修改会在下次执行 install 时被覆盖，白名单除外（会自动保留）"
    echo "[sshd]"
    echo "enabled   = true"
    echo "filter    = $FILTER[mode=aggressive]"
    echo "mode      = aggressive"
    echo "port      = $PORTS"
    echo "backend   = $BACKEND"
    [ -n "$SSH_LOG" ] && echo "logpath   = $SSH_LOG"
    echo "maxretry  = $MAXRETRY"
    echo "findtime  = $FINDTIME"
    echo "bantime   = $BANTIME"
    echo "ignoreip  = $IGNORE_LIST"
    echo "action    = $action_lines"
  } >"$JAIL_FILE"

  # 永久封禁记录存在 fail2ban 数据库里，默认 1 天就清理，调大以便重启后恢复
  mkdir -p "$(dirname "$F2B_CONF_FILE")"
  if [ "$BANTIME" = "-1" ]; then
    printf '%s\n[Definition]\ndbpurgeage = 3650d\n' "$MARK" >"$F2B_CONF_FILE"
  else
    rm -f "$F2B_CONF_FILE"
  fi

  # 开机时等 Docker 先建好 DOCKER-USER 链
  if [ "$USE_DOCKER" = 1 ] && [ -d /etc/systemd/system ]; then
    mkdir -p "$(dirname "$SYSTEMD_DROPIN")"
    printf '%s\n[Unit]\nAfter=docker.service\n' "$MARK" >"$SYSTEMD_DROPIN"
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
}

# 用最近 24 小时的日志对比 normal / aggressive 两种模式的识别行数
verify_filter() {
  local tmp mode line
  tmp=$(mktemp)
  if [ "$BACKEND" = systemd ]; then
    journalctl _COMM=sshd + _COMM=sshd-session --since "24 hours ago" -o short --no-pager >"$tmp" 2>/dev/null
  else
    tail -n 100000 "$SSH_LOG" >"$tmp"
  fi
  if [ ! -s "$tmp" ]; then
    info "最近 24 小时没有 SSH 日志，跳过过滤器验证"
  else
    info "用最近 24 小时日志（$(wc -l <"$tmp") 行）验证过滤器："
    for mode in normal aggressive; do
      line=$(fail2ban-regex "$tmp" "$FILTER[mode=$mode]" 2>/dev/null | grep -E '^Failregex:' | head -n1)
      printf '      %-10s %s\n' "$mode" "${line:-（验证失败）}"
    done
  fi
  rm -f "$tmp"
}

wait_f2b() {
  local i
  for i in $(seq 1 20); do
    fail2ban-client ping >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

do_install() {
  need_root
  install_fail2ban
  detect_backend
  [ "$BACKEND" = systemd ] && ensure_journal_support
  PORTS=$(sshd_opt port | paste -sd, -)
  PORTS=${PORTS:-22}
  choose_actions
  collect_ignoreip

  # 备份旧配置，测试失败时回滚
  local f out
  for f in "$JAIL_FILE" "$FILTER_FILE" "$F2B_CONF_FILE"; do
    rm -f "$f.prev"; [ -f "$f" ] && cp -p "$f" "$f.prev"
  done
  mkdir -p "$(dirname "$JAIL_FILE")"
  write_filter
  write_jail

  if ! out=$(fail2ban-client -t 2>&1); then
    for f in "$JAIL_FILE" "$FILTER_FILE" "$F2B_CONF_FILE"; do
      rm -f "$f"; [ -f "$f.prev" ] && mv -f "$f.prev" "$f"
    done
    printf '%s\n' "$out" | tail -n 20 >&2
    die "fail2ban 配置测试失败，已撤销本次修改"
  fi
  rm -f "$JAIL_FILE.prev" "$FILTER_FILE.prev" "$F2B_CONF_FILE.prev"

  verify_filter

  info "重启 fail2ban ..."
  if command -v systemctl >/dev/null 2>&1; then systemctl enable fail2ban >/dev/null 2>&1 || true; fi
  svc restart fail2ban || die "fail2ban 启动失败，请查看: journalctl -u fail2ban -n 50"
  wait_f2b || die "fail2ban 未能在 20 秒内就绪，请查看: journalctl -u fail2ban -n 50"

  ok "防护已启用"
  printf '      日志后端   %s %s\n' "$BACKEND" "$SSH_LOG"
  printf '      SSH 端口   %s\n' "$PORTS"
  printf '      规则       %s 内失败 %s 次 → 封禁 %s\n' "$FINDTIME" "$MAXRETRY" "$([ "$BANTIME" = -1 ] && echo 永久 || echo "$BANTIME")"
  printf '      封禁动作   %s\n' "$(IFS=';'; echo "${ACTIONS[*]}")"
  printf '      白名单     %s\n' "$IGNORE_LIST"
  [ "$USE_DOCKER" = 1 ] && printf '      Docker     已同时在 DOCKER-USER 链封禁\n'
  echo
  do_status_brief

  [ "$DISABLE_PW" = 1 ] && { echo; do_harden; }
  return 0
}

# -------------------------------------------------------------- report ---

# 每行取第一个 IP（IPv4 或 IPv6），输出: 时间<TAB>IP
extract_ips() {
  awk '
    {
      if ($1 ~ /^[0-9][0-9][0-9][0-9]-/) { t = substr($1, 1, 19); s = 3 } else { t = $1 " " $2 " " $3; s = 5 }
      for (i = s; i <= NF; i++) {
        f = $i
        if (f ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ || (f ~ /^[0-9a-fA-F:]+$/ && f ~ /:.*:/)) { print t "\t" f; break }
      }
    }' "$@"
}

# 解析日志，在目录 $1 下生成：
#   all.log   SSH 日志
#   stats     次数<TAB>IP<TAB>首次<TAB>末次（按次数降序）
#   banned    fail2ban 当前封禁的 IP
#   accepted  曾经成功登录过的 IP
# 返回 1 表示没有失败记录
build_stats() {
  local d=$1
  collect_logs >"$d/all.log"
  [ -s "$d/all.log" ] || die "没有读到 SSH 日志"
  grep -E "$FAIL_RE" "$d/all.log" | extract_ips | awk -F'\t' '
    { c[$2]++; if (!($2 in first)) first[$2] = $1; last[$2] = $1 }
    END { for (k in c) printf "%d\t%s\t%s\t%s\n", c[k], k, first[k], last[k] }
  ' | sort -t"$(printf '\t')" -k1,1nr >"$d/stats"
  grep -E 'Accepted (password|publickey|keyboard-interactive|gssapi)' "$d/all.log" | extract_ips | cut -f2 | sort -u >"$d/accepted"
  : >"$d/banned"
  if command -v fail2ban-client >/dev/null 2>&1; then
    fail2ban-client status sshd 2>/dev/null | sed -n 's/.*Banned IP list:[[:space:]]*//p' | tr ' \t' '\n\n' | grep . >"$d/banned"
  fi
  [ -s "$d/stats" ]
}

log_time() { awk '{print ($1 ~ /^[0-9][0-9][0-9][0-9]-/) ? substr($1,1,19) : $1" "$2" "$3}'; }

do_report() {
  local tmp total uniq_n
  tmp=$(mktemp -d)
  if ! build_stats "$tmp"; then
    rm -rf "$tmp"; ok "日志中没有失败登录记录"; return 0
  fi
  [ -f "$NETS_FILE" ] && cp "$NETS_FILE" "$tmp/nets" || : >"$tmp/nets"

  total=$(awk -F'\t' '{s+=$1} END{print s+0}' "$tmp/stats")
  uniq_n=$(wc -l <"$tmp/stats")
  echo "======== SSH 爆破分析  $(hostname)  $(date '+%F %T') ========"
  printf '日志范围: %s ~ %s\n' "$(head -n1 "$tmp/all.log" | log_time)" "$(tail -n1 "$tmp/all.log" | log_time)"
  printf '失败/异常连接: %s 次，来源 IP: %s 个，当前已封禁: %s 个 IP、%s 个网段\n\n' \
    "$total" "$uniq_n" "$(wc -l <"$tmp/banned")" "$(grep -c . "$tmp/nets")"

  if [ "$TOP" -gt 0 ] 2>/dev/null; then echo "---- 失败次数前 $TOP 的 IP ----"; else echo "---- 全部 $uniq_n 个 IP（按失败次数排序）----"; fi
  printf '%6s  %-39s %-41s %s\n' 次数 IP "首次 ~ 末次" 状态
  { if [ "$TOP" -gt 0 ] 2>/dev/null; then head -n "$TOP" "$tmp/stats"; else cat "$tmp/stats"; fi; } | awk -F'\t' -v B="$tmp/banned" -v NETS="$tmp/nets" '
    BEGIN { while ((getline l < B) > 0) b[l] = 1; while ((getline l < NETS) > 0) { sub(/\.0\/24$/, "", l); n[l] = 1 } }
    {
      s = ""
      if ($2 in b) s = "封禁中"
      else { k = $2; sub(/\.[0-9]+$/, "", k); if (k in n) s = "网段已封" }
      printf "%6d  %-39s %s ~ %s  %s\n", $1, $2, $3, $4, s
    }'

  echo
  echo "---- 按 /24 网段汇总（前 10）----"
  printf '%6s  %6s  %s\n' 次数 IP数 网段
  awk -F'\t' '$2 ~ /^[0-9.]+$/ { split($2, a, "."); k = a[1] "." a[2] "." a[3] ".0/24"; n[k] += $1; u[k]++ }
    END { for (k in n) printf "%6d  %6d  %s\n", n[k], u[k], k }' "$tmp/stats" | sort -rn | head -n 10

  local pw
  pw=$(sshd_opt passwordauthentication)
  echo
  info "一键封禁以上所有爆破 IP 和网段: ssh-guard.sh banlog（加 --dry-run 先预览）"
  [ "$pw" = yes ] && warn "当前仍允许密码登录，建议配置好密钥后执行: ssh-guard.sh harden"
  command -v fail2ban-client >/dev/null 2>&1 && [ -f "$JAIL_FILE" ] \
    || warn "尚未安装 ssh-guard 防护，执行: ssh-guard.sh install"
  rm -rf "$tmp"
}

# -------------------------------------------------------------- banlog ---

# IP 段封禁不走 fail2ban（它的 ipset/nft 集合只能放单个 IP），单独维护一个 hash:net 集合
net_backend() {
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then echo firewalld
  elif command -v iptables >/dev/null 2>&1 && command -v ipset >/dev/null 2>&1; then echo ipset
  elif command -v nft >/dev/null 2>&1; then echo nft
  else echo none; fi
}

# 按 $NETS_FILE 全量重建网段封禁规则（开机时由 ssh-guard-nets.service 调用）
apply_nets() {
  need_root
  local be chain cur
  be=$(net_backend)
  mkdir -p "$(dirname "$NETS_FILE")"
  touch "$NETS_FILE"
  case "$be" in
    ipset)
      ipset -exist create "$NET_SET" hash:net maxelem 1048576
      { echo "flush $NET_SET"; grep -E '^[0-9.]+/[0-9]+$' "$NETS_FILE" | sed "s|^|add $NET_SET |"; } | ipset -exist restore
      # Docker 映射端口走 FORWARD，所以 DOCKER-USER 里也要拦
      for chain in INPUT DOCKER-USER; do
        iptables -nL "$chain" >/dev/null 2>&1 || continue
        iptables -C "$chain" -m set --match-set "$NET_SET" src -j DROP 2>/dev/null \
          || iptables -I "$chain" -m set --match-set "$NET_SET" src -j DROP
      done
      ;;
    firewalld)
      firewall-cmd --permanent --get-ipsets | tr ' ' '\n' | grep -qx "$NET_SET" \
        || firewall-cmd --permanent --new-ipset="$NET_SET" --type=hash:net --option=maxelem=1048576 >/dev/null
      cur=$(mktemp)
      firewall-cmd --permanent --ipset="$NET_SET" --get-entries >"$cur"
      [ -s "$cur" ] && firewall-cmd --permanent --ipset="$NET_SET" --remove-entries-from-file="$cur" >/dev/null
      [ -s "$NETS_FILE" ] && firewall-cmd --permanent --ipset="$NET_SET" --add-entries-from-file="$NETS_FILE" >/dev/null
      rm -f "$cur"
      firewall-cmd --permanent --zone=drop --query-source="ipset:$NET_SET" >/dev/null 2>&1 \
        || firewall-cmd --permanent --zone=drop --add-source="ipset:$NET_SET" >/dev/null
      firewall-cmd --reload >/dev/null
      ;;
    nft)
      local elems
      elems=$(grep -E '^[0-9.]+/[0-9]+$' "$NETS_FILE" | paste -sd, -)
      nft -f - <<EOF
add table inet ssh_guard
delete table inet ssh_guard
table inet ssh_guard {
  set nets {
    type ipv4_addr
    flags interval
    ${elems:+elements = { $elems }}
  }
  chain input { type filter hook input priority -5; policy accept; ip saddr @nets drop; }
  chain forward { type filter hook forward priority -5; policy accept; ip saddr @nets drop; }
}
EOF
      ;;
    *) die "未找到 firewalld / iptables+ipset / nftables，无法封禁网段" ;;
  esac
}

# 开机恢复：firewalld 自己会持久化，ipset / nft 需要开机重建
persist_nets() {
  [ "$(net_backend)" = firewalld ] && return 0
  command -v systemctl >/dev/null 2>&1 || { warn "非 systemd 系统，网段封禁重启后不会自动恢复，开机后请执行: ssh-guard.sh apply-nets"; return 0; }
  # 只导出需要的函数，生成独立的恢复脚本，开机时不依赖网络
  {
    echo '#!/usr/bin/env bash'
    echo "$MARK：开机重建 IP 段封禁，由 ssh-guard banlog 生成"
    declare -p NETS_FILE NET_SET
    echo "R='' G='' Y='' B='' N=''"
    declare -f info ok warn die need_root net_backend apply_nets
    echo 'apply_nets'
  } >"$NETS_RESTORE"
  chmod 755 "$NETS_RESTORE"
  cat >"$NETS_UNIT" <<EOF
$MARK
[Unit]
Description=ssh-guard: restore blocked IP ranges
After=network-pre.target docker.service firewalld.service
Before=fail2ban.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$NETS_RESTORE

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload >/dev/null 2>&1
  systemctl enable ssh-guard-nets.service >/dev/null 2>&1 || warn "ssh-guard-nets.service 启用失败"
}

clear_nets() {
  case "$(net_backend)" in
    ipset)
      local chain
      for chain in INPUT DOCKER-USER; do
        while iptables -D "$chain" -m set --match-set "$NET_SET" src -j DROP 2>/dev/null; do :; done
      done
      ipset destroy "$NET_SET" 2>/dev/null ;;
    firewalld)
      firewall-cmd --permanent --zone=drop --remove-source="ipset:$NET_SET" >/dev/null 2>&1
      firewall-cmd --permanent --delete-ipset="$NET_SET" >/dev/null 2>&1
      firewall-cmd --reload >/dev/null 2>&1 ;;
    nft) nft delete table inet ssh_guard 2>/dev/null ;;
  esac
  if [ -f "$NETS_UNIT" ]; then
    systemctl disable ssh-guard-nets.service >/dev/null 2>&1
    rm -f "$NETS_UNIT"; systemctl daemon-reload >/dev/null 2>&1
  fi
  rm -f "$NETS_RESTORE" "$NETS_FILE"
}

# 根据日志算出要封的 IP 和网段，写到 $1/ban_ips（IP<TAB>次数）和 $1/ban_nets（网段<TAB>IP数<TAB>次数）
plan_bans() {
  local d=$1
  collect_ignoreip
  # 白名单 = jail 的 ignoreip + 当前登录会话 + 日志里成功登录过的 IP（防止误封自己人输错密码）
  { printf '%s\n' $IGNORE_LIST; cat "$d/accepted"; } | grep . >"$d/whitelist"
  [ -f "$NETS_FILE" ] && cp "$NETS_FILE" "$d/nets" || : >"$d/nets"
  awk -F'\t' -v MIN="$BAN_MIN" -v SMIN="$SUBNET_MIN" -v NOSUB="$NO_SUBNET" \
      -v WL="$d/whitelist" -v BANNED="$d/banned" -v NETS="$d/nets" \
      -v OUT_IP="$d/ban_ips" -v OUT_NET="$d/ban_nets" '
    function ip2n(ip,   a) { split(ip, a, "."); return ((a[1] * 256 + a[2]) * 256 + a[3]) * 256 + a[4] }
    function is_v4(s) { return s ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/ }
    function in_wl(ip,   n, i) {
      if (ip in wlx) return 1
      if (!is_v4(ip)) return 0
      n = ip2n(ip)
      for (i = 1; i <= nw; i++) if (n >= ws[i] && n <= we[i]) return 1
      return 0
    }
    # 网段 [s, s+255] 与任一白名单范围重叠则不封
    function net_conflict(s,   i) {
      for (i = 1; i <= nw; i++) if (ws[i] <= s + 255 && we[i] >= s) return 1
      return 0
    }
    # 内网、保留地址不按网段封
    function reserved(ip,   a) {
      split(ip, a, ".")
      return a[1] == 0 || a[1] == 10 || a[1] == 127 || a[1] >= 224 || (a[1] == 172 && a[2] >= 16 && a[2] <= 31) \
        || (a[1] == 192 && a[2] == 168) || (a[1] == 169 && a[2] == 254) || (a[1] == 100 && a[2] >= 64 && a[2] <= 127)
    }
    BEGIN {
      while ((getline l < WL) > 0) {
        wlx[l] = 1
        if (!is_v4(l)) continue
        bits = 32; ip = l
        if (l ~ /\//) { split(l, p, "/"); ip = p[1]; bits = p[2] + 0 }
        size = 2 ^ (32 - bits); s = ip2n(ip); s = s - s % size
        nw++; ws[nw] = s; we[nw] = s + size - 1
      }
      while ((getline l < BANNED) > 0) banned[l] = 1
      while ((getline l < NETS) > 0) { sub(/\.0\/24$/, "", l); oldnet[l] = 1 }
    }
    {
      c = $1; ip = $2
      if (in_wl(ip)) next
      if (is_v4(ip)) { k = ip; sub(/\.[0-9]+$/, "", k); u[k]++; t[k] += c }
      if (c >= MIN && !(ip in banned)) cand[ip] = c
    }
    END {
      if (!NOSUB) for (k in u) {
        if (u[k] < SMIN || (k in oldnet) || reserved(k ".0") || net_conflict(ip2n(k ".0"))) continue
        newnet[k] = 1
        printf "%s.0/24\t%d\t%d\n", k, u[k], t[k] > OUT_NET
      }
      for (ip in cand) {
        if (is_v4(ip)) { k = ip; sub(/\.[0-9]+$/, "", k); if ((k in newnet) || (k in oldnet)) continue }
        printf "%s\t%d\n", ip, cand[ip] > OUT_IP
      }
    }' "$d/stats"
  touch "$d/ban_ips" "$d/ban_nets"
  sort -t"$(printf '\t')" -k2,2nr -o "$d/ban_ips" "$d/ban_ips"
  sort -t"$(printf '\t')" -k2,2nr -o "$d/ban_nets" "$d/ban_nets"
}

do_banlog() {
  need_root
  command -v fail2ban-client >/dev/null 2>&1 && fail2ban-client status sshd >/dev/null 2>&1 \
    || die "fail2ban 的 sshd jail 没有运行，请先执行 install"
  local tmp n_ip n_net
  tmp=$(mktemp -d)
  if ! build_stats "$tmp"; then rm -rf "$tmp"; ok "日志中没有爆破记录"; return "${BANLOG_EMPTY_RC:-0}"; fi
  plan_bans "$tmp"
  n_ip=$(grep -c . "$tmp/ban_ips")
  n_net=$(grep -c . "$tmp/ban_nets")

  info "白名单（不会被封，所在网段也不会被封）: $(grep -c . "$tmp/whitelist") 个，含日志中成功登录过的 IP"
  info "待封禁: $n_ip 个 IP（失败 ≥ $BAN_MIN 次），$n_net 个 /24 网段（≥ $SUBNET_MIN 个 IP 参与爆破）"
  if [ "$n_net" -gt 0 ]; then
    echo "---- 网段（前 20）----"
    printf '%-20s %6s %6s\n' 网段 IP数 次数
    head -n 20 "$tmp/ban_nets" | awk -F'\t' '{printf "%-20s %6d %6d\n", $1, $2, $3}'
  fi
  if [ "$n_ip" -gt 0 ]; then
    echo "---- IP（前 20，已被上面网段覆盖的不再单独列出）----"
    head -n 20 "$tmp/ban_ips" | awk -F'\t' '{printf "%-39s %6d 次\n", $1, $2}'
  fi
  if [ "$n_ip" -eq 0 ] && [ "$n_net" -eq 0 ]; then rm -rf "$tmp"; ok "没有需要新封禁的 IP 或网段"; return "${BANLOG_EMPTY_RC:-0}"; fi
  if [ "$DRY_RUN" = 1 ]; then rm -rf "$tmp"; info "预览模式，未做任何修改"; return 0; fi

  if [ "$n_ip" -gt 0 ]; then
    info "封禁 IP ..."
    # 每批 200 个；老版本 fail2ban 不支持一次多个时逐个封
    cut -f1 "$tmp/ban_ips" | xargs -n 200 sh -c 'fail2ban-client set sshd banip "$@" >/dev/null 2>&1 \
      || for ip in "$@"; do fail2ban-client set sshd banip "$ip" >/dev/null 2>&1; done' _
    ok "已通过 fail2ban 封禁 $n_ip 个 IP（bantime 与 sshd jail 相同）"
  fi
  if [ "$n_net" -gt 0 ]; then
    info "封禁网段 ..."
    mkdir -p "$(dirname "$NETS_FILE")"
    touch "$NETS_FILE"
    { cat "$NETS_FILE"; cut -f1 "$tmp/ban_nets"; } | grep . | sort -u -t. -k1,1n -k2,2n -k3,3n -o "$NETS_FILE"
    apply_nets
    persist_nets
    ok "已永久封禁 $n_net 个网段（共 $(grep -c . "$NETS_FILE") 个，列表: $NETS_FILE）"
  fi
  rm -rf "$tmp"
}

# -------------------------------------------------------------- harden ---

count_pubkeys() {
  local n=0 f user home _
  while IFS=: read -r user _ _ _ _ home _; do
    case "$home" in /root|/home/*) ;; *) continue ;; esac
    for f in $(authkeys_files "$user" "$home"); do
      [ -f "$f" ] && n=$((n + $(grep -cE '^[^#]*(ssh-|ecdsa-|sk-)' "$f" 2>/dev/null || true)))
    done
  done </etc/passwd
  echo "$n"
}

reload_sshd() { svc reload ssh sshd || svc restart ssh sshd; }

do_harden() {
  need_root
  local bin; bin=$(sshd_bin) || die "找不到 sshd"
  local keys; keys=$(count_pubkeys)
  if [ "$keys" -eq 0 ] && [ "$FORCE" != 1 ]; then
    die "没有在任何用户的 authorized_keys 中找到公钥，关闭密码登录会把自己锁在外面。确认无误请加 --force"
  fi
  info "检测到 $keys 个公钥"

  local lines="PasswordAuthentication no
ChallengeResponseAuthentication no"
  # 只把 yes 收紧为 prohibit-password，已经是 no 的不动
  [ "$(sshd_opt permitrootlogin)" = yes ] && lines+=$'\nPermitRootLogin prohibit-password'

  local bak; bak="$SSHD_CONFIG.ssh-guard.bak.$(date +%Y%m%d%H%M%S)"
  cp -p "$SSHD_CONFIG" "$bak"
  remove_harden_block

  # sshd 配置是先出现的生效，drop-in 用 00- 前缀，排在 50-cloud-init.conf 等之前
  if [ -d "$(dirname "$SSHD_DROPIN")" ] && grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' "$SSHD_CONFIG"; then
    printf '%s\n%s\n' "$MARK" "$lines" >"$SSHD_DROPIN"
  fi
  if [ "$(sshd_opt passwordauthentication)" != no ]; then
    # 不支持 Include 或被别处覆盖：直接插到主配置文件最前面
    rm -f "$SSHD_DROPIN"
    { echo "$MARK begin"; echo "$lines"; echo "$MARK end"; cat "$bak"; } >"$SSHD_CONFIG"
  fi

  if ! "$bin" -t 2>/tmp/ssh-guard-sshd.err || [ "$(sshd_opt passwordauthentication)" != no ]; then
    cp -p "$bak" "$SSHD_CONFIG"; rm -f "$SSHD_DROPIN"
    cat /tmp/ssh-guard-sshd.err >&2
    die "sshd 配置校验失败，已回滚"
  fi
  reload_sshd || warn "sshd 重载失败，请手动执行 systemctl reload ssh 或 sshd"
  ok "已关闭密码登录（原配置备份: $bak）"
  warn "请保持当前会话不要断开，另开一个窗口用密钥登录测试成功后再退出"
}

remove_harden_block() {
  rm -f "$SSHD_DROPIN"
  if grep -qF "$MARK begin" "$SSHD_CONFIG"; then
    sed -i "\|^$MARK begin\$|,\|^$MARK end\$|d" "$SSHD_CONFIG"
  fi
}

do_unharden() {
  need_root
  local bin; bin=$(sshd_bin) || die "找不到 sshd"
  remove_harden_block
  "$bin" -t || die "sshd 配置校验失败，请手动检查 $SSHD_CONFIG"
  reload_sshd || warn "sshd 重载失败，请手动重载"
  ok "已撤销 harden，当前 PasswordAuthentication = $(sshd_opt passwordauthentication)"
}

# -------------------------------------------------------------- addkey ---

user_home() {
  if command -v getent >/dev/null 2>&1; then getent passwd "$1" | cut -d: -f6
  else awk -F: -v u="$1" '$1==u{print $6}' /etc/passwd; fi
}

# 按 sshd 的 AuthorizedKeysFile 展开某用户的公钥文件路径（%h %u %%）
authkeys_files() {
  local user=$1 home=$2 files f
  files=$(sshd_opt authorizedkeysfile)
  for f in ${files:-.ssh/authorized_keys}; do
    [ "$f" = none ] && continue
    f=${f//%h/$home}; f=${f//%u/$user}; f=${f//%%/%}
    case "$f" in /*) ;; *) f="$home/$f" ;; esac
    echo "$f"
  done
}

# 提取公钥本体（base64 部分），用于判重；行首可能带 from="..." 等选项
key_body() { awk '{for (i = 1; i <= NF; i++) if ($i ~ /^AAAA/) { print $i; exit }}'; }

# sshd 没开公钥认证时打开（极少见，多数发行版默认开启）
ensure_pubkey_auth() {
  [ "$(sshd_opt pubkeyauthentication)" = no ] || return 0
  local bin bak
  bin=$(sshd_bin) || die "找不到 sshd"
  bak="$SSHD_CONFIG.ssh-guard.bak.$(date +%Y%m%d%H%M%S)"
  cp -p "$SSHD_CONFIG" "$bak"
  if [ -d "$(dirname "$SSHD_PUBKEY_DROPIN")" ] && grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' "$SSHD_CONFIG"; then
    printf '%s\nPubkeyAuthentication yes\n' "$MARK" >"$SSHD_PUBKEY_DROPIN"
  fi
  if [ "$(sshd_opt pubkeyauthentication)" != yes ]; then
    rm -f "$SSHD_PUBKEY_DROPIN"
    { echo "$MARK pubkey begin"; echo "PubkeyAuthentication yes"; echo "$MARK pubkey end"; cat "$bak"; } >"$SSHD_CONFIG"
  fi
  if ! "$bin" -t 2>/tmp/ssh-guard-sshd.err || [ "$(sshd_opt pubkeyauthentication)" != yes ]; then
    cp -p "$bak" "$SSHD_CONFIG"; rm -f "$SSHD_PUBKEY_DROPIN"
    cat /tmp/ssh-guard-sshd.err >&2
    die "开启 PubkeyAuthentication 失败，已回滚 sshd 配置"
  fi
  reload_sshd || warn "sshd 重载失败，请手动执行 systemctl reload ssh 或 sshd"
  ok "已开启 sshd 公钥认证（原配置备份: $bak）"
}

do_addkey() {
  need_root
  command -v ssh-keygen >/dev/null 2>&1 || pkg_install openssh-client >/dev/null 2>&1 || true
  command -v ssh-keygen >/dev/null 2>&1 || die "找不到 ssh-keygen"
  # 默认给通过 sudo 调用的那个用户加，否则给 root
  local user=${KEY_USER:-${SUDO_USER:-root}} home akf tmp one line body added=0 skipped=0 genkey=""
  home=$(user_home "$user")
  [ -n "$home" ] || die "用户 $user 不存在"
  tmp=$(mktemp -d)

  [ -n "$KEY_TEXT" ] && printf '%s\n' "$KEY_TEXT" >>"$tmp/keys"
  if [ -n "$KEY_FILE" ]; then
    [ -f "$KEY_FILE" ] || { rm -rf "$tmp"; die "公钥文件不存在: $KEY_FILE"; }
    cat "$KEY_FILE" >>"$tmp/keys"
  fi
  if [ -n "$KEY_GITHUB" ]; then
    info "从 https://github.com/$KEY_GITHUB.keys 获取公钥 ..."
    { curl -fsSL "https://github.com/$KEY_GITHUB.keys" 2>/dev/null || wget -qO- "https://github.com/$KEY_GITHUB.keys" 2>/dev/null; } >"$tmp/gh" \
      && [ -s "$tmp/gh" ] || { rm -rf "$tmp"; die "获取失败：用户名不存在、该账号未上传公钥，或服务器访问不了 GitHub"; }
    cat "$tmp/gh" >>"$tmp/keys"
  fi
  if [ "$KEY_GEN" = 1 ]; then
    mkdir -p "$KEYS_DIR"; chmod 700 "$KEYS_DIR"
    genkey="$KEYS_DIR/${user}@$(hostname)_ed25519"
    rm -f "$genkey" "$genkey.pub"
    ssh-keygen -q -t ed25519 -N "" -C "${user}@$(hostname) ssh-guard $(date +%F)" -f "$genkey" \
      || { rm -rf "$tmp"; die "生成密钥失败"; }
    cat "$genkey.pub" >>"$tmp/keys"
  fi
  [ -s "$tmp/keys" ] || { rm -rf "$tmp"; die "没有提供公钥：请用 --key / --key-file / --github / --generate"; }

  akf=$(authkeys_files "$user" "$home" | head -n1)
  [ -n "$akf" ] || { rm -rf "$tmp"; die "sshd 的 AuthorizedKeysFile 为 none，无法添加公钥"; }
  mkdir -p "$(dirname "$akf")"
  touch "$akf"

  while IFS= read -r line || [ -n "$line" ]; do
    line=$(printf '%s' "$line" | tr -d '\r')
    case "$line" in ''|'#'*) continue ;; esac
    printf '%s\n' "$line" >"$tmp/one"
    if ! ssh-keygen -l -f "$tmp/one" >/dev/null 2>&1; then
      warn "不是有效的公钥，已跳过: ${line:0:50}..."; continue
    fi
    body=$(key_body <"$tmp/one")
    if [ -n "$body" ] && grep -qF "$body" "$akf"; then
      skipped=$((skipped + 1)); continue
    fi
    # 原文件末尾没有换行时先补一个，避免两把公钥粘在同一行
    [ -s "$akf" ] && [ "$(tail -c1 "$akf" | od -An -c | tr -d ' ')" != '\n' ] && echo >>"$akf"
    printf '%s\n' "$line" >>"$akf"
    added=$((added + 1))
    printf '      + %s\n' "$(ssh-keygen -l -f "$tmp/one" 2>/dev/null)"
  done <"$tmp/keys"
  rm -rf "$tmp"

  # 权限不对 sshd 会直接忽略公钥（StrictModes）
  case "$akf" in
    "$home"/*)
      chown "$user": "$(dirname "$akf")" "$akf" 2>/dev/null || chown "$user" "$(dirname "$akf")" "$akf"
      chmod 700 "$(dirname "$akf")"; chmod 600 "$akf" ;;
    *) chown root: "$akf" 2>/dev/null; chmod 644 "$akf" ;;
  esac
  command -v restorecon >/dev/null 2>&1 && restorecon -R "$(dirname "$akf")" >/dev/null 2>&1

  ensure_pubkey_auth
  ok "用户 $user：新增 $added 把公钥，已存在 $skipped 把（$akf，共 $(grep -cE '^[^#]*(ssh-|ecdsa-|sk-)' "$akf") 把）"
  if [ "$user" = root ] && [ "$(sshd_opt permitrootlogin)" = no ]; then
    warn "PermitRootLogin 为 no，root 即使有公钥也无法登录，请改用普通用户或调整 sshd 配置"
  fi
  if [ -n "$genkey" ]; then
    echo
    warn "已生成新密钥对，下面是私钥，请立即保存到本机（如 ~/.ssh/$(basename "$genkey")，权限 600）："
    echo "-----------------------------------------------------------------"
    cat "$genkey"
    echo "-----------------------------------------------------------------"
    info "私钥副本: $genkey（保存到本机后请删除: rm -f $genkey）"
    info "本机登录: ssh -i ~/.ssh/$(basename "$genkey") $user@<服务器IP>"
  fi
  echo
  info "请另开一个窗口测试密钥登录，成功后可关闭密码登录: ssh-guard.sh harden"
  [ "$DISABLE_PW" = 1 ] && { echo; do_harden; }
  return 0
}

# ------------------------------------------------------- status/unban ---

do_status_brief() {
  local s
  s=$(fail2ban-client status sshd 2>/dev/null) || { warn "sshd jail 未运行"; return 1; }
  printf '%s\n' "$s" | grep -E 'Currently failed|Total failed|Currently banned|Total banned' | sed 's/^[|` -]*/      /'
}

do_status() {
  need_root
  command -v fail2ban-client >/dev/null 2>&1 || die "未安装 fail2ban"
  info "sshd jail："
  do_status_brief || return 1
  local list
  list=$(fail2ban-client get sshd banip --with-time 2>/dev/null) || list=""
  if [ -n "$list" ]; then
    echo; info "最近封禁的 20 个 IP："
    printf '%s\n' "$list" | sort -k2,3 | tail -n 20 | sed 's/^/      /'
  fi
  if [ -s "$NETS_FILE" ]; then
    echo; info "已封禁网段 $(grep -c . "$NETS_FILE") 个（$NETS_FILE），最近 10 个："
    tail -n 10 "$NETS_FILE" | sed 's/^/      /'
  fi
  echo
  info "SSH 密码登录：$(sshd_opt passwordauthentication)"
}

# 支持单个 IP 和网段（如 1.2.3.0/24）；解封的 IP 若所在网段被封会给出提示
do_unban() {
  need_root
  [ $# -gt 0 ] || die "用法: ssh-guard.sh unban <IP 或 网段>..."
  local ip net nets_changed=0
  for ip in "$@"; do
    case "$ip" in
      */*)
        if [ -f "$NETS_FILE" ] && grep -qxF "$ip" "$NETS_FILE"; then
          grep -vxF "$ip" "$NETS_FILE" >"$NETS_FILE.tmp"; mv -f "$NETS_FILE.tmp" "$NETS_FILE"
          nets_changed=1; ok "已解封网段 $ip"
        else
          warn "$ip 不在网段封禁列表中"
        fi ;;
      *)
        fail2ban-client set sshd unbanip "$ip" >/dev/null 2>&1 && ok "已解封 $ip" || warn "$ip 不在 fail2ban 封禁列表中"
        net="${ip%.*}.0/24"
        [ -f "$NETS_FILE" ] && grep -qxF "$net" "$NETS_FILE" \
          && warn "$ip 所在网段 $net 仍被封禁，如需放行执行: ssh-guard.sh unban $net" ;;
    esac
  done
  [ "$nets_changed" = 1 ] && apply_nets
  return 0
}

do_uninstall() {
  need_root
  rm -f "$JAIL_FILE" "$FILTER_FILE" "$F2B_CONF_FILE" "$SYSTEMD_DROPIN"
  command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload >/dev/null 2>&1
  svc restart fail2ban || true
  ok "已移除 ssh-guard 的 fail2ban 配置（fail2ban 恢复系统默认配置）"
  if [ -f "$NETS_FILE" ] || [ -f "$NETS_UNIT" ]; then
    clear_nets
    ok "已移除网段封禁"
  fi
  [ -f "$SSHD_DROPIN" ] || grep -qF "$MARK begin" "$SSHD_CONFIG" 2>/dev/null \
    && info "密码登录仍是关闭状态，如需恢复执行: ssh-guard.sh unharden"
  return 0
}

# -------------------------------------------------------------- deploy ---

# 本脚本自身的路径；通过 curl | bash 运行时没有文件，从 GitHub 重新下载一份
self_script() {
  local src=${BASH_SOURCE[0]:-}
  if [ -n "$src" ] && [ -f "$src" ] && grep -q 'ssh-guard' "$src" 2>/dev/null; then echo "$src"; return 0; fi
  local tmp; tmp=$(mktemp)
  if curl -fsSL "$RAW_URL" -o "$tmp" 2>/dev/null || wget -qO "$tmp" "$RAW_URL" 2>/dev/null; then echo "$tmp"; return 0; fi
  rm -f "$tmp"
  return 1
}

deploy_one() {
  local spec=$1 user host port name rc
  spec=${spec%%#*}
  spec=$(printf '%s' "$spec" | tr -d '[:space:]')
  [ -n "$spec" ] || return 0
  case "$spec" in *@*) user=${spec%%@*}; host=${spec#*@} ;; *) user=$DEPLOY_USER; host=$spec ;; esac
  case "$host" in *:*) port=${host##*:}; host=${host%:*} ;; *) port=22 ;; esac
  name=$host
  [ "$port" != 22 ] && name="$host-$port"

  local opts=(-p "$port" -o BatchMode="$DEPLOY_BATCH" -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new)
  [ -n "$DEPLOY_IDENTITY" ] && opts+=(-i "$DEPLOY_IDENTITY")
  # 密码模式：ssh 从 /dev/tty 读密码，不影响 stdin 传脚本
  [ "$DEPLOY_BATCH" = no ] && echo "[*] 连接 $user@$host:$port（如提示请输入密码）"
  ssh "${opts[@]}" "$user@$host" "$DEPLOY_CMD" <"$DEPLOY_SCRIPT" >"$DEPLOY_LOG_DIR/$name.log" 2>&1
  rc=$?
  echo "$rc" >"$DEPLOY_LOG_DIR/$name.rc"
  if [ "$rc" -eq 0 ]; then echo "[成功] $user@$host:$port"; else echo "[失败] $user@$host:$port (退出码 $rc) → $DEPLOY_LOG_DIR/$name.log"; fi
}

do_deploy() {
  local hosts_file="" parallel=10 show=0
  DEPLOY_IDENTITY="" DEPLOY_USER=root DEPLOY_BATCH=yes
  while [ $# -gt 0 ]; do
    case "$1" in
      -p|--password) DEPLOY_BATCH=no; shift ;;
      -f|--hosts) hosts_file=${2:?}; shift 2 ;;
      -P|--parallel) parallel=${2:?}; shift 2 ;;
      -i|--identity) DEPLOY_IDENTITY=${2:?}; shift 2 ;;
      -u|--user) DEPLOY_USER=${2:?}; shift 2 ;;
      -s|--show) show=1; shift ;;
      --) shift; break ;;
      *) die "deploy 未知选项: $1（ssh-guard.sh help 查看用法）" ;;
    esac
  done
  [ -n "$hosts_file" ] && [ -f "$hosts_file" ] || die "服务器列表不存在: ${hosts_file:-（未指定 -f）}"
  [ $# -gt 0 ] || set -- install
  case "$1" in deploy|menu) die "远程命令不能是 $1" ;; esac
  command -v ssh >/dev/null 2>&1 || die "本机没有 ssh 命令"

  DEPLOY_SCRIPT=$(self_script) || die "获取脚本失败，请先下载 ssh-guard.sh 到本地再执行: $RAW_URL"
  DEPLOY_LOG_DIR="ssh-guard-logs/$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$DEPLOY_LOG_DIR"
  # sudo 会清掉 SSH_CLIENT，显式传进去，让远程把本机 IP 加入白名单
  local args; args=$(printf '%q ' "$@")
  DEPLOY_CMD="if [ \"\$(id -u)\" -eq 0 ]; then bash -s -- $args; else sudo -n env SSH_CLIENT=\"\$SSH_CLIENT\" bash -s -- $args; fi"
  export DEPLOY_SCRIPT DEPLOY_LOG_DIR DEPLOY_CMD DEPLOY_IDENTITY DEPLOY_USER DEPLOY_BATCH
  export -f deploy_one

  if [ "$DEPLOY_BATCH" = no ]; then
    tty_ok || die "密码模式需要在终端中运行"
    parallel=1
  fi
  info "执行: ssh-guard.sh $*    并发: $parallel    日志: $DEPLOY_LOG_DIR/"
  grep -vE '^[[:space:]]*(#|$)' "$hosts_file" | xargs -P "$parallel" -I{} bash -c 'deploy_one "$1"' _ {}

  local total failed f
  total=$(ls "$DEPLOY_LOG_DIR"/*.rc 2>/dev/null | wc -l)
  failed=$(grep -lv '^0$' "$DEPLOY_LOG_DIR"/*.rc 2>/dev/null | wc -l)
  echo
  info "完成: 共 $total 台，成功 $((total - failed)) 台，失败 $failed 台"
  if [ "$show" = 1 ]; then
    for f in "$DEPLOY_LOG_DIR"/*.log; do
      [ -f "$f" ] || continue
      printf '\n################ %s ################\n' "$(basename "$f" .log)"
      cat "$f"
    done
  fi
  [ "$failed" -eq 0 ]
}

# ---------------------------------------------------------------- menu ---

tty_ok() { { : </dev/tty; } 2>/dev/null; }

# ask 变量名 提示 [默认值]：从终端读取（curl | bash 时 stdin 是脚本本身，必须读 /dev/tty）
ask() {
  local __v=""
  # 输入结束（Ctrl-D）时直接退出，避免菜单死循环
  read -r -p "$2${3:+ [$3]}: " __v </dev/tty || { echo; exit 0; }
  printf -v "$1" '%s' "${__v:-${3:-}}"
}

confirm() { # confirm 提示 默认(y/n)
  local __a
  ask __a "$1 (y/n)" "$2"
  case "$__a" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

ask_int() { # ask_int 变量名 提示 默认值
  while true; do
    ask "$1" "$2" "$3"
    case "${!1}" in ''|*[!0-9]*) warn "请输入正整数" ;; *) return 0 ;; esac
  done
}

# 交互式收集 install 参数，结果放在 INSTALL_ARGS
ask_install_opts() {
  ask_int MAXRETRY "失败几次封禁" "$MAXRETRY"
  ask FINDTIME "统计窗口（如 10m / 1h / 1d）" "$FINDTIME"
  ask BANTIME "封禁时长（-1 为永久，或如 1d / 7d）" "$BANTIME"
  ask IGNOREIP "额外白名单 IP（空格分隔，可留空；当前登录 IP 会自动加入）" ""
  if confirm "检测到 Docker 时也在 DOCKER-USER 链封禁" y; then DOCKER=auto; else DOCKER=no; fi
  if confirm "同时关闭 SSH 密码登录（需已配置并测试过密钥）" n; then DISABLE_PW=1; else DISABLE_PW=0; fi
  INSTALL_ARGS=(install --maxretry "$MAXRETRY" --findtime "$FINDTIME" --bantime "$BANTIME")
  [ -n "$IGNOREIP" ] && INSTALL_ARGS+=(--ignoreip "$IGNOREIP")
  [ "$DOCKER" = no ] && INSTALL_ARGS+=(--no-docker)
  [ "$DISABLE_PW" = 1 ] && INSTALL_ARGS+=(--disable-password)
  return 0
}

menu_addkey() {
  local m
  ask KEY_USER "给哪个用户添加公钥" "${SUDO_USER:-root}"
  echo "公钥来源："
  echo "  1) 粘贴公钥（本机执行 cat ~/.ssh/id_ed25519.pub 得到的一整行）"
  echo "  2) 从 GitHub 账号导入（https://github.com/<用户名>.keys）"
  echo "  3) 在服务器上生成新的密钥对（会打印私钥，需要保存到本机）"
  ask m "请选择" 1
  KEY_TEXT="" KEY_GITHUB="" KEY_GEN=0
  case "$m" in
    1) ask KEY_TEXT "粘贴公钥" ""; [ -n "$KEY_TEXT" ] || { warn "没有输入公钥"; return 1; } ;;
    2) ask KEY_GITHUB "GitHub 用户名" ""; [ -n "$KEY_GITHUB" ] || { warn "没有输入用户名"; return 1; } ;;
    3) KEY_GEN=1 ;;
    *) warn "无效选择"; return 1 ;;
  esac
  DISABLE_PW=0
  ( do_addkey )
}

# 本机公钥，没有就询问是否生成，结果放在 LOCAL_PUBKEY
local_pubkey() {
  local f
  LOCAL_PUBKEY=""
  for f in ~/.ssh/id_ed25519.pub ~/.ssh/id_ecdsa.pub ~/.ssh/id_rsa.pub; do
    [ -f "$f" ] && { LOCAL_PUBKEY=$f; return 0; }
  done
  confirm "本机没有 SSH 密钥，现在生成 ~/.ssh/id_ed25519" y || return 1
  mkdir -p ~/.ssh && chmod 700 ~/.ssh
  ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 </dev/tty || return 1
  LOCAL_PUBKEY=~/.ssh/id_ed25519.pub
}

menu_deploy() {
  local hosts_file line opt parallel user identity="" use_pw=0 remote=() args=()
  ask hosts_file "服务器列表文件（每行 [user@]host[:port]，留空则现在逐行输入）" ""
  if [ -z "$hosts_file" ]; then
    hosts_file=$(mktemp)
    echo "逐行输入服务器，输入空行结束："
    while read -r -p "> " line </dev/tty && [ -n "$line" ]; do echo "$line" >>"$hosts_file"; done
  fi
  [ -s "$hosts_file" ] || { warn "服务器列表为空"; return 1; }
  echo "  共 $(grep -cvE '^[[:space:]]*(#|$)' "$hosts_file") 台服务器"

  echo "在这些服务器上执行："
  echo "  1) 安装/更新防护    2) 爆破分析报告    3) 查看封禁状态    4) 关闭密码登录"
  echo "  5) 一键封禁日志中的爆破 IP 和 IP 段    6) 预览将要封禁的 IP 和 IP 段（不修改）"
  echo "  7) 启用密钥登录（把本机公钥推送到这些服务器）"
  ask opt "请选择" 1
  case "$opt" in
    7) local_pubkey || return 1
       info "推送公钥: $LOCAL_PUBKEY"
       remote=(addkey --key "$(cat "$LOCAL_PUBKEY")")
       confirm "这些服务器目前只能用密码登录（逐台连接并输入密码）" y && use_pw=1 ;;
    1) ask_install_opts; remote=("${INSTALL_ARGS[@]}") ;;
    2) ask_int TOP "每台显示前几个 IP（0 = 全部）" 0; remote=(report --top "$TOP") ;;
    3) remote=(status) ;;
    4) confirm "确认所有服务器都已配置公钥并测试过密钥登录" n || return 0; remote=(harden) ;;
    5) ask_banlog_opts; remote=("${BANLOG_ARGS[@]}") ;;
    6) ask_banlog_opts; remote=("${BANLOG_ARGS[@]}" --dry-run) ;;
    *) warn "无效选择"; return 1 ;;
  esac
  if [ "$use_pw" = 1 ]; then parallel=1; else ask_int parallel "并发数" 10; fi
  ask user "未写用户名时的默认用户" root
  [ "$use_pw" = 1 ] || ask identity "SSH 私钥路径（留空使用默认密钥）" ""

  args=(-f "$hosts_file" -P "$parallel" -u "$user")
  [ -n "$identity" ] && args+=(-i "$identity")
  [ "$use_pw" = 1 ] && args+=(-p)
  case "${remote[0]}" in report|status|banlog) args+=(-s) ;; esac
  confirm "开始执行 ssh-guard.sh ${remote[*]}" y || return 0
  ( do_deploy "${args[@]}" -- "${remote[@]}" )
}

# 交互式收集 banlog 参数，结果放在 BANLOG_ARGS
ask_banlog_opts() {
  ask_int BAN_MIN "失败至少几次的 IP 才封（1 = 日志中所有爆破 IP）" "$BAN_MIN"
  if confirm "同时封禁爆破集中的 /24 网段" y; then
    NO_SUBNET=0
    ask_int SUBNET_MIN "同一 /24 中至少几个 IP 参与爆破才封整段" "$SUBNET_MIN"
  else
    NO_SUBNET=1
  fi
  ask SINCE "只分析某时间之后的日志（如 7 days ago，留空为全部）" ""
  BANLOG_ARGS=(banlog --min "$BAN_MIN" --subnet-min "$SUBNET_MIN")
  [ "$NO_SUBNET" = 1 ] && BANLOG_ARGS+=(--no-subnet)
  [ -n "$SINCE" ] && BANLOG_ARGS+=(--since "$SINCE")
  return 0
}

do_menu() {
  local choice ips root_tip=""
  [ "$(id -u)" -eq 0 ] || root_tip="  （当前不是 root，只能使用 9 批量部署；其他功能请用 sudo 运行）"
  while true; do
    cat <<EOF

=================== ssh-guard $VERSION ===================
  1) 安装/更新防护（fail2ban aggressive 模式 + 自动封禁）
  2) 爆破分析报告（Top IP、首/末次时间、/24 网段）
  3) 一键封禁日志中的爆破 IP 和 IP 段
  4) 查看封禁状态
  5) 解封 IP 或 IP 段
  6) 启用 SSH 密钥登录（添加公钥）
  7) 关闭 SSH 密码登录（仅允许密钥）
  8) 恢复 SSH 密码登录
  9) 批量部署到多台服务器
 10) 卸载 ssh-guard 的 fail2ban 配置和网段封禁
  0) 退出
$root_tip
EOF
    ask choice "请选择" ""
    # 每个功能在子 shell 中执行，出错 die 时只退出该功能，回到菜单
    case "$choice" in
      1) ask_install_opts; ( do_install ) ;;
      2) ask_int TOP "显示前几个 IP（0 = 全部）" "$TOP"
         ask SINCE "只看某时间之后的日志（如 24 hours ago，留空为全部）" ""
         ( do_report ) ;;
      3) ask_banlog_opts
         # 先预览，确认后再执行
         if ( DRY_RUN=1 BANLOG_EMPTY_RC=2; do_banlog ) && confirm "确认封禁以上 IP 和网段" n; then
           ( DRY_RUN=0; do_banlog )
         fi ;;
      4) ( do_status ) ;;
      5) ask ips "要解封的 IP 或网段（如 1.2.3.4 5.6.7.0/24，空格分隔）" ""
         # shellcheck disable=SC2086
         [ -n "$ips" ] && ( do_unban $ips ) ;;
      6) menu_addkey ;;
      7) if confirm "确认已配置公钥，并已在另一个窗口测试过密钥登录" n; then
           if confirm "没检测到公钥时也强制关闭（可能把自己锁在外面）" n; then FORCE=1; else FORCE=0; fi
           ( do_harden )
         fi ;;
      8) ( do_unharden ) ;;
      9) menu_deploy ;;
      10) confirm "确认移除 ssh-guard 的 fail2ban 配置和网段封禁" n && ( do_uninstall ) ;;
      0|q|Q|exit) exit 0 ;;
      *) warn "无效选择"; continue ;;
    esac
    ask choice "按回车返回菜单" ""
  done
}

# ---------------------------------------------------------------- main ---

CMD=""
if [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; then CMD=$1; shift; fi
if [ "$CMD" = deploy ]; then do_deploy "$@"; exit; fi
# 不带任何参数且有终端 → 菜单；否则保持原来的默认行为 install
if [ -z "$CMD" ]; then
  if [ $# -eq 0 ] && tty_ok; then CMD=menu; else CMD=install; fi
fi
ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --maxretry) MAXRETRY=${2:?}; shift 2 ;;
    --findtime) FINDTIME=${2:?}; shift 2 ;;
    --bantime) BANTIME=${2:?}; shift 2 ;;
    --ignoreip) IGNOREIP=${2:?}; shift 2 ;;
    --no-docker) DOCKER=no; shift ;;
    --disable-password) DISABLE_PW=1; shift ;;
    --force) FORCE=1; shift ;;
    --since) SINCE=${2:?}; shift 2 ;;
    --top) TOP=${2:?}; [ "$TOP" = all ] && TOP=0; shift 2 ;;
    --log) LOGFILE=${2:?}; shift 2 ;;
    --min) BAN_MIN=${2:?}; shift 2 ;;
    --subnet-min) SUBNET_MIN=${2:?}; shift 2 ;;
    --no-subnet) NO_SUBNET=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --user) KEY_USER=${2:?}; shift 2 ;;
    --key) KEY_TEXT+="${KEY_TEXT:+$'\n'}${2:?}"; shift 2 ;;
    --key-file) KEY_FILE=${2:?}; shift 2 ;;
    --github) KEY_GITHUB=${2:?}; shift 2 ;;
    --generate) KEY_GEN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    -v|--version) echo "ssh-guard $VERSION"; exit 0 ;;
    -*) die "未知选项: $1（ssh-guard.sh help 查看用法）" ;;
    *) ARGS+=("$1"); shift ;;
  esac
done

case "$CMD" in
  menu) tty_ok || die "没有可用的终端，无法进入交互菜单"; do_menu ;;
  install) do_install ;;
  report) do_report ;;
  addkey) do_addkey ;;
  harden) do_harden ;;
  unharden) do_unharden ;;
  status) do_status ;;
  banlog) do_banlog ;;
  apply-nets) apply_nets ;;
  unban) do_unban "${ARGS[@]+"${ARGS[@]}"}" ;;
  uninstall) do_uninstall ;;
  help) usage ;;
  *) die "未知命令: $CMD（ssh-guard.sh help 查看用法）" ;;
esac
