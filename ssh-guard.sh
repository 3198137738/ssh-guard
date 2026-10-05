#!/usr/bin/env bash
# ssh-guard —— SSH 爆破防护一键脚本
#   - fail2ban sshd jail：aggressive 模式（关掉密码登录后也能识别 preauth 断开）、永久封禁、封全部端口
#   - 检测到 Docker 时额外在 DOCKER-USER 链封禁（容器映射端口不走 INPUT 链）
#   - 爆破分析报告：失败次数 Top IP、首/末次时间、是否已封、/24 网段汇总
#   - 可选关闭 SSH 密码登录（带密钥检查与自动回滚）
#
# 一键运行：
#   curl -fsSL https://raw.githubusercontent.com/3198137738/ssh-guard/main/ssh-guard.sh | sudo bash
#   curl -fsSL https://raw.githubusercontent.com/3198137738/ssh-guard/main/ssh-guard.sh | sudo bash -s -- report
set -uo pipefail

VERSION="1.0.0"
JAIL_FILE=/etc/fail2ban/jail.d/ssh-guard.local
F2B_CONF_FILE=/etc/fail2ban/fail2ban.d/ssh-guard.local
FILTER_NAME=ssh-guard-sshd
FILTER_FILE=/etc/fail2ban/filter.d/${FILTER_NAME}.conf
SYSTEMD_DROPIN=/etc/systemd/system/fail2ban.service.d/ssh-guard.conf
SSHD_CONFIG=/etc/ssh/sshd_config
SSHD_DROPIN=/etc/ssh/sshd_config.d/00-ssh-guard.conf
MARK="# managed by ssh-guard"

# 默认参数
MAXRETRY=3
FINDTIME=1h
BANTIME=-1
IGNOREIP=""
DOCKER=auto
DISABLE_PW=0
FORCE=0
SINCE=""
TOP=30
LOGFILE=""

if [ -t 1 ]; then R=$'\e[31m' G=$'\e[32m' Y=$'\e[33m' B=$'\e[36m' N=$'\e[0m'; else R='' G='' Y='' B='' N=''; fi
info() { printf '%s[*]%s %s\n' "$B" "$N" "$*"; }
ok()   { printf '%s[✓]%s %s\n' "$G" "$N" "$*"; }
warn() { printf '%s[!]%s %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '%s[✗]%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
用法: ssh-guard.sh [命令] [选项]

命令:
  install              安装/更新 fail2ban 防护（默认命令，可重复执行）
  report               分析 SSH 爆破日志：Top IP、首/末次时间、是否已封、/24 网段汇总
  harden               关闭 SSH 密码登录，只允许密钥（会先检查是否已配置公钥）
  unharden             撤销 harden，恢复原来的密码登录设置
  status               查看当前封禁情况
  unban <IP>...        解封 IP
  uninstall            移除 ssh-guard 写入的 fail2ban 配置（不卸载 fail2ban）
  help                 显示本帮助

install 选项:
  --maxretry N         findtime 内失败 N 次即封禁（默认 3）
  --findtime T         统计窗口，如 10m / 1h / 1d（默认 1h）
  --bantime T          封禁时长，-1 为永久（默认 -1）
  --ignoreip "IP ..."  白名单，空格或逗号分隔；当前登录会话的 IP 会自动加入
  --no-docker          不在 DOCKER-USER 链封禁
  --disable-password   安装完成后顺便执行 harden

harden 选项:
  --force              未检测到任何 authorized_keys 也强制关闭密码登录（可能把自己锁在外面）

report 选项:
  --since T            只分析该时间之后的日志（仅 journal 有效），如 "2026-10-01" / "24 hours ago"
  --top N              显示前 N 个 IP（默认 30）
  --log FILE           指定日志文件（支持 .gz）

示例:
  curl -fsSL <RAW_URL> | sudo bash
  curl -fsSL <RAW_URL> | sudo bash -s -- install --maxretry 5 --ignoreip "1.2.3.4" --disable-password
  curl -fsSL <RAW_URL> | sudo bash -s -- report --since "24 hours ago"
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

do_report() {
  local tmp total uniq_n
  tmp=$(mktemp -d)
  collect_logs >"$tmp/all.log"
  [ -s "$tmp/all.log" ] || { rm -rf "$tmp"; die "没有读到 SSH 日志"; }
  grep -E "$FAIL_RE" "$tmp/all.log" >"$tmp/fail.log"
  if [ ! -s "$tmp/fail.log" ]; then
    rm -rf "$tmp"; ok "日志中没有失败登录记录"; return 0
  fi

  # 每行取第一个 IP，统计 次数 / 首次 / 末次
  awk '
    {
      if ($1 ~ /^[0-9][0-9][0-9][0-9]-/) { t = substr($1, 1, 19); s = 3 } else { t = $1 " " $2 " " $3; s = 5 }
      ip = ""
      for (i = s; i <= NF; i++) {
        f = $i
        if (f ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ || (f ~ /^[0-9a-fA-F:]+$/ && f ~ /:.*:/)) { ip = f; break }
      }
      if (ip == "") next
      c[ip]++; if (!(ip in first)) first[ip] = t; last[ip] = t
    }
    END { for (k in c) printf "%d\t%s\t%s\t%s\n", c[k], k, first[k], last[k] }
  ' "$tmp/fail.log" | sort -t"$(printf '\t')" -k1,1nr >"$tmp/stats"

  if command -v fail2ban-client >/dev/null 2>&1; then
    fail2ban-client status sshd 2>/dev/null | sed -n 's/.*Banned IP list:[[:space:]]*//p' | tr ' \t' '\n\n' | grep . >"$tmp/banned"
  fi
  touch "$tmp/banned"

  total=$(awk -F'\t' '{s+=$1} END{print s+0}' "$tmp/stats")
  uniq_n=$(wc -l <"$tmp/stats")
  echo "======== SSH 爆破分析  $(hostname)  $(date '+%F %T') ========"
  printf '日志范围: %s ~ %s\n' "$(head -n1 "$tmp/all.log" | awk '{print ($1 ~ /^[0-9][0-9][0-9][0-9]-/) ? substr($1,1,19) : $1" "$2" "$3}')" \
    "$(tail -n1 "$tmp/all.log" | awk '{print ($1 ~ /^[0-9][0-9][0-9][0-9]-/) ? substr($1,1,19) : $1" "$2" "$3}')"
  printf '失败/异常连接: %s 次，来源 IP: %s 个，当前已封禁: %s 个\n\n' "$total" "$uniq_n" "$(wc -l <"$tmp/banned")"

  echo "---- 失败次数前 $TOP 的 IP ----"
  printf '%6s  %-39s %-41s %s\n' 次数 IP "首次 ~ 末次" 状态
  head -n "$TOP" "$tmp/stats" | awk -F'\t' -v B="$tmp/banned" '
    BEGIN { while ((getline l < B) > 0) b[l] = 1 }
    { printf "%6d  %-39s %s ~ %s  %s\n", $1, $2, $3, $4, ($2 in b) ? "封禁中" : "" }'

  echo
  echo "---- 按 /24 网段汇总（前 10）----"
  printf '%6s  %6s  %s\n' 次数 IP数 网段
  awk -F'\t' '$2 ~ /^[0-9.]+$/ { split($2, a, "."); k = a[1] "." a[2] "." a[3] ".0/24"; n[k] += $1; u[k]++ }
    END { for (k in n) printf "%6d  %6d  %s\n", n[k], u[k], k }' "$tmp/stats" | sort -rn | head -n 10

  local pw
  pw=$(sshd_opt passwordauthentication)
  echo
  [ "$pw" = yes ] && warn "当前仍允许密码登录，建议配置好密钥后执行: ssh-guard.sh harden"
  command -v fail2ban-client >/dev/null 2>&1 && [ -f "$JAIL_FILE" ] \
    || warn "尚未安装 ssh-guard 防护，执行: ssh-guard.sh install"
  rm -rf "$tmp"
}

# -------------------------------------------------------------- harden ---

count_pubkeys() {
  local n=0 files f home
  files=$(sshd_opt authorizedkeysfile)
  files=${files:-.ssh/authorized_keys}
  for home in /root /home/*; do
    for f in $files; do
      case "$f" in /*) ;; *) f="$home/$f" ;; esac
      f=${f//%h/$home}
      [ -f "$f" ] && n=$((n + $(grep -cE '^[^#]*(ssh-|ecdsa-|sk-)' "$f" 2>/dev/null || true)))
    done
  done
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
  echo
  info "SSH 密码登录：$(sshd_opt passwordauthentication)"
}

do_unban() {
  need_root
  [ $# -gt 0 ] || die "用法: ssh-guard.sh unban <IP>..."
  local ip
  for ip in "$@"; do
    fail2ban-client set sshd unbanip "$ip" >/dev/null 2>&1 && ok "已解封 $ip" || warn "$ip 不在封禁列表中"
  done
}

do_uninstall() {
  need_root
  rm -f "$JAIL_FILE" "$FILTER_FILE" "$F2B_CONF_FILE" "$SYSTEMD_DROPIN"
  command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload >/dev/null 2>&1
  svc restart fail2ban || true
  ok "已移除 ssh-guard 的 fail2ban 配置（fail2ban 恢复系统默认配置）"
  [ -f "$SSHD_DROPIN" ] || grep -qF "$MARK begin" "$SSHD_CONFIG" 2>/dev/null \
    && info "密码登录仍是关闭状态，如需恢复执行: ssh-guard.sh unharden"
  return 0
}

# ---------------------------------------------------------------- main ---

CMD=install
if [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; then CMD=$1; shift; fi
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
    --top) TOP=${2:?}; shift 2 ;;
    --log) LOGFILE=${2:?}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    -v|--version) echo "ssh-guard $VERSION"; exit 0 ;;
    -*) die "未知选项: $1（ssh-guard.sh help 查看用法）" ;;
    *) ARGS+=("$1"); shift ;;
  esac
done

case "$CMD" in
  install) do_install ;;
  report) do_report ;;
  harden) do_harden ;;
  unharden) do_unharden ;;
  status) do_status ;;
  unban) do_unban "${ARGS[@]+"${ARGS[@]}"}" ;;
  uninstall) do_uninstall ;;
  help) usage ;;
  *) die "未知命令: $CMD（ssh-guard.sh help 查看用法）" ;;
esac
