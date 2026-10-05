# ssh-guard

SSH 爆破防护一键脚本，基于 fail2ban：

- **aggressive 模式**：关掉密码登录后，扫描器只会留下 preauth 阶段的断开日志，fail2ban 默认的 normal 模式认不出来，aggressive 模式可以
- **默认永久封禁**，封全部端口；优先用 ipset，封几万个 IP 也不影响性能
- **Docker 兼容**：检测到 Docker 时额外在 `DOCKER-USER` 链封禁（容器映射端口不走 INPUT 链）
- **自动白名单**：当前登录会话的来源 IP 自动加入 ignoreip，避免把自己封掉
- **爆破分析报告**：失败次数 Top IP、首次/末次出现时间、是否已封、/24 网段汇总
- **一键封禁日志中的爆破 IP 和 IP 段**：IP 交给 fail2ban 封；同一 /24 有多个 IP 参与爆破时封整段（独立的 hash:net 集合，重启自动恢复）；白名单和成功登录过的 IP 不会误封
- **启用密钥登录**：给用户添加公钥（粘贴 / 从 GitHub 账号导入 / 服务器上生成），自动修正 `.ssh` 权限并确保 sshd 开启公钥认证；可批量把本机公钥推送到只能密码登录的服务器
- **关闭密码登录**（可选）：先检查是否配置了公钥，`sshd -t` 校验失败自动回滚
- 兼容 Debian / Ubuntu / CentOS / Rocky / Alma / openSUSE / Alpine；iptables / nftables / firewalld；auth.log / secure / journal；OpenSSH 9.8+ 的 `sshd-session`

所有功能都在 `ssh-guard.sh` 这一个脚本里，可以用交互菜单选择，也可以用命令行参数直接执行。

## 交互菜单（推荐）

```bash
curl -fsSL https://raw.githubusercontent.com/3198137738/ssh-guard/main/ssh-guard.sh | sudo bash
```

```
=================== ssh-guard ===================
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
```

选择后会逐项询问参数（回车使用默认值），执行完返回菜单。

## 命令行（适合脚本、cron、批量）

没有终端时（如 cron、批量部署）不带参数默认执行 `install`。

```bash
# 安装防护（可重复执行，用于更新配置）
curl -fsSL https://raw.githubusercontent.com/3198137738/ssh-guard/main/ssh-guard.sh | sudo bash -s -- install

# 查看爆破分析报告
curl -fsSL https://raw.githubusercontent.com/3198137738/ssh-guard/main/ssh-guard.sh | sudo bash -s -- report

# 一键封禁日志中所有爆破 IP 和爆破集中的 /24 网段（建议先加 --dry-run 预览）
curl -fsSL https://raw.githubusercontent.com/3198137738/ssh-guard/main/ssh-guard.sh | sudo bash -s -- banlog --dry-run
curl -fsSL https://raw.githubusercontent.com/3198137738/ssh-guard/main/ssh-guard.sh | sudo bash -s -- banlog

# 启用密钥登录：导入 GitHub 账号上的公钥 / 直接给出公钥 / 在服务器上生成密钥对
curl -fsSL https://raw.githubusercontent.com/3198137738/ssh-guard/main/ssh-guard.sh | sudo bash -s -- addkey --github your-github-name
curl -fsSL https://raw.githubusercontent.com/3198137738/ssh-guard/main/ssh-guard.sh | sudo bash -s -- addkey --key "ssh-ed25519 AAAA... me@pc"
curl -fsSL https://raw.githubusercontent.com/3198137738/ssh-guard/main/ssh-guard.sh | sudo bash -s -- addkey --generate

# 安装防护，同时关闭密码登录（请先确认密钥能登录）
curl -fsSL https://raw.githubusercontent.com/3198137738/ssh-guard/main/ssh-guard.sh | sudo bash -s -- install --disable-password
```

也可以下载下来使用：

```bash
curl -fsSLO https://raw.githubusercontent.com/3198137738/ssh-guard/main/ssh-guard.sh && chmod +x ssh-guard.sh
sudo ./ssh-guard.sh help
```

## 命令

| 命令 | 说明 |
| --- | --- |
| `menu` | 交互菜单（有终端时不带参数的默认行为） |
| `install` | 安装/更新 fail2ban 防护（无终端时的默认行为） |
| `report` | 爆破分析报告 |
| `addkey` | 启用 SSH 密钥登录：添加公钥 |
| `harden` | 关闭密码登录，只允许密钥 |
| `unharden` | 撤销 harden |
| `status` | 查看封禁情况 |
| `banlog` | 一键封禁日志中的爆破 IP 和 IP 段 |
| `unban <IP 或网段>...` | 解封 IP 或网段（如 `1.2.3.0/24`） |
| `apply-nets` | 手动编辑 `/etc/ssh-guard/blocked-nets.txt` 后重建网段规则 |
| `uninstall` | 移除 ssh-guard 写入的 fail2ban 配置和网段封禁 |
| `deploy` | 批量在多台服务器上执行上面的命令 |

`install` 选项：

| 选项 | 默认 | 说明 |
| --- | --- | --- |
| `--maxretry N` | 3 | findtime 内失败 N 次即封 |
| `--findtime T` | 1h | 统计窗口，如 `10m` / `1h` / `1d` |
| `--bantime T` | -1 | 封禁时长，`-1` 为永久 |
| `--ignoreip "IP ..."` | | 额外白名单，空格或逗号分隔，再次 install 时会保留 |
| `--no-docker` | | 不在 DOCKER-USER 链封禁 |
| `--disable-password` | | 安装后顺便执行 harden |

`report` 选项：`--since "24 hours ago"`（只对 journal 有效）、`--top N`、`--log FILE`。

`addkey` 选项（公钥来源至少一种，可组合）：

| 选项 | 说明 |
| --- | --- |
| `--user USER` | 给哪个用户添加，默认为 sudo 前的原用户，否则 root |
| `--key "ssh-ed25519 AAAA..."` | 直接给出公钥，可重复 |
| `--key-file FILE` | 从文件读取公钥（可多行） |
| `--github NAME` | 导入 `https://github.com/NAME.keys` 的全部公钥 |
| `--generate` | 在服务器上生成 ed25519 密钥对并打印私钥；私钥副本在 `/root/ssh-guard-keys/`，保存到本机后请删除 |
| `--disable-password` | 添加后顺便关闭密码登录（确认密钥可用时再用） |

会校验公钥格式、跳过已存在的公钥，修正 `~/.ssh` 为 700、`authorized_keys` 为 600（SELinux 下执行 restorecon）；sshd 若关闭了 `PubkeyAuthentication` 会自动打开（校验失败回滚）。

`harden` 选项：`--force`（没检测到公钥也强制关闭，慎用）。

`banlog` 选项：

| 选项 | 默认 | 说明 |
| --- | --- | --- |
| `--min N` | 1 | 失败 ≥ N 次的 IP 才封，默认即日志中所有爆破 IP |
| `--subnet-min N` | 3 | 同一 /24 中 ≥ N 个 IP 参与爆破时封整个网段 |
| `--no-subnet` | | 只封单个 IP |
| `--dry-run` | | 只预览不修改 |
| `--since T` / `--log FILE` | | 限定分析的日志范围 |

不会被封的：ignoreip 白名单、当前登录会话 IP、日志中成功登录过的 IP；这些 IP 所在的 /24 以及内网/保留网段（10/8、172.16/12、192.168/16、100.64/10 等）也不会整段封。已被网段覆盖的 IP 不再单独封。单个 IP 通过 fail2ban 封禁（封禁时长与 sshd jail 相同），网段为永久封禁。

## 多台服务器批量执行

在任意一台能 SSH 到其他服务器的机器（Linux / macOS / WSL / Git Bash）上执行，脚本内容通过 SSH 传过去，目标服务器不需要能访问 GitHub。本机执行 deploy 不需要 root。

交互方式：菜单里选 `7`，按提示输入服务器列表文件（或直接逐行输入服务器）、要执行的操作和参数即可。

命令行方式：

```bash
# 服务器列表，每行一台: [user@]host[:port]，# 开头为注释
cat > hosts.txt <<'EOF'
192.168.1.10
ubuntu@10.0.0.5:2222
EOF

S=https://raw.githubusercontent.com/3198137738/ssh-guard/main/ssh-guard.sh
curl -fsSL $S | bash -s -- deploy -f hosts.txt                          # 全部安装防护
curl -fsSL $S | bash -s -- deploy -f hosts.txt -s -- report --top 10    # 全部出报告并打印
curl -fsSL $S | bash -s -- deploy -f hosts.txt -- install --disable-password
curl -fsSL $S | bash -s -- deploy -f hosts.txt -P 20 -i ~/.ssh/id_ed25519 -- status
```

| deploy 选项 | 说明 |
| --- | --- |
| `-f, --hosts FILE` | 服务器列表 |
| `-P, --parallel N` | 并发数（默认 10） |
| `-i, --identity KEY` | SSH 私钥 |
| `-u, --user USER` | 未写用户名时的默认用户（默认 root） |
| `-s, --show` | 结束后打印每台服务器的输出 |
| `-p, --password` | 目标服务器还没有密钥时用密码登录，逐台连接并提示输入密码 |

`--` 后面是要在远程执行的命令和参数，默认 `install`。每台服务器的输出保存在 `ssh-guard-logs/<时间>/<host>.log`。要求本机能用密钥免密登录这些服务器；非 root 用户需要免密 sudo。执行 deploy 的这台机器的 IP 会自动加入各服务器的白名单。

**批量启用密钥登录**：把本机公钥推送到一批目前只能密码登录的服务器（菜单 9 → 7 会自动找本机公钥，没有则帮你生成）：

```bash
curl -fsSL $S | bash -s -- deploy -f hosts.txt -p -- addkey --key "$(cat ~/.ssh/id_ed25519.pub)"
```

密码模式下用 root 登录最省事；用普通用户时需要该用户有免密 sudo。

## 写入的文件

| 文件 | 作用 |
| --- | --- |
| `/etc/fail2ban/jail.d/ssh-guard.local` | sshd jail 配置 |
| `/etc/fail2ban/fail2ban.d/ssh-guard.local` | 永久封禁时调大 `dbpurgeage`，重启后封禁记录还在 |
| `/etc/fail2ban/filter.d/ssh-guard-sshd.conf` | 仅 OpenSSH 9.8+ 且 fail2ban < 1.1 时，兼容 `sshd-session` |
| `/etc/systemd/system/fail2ban.service.d/ssh-guard.conf` | 有 Docker 时让 fail2ban 在 Docker 之后启动 |
| `/etc/ssh/sshd_config.d/00-ssh-guard.conf` | harden 写入；不支持 Include 时改为插入到 `sshd_config` 开头 |
| `/etc/ssh/sshd_config.d/00-ssh-guard-pubkey.conf` | 仅当 sshd 关闭了公钥认证时由 addkey 写入 |
| `/root/ssh-guard-keys/` | `addkey --generate` 生成的密钥对（私钥保存到本机后请删除） |
| `/etc/ssh-guard/blocked-nets.txt` | banlog 封禁的网段列表 |
| `/usr/local/sbin/ssh-guard-nets-restore`、`ssh-guard-nets.service` | 开机重建网段封禁（firewalld 自身会持久化，不需要） |

## 注意

- 关闭密码登录后**不要断开当前会话**，另开窗口用密钥登录成功再退出
- 误封自己：从控制台登录后执行 `ssh-guard.sh unban <IP>`（网段用 `unban 1.2.3.0/24`），并用 `install --ignoreip <IP>` 加入白名单
- 国内服务器访问 `raw.githubusercontent.com` 不稳定时，在能访问 GitHub 的机器上用 `deploy` 推送
