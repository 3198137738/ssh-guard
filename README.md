# ssh-guard

SSH 爆破防护一键脚本，基于 fail2ban：

- **aggressive 模式**：关掉密码登录后，扫描器只会留下 preauth 阶段的断开日志，fail2ban 默认的 normal 模式认不出来，aggressive 模式可以
- **默认永久封禁**，封全部端口；优先用 ipset，封几万个 IP 也不影响性能
- **Docker 兼容**：检测到 Docker 时额外在 `DOCKER-USER` 链封禁（容器映射端口不走 INPUT 链）
- **自动白名单**：当前登录会话的来源 IP 自动加入 ignoreip，避免把自己封掉
- **爆破分析报告**：失败次数 Top IP、首次/末次出现时间、是否已封、/24 网段汇总
- **关闭密码登录**（可选）：先检查是否配置了公钥，`sshd -t` 校验失败自动回滚
- 兼容 Debian / Ubuntu / CentOS / Rocky / Alma / openSUSE / Alpine；iptables / nftables / firewalld；auth.log / secure / journal；OpenSSH 9.8+ 的 `sshd-session`

## 单台服务器一键运行

```bash
# 安装防护（可重复执行，用于更新配置）
curl -fsSL https://raw.githubusercontent.com/3198137738/ssh-guard/main/ssh-guard.sh | sudo bash

# 查看爆破分析报告
curl -fsSL https://raw.githubusercontent.com/3198137738/ssh-guard/main/ssh-guard.sh | sudo bash -s -- report

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
| `install`（默认） | 安装/更新 fail2ban 防护 |
| `report` | 爆破分析报告 |
| `harden` | 关闭密码登录，只允许密钥 |
| `unharden` | 撤销 harden |
| `status` | 查看封禁情况 |
| `unban <IP>...` | 解封 IP |
| `uninstall` | 移除 ssh-guard 写入的 fail2ban 配置 |

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

`harden` 选项：`--force`（没检测到公钥也强制关闭，慎用）。

## 多台服务器批量执行

在本机（Linux / macOS / WSL / Git Bash）执行，脚本内容通过 SSH 传过去，服务器不需要能访问 GitHub：

```bash
git clone https://github.com/3198137738/ssh-guard.git && cd ssh-guard
cp hosts.example.txt hosts.txt   # 每行一台: [user@]host[:port]
vi hosts.txt

./deploy.sh -f hosts.txt                              # 全部安装防护
./deploy.sh -f hosts.txt -s -- report --top 10        # 全部出报告并打印
./deploy.sh -f hosts.txt -- install --disable-password
./deploy.sh -f hosts.txt -P 20 -i ~/.ssh/id_ed25519 -- status
```

每台服务器的输出保存在 `logs/<时间>/<host>.log`。要求本机能用密钥免密登录这些服务器；非 root 用户需要免密 sudo。

## 写入的文件

| 文件 | 作用 |
| --- | --- |
| `/etc/fail2ban/jail.d/ssh-guard.local` | sshd jail 配置 |
| `/etc/fail2ban/fail2ban.d/ssh-guard.local` | 永久封禁时调大 `dbpurgeage`，重启后封禁记录还在 |
| `/etc/fail2ban/filter.d/ssh-guard-sshd.conf` | 仅 OpenSSH 9.8+ 且 fail2ban < 1.1 时，兼容 `sshd-session` |
| `/etc/systemd/system/fail2ban.service.d/ssh-guard.conf` | 有 Docker 时让 fail2ban 在 Docker 之后启动 |
| `/etc/ssh/sshd_config.d/00-ssh-guard.conf` | harden 写入；不支持 Include 时改为插入到 `sshd_config` 开头 |

## 注意

- 关闭密码登录后**不要断开当前会话**，另开窗口用密钥登录成功再退出
- 误封自己：从控制台登录后执行 `ssh-guard.sh unban <IP>`，并用 `install --ignoreip <IP>` 加入白名单
- 国内服务器访问 `raw.githubusercontent.com` 不稳定时，用 `deploy.sh` 从本机推送
