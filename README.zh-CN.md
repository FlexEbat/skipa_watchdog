# Skipa Watchdog

[English](README.en.md) · [Русский](README.md) · **简体中文**

[![tests](https://github.com/FlexEbat/skipa_watchdog/actions/workflows/tests.yml/badge.svg)](https://github.com/FlexEbat/skipa_watchdog/actions/workflows/tests.yml)
[![license: GPL v3](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)
[![XERJ Corpus Hub contributor](https://hub.xerj.org/contributors/FlexEbat/badge.svg)](https://hub.xerj.org/contributors/FlexEbat)

Skipa Watchdog 能发现已知扫描器（CyberOK/Skipa、GRChTs、NKTsKI 及其他附加名单）对服务器的连接，
对其进行封锁和/或发送通知。防护对主机本身以及通过 Docker 和 Kubernetes 发布的服务均有效。

- **内核级封锁。** 整个名单加载到 `ipset` 中，扫描器在第一个数据包就会被拦截。
- **统一配置。** 两种安装方式读取同一个 `config.yaml`。
- **Telegram 可选。** 不使用 Telegram 时，一切通过本地日志工作。
- **自我恢复。** 重启、Docker 重启或 `ufw reload` 之后，规则会自动恢复（Telegram 方式）。
- **防止自我封锁。** 内部网络和你自己的 SSH 会话不会被封锁。

## 目录

- [安装方式](#安装方式)
- [快速开始](#快速开始)
- [工作原理](#工作原理)
- [配置](#配置)
- [防止自我封锁](#防止自我封锁)
- [Docker 与 Kubernetes](#docker-与-kubernetes)
- [Telegram](#telegram)
- [附加功能](#附加功能)
- [运维](#运维)
- [安全](#安全)
- [常见问题](#常见问题)
- [开发](#开发)
- [许可证](#许可证)

## 安装方式

| | 仅服务 | 服务 + Telegram |
| --- | --- | --- |
| 实现 | bash、`iptables`、`ipset` | `watchdog.py`（Python 3.10+）、venv |
| Python | 不需要 | 需要 |
| 封锁 | 在内核中，名单由 systemd 定时器更新 | 在内核中，进程自行更新并修复规则 |
| 通知 | 写入 `detections.log` | `detections.log` 以及 Telegram 消息 |
| “封禁”按钮、`/stats`、仪表盘、健康检查 | 无 | 有 |
| 附加来源（`sources.extra`） | 无 | 有 |

可以先用第一种方式，之后再从菜单中接入 Telegram。无法切换回纯 bash 方式：需要卸载后重新安装。

## 快速开始

需要 root 权限和 `git`（如果没有，`install.sh` 会自动安装）。

```bash
curl -fsSL https://raw.githubusercontent.com/FlexEbat/skipa_watchdog/main/install.sh -o install.sh
sudo bash install.sh
```

安装程序会显示说明，询问安装方式，并应用 `iptables` 规则。代码安装到 `/opt/skipa_watchdog`，
日志写入 `/var/log/skipa_watchdog`。之后使用下面的命令进行管理：

```bash
sudo skipa-watchdog
```

菜单的每一项都可以退出（`0`），每个会修改系统的操作都会要求确认。菜单项包括：运行状况检查、服务管理、
检测设置、Telegram、Docker/Kubernetes、已封锁的 IP、更新数据库、日志、编辑配置、更新项目、卸载。

不使用菜单：

```bash
sudo bash install.sh install       # 安装或更新
sudo bash install.sh status        # 简要状态
sudo bash install.sh fw-rules      # 应用 Docker/Kubernetes 规则
sudo bash install.sh check-lists   # 检查名单是否有新版本
sudo bash install.sh uninstall     # 卸载（会询问是否移除规则和 ipset）
```

**安装完成后请立即**把你自己的 SSH IP（如果是固定 IP）写入 `/opt/skipa_watchdog/config.yaml` 中的
`monitoring.ignore_ips`。

> 安装程序菜单和机器人的消息目前为俄语。

<details>
<summary>手动安装（不使用 install.sh）</summary>

仅服务：

```bash
sudo apt install ipset curl
cp config.example.yaml config.yaml && chmod 600 config.yaml
sudo bash service/sync-lists.sh config.yaml          # 填充 ipset
sudo bash service/setup-ipset-rules.sh config.yaml   # iptables 规则
sudo bash service/notify-tail.sh config.yaml         # （可选）写入 detections.log
```

使用 Telegram：

```bash
python3 -m venv venv && . venv/bin/activate
pip install -r requirements.txt -r requirements-telegram.txt
cp config.example.yaml config.yaml && chmod 600 config.yaml   # 填写 telegram.*
sudo bash install-firewall-rules.sh
python watchdog.py config.yaml
```

</details>

## 工作原理

```
IP 名单 ──► 数据库（缓存 data/ip_cache.json）──► ipset skipa-db ──► 内核级拦截
                      │
 poll（/proc/net/tcp、conntrack）─┐
                                  ├─► 命中 ─► 封锁 + detections.log + Telegram
 kernel_log（LOG 规则）───────────┘          （具体做什么由 action.mode 决定）
```

**检测方式**（`monitoring.method`）：

| 方法 | 原理 | 能看到什么 |
| --- | --- | --- |
| `poll` | 每隔 `poll_interval_seconds` 读取 `/proc/net/tcp` 和内核 conntrack | 入站连接、发往 Docker 容器端口的流量、短时扫描 |
| `kernel_log` | 读取 iptables LOG 规则写入的内核日志 | 扫描器的每一个首包，即时发现 |
| `both`（默认） | 两者同时 | 以上全部 |

**封锁。** 规则位于独立的 `SKIPA-BLOCK` 链中，`INPUT`、`DOCKER-USER` 和 `KUBE-*` 会跳转到该链。
如果安装了 `ipset`，整个数据库会加载到 `skipa-db` 集合中，动态封锁（带超时）放在 `skipa-dyn`，
你自己的地址放在 `skipa-allow`。没有 `ipset` 时，会为每个 IP 单独创建一条 `DROP` 规则。

**动作模式**（`action.mode`）：

| 模式 | 封锁 | 通知 |
| --- | --- | --- |
| `block_notify`（默认） | 是 | 是 |
| `block` | 是 | 仅写入日志 |
| `notify` | 否 | 是 |

## 配置

使用单一的 `config.yaml` 文件（模板：[`config.example.yaml`](config.example.yaml)，所有参数都在其中以注释说明）。
“仅服务”方式只读取其中一部分，最后一列已标出。

| 键 | 默认值 | 用途 | bash |
| --- | --- | --- | --- |
| `action.mode` | `block_notify` | 动作模式 | 是 |
| `action.block_timeout_hours` | `72` | 自动封锁时长，`0` 表示永久 | 否 |
| `action.preload_db` | `true` | 预先把整个数据库加载到 ipset | 否 |
| `sources.active_list` | `merged` | 使用哪些名单：`list1`、`list2`、`merged` | 是 |
| `sources.primary_list_url` / `blacklist_url` | 见模板 | 名单地址 | 是 |
| `sources.update_interval_days` | `7` | 数据库更新频率 | 是 |
| `sources.extra` | 空 | 附加来源 | 否 |
| `monitoring.method` | `both` | `poll`、`kernel_log`、`both` | 否 |
| `monitoring.ignore_ips` | 空 | 永不封锁的地址 | 是 |
| `monitoring.alert_cooldown_minutes` | `60` | 同一 IP 的记录间隔不低于此值 | 是 |
| `monitoring.use_conntrack` | `true` | `poll` 同时读取 conntrack | 否 |
| `monitoring.auto_allowlist` | `true` | 不封锁当前 SSH 会话的 IP | 否 |
| `telegram.bot_token`、`chat_id`、`admin_ids` | 空 | 接入 Telegram | 否 |
| `firewall.log_limit`、`log_burst` | `30/second`、`40` | LOG 规则的速率限制 | 是 |
| `logging.log_dir` | `/var/log/skipa_watchdog` | 日志目录 | 是 |

默认来源：

- **名单 1** —— [tread-lightly/CyberOK_Skipa_ips](https://github.com/tread-lightly/CyberOK_Skipa_ips)
  （CyberOK/Skipa、GRChTs、NKTsKI）。
- **名单 2** —— [sngvy](https://gist.github.com/sngvy/07cee7ac810c9d222fbebddff8c1d1b8) 的黑名单
  （CIDR、地址范围和单个 IP；包含 Censys 等扫描器的网段）。

两份名单始终都会下载，`active_list` 决定哪些条目进入数据库。如果某个来源不可用，或返回的条目数只有
之前的一半，则使用其上一个版本，并在一小时后重新检查不完整的数据库。名单中比 `/16` 更大的网段会被丢弃。

可以通过菜单修改设置（第 3 项：名单来源、动作模式、检测方式；第 9 项：编辑文件），也可以手动修改；
修改后请通过菜单应用，或执行 `sudo systemctl restart skipa-watchdog`。

## 防止自我封锁

名单来自外部，而封锁是自动进行的，因此以下内容永远不会被封锁：

- 回环地址、私有网络（`10/8`、`172.16/12`、`192.168/16`）和链路本地地址；
- `monitoring.ignore_ips` 中的地址；
- 在 `monitoring.ssh_ports` 上有打开的 SSH 会话的 IP（`monitoring.auto_allowlist`）；
- 前缀短于 `/16` 的网段（包括 `0.0.0.0/0`）、IPv6，以及与白名单有交集的任何内容。

`poll` 方法只统计入站连接：服务器自己发起的出站连接不会被当作扫描。

## Docker 与 Kubernetes

发往容器已发布端口的流量走的是 `FORWARD` 链，而不是 `INPUT`。因此，到 `SKIPA-BLOCK` 的跳转会同时设置在
`DOCKER-USER` 中，以及（如果存在）`KUBE-EXTERNAL-SERVICES` 和 `KUBE-NODEPORTS` 中。安装程序会自动找到它们；
可以通过菜单（第 5 项）或 `sudo bash install.sh fw-rules` 重新应用规则。要禁用这些链：
`environment.docker_scan: false`、`environment.k8s_scan: false`。

这类流量在主机的 `/proc/net/tcp` 中看不到，所以 `poll` 会读取内核 conntrack（需要 root），
而 `kernel_log` 通过 `DOCKER-USER` 上的 LOG 规则工作。

## Telegram

可以通过菜单（第 4 项）接入，或在 `config.yaml` 中设置：`telegram.bot_token`（从
[@BotFather](https://t.me/BotFather) 获取）、`chat_id` 和 `admin_ids`。`admin_ids` 为空表示只接受来自
`chat_id` 聊天的命令。如果无法直接访问 Telegram，请设置 `telegram.proxy`（使用 `socks5://` 需要
`pip install "python-telegram-bot[socks]"`）。

Telegram 不可用不会中断防护：该层在后台启动并重试，未发送的告警会进入队列等待（最多 500 条，最长一周）。

| 命令 | 作用 |
| --- | --- |
| `/menu`、`/status` | 菜单，数据库、规则和监视器的状态 |
| `/update` | 立即更新数据库 |
| `/blocklist`（`/banlist`） | 封锁列表 |
| `/block <ip 或网段> [小时]` | 封锁（默认永久） |
| `/unblock <ip>`（`/unban`） | 解除封锁 |
| `/stats [天数]`、`/export [天数]` | 带图表的统计，以及事件导出 |
| `/testalert [ip]` | 测试通知 |
| `/pending`、`/env` | 未发送告警的队列、Docker/Kubernetes 环境 |

通知示例（数值取自文档专用地址段，RFC 5737 和 RFC 5398；机器人的消息文本为俄语）：

```
🚨 УГРОЗА. СКАНЕР ОБНАРУЖЕН - IP

IP: 203.0.113.42
▢ MaxMind & IPinfo & Cloudflare:
🇩🇪 DE Germany, Bavaria, Example City
AS64500 / Example Hosting GmbH
База: Skipa | Совпадение: 203.0.113.0/24

🚫 IP заблокирован.
```

## 附加功能

仅在 Telegram 方式下可用，并在 `config.yaml` 中启用。

- **附加来源**（`sources.extra`）：Spamhaus DROP、FireHOL、AbuseIPDB 或你自己的名单。
  每个来源在告警中以各自的名称显示。
- **按钮封禁**（`banning.enabled`）：告警下方会出现“🚫 Забанить”（封禁）按钮
  （时长为 `manual_ban_duration_minutes`）。`auto_ban_new_hits` 会自动封禁每个发现的 IP，
  `fail2ban_jail` 会把封禁同步到 fail2ban。历史记录写入 `data/bans.jsonl`。
  替代方案：[`fail2ban/`](fail2ban) 中的过滤器和 jail，根据 `detections.log` 进行封禁。
- **统计**（`/stats`、`/export`、每周摘要 `digest.*`）：事件写入 `data/events.jsonl`。
  图表由 `matplotlib` 绘制（`pip install -r requirements-extras.txt`），没有它时会收到文本直方图。
- **仪表盘**（`dashboard.enabled`）：显示数据库状态、事件、封锁和监视器状态的页面。
  它监听 `127.0.0.1`，请通过 SSH 隧道访问：`ssh -L 8080:localhost:8080 user@server`。
  如果要在 localhost 之外访问，请设置 `username`/`password`（HTTP Basic Auth），并放在带 TLS 的代理之后。
- **健康检查**（`healthcheck.*`）：如果监视器沉默超过 `stale_after_minutes`，会收到警告，恢复后也会收到消息。

## 运维

**日志。**

| 内容 | 位置 |
| --- | --- |
| 检测记录 | `/var/log/skipa_watchdog/detections.log` |
| 进程 | `/var/log/skipa_watchdog/skipa-watchdog.log`、`journalctl -u skipa-watchdog` |
| 名单和定时器（仅服务） | `journalctl -u skipa-watchdog-sync-lists -u skipa-watchdog-notify` |

**重启与规则。** Telegram 方式每隔 `monitoring.guard_interval_seconds`（60 秒）自行检查并修复跳转和 ipset，
同时还会安装 `skipa-watchdog-fw-rules.service` 单元。在“仅服务”方式中，`skipa-watchdog-sync-lists.timer`
会在开机 10 分钟后重新填充 ipset，之后按计划执行；而 `iptables` 规则需要通过系统手段保存
（`iptables-persistent`），或在重启后运行 `sudo bash install.sh fw-rules`。

**手动封锁。** 通过菜单（第 6 项）、Telegram 中的 `/block` 命令，或
`sudo bash /opt/skipa_watchdog/service/blockctl.sh {block|unblock|list} [ip]`。
Telegram 方式下的封锁保存在 `data/blocked_ips.json` 中，并在启动时恢复。

**服务。** `skipa-watchdog.service` 以 root 身份运行，不使用沙箱：它需要 `iptables`、`ipset`、
读取 conntrack 的权限，以及对安装目录和日志的写权限。

**更新。** 菜单第 10 项或 `sudo bash install.sh install`。如果 `git pull` 失败（仓库历史被改写），
安装程序会提示切换到最新版本：`config.yaml` 和 `data/` 不受影响。

**卸载。** 菜单第 11 项。安装程序会单独询问是否移除 `iptables` 规则和 `ipset` 集合。

## 安全

- `config.yaml` 包含机器人令牌：安装程序会将权限设置为 `600`。
- 机器人令牌和 API 密钥在日志中会被屏蔽（`skipa-watchdog.log`、`journalctl`）。
- 机器人命令只接受管理员（`admin_ids`，或 `chat_id` 聊天）的指令。
- 防止自我封锁的机制见上文。如果你仍然被挡在外面，请通过主机控制台登录并运行 `sudo skipa-watchdog`：
  第 6 项可解除指定 IP 的封锁，第 11 项会连同规则一起删除项目。
- 来自外部 API 的数据（组织、ASN）在 Telegram 和仪表盘页面中会被转义。
- 未设置 `username` 的仪表盘对任何能访问该端口的人开放：请勿将其发布到互联网。
- 发现漏洞请私下联系仓库所有者，不要发布到公开的 issue 中。

## 常见问题

**收到了针对一个“不在规则里”的 IP 的告警。** 请检查该地址是否属于某个名单，包括第二个名单中的地址范围：

```bash
sudo ipset test skipa-scanners 66.132.186.215        # 仅服务
sudo ipset test skipa-db 66.132.186.215              # 服务 + Telegram（ipset）
```

名单中的扫描器网段比单个地址更大：例如，`66.132.186.215` 属于第二个名单中的 `66.132.186.0/24`。
命中的网段会显示在告警和 `detections.log` 中。扫描器的任何数据包都会产生记录：在“仅服务”方式下，
LOG 规则对所有协议生效（在 `detections.log` 中可以看到 `proto=UDP port=3478`），数据包在记录后被丢弃。

**菜单提示 INPUT 未连接，但规则已经存在。** 请更新项目（第 10 项）。之前的检查只查找旧格式的规则，
现在会查找该链中项目的任何规则。

**服务无法启动。** 执行 `journalctl -u skipa-watchdog -n 50`。常见原因：没有 `ipset`
（服务以简化的 iptables 模式运行）、`config.yaml` 无效、仪表盘端口被占用。

**对合法扫描器的误报**（例如你自己的安全监控）：将其 IP 添加到 `monitoring.ignore_ips`。

**对容器不起作用。** 打开菜单第 5 项 → “显示当前规则”：`DOCKER-USER` 中也必须有到 `SKIPA-BLOCK`
的跳转。在服务之后启动的 Docker 会在一分钟内被识别。

## 开发

```bash
python3 -m unittest discover -s tests -t .     # 80+ 个测试，无需 root
shellcheck -S warning service/*.sh install-firewall-rules.sh
```

测试用模拟对象替代 `iptables` 和 `ipset`（[`tests/fakes.py`](tests/fakes.py)）；CI 在 Python 3.10–3.13
上运行测试，同时执行 `bash -n` 和 `shellcheck`。

目录结构：

```
watchdog.py            Telegram 方式的入口
install.sh             安装程序和菜单
bot/                   Python 模块（监控、封锁、名单、Telegram、仪表盘）
service/               bash 方式以及读取 config.yaml 的公共库
fail2ban/              过滤器和 jail（另一种封禁方式）
tests/                 测试
config.example.yaml    统一配置模板
```

## 许可证

[GNU GPLv3](LICENSE)。衍生作品须以相同的开源许可证发布。
