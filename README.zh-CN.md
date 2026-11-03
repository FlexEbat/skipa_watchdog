# Skipa Watchdog

[English](README.en.md) · [Русский](README.md) · **简体中文**

[![tests](https://github.com/FlexEbat/skipa_watchdog/actions/workflows/tests.yml/badge.svg)](https://github.com/FlexEbat/skipa_watchdog/actions/workflows/tests.yml)
[![license: GPL v3](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)
[![XERJ Corpus Hub contributor](https://hub.xerj.org/contributors/FlexEbat/badge.svg)](https://hub.xerj.org/contributors/FlexEbat)

Skipa Watchdog 会在你的服务器上封锁来自已知扫描器（CyberOK/Skipa、GRCHTs、NKTsKI 及额外名单）的连接，并可选地通过
Telegram 或 Matrix 通知你。防护覆盖主机，以及通过 Docker 和 Kubernetes 发布的服务。

- **在内核中封锁。** 名单加载进 `ipset`，扫描器的第一个数据包就会被丢弃。封锁不依赖任何常驻进程。
- **纯 bash。** 只需要 `iptables`、`ipset`、`curl`、`systemd`。安装和运行都不需要 Python。
- **全自动。** 名单由定时器更新，封锁自动完成，没有手动封锁/解除。唯一的手动手段是白名单。
- **通知可选。** Telegram 和/或 Matrix，一波扫描只发一条消息。不配置时仍有本地日志。
- **自我恢复。** 重启后 ipset 集合和规则会自动恢复。
- **防止把自己锁在外面。** 内部网络和你自己的 SSH 会话无法被封锁。

## 目录

- [快速开始](#快速开始)
- [工作原理](#工作原理)
- [配置](#配置)
- [防止自我封锁](#防止自我封锁)
- [Docker 和 Kubernetes](#docker-和-kubernetes)
- [通知：Telegram 和 Matrix](#通知telegram-和-matrix)
- [额外来源](#额外来源)
- [运维](#运维)
- [从 Python 机器人版本升级](#从-python-机器人版本升级)
- [安全](#安全)
- [常见问题](#常见问题)
- [开发](#开发)

## 快速开始

需要 root 和 `git`（缺少时 `install.sh` 会自动安装，`iptables`、`ipset`、`curl` 同理）。

```bash
curl -fsSL https://raw.githubusercontent.com/FlexEbat/skipa_watchdog/main/install.sh -o install.sh
sudo bash install.sh
```

安装程序会显示说明、下载名单、构建 `ipset` 并应用 `iptables` 规则。代码安装到 `/opt/skipa_watchdog`，日志写入
`/var/log/skipa_watchdog`。之后用下面的命令管理：

```bash
sudo skipa-watchdog
```

菜单项：1 运行状况检查，2 服务管理，3 检测设置，4 通知，5 Docker/Kubernetes，6 已封锁的 IP（仅查看），7 白名单，
8 统计，9 更新数据库，10 日志，11 编辑配置，12 更新项目，13 卸载。每次启动菜单时会检查是否有新版本并提示安装。

不使用菜单：

```bash
sudo bash install.sh install       # 安装或更新
sudo bash install.sh status        # 简要状态
sudo bash install.sh fw-rules      # 应用 Docker/Kubernetes 规则
sudo bash install.sh check-lists   # 检查名单新版本
sudo bash install.sh test-notify   # 向 Telegram/Matrix 发送测试消息
sudo bash install.sh stats [天数]  # 检测统计
sudo bash install.sh uninstall     # 卸载（会询问是否移除规则和 ipset）
```

**安装后请立即把你的 SSH IP 加入白名单**（菜单第 7 项），如果它是固定的。

<details>
<summary>不使用 install.sh 手动安装</summary>

```bash
sudo apt install ipset curl
cp config.example.yaml config.yaml && chmod 600 config.yaml
sudo bash service/sync-lists.sh config.yaml          # 填充 ipset
sudo bash service/setup-ipset-rules.sh config.yaml   # iptables 规则
sudo bash service/notify-tail.sh config.yaml         # （可选）detections.log 和通知
```

</details>

## 工作原理

```
IP 名单 ──► sync-lists.sh（定时器）──► ipset skipa-scanners ──► 内核 DROP（INPUT、DOCKER-USER、KUBE-*）
                                                  │
                                 LOG 规则 ──► 内核日志 ──► notify-tail.sh ──► detections.log
                                                                           └──► Telegram / Matrix
```

**封锁。** `iptables` 规则把源地址与 `ipset` 集合比对：`skipa-scanners`（名单）、`skipa-manual`（从旧版本迁移来的永久封锁）
和 `skipa-allow`（白名单）。一切由内核决定，封锁不涉及用户态进程。

**检测与通知。** LOG 规则把扫描器的第一个数据包写入内核日志，`skipa-watchdog-notify.service` 读取它（`journalctl -k`），
写入 `detections.log` 并发送通知。同一个 IP 在 `alert_cooldown_minutes` 内不会重复记录或发送。

**动作模式**（`action.mode`，菜单第 3 项）：

| 模式 | 封锁 | 日志和通知 |
| --- | --- | --- |
| `block_notify`（默认） | 是 | 是 |
| `block` | 是 | 否（不启动 `notify` 守护进程） |
| `notify` | 否 | 是 |

## 配置

统一的 `config.yaml`（模板：[`config.example.yaml`](config.example.yaml)，所有参数都有注释）。最简单的修改方式是通过菜单；
手动编辑后请应用更改（菜单第 11 项会自动提示）。

| 键 | 默认值 | 作用 |
| --- | --- | --- |
| `action.mode` | `block_notify` | 动作模式 |
| `sources.active_list` | `merged` | 使用哪些名单：`list1`、`list2`、`merged` |
| `sources.primary_list_url`、`blacklist_url` | 见模板 | 名单地址 |
| `sources.update_interval_days` | `7` | 数据库更新频率 |
| `sources.min_prefix` | `20` | 接受的最宽网络（前缀长度）；Spamhaus DROP 请设为 `16` |
| `sources.allow_insecure_http` | `false` | 允许通过普通 http 下载名单（默认仅 https） |
| `sources.min_entries` | `10` | 首次下载时来源的最少条目数（防止只有三行的垃圾名单） |
| `sources.extra` | 空 | 额外来源 |
| `firewall.keep_established_tcp` | `false` | 不切断已建立的 TCP 会话：只封锁新的 TCP 连接（SYN）和所有非 TCP 流量。注意：已建立会话的扫描器会在该会话内继续工作。修改后请重新应用规则（第 5 项） |
| `firewall.log_limit`、`log_burst` | `30/second`、`40` | LOG 规则限速 |
| `monitoring.ignore_ips` | 空 | 永不封锁的地址 |
| `monitoring.auto_allowlist`、`ssh_ports` | `true`、`[22]` | 不封锁当前 SSH 会话的 IP |
| `monitoring.alert_cooldown_minutes` | `60` | 同一 IP 的重复记录间隔 |
| `monitoring.kernel_log_prefix` | `CONN: ` | LOG 规则在内核日志中的前缀 |
| `telegram.*`、`matrix.*` | 空 | 通知渠道 |
| `notifications.batch_seconds`、`batch_max` | `30`、`20` | 消息累积秒数和列出的地址数 |
| `notifications.language` | `ru` | 消息文本语言：`ru` 或 `en` |
| `environment.docker_scan`、`k8s_scan` | `true` | 是否把规则挂到 `DOCKER-USER` 和 `KUBE-*` |
| `logging.log_dir` | `/var/log/skipa_watchdog` | 日志目录 |

默认来源：

- **名单 1** — [tread-lightly/CyberOK_Skipa_ips](https://github.com/tread-lightly/CyberOK_Skipa_ips)
  （CyberOK/Skipa、GRCHTs、NKTsKI）。
- **名单 2** — [sngvy](https://gist.github.com/sngvy/07cee7ac810c9d222fbebddff8c1d1b8) 的黑名单
  （CIDR、范围和单个 IP；包含 Censys 等扫描器网络）。

两个名单始终都会下载，`active_list` 决定哪些条目进入集合。如果某个来源不可用或返回的条目数只有之前的一半，则使用它上一次的版本。
比 `sources.min_prefix` 更宽的网络会被丢弃，总共覆盖超过约 400 万个地址的来源会被拒绝，因此“膨胀”的第三方名单不会把半个互联网封掉。
名单只通过 https 下载，重定向到 http 会被拒绝。形如 `1.2.3.0/24/垃圾` 的条目会被整体丢弃。

## 防止自我封锁

名单来自外部且封锁是自动的，因此以下内容永远不会被封锁：

- 回环、私有网络（`10/8`、`172.16/12`、`192.168/16`）和 link-local；
- `monitoring.ignore_ips` 中的地址；
- 在 `monitoring.ssh_ports` 上有打开的 SSH 会话的 IP（`monitoring.auto_allowlist`），由 `skipa-watchdog-allow-ssh.timer`
  每分钟添加一次；
- 比 `/16` 更短的网络（包括 `0.0.0.0/0`）、IPv6，以及与白名单相交的任何内容。

## Docker 和 Kubernetes

发往已发布容器端口的流量走 `FORWARD` 链，而不是 `INPUT`。因此规则会同时挂到 `DOCKER-USER`，以及（如果存在）
`KUBE-EXTERNAL-SERVICES`、`KUBE-NODEPORTS`。安装程序会自动找到它们；可通过菜单（第 5 项）或
`sudo bash install.sh fw-rules` 重新应用规则。关闭这些链：`environment.docker_scan: false`、`environment.k8s_scan: false`。

## 通知：Telegram 和 Matrix

通知只负责发送：没有聊天命令，不需要管理机器人，也不需要 Python。一切都由 bash 里的 `curl` 完成。通过菜单第 4 项配置
（令牌输入时不回显，写入 `config.yaml` 之前先检查格式），用 `sudo bash install.sh test-notify` 验证。

**Telegram。** 在 [@BotFather](https://t.me/BotFather) 创建机器人，把它加入聊天或频道，并填写令牌和 `chat_id`（群组为负数）。
如果无法直接访问 Telegram，请设置 `telegram.proxy`（`http://`、`https://`、`socks5://`、`socks5h://`）。

**Matrix。** 需要 homeserver 地址（`https://matrix.example.org`；`http` 仅允许用于 localhost）、用户或机器人的
`access_token`，以及形如 `!abc:example.org` 的 `room_id`（不是 `#房间` 别名）。该用户必须已在房间中。

可以同时启用两个渠道。保证如下：

- **一波一条消息。** 检测结果累积 `notifications.batch_seconds` 秒（默认 30），以最多 `batch_max` 个地址的列表发送，其余以
  “还有 N 个”一行表示。
- **带重试的队列。** 消息先进入队列（`/var/lib/skipa_watchdog/notify-spool`），每个渠道一个文件。网络错误和 5xx 会按顺序重试；
  遇到 429 会等待 `retry_after`（最长 60 秒）。如果服务器返回 400/401/403/404（令牌、聊天或房间错误），消息会被丢弃并在
  `skipa-watchdog.log` 中留下记录，而不是永远堆积。超过一天的消息和超过 200 个文件的部分会被丢弃。重试时 Matrix 收到相同的
  `txnId`，因此不会重复。
- **秘密不会出现在 `ps` 中。** 带令牌的 URL 和 `Authorization` 头通过 stdin（`-K -`）传给 `curl`，而不是作为参数。
- **纯文本。** 没有 HTML 或 Markdown，因此无需转义。

消息示例（`notifications.language: "en"`）：

```
Skipa Watchdog @ my-server
Scanners detected: 3 (blocked by the kernel)
• 203.0.113.42  TCP/22
• 203.0.113.43  TCP/443
• 198.51.100.7  UDP/3478
```

通知由 `skipa-watchdog-notify` 守护进程发送，它只在 `action.mode` 包含通知（`notify`、`block_notify`）时运行。如果在 `block`
模式下启用渠道，菜单会提示切换到 `block_notify`。

## 额外来源

`config.yaml` 中的 `sources.extra`：Spamhaus DROP、FireHOL、AbuseIPDB 或你自己的名单。类型为 `cidr_list`（纯文本名单，
`#` 和 `;` 为注释）和 `abuseipdb`（需要你自己的 `api_key`，字段 `min_confidence`），每个都可以设置 `min_entries`。只要
`enabled: true`，它们就与 `active_list` 无关地参与。仅支持 IPv4：IPv6 条目会被跳过并记录日志。

可以用 fail2ban 替代内核封锁：[`fail2ban/`](fail2ban) 中的过滤器和 jail 根据 `detections.log` 封禁。

## 运维

**日志。**

| 内容 | 位置 |
| --- | --- |
| 检测记录 | `/var/log/skipa_watchdog/detections.log` |
| 进程、通知错误 | `/var/log/skipa_watchdog/skipa-watchdog.log` |
| 名单与守护进程 | `journalctl -u skipa-watchdog-sync-lists -u skipa-watchdog-notify` |

日志轮转（`/etc/logrotate.d/skipa-watchdog`）由安装程序配置。

**重启与规则。** ipset 集合和规则只存在于内核内存中，因此会被保存并在开机时恢复（`/var/lib/skipa_watchdog/ipsets.save`，
每次同步和每次修改白名单后更新）：

- `skipa-watchdog-ipset.service` — 很早，在 `netfilter-persistent` 之前：恢复集合（没有文件则创建空集合）。这很重要：如果保存的规则
  引用了 `skipa-*` 而集合尚不存在，`iptables-restore` 会拒绝整个规则文件，服务器将完全没有防火墙；
- `skipa-watchdog-rules.service` — 稍后，在 Docker 和 kubelet 之后（它们需要 `DOCKER-USER` 和 `KUBE-*` 链）：应用规则并检查结果；
- `skipa-watchdog-sync-lists.timer` 在开机 10 分钟后更新名单，之后按计划更新。

不能只用一个单元：`After=docker.service` 加 `Before=netfilter-persistent.service` 会形成排序环，systemd 会随机删除一个任务来打破它。

所有对集合的操作（定时器、菜单第 9 项、`blockctl.sh`、应用规则、开机）都在同一个 `flock`（`/var/lib/skipa_watchdog/ipset.lock`）下运行，
因此不会交叉。应用规则后，脚本会检查集合存在，且 `INPUT`、`DOCKER-USER`、`KUBE-*` 中有规则，并报告结果（`✓`/`✗`）；菜单第 1 项显示同样内容。

**白名单。** 菜单第 7 项或 `sudo bash service/blockctl.sh allow|unallow|allowlist [ip]`：立即写入 `config.yaml` 和 `ipset`。
没有手动封锁/解除：一切自动。

**单元。** 以 root 运行（需要 `iptables`、`ipset`、内核日志）。启用了不妨碍运行的 systemd 限制：`NoNewPrivileges`、`PrivateTmp`、
`PrivateDevices`、`ProtectSystem=full`、`RestrictNamespaces`、`RestrictAddressFamilies` 等；通知守护进程另外有
`ProtectKernelModules`/`ProtectKernelTunables`。调用 `iptables` 的单元不使用严格沙箱：`iptables` 会加载内核模块，沙箱在部分系统上会导致启动失败。

**更新。** 每次启动面板（`sudo skipa-watchdog`）都会检查是否有新版本并提示安装；拒绝不是永久的：菜单标题中会保留提醒。
`SKIPA_NO_UPDATE_CHECK=1` 可单次关闭检查，`sudo bash install.sh check-update` 无提示检查（退出码 10 表示有更新）。手动更新：
菜单第 12 项或 `sudo bash install.sh install`。如果 `git pull` 失败（仓库历史被改写），安装程序会提议切换到当前版本：
`config.yaml` 和 `data/` 不受影响。

**卸载。** 菜单第 13 项。安装程序会单独询问是否移除 `iptables` 规则和 `ipset` 集合。

## 从 Python 机器人版本升级

从 4.0 起，项目中不再有 Python。如果你之前用的是“服务 + Telegram 机器人”版本，更新（`sudo skipa-watchdog` → 第 12 项，或
`sudo bash install.sh install`）会自动把它迁移到 bash，防护不中断：先启动 bash 单元和 `ipset` 规则，然后才移除机器人的单元、
`SKIPA-BLOCK` 链和 `skipa-dyn`/`skipa-db` 集合，并删除 venv。

- **保留：** `config.yaml`（Telegram 令牌和 `chat_id` 继续作为通知使用）、`data/`、白名单和永久手动封锁（迁移到 `skipa-manual`）。
- **消失：** 有时限的封锁（包括自动封锁；它们本来就会过期）、聊天命令（`/block`、`/allow`、`/stats` 等）、“封禁”按钮、仪表盘、
  告警补充信息（国家、ASN）、每周摘要和机器人的健康检查。白名单取代手动封锁，其余已不再需要。

## 安全

- `config.yaml` 含有令牌：安装程序设置权限 `600`，若配置含秘密而权限不同会发出警告。
- 令牌通过 stdin 而不是参数传给 `curl`，在 `ps` 中不可见。
- 菜单中输入的值在写入前会检查格式（Telegram 令牌、`chat_id`、`homeserver`、`room_id`），写入 `config.yaml` 时不会展开 `\n`，
  并拒绝可用来夹带额外键的引号、反斜杠和换行。
- 内核日志写入 `detections.log` 前会去除控制字符（否则可以为 fail2ban 伪造相邻记录）。
- 防自我封锁见上文。如果仍被挡在外面，请通过主机控制台登录并运行 `sudo skipa-watchdog`：把你的 IP 加入白名单（第 7 项）；
  第 13 项会连同规则一起删除项目。
- 更新项目就是以 root 身份从仓库执行 `git pull`：谁控制仓库，谁就控制你的服务器。请为 GitHub 账号启用 2FA；如果想在更新前审阅改动，
  请把 `SKIPA_REPO_URL` 指向你自己的 fork。
- 发现漏洞请私下联系仓库所有者，不要提公开 issue。

## 常见问题

**收到了“不在规则里”的 IP 的通知。** 检查该地址是否属于某个名单，包括第二个名单中的范围：

```bash
sudo ipset test skipa-scanners 66.132.186.215
```

名单中的扫描器网络比单个地址更宽：例如 `66.132.186.215` 属于第二个名单中的 `66.132.186.0/24`。扫描器的任何数据包都会产生记录：
LOG 规则对所有协议生效（`detections.log` 中能看到 `proto=UDP port=3478`），记录后数据包会被丢弃。

**收不到通知。** 菜单第 4 项 →“发送测试消息”会按渠道报告结果：“已送达”、“服务器拒绝请求”（令牌、`chat_id` 或房间错误）或“无连接”。
还要检查 `action.mode` 不是 `block`，以及守护进程是否存活：`systemctl status skipa-watchdog-notify`。发送错误会写入
`skipa-watchdog.log`。菜单第 1 项会显示未发送消息队列的大小。

**对合法扫描器的误报**（例如你自己的安全监控）：把它的 IP 加入白名单（第 7 项）。

**对容器不生效。** 打开菜单第 5 项 →“显示当前规则”：`DOCKER-USER` 中也必须有规则。如果 Docker 启动得更晚，请重新应用规则
（第 5 项；开机时由 `skipa-watchdog-rules.service` 完成）。

## 开发

```bash
python3 -m unittest discover -s tests -t .     # 100+ 个测试，无需 root
shellcheck -S warning install.sh service/*.sh
```

项目本身是纯 bash；Python 只用于测试（它们运行 bash 脚本）和用 PyYAML 检查 `config.yaml`。测试用模拟实现替换 `iptables`、`ipset`、
`curl` 和 `journalctl`（[`tests/netfake.py`](tests/netfake.py) 以及测试内的桩脚本），不会触碰真实防火墙和网络。使用真实
`ipset`/`iptables` 的端到端场景（重启、`iptables-restore`、flock）需要显式开启，因为它会修改主机的集合和规则：
在一次性环境中以 root 运行 `SKIPA_REAL_NETFILTER_TESTS=1 python3 -m unittest tests.test_real_netfilter`。

结构：

```
install.sh             安装程序和菜单
service/               脚本：名单、规则、通知、config.yaml 读取、白名单
fail2ban/              过滤器和 jail（另一种封禁方式）
tests/                 测试
config.example.yaml    配置模板
```

## 许可证

[GNU GPLv3](LICENSE)。衍生作品须以相同的开源许可证发布。
