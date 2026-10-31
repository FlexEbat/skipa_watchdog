# Skipa Watchdog

**English** · [Русский](README.md) · [简体中文](README.zh-CN.md)

[![tests](https://github.com/FlexEbat/skipa_watchdog/actions/workflows/tests.yml/badge.svg)](https://github.com/FlexEbat/skipa_watchdog/actions/workflows/tests.yml)
[![license: GPL v3](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)
[![XERJ Corpus Hub contributor](https://hub.xerj.org/contributors/FlexEbat/badge.svg)](https://hub.xerj.org/contributors/FlexEbat)

Skipa Watchdog detects connections to your server from known scanners (CyberOK/Skipa,
GRChTs, NKTsKI and additional lists), blocks them and/or sends a notification. Protection
works on the host and for services published through Docker and Kubernetes.

- **Kernel-level blocking.** The whole list is loaded into `ipset`, so a scanner is cut off
  at its first packet.
- **One config.** Both installation variants read the same `config.yaml`.
- **Telegram is optional.** Without it everything works through local logs.
- **Self-healing.** After a reboot, a Docker restart or `ufw reload`, the rules come back
  on their own (in the Telegram variant).
- **Self-lockout protection.** Service networks and your own SSH sessions cannot be blocked.

## Table of contents

- [Installation options](#installation-options)
- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Configuration](#configuration)
- [Self-lockout protection](#self-lockout-protection)
- [Docker and Kubernetes](#docker-and-kubernetes)
- [Telegram](#telegram)
- [Additional features](#additional-features)
- [Operations](#operations)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [License](#license)

## Installation options

| | Service only | Service + Telegram |
| --- | --- | --- |
| Implementation | bash, `iptables`, `ipset` | `watchdog.py` (Python 3.10+), venv |
| Python | not needed | required |
| Blocking | in the kernel, list refreshed by a systemd timer | in the kernel, the process refreshes and repairs rules itself |
| Notifications | entries in `detections.log` | `detections.log` and Telegram messages |
| "Ban" button, `/stats`, dashboard, health-check | no | yes |
| Extra sources (`sources.extra`) | no | yes |

You can start with the first variant and add Telegram later from the menu. Switching back
to plain bash is not possible: uninstall and install again.

## Quick start

Requires root and `git` (`install.sh` installs it if missing).

```bash
curl -fsSL https://raw.githubusercontent.com/FlexEbat/skipa_watchdog/main/install.sh -o install.sh
sudo bash install.sh
```

The installer shows a description, asks which variant you want and applies the `iptables`
rules. The code is installed to `/opt/skipa_watchdog`, logs go to `/var/log/skipa_watchdog`.
After that, manage everything with:

```bash
sudo skipa-watchdog
```

Every menu item has an exit (`0`), and every action that changes something asks for
confirmation. Menu items: health check, service management, detection settings, Telegram,
Docker/Kubernetes, blocked IPs, database update, logs, config editing, project update,
uninstall.

Without the menu:

```bash
sudo bash install.sh install       # install or update
sudo bash install.sh status        # short status
sudo bash install.sh fw-rules      # apply Docker/Kubernetes rules
sudo bash install.sh check-lists   # check for new list versions
sudo bash install.sh uninstall     # uninstall (offers to remove rules and ipsets)
```

**Right after installation, add your own SSH IP** to `monitoring.ignore_ips` in
`/opt/skipa_watchdog/config.yaml` if it is static.

> The installer menu and the bot's messages are currently in Russian.

<details>
<summary>Manual installation, without install.sh</summary>

Service only:

```bash
sudo apt install ipset curl
cp config.example.yaml config.yaml && chmod 600 config.yaml
sudo bash service/sync-lists.sh config.yaml          # fill the ipset
sudo bash service/setup-ipset-rules.sh config.yaml   # iptables rules
sudo bash service/notify-tail.sh config.yaml         # (optional) write detections.log
```

With Telegram:

```bash
python3 -m venv venv && . venv/bin/activate
pip install -r requirements.txt -r requirements-telegram.txt
cp config.example.yaml config.yaml && chmod 600 config.yaml   # fill in telegram.*
sudo bash install-firewall-rules.sh
python watchdog.py config.yaml
```

</details>

## How it works

```
IP lists ──► database (cache data/ip_cache.json) ──► ipset skipa-db ──► kernel-level drop
                      │
 poll (/proc/net/tcp, conntrack) ─┐
                                  ├─► match ─► block + detections.log + Telegram
 kernel_log (LOG rule) ───────────┘            (what exactly happens is set by action.mode)
```

**Detection** (`monitoring.method`):

| method | how | what it sees |
| --- | --- | --- |
| `poll` | reads `/proc/net/tcp` and kernel conntrack every `poll_interval_seconds` | incoming connections, traffic to Docker container ports, short scans |
| `kernel_log` | reads the kernel log that the iptables LOG rule writes to | every first packet from a scanner, instantly |
| `both` (default) | both | everything above |

**Blocking.** Rules live in a dedicated `SKIPA-BLOCK` chain, which `INPUT`, `DOCKER-USER`
and `KUBE-*` jump to. If `ipset` is installed, the whole database is loaded into the
`skipa-db` set, dynamic blocks (with a timeout) go to `skipa-dyn`, and your own addresses to
`skipa-allow`. Without `ipset`, a separate `DROP` rule is created for every IP.

**Action modes** (`action.mode`):

| mode | blocking | notification |
| --- | --- | --- |
| `block_notify` (default) | yes | yes |
| `block` | yes | log entry only |
| `notify` | no | yes |

## Configuration

A single `config.yaml` file (template: [`config.example.yaml`](config.example.yaml), every
parameter is described there in comments). The "service only" variant reads a subset of it,
marked in the last column.

| key | default | purpose | bash |
| --- | --- | --- | --- |
| `action.mode` | `block_notify` | action mode | yes |
| `action.block_timeout_hours` | `72` | auto-block duration, `0` — permanent | no |
| `action.preload_db` | `true` | preload the whole database into ipset | no |
| `sources.active_list` | `merged` | which lists to use: `list1`, `list2`, `merged` | yes |
| `sources.primary_list_url` / `blacklist_url` | see template | list URLs | yes |
| `sources.update_interval_days` | `7` | how often to refresh the database | yes |
| `sources.min_prefix` | `20` | widest network accepted from lists (prefix length); use `16` for Spamhaus DROP | yes |
| `sources.allow_insecure_http` | `false` | allow downloading lists over plain http (https only by default) | yes |
| `sources.extra` | empty | additional sources | no |
| `monitoring.method` | `both` | `poll`, `kernel_log`, `both` | no |
| `monitoring.ignore_ips` | empty | addresses that are never blocked | yes |
| `monitoring.alert_cooldown_minutes` | `60` | don't log the same IP more often than this | yes |
| `monitoring.use_conntrack` | `true` | `poll` also reads conntrack | no |
| `monitoring.auto_allowlist` | `true` | don't block IPs of current SSH sessions | no |
| `telegram.bot_token`, `chat_id`, `admin_ids` | empty | Telegram connection | no |
| `firewall.log_limit`, `log_burst` | `30/second`, `40` | LOG rule rate limit | yes |
| `logging.log_dir` | `/var/log/skipa_watchdog` | log directory | yes |

Default sources:

- **List 1** — [tread-lightly/CyberOK_Skipa_ips](https://github.com/tread-lightly/CyberOK_Skipa_ips)
  (CyberOK/Skipa, GRChTs, NKTsKI).
- **List 2** — blacklist by [sngvy](https://gist.github.com/sngvy/07cee7ac810c9d222fbebddff8c1d1b8)
  (CIDRs, ranges and single IPs; includes scanner networks such as Censys).

Both are always downloaded; `active_list` selects which entries go into the database. If a
source is unavailable or returns half as many entries as before, its previous version is
used, and an incomplete database is rechecked after an hour. Networks wider than
`sources.min_prefix` (`/20` by default) are discarded, and a source that covers more than ~4 million
addresses in total is rejected, so an inflated third-party list cannot block half the internet.
Lists are downloaded over https only; a redirect to http is refused.

You can change settings from the menu (item 3: list source, action mode, detection method;
item 9: edit the file) or by hand; after editing, apply the changes through the menu or with
`sudo systemctl restart skipa-watchdog`.

## Self-lockout protection

The lists are external and blocking is automatic, so the following can never be blocked:

- loopback, private networks (`10/8`, `172.16/12`, `192.168/16`) and link-local;
- addresses from `monitoring.ignore_ips`;
- IPs with open SSH sessions on `monitoring.ssh_ports` (`monitoring.auto_allowlist`); in the
  "service only" variant `skipa-watchdog-allow-ssh.timer` adds them every minute;
- networks shorter than `/16` (including `0.0.0.0/0`), IPv6, and anything that overlaps the
  allowlist.

The `poll` method only considers incoming connections: the server's own outgoing
connections are never counted as scanners.

## Docker and Kubernetes

Traffic to published container ports goes through the `FORWARD` chain, not `INPUT`.
Therefore the jump to `SKIPA-BLOCK` is installed in `DOCKER-USER` and (if present) in
`KUBE-EXTERNAL-SERVICES` and `KUBE-NODEPORTS`. The installer finds them itself; you can
reapply the rules from the menu (item 5) or with `sudo bash install.sh fw-rules`. To
disable these chains: `environment.docker_scan: false`, `environment.k8s_scan: false`.

Such traffic is not visible in the host's `/proc/net/tcp`, so `poll` reads kernel conntrack
(root required), and `kernel_log` works through a LOG rule on `DOCKER-USER`.

## Telegram

Enable it from the menu (item 4) or in `config.yaml`: `telegram.bot_token` (from
[@BotFather](https://t.me/BotFather)), `chat_id` and `admin_ids`. An empty `admin_ids` means
commands are accepted only in the private chat of the `chat_id` user; in a group they are closed until
administrators are listed in `admin_ids`. If Telegram is not reachable directly,
set `telegram.proxy` (`socks5://` requires `pip install "python-telegram-bot[socks]"`).

An unreachable Telegram does not stop protection: the layer starts in the background with
retries, and unsent alerts wait in a queue (up to 500 items, up to a week).

| command | action |
| --- | --- |
| `/menu`, `/status` | menu, database, rules and monitors state |
| `/update` | update the database now |
| `/blocklist` (`/banlist`) | list of blocks |
| `/block <ip or network> [hours]` | block (permanent by default) |
| `/unblock <ip>` (`/unban`) | unblock |
| `/stats [days]`, `/export [days]` | statistics with a chart, and event export |
| `/testalert [ip]` | test notification |
| `/pending`, `/env` | queue of unsent alerts, Docker/Kubernetes environment |

Example notification (values from documentation ranges, RFC 5737 and RFC 5398; the bot's
message text is in Russian):

```
🚨 УГРОЗА. СКАНЕР ОБНАРУЖЕН - IP

IP: 203.0.113.42
▢ MaxMind & IPinfo & Cloudflare:
🇩🇪 DE Germany, Bavaria, Example City
AS64500 / Example Hosting GmbH
База: Skipa | Совпадение: 203.0.113.0/24

🚫 IP заблокирован.
```

## Additional features

Available in the Telegram variant and enabled in `config.yaml`.

- **Extra sources** (`sources.extra`): Spamhaus DROP, FireHOL, AbuseIPDB or your own list.
  Each is shown in the alert under its own name.
- **Ban by button** (`banning.enabled`): a "🚫 Забанить" (Ban) button appears under the alert
  (duration `manual_ban_duration_minutes`). `auto_ban_new_hits` bans every detected IP
  automatically, `fail2ban_jail` duplicates the ban in fail2ban. History is written to
  `data/bans.jsonl`. Alternative: the filter and jail in [`fail2ban/`](fail2ban), which ban
  based on `detections.log`.
- **Statistics** (`/stats`, `/export`, weekly digest `digest.*`): events are written to
  `data/events.jsonl`. The chart is drawn by `matplotlib`
  (`pip install -r requirements-extras.txt`); without it you get a text histogram.
- **Dashboard** (`dashboard.enabled`): a page with database status, events, blocks and
  monitor state. It listens on `127.0.0.1`; open it through an SSH tunnel:
  `ssh -L 8080:localhost:8080 user@server`. Outside localhost, set `username`/`password`
  (HTTP Basic Auth) and keep it behind a TLS proxy.
- **Health-check** (`healthcheck.*`): if a monitor stays silent longer than
  `stale_after_minutes`, you get a warning, and a message again when it recovers.

## Operations

**Logs.**

| what | where |
| --- | --- |
| detections | `/var/log/skipa_watchdog/detections.log` |
| process | `/var/log/skipa_watchdog/skipa-watchdog.log`, `journalctl -u skipa-watchdog` |
| lists and timer (service only) | `journalctl -u skipa-watchdog-sync-lists -u skipa-watchdog-notify` |

**Reboot and rules.** The Telegram variant checks and repairs the jumps and ipset itself
every `monitoring.guard_interval_seconds` (60 s); the `skipa-watchdog-fw-rules.service` unit
is installed as well. In the "service only" variant, `skipa-watchdog-sync-lists.timer`
refills the ipset 10 minutes after boot and then on a schedule, while `iptables` rules must
be persisted by the system (`iptables-persistent`) or restored by running
`sudo bash install.sh fw-rules` after a reboot.

**Manual blocking.** From the menu (item 6), with `/block` in Telegram, or with
`sudo bash /opt/skipa_watchdog/service/blockctl.sh {block|unblock|list} [ip]`.
Blocks in the Telegram variant are saved in `data/blocked_ips.json` and restored on start.

**Service.** `skipa-watchdog.service` runs as root: it needs `iptables`, `ipset`, access to
conntrack and write access to the install directory and logs. Only safe restrictions are enabled
(`NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=full`, `RestrictAddressFamilies`, etc.); a strict
sandbox (`ProtectSystem=strict`, `ProtectKernelModules`) is not used: iptables loads kernel modules
and it broke startup on some systems.

**Updating.** Menu item 10 or `sudo bash install.sh install`. If `git pull` fails (the
repository history changed), the installer offers to switch to the current version;
`config.yaml` and `data/` are not touched.

**Uninstalling.** Menu item 11. The installer separately asks whether to remove the
`iptables` rules and `ipset` sets.

## Security

- `config.yaml` contains the bot token: the installer sets permissions to `600`.
- The bot token and API keys are masked in logs (`skipa-watchdog.log`, `journalctl`).
- Bot commands are accepted only from administrators (`admin_ids`, or the private chat with `chat_id`).
- Self-lockout protection is described above. If you still got cut off, log in through the
  host console and run `sudo skipa-watchdog`: item 6 unblocks a specific IP, item 11 removes
  the project along with its rules.
- Data from external APIs (organization, ASN) is escaped in Telegram and on the dashboard page, and
  newlines and control characters are stripped from it before it reaches text logs (otherwise a network
  owner could feed fail2ban a forged line with someone else's IP).
- A dashboard without `username` is open to anyone who can reach the port: do not expose it
  to the internet. If `dashboard.host` is not a loopback address and there is no login, the dashboard
  listens on `127.0.0.1` only and logs that.
- Report vulnerabilities to the repository owner privately, not in public issues.

## Troubleshooting

**An alert came for an IP that is "not in the rules".** Check whether the address belongs to
any of the lists, including ranges in the second list:

```bash
sudo ipset test skipa-scanners 66.132.186.215        # service only
sudo ipset test skipa-db 66.132.186.215              # service + Telegram (ipset)
```

Scanner networks in the lists are wider than a single address: for example,
`66.132.186.215` belongs to `66.132.186.0/24` from the second list. The matching network is
shown in the alert and in `detections.log`. Any packet from a scanner creates an entry: in
the "service only" variant the LOG rule fires on all protocols (you will see
`proto=UDP port=3478` in `detections.log`), and the packet is dropped after being logged.

**The menu says INPUT is not connected although the rules are in place.** Update the project
(item 10). The check used to look only for rules in the old form; now it looks for any
project rules in the chain.

**The service does not start.** `journalctl -u skipa-watchdog -n 50`. Common causes: no
`ipset` (the service runs in simplified iptables mode), an invalid `config.yaml`, the
dashboard port is taken.

**False positive on a legitimate scanner** (for example, your own security monitoring): add
its IP to `monitoring.ignore_ips`.

**Blocking does not work for containers.** Open menu item 5 → "Show current rules": the jump
to `SKIPA-BLOCK` must be present in `DOCKER-USER` as well. Docker started after the service
is picked up within a minute.

## Development

```bash
python3 -m unittest discover -s tests -t .     # 80+ tests, no root needed
shellcheck -S warning service/*.sh install-firewall-rules.sh
```

The tests replace `iptables` and `ipset` with fakes ([`tests/fakes.py`](tests/fakes.py)); CI
runs them on Python 3.10–3.13 together with `bash -n` and `shellcheck`.

Structure:

```
watchdog.py            entry point of the Telegram variant
install.sh             installer and menu
bot/                   Python modules (monitoring, blocking, lists, Telegram, dashboard)
service/               bash variant and the shared config.yaml reader library
fail2ban/              filter and jail (alternative way to ban)
tests/                 tests
config.example.yaml    template of the unified config
```

## License

[GNU GPLv3](LICENSE). Derivative works are distributed under the same open-source license.
