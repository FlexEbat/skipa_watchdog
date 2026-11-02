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
- **Self-healing.** After a reboot the rules and ipset sets (including saved blocks) come back
  on their own in both variants; a Docker restart or `ufw reload` is repaired by the Telegram variant.
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
| "Ban" button, charts in `/stats`, dashboard, health-check | no | yes |
| Extra sources (`sources.extra`: `cidr_list`, `abuseipdb`) | yes | yes |
| Protection after a reboot | units `skipa-watchdog-ipset` and `skipa-watchdog-rules` | process + `skipa-watchdog-fw-rules` |

You can start with the first variant and add Telegram later from the menu (item 4). Switching works
both ways on the fly, with no reinstall and no gap in protection: to go from the bot back to plain
bash use item 4 → "Switch to service only". Permanent manual blocks are carried over, `config.yaml`
(Telegram settings included) and `data/` stay, and the venv can be removed.

### What is available where

The panel (`sudo skipa-watchdog`), the bot and the service scripts do the same things; only the
way to invoke them differs. Edits to `config.yaml` from any of them go through the same code
(`service/confctl.sh`).

| Feature | Panel | Bot | Service without Python |
| --- | --- | --- | --- |
| Status, health check | item 1, `install.sh status` | `/status` | item 1, `install.sh status` |
| Update the IP database | item 9 | `/update` | item 9, `sync-lists` timer |
| Block / unblock | item 6 (for N hours or permanent) | `/block <ip> [hours]`, `/unblock` | none: blocking is fully automatic, exceptions via the allowlist |
| List of blocks | item 6 | `/blocklist` | item 6, `blockctl.sh list` |
| Allowlist | item 7 | `/allowlist`, `/allow`, `/unallow` | item 7, `blockctl.sh allow\|unallow\|allowlist` |
| Action mode, list source, method | item 3 | `/settings` | item 3 |
| Detection statistics | item 8, `install.sh stats` | `/stats` (with a chart), `/export` | item 8, `service/stats.sh` |
| Logs | item 10 | `/logs [lines]` | item 10 |
| Docker/Kubernetes | item 5 | `/env` | item 5 |
| Project update check | on every menu launch, item 12 | on service start: an "Install" button, `/version` | a log line; install from the panel |

Python-only by nature: the `/testalert` test notification, the `/pending` queue, the "Ban"
button in alerts, the dashboard, time-limited auto-blocking and manual block/unblock (in the service-only
variant everything is automatic, there is no manual blocking).

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

On every launch the menu checks whether a new project version is out and offers to install it.

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
| `updates.check_on_start` | `true` | check for project updates when the panel and the service start | yes |
| `sources.min_entries` | `10` | minimum entries a source must return on its FIRST download (protects against a three-line "garbage" list); lower it for a genuinely tiny custom list | yes |
| `firewall.keep_established_tcp` | `false` | do not cut established TCP sessions: block only new TCP connections (SYN) and all non-TCP traffic. Caution: a scanner that already opened a session keeps working within it. Implemented as a pair of DROP rules, not `RETURN` (in the built-in `INPUT`/`DOCKER-USER` it would skip the host's remaining rules). Re-apply the rules after changing it | yes |
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
item 11: edit the file) or by hand; after editing, apply the changes through the menu or with
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
| `/allowlist`, `/allow <ip or network>`, `/unallow <ip or network>` | allowlist (`monitoring.ignore_ips`): applied immediately, written to `config.yaml` |
| `/settings` | action mode, list source, detection method (with confirmation and a service restart) |
| `/logs [lines]` | last lines of the log (the bot token is masked) |
| `/version` | version and update check with an "Install" button |

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

Enabled in `config.yaml`. Extra sources work in both variants, the rest in the Telegram variant.

- **Extra sources** (`sources.extra`): Spamhaus DROP, FireHOL, AbuseIPDB or your own list
  (in both variants; types `cidr_list` and `abuseipdb`, fields `min_entries`/`min_confidence`).
  In the Telegram variant each is shown in the alert under its own name. `#` and `;` comments
  (Spamhaus format) are supported. IPv4 only: IPv6 entries from sources are skipped, but are
  now written to the log (`... IPv6 entries skipped`).
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
is installed as well.

In the "service only" variant ipset sets and rules live only in kernel memory, so they are saved
and brought back at boot (`/var/lib/skipa_watchdog/ipsets.save`, refreshed after every sync and
every allowlist change and every block carry-over on a mode switch):

- `skipa-watchdog-ipset.service` - early, before `netfilter-persistent`: restores the sets (or
  creates empty ones if there is no file). This matters: if the server has saved rules that
  reference `skipa-*` and the sets do not exist yet, `iptables-restore` rejects the whole rules
  file, leaving the server with no firewall at all;
- `skipa-watchdog-rules.service` - later, after Docker and kubelet (they provide the
  `DOCKER-USER` and `KUBE-*` chains): applies the rules and verifies the result;
- `skipa-watchdog-sync-lists.timer` refreshes the lists 10 minutes after boot and then on a schedule.

It cannot be a single unit: `After=docker.service` together with
`Before=netfilter-persistent.service` forms an ordering cycle (`netfilter-persistent` runs before
`network-pre.target`, Docker after `network-online.target`), and systemd would break it by
deleting an arbitrary job.

All operations on the sets (timer, menu item 9, `blockctl.sh`, applying rules, boot) run under a
single `flock` (`/var/lib/skipa_watchdog/ipset.lock)`, so they never overlap. After applying the
rules the script verifies that the sets exist and that `INPUT`, `DOCKER-USER` and `KUBE-*` carry
the rules, and prints the outcome (`✓`/`✗`); menu item 1 shows the same.
In the Telegram variant, if you persist rules yourself with `netfilter-persistent save`, note that
the process creates the sets on start: saved rules that reference `skipa-*` cannot load before it.

**Manual blocking** exists only in the Telegram variant: from the menu (item 6) or with `/block`.
Those blocks are saved in `data/blocked_ips.json` and restored on start. In the service-only variant
there is no manual block/unblock: everything is automatic (the kernel drops listed scanners, a timer
refreshes the list), and an address is exempted via the allowlist (item 7 or
`blockctl.sh allow <ip>`, which also lifts a block carried over on a mode switch).

**Switching mode.** Menu item 4. Service → service + bot: connect Telegram. Service + bot → service:
the Python process stops, the bash units and `ipset` rules come up, and only then the `SKIPA-BLOCK`
chain and the `skipa-dyn`/`skipa-db` sets are removed, so protection never lapses. Permanent blocks
are carried over; time-limited ones (auto-blocks included) are not.

**Service.** `skipa-watchdog.service` runs as root: it needs `iptables`, `ipset`, access to
conntrack and write access to the install directory and logs. Only safe restrictions are enabled
(`NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=full`, `RestrictAddressFamilies`, etc.); a strict
sandbox (`ProtectSystem=strict`, `ProtectKernelModules`) is not used: iptables loads kernel modules
and it broke startup on some systems.

**Updating.** On every launch the panel (`sudo skipa-watchdog`) checks whether a new version is out and offers to install it; declining is not permanent: a reminder stays in the menu header. When the service starts, the bot sends a message with an "Install" button to the chat (and `/version` on demand); without Telegram and in service-only mode a new version is noted in the log. `updates.check_on_start: false` turns the check off (`SKIPA_NO_UPDATE_CHECK=1` for a single run); `sudo bash install.sh check-update` checks without prompting (exit code 10 means an update is available). Manually: menu item 12 or `sudo bash install.sh install`. If `git pull` fails (the
repository history changed), the installer offers to switch to the current version;
`config.yaml` and `data/` are not touched.

**Uninstalling.** Menu item 13. The installer separately asks whether to remove the
`iptables` rules and `ipset` sets.

## Security

- `config.yaml` contains the bot token: the installer sets permissions to `600`.
- The bot token and API keys are masked in logs (`skipa-watchdog.log`, `journalctl`).
- Bot commands are accepted only from administrators (`admin_ids`, or the private chat with `chat_id`).
- Self-lockout protection is described above. If you still got cut off, log in through the
  host console and run `sudo skipa-watchdog`: in the Telegram variant item 6 unblocks a specific
  IP, in the service-only variant add the IP to the allowlist (item 7); item 13 removes the project
  along with its rules.
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
(item 12). The check used to look only for rules in the old form; now it looks for any
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
python3 -m unittest discover -s tests -t .     # 200+ tests, no root needed
shellcheck -S warning service/*.sh install-firewall-rules.sh
```

The tests replace `iptables` and `ipset` with fakes ([`tests/fakes.py`](tests/fakes.py),
[`tests/netfake.py`](tests/netfake.py)) and never touch the real firewall; CI runs them on
Python 3.10–3.13 together with `bash -n` and `shellcheck`. An end-to-end scenario of the "service
only" variant on real `ipset`/`iptables` (reboot, `iptables-restore`, flock) is opt-in because it
changes the host's sets and rules: `SKIPA_REAL_NETFILTER_TESTS=1 python3 -m unittest
tests.test_real_netfilter` as root in a disposable environment.

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
